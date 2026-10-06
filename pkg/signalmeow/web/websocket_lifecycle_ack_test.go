// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only
package web_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/wspb"
)

// lifecycleConnect runs the complete Connect lifecycle over a net.Pipe peer. Cleanup cancels
// the connection, closes the socket and joins the status drain; release gates first.
func lifecycleConnect(t *testing.T, ctx context.Context, handler web.RequestHandlerFunc) (*web.SignalWebsocket, *websocket.Conn, context.CancelFunc) {
	t.Helper()
	peerReady := make(chan *websocket.Conn, 1)
	original := web.SignalHTTPClient
	web.SignalHTTPClient = &http.Client{Transport: websocketFixtureTransport(func(req *http.Request) (*http.Response, error) {
		clientPipe, serverPipe := net.Pipe()
		writer := &websocketUpgradeRecorder{ResponseRecorder: httptest.NewRecorder(), connection: serverPipe}
		peer, err := websocket.Accept(writer, req, nil)
		if err != nil {
			_ = clientPipe.Close()
			_ = serverPipe.Close()
			return nil, err
		}
		peerReady <- peer
		return &http.Response{StatusCode: writer.Code, Header: writer.Header(), Body: clientPipe}, nil
	})}
	loopCtx, cancel := context.WithCancel(ctx)
	socket := web.NewSignalWebsocket(nil)
	status := socket.Connect(loopCtx, handler)
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		for range status {
		}
	}()
	var peer *websocket.Conn
	select {
	case peer = <-peerReady:
	case <-ctx.Done():
		t.Fatal("upgrade did not complete:", ctx.Err())
	}
	t.Cleanup(func() {
		// t.Context is already canceled during cleanup.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cancel()
		_ = peer.CloseNow()
		closed := make(chan struct{})
		go func() { _ = socket.Close(); close(closed) }()
		lifecycleWait(t, cleanupCtx, closed)
		lifecycleWait(t, cleanupCtx, statusDone)
		web.SignalHTTPClient = original
	})
	return socket, peer, cancel
}

func lifecycleSendRequest(t *testing.T, ctx context.Context, peer *websocket.Conn, id uint64) {
	t.Helper()
	verb, path, kind := http.MethodPut, "/api/v1/message", signalpb.WebSocketMessage_REQUEST
	if err := wspb.Write(ctx, peer, &signalpb.WebSocketMessage{Type: &kind, Request: &signalpb.WebSocketRequestMessage{Id: &id, Verb: &verb, Path: &path}}); err != nil {
		t.Fatal(err)
	}
}

// lifecycleReadMessage reads the next message the client wrote, as "response <id>" or
// "request <path>".
func lifecycleReadMessage(t *testing.T, ctx context.Context, peer *websocket.Conn) (string, *signalpb.WebSocketMessage) {
	t.Helper()
	msg := &signalpb.WebSocketMessage{}
	if err := wspb.Read(ctx, peer, msg); err != nil {
		t.Fatal("peer read:", err)
	}
	if msg.GetType() == signalpb.WebSocketMessage_RESPONSE {
		return "response", msg
	}
	return "request " + msg.GetRequest().GetPath(), msg
}

func lifecycleWaitResult(t *testing.T, ctx context.Context, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatal("fixture did not complete:", ctx.Err())
		return nil
	}
}

func lifecycleStillBlocked(t *testing.T, result <-chan error, what string) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("%s returned early: %v", what, err)
	case <-time.After(lifecycleWatchdog):
	}
}

// A caller that has seen the handler hand out an event waits for its response to be queued
// before it flushes with a request of its own, so the acknowledgement precedes the flush on
// the wire even when the handler works on after handing the event out.
func TestLifecycleAckFlushWaitsForHandler(t *testing.T) {
	ctx := lifecycleContext(t)
	if err := web.NewSignalWebsocket(nil).WaitResponseQueued(ctx); err != nil {
		t.Fatal("no request handled yet:", err)
	}
	handedOut, release := make(chan struct{}), make(chan struct{})
	refused := make(chan struct{})
	var releaseOnce sync.Once
	socket, peer, _ := lifecycleConnect(t, ctx, func(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
		switch req.GetId() {
		case 1:
			close(handedOut)
			select {
			case <-release:
			case <-ctx.Done():
			}
		case 2:
			close(refused)
			return nil, errors.New("event refused")
		}
		return &web.SimpleResponse{Status: http.StatusOK}, nil
	})
	// Registered after the connection's cleanup, so it runs first and unblocks the handler.
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	lifecycleSendRequest(t, ctx, peer, 1)
	lifecycleWait(t, ctx, handedOut)

	flushed := make(chan error, 1)
	go func() {
		if err := socket.WaitResponseQueued(ctx); err != nil {
			flushed <- err
			return
		}
		_, err := socket.SendRequest(ctx, http.MethodGet, "/v1/keepalive", nil, nil)
		flushed <- err
	}()
	lifecycleStillBlocked(t, flushed, "flush")
	releaseOnce.Do(func() { close(release) })

	kind, msg := lifecycleReadMessage(t, ctx, peer)
	if kind != "response" || msg.GetResponse().GetId() != 1 {
		t.Fatalf("first message is %s %v, want the response to request 1", kind, msg)
	}
	kind, msg = lifecycleReadMessage(t, ctx, peer)
	if kind != "request /v1/keepalive" {
		t.Fatalf("second message is %s, want the keepalive", kind)
	}
	status := uint32(http.StatusOK)
	respKind := signalpb.WebSocketMessage_RESPONSE
	if err := wspb.Write(ctx, peer, &signalpb.WebSocketMessage{Type: &respKind, Response: &signalpb.WebSocketResponseMessage{Id: msg.GetRequest().Id, Status: &status}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycleWaitResult(t, ctx, flushed); err != nil {
		t.Fatal("flush:", err)
	}

	// A refused request queues nothing; waiting for it ends with the handler.
	lifecycleSendRequest(t, ctx, peer, 2)
	lifecycleWait(t, ctx, refused)
	if err := socket.WaitRequestDone(ctx); err != nil {
		t.Fatal("refused request:", err)
	}
	lifecycleSendRequest(t, ctx, peer, 3)
	if kind, msg := lifecycleReadMessage(t, ctx, peer); kind != "response" || msg.GetResponse().GetId() != 3 {
		t.Fatalf("got %s %v, want the response to request 3 and none to the refused request 2", kind, msg)
	}
}

// AfterQueued work runs after the response is queued: the acknowledgement neither waits for
// it nor depends on it, and WaitRequestDone covers it.
func TestLifecycleAfterQueuedFollowsAck(t *testing.T) {
	ctx := lifecycleContext(t)
	entered, release, afterDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	socket, peer, _ := lifecycleConnect(t, ctx, func(context.Context, *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
		return &web.SimpleResponse{Status: http.StatusOK, AfterQueued: func(ctx context.Context) {
			defer close(afterDone)
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}}, nil
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	lifecycleSendRequest(t, ctx, peer, 1)
	lifecycleWait(t, ctx, entered)
	if err := socket.WaitResponseQueued(ctx); err != nil {
		t.Fatal(err)
	}
	// The peer receives the acknowledgement while the after-work is still blocked.
	if kind, msg := lifecycleReadMessage(t, ctx, peer); kind != "response" || msg.GetResponse().GetId() != 1 {
		t.Fatalf("got %s %v, want the response to request 1", kind, msg)
	}
	done := make(chan error, 1)
	go func() { done <- socket.WaitRequestDone(ctx) }()
	lifecycleStillBlocked(t, done, "WaitRequestDone")
	waitCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := socket.WaitRequestDone(waitCtx); !errors.Is(err, context.Canceled) {
		t.Errorf("WaitRequestDone with a canceled context = %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := lifecycleWaitResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, ctx, afterDone)
}

// A response that cannot be queued because the connection shuts down is not acknowledged,
// and its AfterQueued work is skipped.
func TestLifecycleAfterQueuedSkippedOnShutdown(t *testing.T) {
	ctx := lifecycleContext(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var mu sync.Mutex
	ran := false
	socket, peer, cancel := lifecycleConnect(t, ctx, func(context.Context, *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
		close(entered)
		<-release
		return &web.SimpleResponse{Status: http.StatusOK, AfterQueued: func(context.Context) {
			mu.Lock()
			ran = true
			mu.Unlock()
		}}, nil
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	lifecycleSendRequest(t, ctx, peer, 1)
	lifecycleWait(t, ctx, entered)
	cancel()
	releaseOnce.Do(func() { close(release) })
	if err := socket.WaitRequestDone(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if ran {
		t.Error("AfterQueued ran although the response was not queued")
	}
}
