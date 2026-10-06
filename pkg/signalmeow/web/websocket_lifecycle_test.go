// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only
package web_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/wspb"
)

const lifecycleWatchdog = 150 * time.Millisecond

func lifecycleContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func lifecycleWait(t *testing.T, ctx context.Context, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("fixture did not complete:", ctx.Err())
	}
}

// Run separately with -race. An already-canceled context performs no HTTP dial.
func TestLifecycleImmediateCancellation(t *testing.T) {
	ctx := lifecycleContext(t)
	for range 128 {
		loopCtx, cancel := context.WithCancel(ctx)
		cancel()
		socket := web.NewSignalWebsocket(nil)
		status := socket.Connect(loopCtx, nil)
		if status == nil {
			t.Fatal("Connect returned a nil status channel")
		}
	drain:
		for {
			select {
			case _, ok := <-status:
				if !ok {
					break drain
				}
			case <-ctx.Done():
				t.Fatal("status channel did not close:", ctx.Err())
			}
		}
		_ = socket.Close()
	}
}

// Full Connect/Close lifecycle with an explicitly gated request handler. All
// HTTP upgrades use net.Pipe, following the pinned fork's websocketPair fixture.
func TestLifecycleCloseWaitsForHandler(t *testing.T) {
	ctx := lifecycleContext(t)
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
	defer func() { web.SignalHTTPClient = original }()
	entered, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	// Always release a gated handler, including when fixture setup fails.
	defer func() {
		releaseOnce.Do(func() { close(release) })
		select {
		case <-entered:
			lifecycleWait(t, ctx, handlerDone)
		default:
		}
	}()
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	socket := web.NewSignalWebsocket(nil)
	status := socket.Connect(loopCtx, func(context.Context, *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		close(handlerDone)
		return nil, nil
	})
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
	defer peer.CloseNow()
	id, verb, path, kind := uint64(1), http.MethodPut, "/fixture", signalpb.WebSocketMessage_REQUEST
	if err := wspb.Write(ctx, peer, &signalpb.WebSocketMessage{Type: &kind, Request: &signalpb.WebSocketRequestMessage{Id: &id, Verb: &verb, Path: &path}}); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, ctx, entered)
	cancel()
	_ = peer.CloseNow()
	closed := make(chan struct{})
	go func() { _ = socket.Close(); close(closed) }()
	select {
	case <-closed:
		t.Error("Close returned before the request handler completed")
	case <-time.After(lifecycleWatchdog):
	}
	// A caller with a live context must be released before the handler join.
	// Otherwise it could retain closeLock.RLock and deadlock channel cleanup.
	sendDone := make(chan struct{})
	go func() {
		_, err := socket.SendRequest(ctx, http.MethodGet, "/during-shutdown", nil, nil)
		if err == nil {
			t.Error("request accepted after shutdown")
		}
		close(sendDone)
	}()
	lifecycleWait(t, ctx, sendDone)
	releaseOnce.Do(func() { close(release) })
	lifecycleWait(t, ctx, handlerDone)
	lifecycleWait(t, ctx, statusDone)
	lifecycleWait(t, ctx, closed)
}

type lifecycleLogHook func(string)

func (h lifecycleLogHook) Run(_ *zerolog.Event, _ zerolog.Level, message string) { h(message) }

func TestLifecycleFullQueueCancellation(t *testing.T) {
	ctx := lifecycleContext(t)
	conn, peer, err := websocketPair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	defer peer.CloseNow()
	incoming := make(chan *signalpb.WebSocketRequestMessage, 256)
	for range cap(incoming) {
		incoming <- &signalpb.WebSocketRequestMessage{}
	}
	decoded, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	logger := zerolog.New(io.Discard).Level(zerolog.TraceLevel).Hook(lifecycleLogHook(func(message string) {
		if message == "Received WS request" {
			close(decoded)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}))
	readCtx, cancel := context.WithCancel(logger.WithContext(ctx))
	defer cancel()
	result := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		result <- web.RunLifecycleReadForTest(readCtx, conn, incoming)
	}()
	defer func() {
		cancel()
		releaseOnce.Do(func() { close(release) })
		_ = conn.CloseNow()
		select {
		case <-incoming:
		default:
		}
		lifecycleWait(t, ctx, readerDone)
	}()
	id, verb, path, kind := uint64(2), http.MethodPut, "/fixture", signalpb.WebSocketMessage_REQUEST
	if err := wspb.Write(ctx, peer, &signalpb.WebSocketMessage{Type: &kind, Request: &signalpb.WebSocketRequestMessage{Id: &id, Verb: &verb, Path: &path}}); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, ctx, decoded)
	cancel()
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(lifecycleWatchdog):
		t.Error("reader stayed blocked on a full queue after cancellation")
		<-incoming // Release the production queue send, then join the reader.
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("reader did not exit after queue space was freed:", ctx.Err())
		}
	}
}

func TestLifecycleRequestCancellation(t *testing.T) {
	ctx := lifecycleContext(t)
	conn, peer, err := websocketPair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseNow()
	socket, stop := web.RunLifecycleRequestLoopsForTest(ctx, conn)
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	callerDone := make(chan struct{})
	go func() {
		defer close(callerDone)
		_, err := socket.SendRequest(requestCtx, http.MethodGet, "/fixture", nil, nil)
		result <- err
	}()
	defer func() {
		cancel()
		stop()
		lifecycleWait(t, ctx, callerDone)
	}()
	request := &signalpb.WebSocketMessage{}
	if err := wspb.Read(ctx, peer, request); err != nil {
		t.Fatal(err)
	}
	cancel() // The peer's read proves enqueue and write completed first.
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("canceled request returned %v", err)
		}
		// A late response still belongs to the reader; cancellation must not
		// close its channel or prevent a subsequent request from succeeding.
		if err := wspb.Write(ctx, peer, web.CreateWSResponse(ctx, request.GetRequest().GetId(), http.StatusOK)); err != nil {
			t.Fatal(err)
		}
		next := make(chan error, 1)
		go func() { _, err := socket.SendRequest(ctx, http.MethodGet, "/next", nil, nil); next <- err }()
		if err := wspb.Read(ctx, peer, request); err != nil {
			t.Fatal(err)
		}
		if err := wspb.Write(ctx, peer, web.CreateWSResponse(ctx, request.GetRequest().GetId(), http.StatusOK)); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-next:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	case <-time.After(lifecycleWatchdog):
		t.Error("request stayed waiting for a response after cancellation")
		// Supply the missing response so the original caller can finish.
		if err := wspb.Write(ctx, peer, web.CreateWSResponse(ctx, request.GetRequest().GetId(), http.StatusOK)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-result:
		case <-ctx.Done():
			t.Fatal("request did not finish after the fixture response:", ctx.Err())
		}
	}
}
