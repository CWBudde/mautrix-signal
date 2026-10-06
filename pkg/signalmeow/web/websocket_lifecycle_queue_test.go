// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only
package web_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/wspb"
)

func TestLifecycleFullQueueShutdownAndReconnect(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		name := "shutdown"
		if reconnect {
			name = "reconnect"
		}
		t.Run(name, func(t *testing.T) {
			ctx := lifecycleContext(t)
			peers := make(chan *websocket.Conn, 4)
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
				peers <- peer
				return &http.Response{StatusCode: writer.Code, Header: writer.Header(), Body: clientPipe}, nil
			})}
			defer func() { web.SignalHTTPClient = original }()
			entered, releaseHandler, decoded, releaseReader := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var handlerOnce, readerOnce sync.Once
			var decodedCount, calls atomic.Int32
			logger := zerolog.New(io.Discard).Level(zerolog.TraceLevel).Hook(lifecycleLogHook(func(message string) {
				if message == "Received WS request" && decodedCount.Add(1) == 258 {
					close(decoded)
					select {
					case <-releaseReader:
					case <-ctx.Done():
					}
				}
			}))
			loopCtx, cancel := context.WithCancel(logger.WithContext(ctx))
			socket := web.NewSignalWebsocket(nil)
			statuses := socket.Connect(loopCtx, func(handlerCtx context.Context, _ *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
				if calls.Add(1) == 1 {
					close(entered)
					select {
					case <-releaseHandler:
					case <-ctx.Done():
					}
				}
				return nil, handlerCtx.Err()
			})
			statusDone := make(chan struct{})
			go func() {
				defer close(statusDone)
				for range statuses {
				}
			}()
			var opened []*websocket.Conn
			defer func() {
				cancel()
				readerOnce.Do(func() { close(releaseReader) })
				handlerOnce.Do(func() { close(releaseHandler) })
				for _, peer := range opened {
					_ = peer.CloseNow()
				}
				_ = socket.Close()
				lifecycleWait(t, ctx, statusDone)
			}()
			nextPeer := func() *websocket.Conn {
				t.Helper()
				select {
				case peer := <-peers:
					opened = append(opened, peer)
					return peer
				case <-ctx.Done():
					t.Fatal("upgrade did not complete:", ctx.Err())
					return nil
				}
			}
			peer := nextPeer()
			send := func(id uint64) {
				t.Helper()
				verb, path, kind := http.MethodPut, "/fixture", signalpb.WebSocketMessage_REQUEST
				if err := wspb.Write(ctx, peer, &signalpb.WebSocketMessage{Type: &kind, Request: &signalpb.WebSocketRequestMessage{Id: &id, Verb: &verb, Path: &path}}); err != nil {
					t.Fatal(err)
				}
			}
			send(1)
			lifecycleWait(t, ctx, entered)
			for id := uint64(2); id <= 258; id++ {
				send(id)
			}
			lifecycleWait(t, ctx, decoded) // active handler + 256 queued + reader awaiting enqueue
			if reconnect {
				socket.ForceReconnect()
				readerOnce.Do(func() { close(releaseReader) })
				peer = nextPeer() // reconnect must finish even while the handler remains gated
				result := make(chan error, 1)
				go func() { _, err := socket.SendRequest(ctx, http.MethodGet, "/reconnected", nil, nil); result <- err }()
				request := &signalpb.WebSocketMessage{}
				if err := wspb.Read(ctx, peer, request); err != nil {
					t.Fatal(err)
				}
				if err := wspb.Write(ctx, peer, web.CreateWSResponse(ctx, request.GetRequest().GetId(), http.StatusOK)); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			cancel()
			readerOnce.Do(func() { close(releaseReader) })
			for _, peer := range opened {
				_ = peer.CloseNow()
			}
			closed := make(chan struct{})
			go func() { _ = socket.Close(); close(closed) }()
			select {
			case <-closed:
				t.Error("Close returned before gated handler")
			case <-time.After(lifecycleWatchdog):
			}
			handlerOnce.Do(func() { close(releaseHandler) })
			lifecycleWait(t, ctx, closed)
			lifecycleWait(t, ctx, statusDone)
			if got := calls.Load(); got != 1 {
				t.Errorf("handled %d requests; queued requests must be discarded on shutdown", got)
			}
		})
	}
}
