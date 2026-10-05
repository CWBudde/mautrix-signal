// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package web_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

// Cancellation while dialing tears down connectLoop while the request handler
// goroutine is still selecting on its incoming channel. Under -race this catches
// clearing the shared channel variable during cleanup, even with no requests.
func TestWebsocketShutdownWhileDialing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dialStarted := make(chan struct{}, 1)
	original := web.SignalHTTPClient.Transport
	web.SignalHTTPClient.Transport = websocketFixtureTransport(func(req *http.Request) (*http.Response, error) {
		dialStarted <- struct{}{}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	defer func() { web.SignalHTTPClient.Transport = original }()

	for range 32 {
		loopCtx, cancelLoop := context.WithCancel(ctx)
		socket := web.NewSignalWebsocket(nil)
		status := socket.Connect(loopCtx, nil)
		select {
		case <-dialStarted:
		case <-ctx.Done():
			cancelLoop()
			t.Fatal("websocket did not start dialing:", ctx.Err())
		}
		cancelLoop()
	drain:
		for {
			select {
			case _, ok := <-status:
				if !ok {
					break drain
				}
			case <-ctx.Done():
				t.Fatal("websocket did not shut down:", ctx.Err())
			}
		}
		if err := socket.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
