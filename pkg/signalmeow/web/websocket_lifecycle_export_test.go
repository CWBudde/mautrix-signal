// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only
package web

import (
	"context"
	"sync"

	"github.com/coder/websocket"
	"go.mau.fi/util/exsync"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
)

// RunLifecycleReadForTest retains the production reader and queue send. Dialing,
// handler dispatch and the connection coordinator are outside this queue probe.
func RunLifecycleReadForTest(ctx context.Context, conn *websocket.Conn, incoming chan *signalpb.WebSocketRequestMessage) error {
	return readLoop(ctx, conn, incoming, exsync.NewMap[uint64, websocketPendingResponse]())
}

// RunLifecycleRequestLoopsForTest exercises the real reader, writer and public
// SendRequest without the coordinator. Teardown joins workers before draining
// responses so even a failed fixture can release and join its caller.
// This teardown is fixture cleanup, not a reproduction of production cleanup.
func RunLifecycleRequestLoopsForTest(ctx context.Context, conn *websocket.Conn) (*SignalWebsocket, func()) {
	ctx, cancel := context.WithCancel(ctx)
	socket := NewSignalWebsocket(nil)
	responses := exsync.NewMap[uint64, websocketPendingResponse]()
	incoming := make(chan *signalpb.WebSocketRequestMessage, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = readLoop(ctx, conn, incoming, responses) }()
	go func() { defer wg.Done(); _ = writeLoop(ctx, conn, socket.sendChannel, responses) }()
	return socket, func() {
		cancel()
		_ = conn.CloseNow()
		wg.Wait()
		for _, pending := range responses.SwapData(nil) {
			close(pending.channel)
		}
	}
}
