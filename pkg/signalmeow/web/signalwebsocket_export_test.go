// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"context"
	"sync"

	"github.com/coder/websocket"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"go.mau.fi/util/exsync"
)

// Runs the production queue and read/write loops with a fixture connection;
// only dialing/reconnect/ping lifecycle is replaced in the offline test.
func RunWebsocketLoopsForTest(ctx context.Context, conn *websocket.Conn) (*SignalWebsocket, func()) {
	ctx, cancel := context.WithCancel(ctx)
	socket := NewSignalWebsocket(nil)
	responses := exsync.NewMap[uint64, websocketPendingResponse]()
	incoming := make(chan *signalpb.WebSocketRequestMessage, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = readLoop(ctx, conn, incoming, responses) }()
	go func() { defer wg.Done(); _ = writeLoop(ctx, conn, socket.sendChannel, responses) }()
	return socket, func() { cancel(); _ = conn.CloseNow(); wg.Wait() }
}
