// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"time"

	"github.com/coder/websocket"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
)

// ProvisioningMessageForTest exercises the scan stage with an offline websocket opener.
func ProvisioningMessageForTest(ctx context.Context, refresh time.Duration, open func(context.Context) (*websocket.Conn, error), onURL func(string)) (*signalpb.ProvisionMessage, error) {
	return awaitProvisioningMessage(ctx, false, refresh, open, onURL)
}
