// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

func openProvisioningSocket(ctx context.Context) (*websocket.Conn, error) {
	ws, _, err := web.OpenWebsocket(ctx, (&url.URL{
		Scheme: "wss", Host: web.APIHostname, Path: web.WebsocketProvisioningPath,
	}).String())
	return ws, err
}

func awaitProvisioningMessage(ctx context.Context, allowBackup bool, refresh time.Duration,
	open func(context.Context) (*websocket.Conn, error), onURL func(string),
) (*signalpb.ProvisionMessage, error) {
	timeout := refresh
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		message, expired, err := provisioningScan(ctx, allowBackup, timeout, open, onURL)
		if refresh > 0 && expired && ctx.Err() == nil {
			continue
		}
		return message, err
	}
}

func provisioningScan(ctx context.Context, allowBackup bool, timeout time.Duration,
	open func(context.Context) (*websocket.Conn, error), onURL func(string),
) (*signalpb.ProvisionMessage, bool, error) {
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ws, err := open(scanCtx)
	if err != nil {
		return nil, false, err
	}
	defer ws.CloseNow()
	cipher := NewProvisioningCipher()
	uri, err := startProvisioning(scanCtx, ws, cipher, allowBackup)
	if err != nil {
		return nil, false, err
	}
	onURL(uri)
	envelope, err := readProvisioningEnvelope(scanCtx, ws)
	if err != nil {
		expired := envelope == nil && errors.Is(err, context.DeadlineExceeded) && errors.Is(scanCtx.Err(), context.DeadlineExceeded)
		return nil, expired, err
	}
	// Stop the refresh deadline before decrypting. Once the phone has submitted
	// an envelope, no error may trigger another scan or a second registration.
	cancel()
	message, err := cipher.Decrypt(envelope)
	return message, false, err
}
