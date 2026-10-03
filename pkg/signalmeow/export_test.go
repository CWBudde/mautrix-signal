// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"

	"github.com/google/uuid"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

// Authorization is injected; preview transport and validation are production code.
func PreviewGroupJoinRequestForTest(ctx context.Context, key types.SerializedGroupMasterKey) (GroupJoinPreview, error) {
	return previewGroupJoinRequest(ctx, key, func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error) {
		return &GroupAuth{Username: "test-user", Password: "test-auth"}, nil
	})
}

// Inject only the nonproduction signature parameters and authorization; the
// wire action, single HTTP attempt, and signed-response gate are production code.
func GroupJoinRequestCancellationOnceForTest(ctx context.Context, key types.SerializedGroupMasterKey, revision uint32, aci uuid.UUID, server *libsignalgo.ServerPublicParams, authErr error) (GroupJoinRequestCancelOutcome, error) {
	cli := &Client{Store: &store.Device{DeviceData: store.DeviceData{ACI: aci}}}
	return cli.cancelGroupJoinRequestOnce(ctx, key, revision, server, func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error) {
		return &GroupAuth{Username: "test-user", Password: "test-auth"}, authErr
	})
}
