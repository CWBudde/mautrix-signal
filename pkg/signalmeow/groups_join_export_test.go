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

// Test adapters inject authorization; requests and decoding use production code.
func PreviewGroupJoinForTest(ctx context.Context, key types.SerializedGroupMasterKey, password []byte) (GroupJoinPreview, error) {
	return previewGroupJoin(ctx, key, password, func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error) {
		return &GroupAuth{Username: "test-user", Password: "test-auth"}, nil
	})
}
func GroupJoinHTTPForTest(ctx context.Context, method string, password []byte) ([]byte, bool, bool, error) {
	result, err := groupJoinHTTPRequest(ctx, method, password, nil, &GroupAuth{Username: "test-user", Password: "test-auth"})
	return result.Body, result.Attempted, result.Accepted, err
}

// Both backends use the same real crypto with test public parameters; production
// methods always select the pinned production parameters and credential fetcher.
func GroupJoinOnceForTest(ctx context.Context, key types.SerializedGroupMasterKey, password []byte, preview GroupJoinPreview, self uuid.UUID, server *libsignalgo.ServerPublicParams, credential *libsignalgo.ExpiringProfileKeyCredential, credentialErr, authErr error) (GroupJoinOutcome, error) {
	cli := &Client{Store: &store.Device{DeviceData: store.DeviceData{ACI: self}}}
	return cli.joinGroupOnce(ctx, key, password, preview, server,
		func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error) {
			return &GroupAuth{Username: "test-user", Password: "test-auth"}, authErr
		},
		func(context.Context, uuid.UUID) (*libsignalgo.ExpiringProfileKeyCredential, error) {
			return credential, credentialErr
		})
}
