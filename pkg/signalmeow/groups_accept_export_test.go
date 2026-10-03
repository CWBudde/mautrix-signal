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

// Authorization is injected; the HTTP and strict decoder remain production code.
func FetchGroupForAcceptanceForTest(ctx context.Context, key types.SerializedGroupMasterKey) (*Group, error) {
	cli := &Client{}
	return cli.fetchGroupForAcceptance(ctx, key, func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error) {
		return &GroupAuth{Username: "test-user", Password: "test-auth"}, nil
	})
}

// The credential callback validates that production requested the account ACI.
func GroupAcceptanceOnceForTest(ctx context.Context, key types.SerializedGroupMasterKey, revision uint32, invited libsignalgo.ServiceID, aci, pni uuid.UUID, server *libsignalgo.ServerPublicParams, credential *libsignalgo.ExpiringProfileKeyCredential, credentialErr, authErr error) (GroupInvitationAcceptOutcome, error) {
	cli := &Client{Store: &store.Device{DeviceData: store.DeviceData{ACI: aci, PNI: pni}}}
	return cli.acceptGroupInvitationOnce(ctx, key, revision, invited, server,
		func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error) {
			return &GroupAuth{Username: "test-user", Password: "test-auth"}, authErr
		},
		func(_ context.Context, id uuid.UUID) (*libsignalgo.ExpiringProfileKeyCredential, error) {
			if id != aci {
				return nil, ErrGroupAcceptanceInvalid
			}
			return credential, credentialErr
		})
}
