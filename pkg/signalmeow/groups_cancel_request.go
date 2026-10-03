// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"math"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

var (
	ErrGroupCancellationInvalid    = errors.New("invalid group join request cancellation data")
	ErrGroupCancellationUncertain  = errors.New("group join request cancellation outcome is uncertain; inspect before retrying")
	ErrGroupCancellationTerminated = errors.New("group is terminated")
)

func groupCancellationMasterKey(key types.SerializedGroupMasterKey) (libsignalgo.GroupMasterKey, error) {
	raw, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil || len(raw) != len(libsignalgo.GroupMasterKey{}) {
		return libsignalgo.GroupMasterKey{}, ErrGroupCancellationInvalid
	}
	return libsignalgo.GroupMasterKey(raw), nil
}

// PreviewGroupJoinRequest fetches a password-free authenticated preview for the
// selected account. Preview data is not full membership state and is not cached.
// Disabled invite links do not block this operation. Normal group authorization
// credential caching is retained; no profile credential is needed.
func (cli *Client) PreviewGroupJoinRequest(ctx context.Context, key types.SerializedGroupMasterKey) (GroupJoinPreview, error) {
	if cli == nil || cli.Store == nil || cli.Store.ACI == uuid.Nil {
		return GroupJoinPreview{}, ErrGroupCancellationInvalid
	}
	return previewGroupJoinRequest(ctx, key, cli.GetAuthorizationForToday)
}

func previewGroupJoinRequest(ctx context.Context, key types.SerializedGroupMasterKey, authorize groupJoinAuthorize) (preview GroupJoinPreview, err error) {
	master, err := groupCancellationMasterKey(key)
	if err != nil {
		return preview, err
	}
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	if err = ctx.Err(); err != nil {
		return preview, groupJoinSafeError("group request preview canceled", err)
	}
	auth, err := authorize(ctx, master)
	if err != nil {
		return preview, groupJoinSafeError("could not authorize group request preview", err)
	}
	response, err := groupCancellationHTTPRequest(ctx, http.MethodGet, nil, auth)
	if err != nil {
		return preview, err
	}
	preview, err = decodeGroupJoinPreview(response.Body, master)
	if err != nil {
		return GroupJoinPreview{}, groupJoinSafeError("could not validate group request preview", errors.Join(ErrGroupCancellationInvalid, err))
	}
	return preview, nil
}

func groupCancellationHTTPRequest(ctx context.Context, method string, body []byte, auth *GroupAuth) (groupJoinHTTPResult, error) {
	path := "/v2/groups/"
	switch method {
	case http.MethodGet:
		path += "join/"
	case http.MethodPatch:
	default:
		return groupJoinHTTPResult{}, ErrGroupCancellationInvalid
	}
	return groupMembershipHTTPRequest(ctx, method, path, body, auth, groupMembershipHTTPPolicy{
		Operation: "group request cancellation", Invalid: ErrGroupCancellationInvalid, Uncertain: ErrGroupCancellationUncertain, Terminated: ErrGroupCancellationTerminated,
		RejectEmpty: true, TransportHint: "; inspect before retrying",
	})
}

// GroupJoinRequestCancelOutcome preserves submission and HTTP acceptance even
// when verification fails. Only a verified outcome contains propagation artifacts.
// Verified proves the exact own ACI deletion at Revision, not future absence.
type GroupJoinRequestCancelOutcome struct {
	Attempted    bool
	Accepted     bool
	Verified     bool
	Revision     uint32
	GroupContext *signalpb.GroupContextV2
	Change       *GroupChange
}

// CancelGroupJoinRequestOnce deletes only the selected account's pending ACI
// request at revision+1. It does not retry, fetch full state/profile credentials,
// touch group-state caches/stores, persist keys, or notify members/devices. Normal
// authorization credential caching is retained. Callers must obtain a fresh
// preview and inspect Accepted/Attempted before considering another invocation.
func (cli *Client) CancelGroupJoinRequestOnce(ctx context.Context, key types.SerializedGroupMasterKey, revision uint32) (GroupJoinRequestCancelOutcome, error) {
	if cli == nil || cli.Store == nil {
		return GroupJoinRequestCancelOutcome{}, ErrGroupCancellationInvalid
	}
	return cli.cancelGroupJoinRequestOnce(ctx, key, revision, prodServerPublicParams, cli.GetAuthorizationForToday)
}

func (cli *Client) cancelGroupJoinRequestOnce(ctx context.Context, key types.SerializedGroupMasterKey, revision uint32, server *libsignalgo.ServerPublicParams, authorize groupJoinAuthorize) (out GroupJoinRequestCancelOutcome, err error) {
	master, err := groupCancellationMasterKey(key)
	if err != nil {
		return out, err
	}
	if cli == nil || cli.Store == nil || cli.Store.ACI == uuid.Nil || revision == math.MaxUint32 || server == nil {
		return out, ErrGroupCancellationInvalid
	}
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	if err = ctx.Err(); err != nil {
		return out, groupJoinSafeError("group request cancellation canceled before submission", err)
	}
	out.Revision = revision + 1
	secret, err := master.SecretParams()
	if err != nil {
		return out, groupJoinSafeError("could not derive group cancellation parameters", errors.Join(ErrGroupCancellationInvalid, err))
	}
	self := libsignalgo.NewACIServiceID(cli.Store.ACI)
	encryptedSelf, err := secret.EncryptServiceID(self)
	if err != nil {
		return out, groupJoinSafeError("could not encrypt own group request identity", errors.Join(ErrGroupCancellationInvalid, err))
	}
	actions := &signalpb.GroupChange_Actions{
		SourceUserId: self.Bytes(), Version: out.Revision,
		DeleteMembersPendingAdminApproval: []*signalpb.GroupChange_Actions_DeleteMemberPendingAdminApprovalAction{{DeletedUserId: bytes.Clone(encryptedSelf[:])}},
	}
	body, err := proto.Marshal(actions)
	if err != nil {
		return out, groupJoinSafeError("could not encode group request cancellation", errors.Join(ErrGroupCancellationInvalid, err))
	}
	auth, err := authorize(ctx, master)
	if err != nil {
		return out, groupJoinSafeError("could not authorize group request cancellation", err)
	}
	response, err := groupCancellationHTTPRequest(ctx, http.MethodPatch, body, auth)
	out.Attempted, out.Accepted = response.Attempted, response.Accepted
	if err != nil {
		return out, groupJoinSafeError("group request cancellation response failed; inspect before retrying", err)
	}
	changeContext, change, err := verifyGroupCancellationResponse(response.Body, key, master, secret, self, out.Revision, server)
	if err != nil {
		return out, groupJoinSafeError("group request cancellation accepted, but signed response could not be verified; inspect before retrying", err)
	}
	out.Verified, out.GroupContext, out.Change = true, changeContext, change
	return out, nil
}

func verifyGroupCancellationResponse(raw []byte, key types.SerializedGroupMasterKey, master libsignalgo.GroupMasterKey, secret libsignalgo.GroupSecretParams, self libsignalgo.ServiceID, revision uint32, server *libsignalgo.ServerPublicParams) (*signalpb.GroupContextV2, *GroupChange, error) {
	invalid := func() (*signalpb.GroupContextV2, *GroupChange, error) { return nil, nil, ErrGroupCancellationInvalid }
	response := &signalpb.GroupChangeResponse{}
	if err := proto.Unmarshal(raw, response); err != nil {
		return invalid()
	}
	signed := response.GroupChange
	if signed == nil || len(signed.Actions) == 0 || len(signed.ServerSignature) != len(libsignalgo.NotarySignature{}) || signed.ChangeEpoch > 7 || !groupJoinFields(signed, "actions", "serverSignature", "changeEpoch") {
		return invalid()
	}
	if err := libsignalgo.ServerPublicParamsVerifySignature(server, signed.Actions, libsignalgo.NotarySignature(signed.ServerSignature)); err != nil {
		return invalid()
	}
	actions := &signalpb.GroupChange_Actions{}
	if err := proto.Unmarshal(signed.Actions, actions); err != nil {
		return invalid()
	}
	id, err := master.GroupIdentifier()
	if err != nil || !bytes.Equal(actions.GroupId, id[:]) || actions.Version != revision || len(actions.SourceUserId) != len(libsignalgo.UUIDCiphertext{}) || !groupJoinFields(actions, "sourceUserId", "group_id", "version", "deleteMembersPendingAdminApproval") {
		return invalid()
	}
	source, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(actions.SourceUserId))
	if err != nil || source != self || len(actions.DeleteMembersPendingAdminApproval) != 1 {
		return invalid()
	}
	deletion := actions.DeleteMembersPendingAdminApproval[0]
	if deletion == nil || !groupJoinFields(deletion, "deletedUserId") || len(deletion.DeletedUserId) != len(libsignalgo.UUIDCiphertext{}) {
		return invalid()
	}
	deleted, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(deletion.DeletedUserId))
	if err != nil || deleted != self {
		return invalid()
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		return invalid()
	}
	deletedACI := deleted.UUID
	change := &GroupChange{GroupMasterKey: key, SourceServiceID: source, Revision: revision, DeleteRequestingMembers: []*uuid.UUID{&deletedACI}}
	return &signalpb.GroupContextV2{MasterKey: bytes.Clone(master[:]), Revision: &revision, GroupChange: signedBytes}, change, nil
}
