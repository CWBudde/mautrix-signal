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
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

var (
	ErrGroupAcceptanceInvalid    = errors.New("invalid group invitation acceptance data")
	ErrGroupAcceptanceUncertain  = errors.New("group invitation acceptance outcome is uncertain; inspect membership before retrying")
	ErrGroupAcceptanceTerminated = errors.New("group is terminated")
)

func groupAcceptanceMasterKey(key types.SerializedGroupMasterKey) (libsignalgo.GroupMasterKey, error) {
	raw, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil || len(raw) != len(libsignalgo.GroupMasterKey{}) {
		return libsignalgo.GroupMasterKey{}, ErrGroupAcceptanceInvalid
	}
	return libsignalgo.GroupMasterKey(raw), nil
}

// GroupInvitationAcceptOutcome distinguishes HTTP acceptance from signed-change
// verification. Full own ACI membership still requires a fresh full-state read.
type GroupInvitationAcceptOutcome struct {
	Attempted    bool
	Accepted     bool
	Verified     bool
	Revision     uint32
	GroupContext *signalpb.GroupContextV2
	Change       *GroupChange
}

// AcceptGroupInvitationOnce promotes only the selected account's invitation.
// It never fetches full state, retries, reads or updates the group-state
// cache/store, persists master keys, or sends notifications. It retains normal
// authorization credential caching through GetAuthorizationForToday.
func (cli *Client) AcceptGroupInvitationOnce(ctx context.Context, key types.SerializedGroupMasterKey, revision uint32, invited libsignalgo.ServiceID) (GroupInvitationAcceptOutcome, error) {
	if cli == nil || cli.Store == nil {
		return GroupInvitationAcceptOutcome{}, ErrGroupAcceptanceInvalid
	}
	return cli.acceptGroupInvitationOnce(ctx, key, revision, invited, prodServerPublicParams, cli.GetAuthorizationForToday, cli.FetchExpiringProfileKeyCredentialById)
}

func (cli *Client) acceptGroupInvitationOnce(ctx context.Context, key types.SerializedGroupMasterKey, revision uint32, invited libsignalgo.ServiceID, server *libsignalgo.ServerPublicParams, authorize groupJoinAuthorize, credential groupJoinCredential) (out GroupInvitationAcceptOutcome, err error) {
	master, err := groupAcceptanceMasterKey(key)
	if err != nil {
		return out, err
	}
	if cli == nil || cli.Store == nil || cli.Store.ACI == uuid.Nil || revision == math.MaxUint32 {
		return out, ErrGroupAcceptanceInvalid
	}
	self := libsignalgo.NewACIServiceID(cli.Store.ACI)
	if invited != self && (cli.Store.PNI == uuid.Nil || invited != libsignalgo.NewPNIServiceID(cli.Store.PNI)) {
		return out, ErrGroupAcceptanceInvalid
	}
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	if err = ctx.Err(); err != nil {
		return out, groupJoinSafeError("group acceptance canceled before submission", err)
	}
	out.Revision = revision + 1
	secret, err := master.SecretParams()
	if err != nil {
		return out, groupJoinSafeError("could not derive group acceptance parameters", err)
	}
	own, err := credential(ctx, cli.Store.ACI)
	if err != nil {
		return out, groupJoinSafeError("could not obtain own acceptance credential", err)
	}
	if own == nil || server == nil {
		return out, ErrGroupAcceptanceInvalid
	}
	presentation, err := secret.CreateExpiringProfileKeyCredentialPresentation(server, *own)
	if err != nil {
		return out, groupJoinSafeError("could not prepare acceptance presentation", err)
	}
	expectedID, expectedKey, err := decryptPKeyAndIDorPresentation(ctx, nil, nil, *presentation, secret)
	if err != nil {
		return out, groupJoinSafeError("could not validate own acceptance presentation", err)
	}
	if *expectedID != self.UUID {
		return out, ErrGroupAcceptanceInvalid
	}
	actions := &signalpb.GroupChange_Actions{Version: out.Revision, SourceUserId: invited.Bytes()}
	if invited.Type == libsignalgo.ServiceIDTypePNI {
		actions.PromoteMembersPendingPniAciProfileKey = []*signalpb.GroupChange_Actions_PromoteMemberPendingPniAciProfileKeyAction{{Presentation: bytes.Clone(*presentation)}}
	} else {
		actions.PromoteMembersPendingProfileKey = []*signalpb.GroupChange_Actions_PromoteMemberPendingProfileKeyAction{{Presentation: bytes.Clone(*presentation)}}
	}
	body, err := proto.Marshal(actions)
	if err != nil {
		return out, groupJoinSafeError("could not encode group acceptance", err)
	}
	auth, err := authorize(ctx, master)
	if err != nil {
		return out, groupJoinSafeError("could not authorize group acceptance", err)
	}
	response, err := groupAcceptanceHTTPRequest(ctx, http.MethodPatch, body, auth)
	out.Attempted = response.Attempted
	out.Accepted = response.Accepted
	if err != nil {
		return out, groupJoinSafeError("group acceptance response failed; inspect membership before retrying", err)
	}
	context, change, err := verifyGroupAcceptanceResponse(ctx, response.Body, key, master, secret, self, invited, *expectedKey, out.Revision, server)
	if err != nil {
		return out, groupJoinSafeError("group invitation accepted, but signed response could not be verified; inspect membership before retrying", err)
	}
	out.Verified = true
	out.GroupContext = context
	out.Change = change
	return out, nil
}

func verifyGroupAcceptanceResponse(ctx context.Context, raw []byte, key types.SerializedGroupMasterKey, master libsignalgo.GroupMasterKey, secret libsignalgo.GroupSecretParams, self, invited libsignalgo.ServiceID, profileKey libsignalgo.ProfileKey, revision uint32, server *libsignalgo.ServerPublicParams) (*signalpb.GroupContextV2, *GroupChange, error) {
	invalid := func() (*signalpb.GroupContextV2, *GroupChange, error) { return nil, nil, ErrGroupAcceptanceInvalid }
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
	groupID, err := master.GroupIdentifier()
	if err != nil {
		return invalid()
	}
	if !bytes.Equal(actions.GroupId, groupID[:]) || actions.Version != revision || len(actions.SourceUserId) != len(libsignalgo.UUIDCiphertext{}) {
		return invalid()
	}
	field := protoreflect.Name("promoteMembersPendingProfileKey")
	pni := invited.Type == libsignalgo.ServiceIDTypePNI
	if pni {
		field = "promote_members_pending_pni_aci_profile_key"
	}
	if !groupJoinFields(actions, "sourceUserId", "group_id", "version", field) {
		return invalid()
	}
	source, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(actions.SourceUserId))
	if err != nil || (source != self && (!pni || source != invited)) {
		return invalid()
	}
	var userID, keyBytes, presentation []byte
	if pni {
		if len(actions.PromoteMembersPendingPniAciProfileKey) != 1 {
			return invalid()
		}
		promotion := actions.PromoteMembersPendingPniAciProfileKey[0]
		if promotion == nil || !groupJoinFields(promotion, "presentation", "user_id", "pni", "profile_key") || len(promotion.Pni) != len(libsignalgo.UUIDCiphertext{}) {
			return invalid()
		}
		decryptedPNI, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(promotion.Pni))
		if err != nil || decryptedPNI != invited {
			return invalid()
		}
		userID, keyBytes, presentation = promotion.UserId, promotion.ProfileKey, promotion.Presentation
	} else {
		if len(actions.PromoteMembersPendingProfileKey) != 1 {
			return invalid()
		}
		promotion := actions.PromoteMembersPendingProfileKey[0]
		if promotion == nil || !groupJoinFields(promotion, "presentation", "user_id", "profile_key") {
			return invalid()
		}
		userID, keyBytes, presentation = promotion.UserId, promotion.ProfileKey, promotion.Presentation
	}
	if !groupJoinIdentityFields(userID, keyBytes, presentation) {
		return invalid()
	}
	aci, actualKey, err := decryptPKeyAndIDorPresentation(ctx, userID, keyBytes, presentation, secret)
	if err != nil || *aci != self.UUID || *actualKey != profileKey {
		return invalid()
	}
	change := &GroupChange{GroupMasterKey: key, Revision: revision, SourceServiceID: source}
	if pni {
		change.PromotePendingPniAciMembers = []*PromotePendingPniAciMember{{ACI: *aci, PNI: invited.UUID, ProfileKey: *actualKey}}
	} else {
		change.PromotePendingMembers = []*PromotePendingMember{{ACI: *aci, ProfileKey: *actualKey}}
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		return invalid()
	}
	return &signalpb.GroupContextV2{MasterKey: bytes.Clone(master[:]), Revision: &revision, GroupChange: signedBytes}, change, nil
}
