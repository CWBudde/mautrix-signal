// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"bytes"
	"context"
	"encoding/base64"
	"math"
	"net/http"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

// GroupJoinPreview is authenticated preview data, not proof of full membership.
type GroupJoinPreview struct {
	Revision             uint32
	Access               AccessControl
	PendingAdminApproval bool
	Title                string
	Description          string
}

// GroupJoinOutcome distinguishes submission, HTTP acceptance, and verification
// of a signed self action. Full membership still requires a fresh group fetch.
type GroupJoinOutcome struct {
	Attempted    bool
	Accepted     bool
	Verified     bool
	Revision     uint32
	Requesting   bool
	GroupContext *signalpb.GroupContextV2
	Change       *GroupChange
}

type groupJoinAuthorize func(context.Context, libsignalgo.GroupMasterKey) (*GroupAuth, error)

func groupJoinMasterKey(key types.SerializedGroupMasterKey, password []byte) (libsignalgo.GroupMasterKey, error) {
	raw, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil || len(raw) != 32 || len(password) != 16 {
		return libsignalgo.GroupMasterKey{}, groupJoinSafeError("invalid group invite key or password", ErrGroupJoinInvalid)
	}
	return libsignalgo.GroupMasterKey(raw), nil
}

// PreviewGroupJoin fetches an authenticated, validated preview without requiring
// a stored group key or existing membership. key and password are sensitive.
func (cli *Client) PreviewGroupJoin(ctx context.Context, key types.SerializedGroupMasterKey, password []byte) (GroupJoinPreview, error) {
	return previewGroupJoin(ctx, key, password, cli.GetAuthorizationForToday)
}

func previewGroupJoin(ctx context.Context, key types.SerializedGroupMasterKey, password []byte, authorize groupJoinAuthorize) (preview GroupJoinPreview, err error) {
	master, err := groupJoinMasterKey(key, password)
	if err != nil {
		return preview, err
	}
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	if err = ctx.Err(); err != nil {
		return preview, groupJoinSafeError("group preview canceled", err)
	}
	auth, err := authorize(ctx, master)
	if err != nil {
		return preview, groupJoinSafeError("could not authorize group preview", err)
	}
	response, err := groupJoinHTTPRequest(ctx, http.MethodGet, password, nil, auth)
	if err != nil {
		return preview, err
	}
	return decodeGroupJoinPreview(response.Body, master)
}

// Shared validation for password-bearing links and password-free request previews.
func decodeGroupJoinPreview(raw []byte, master libsignalgo.GroupMasterKey) (preview GroupJoinPreview, err error) {
	info := &signalpb.GroupJoinInfo{}
	if err = proto.Unmarshal(raw, info); err != nil {
		return preview, groupJoinSafeError("could not decode group preview", err)
	}
	secret, err := master.SecretParams()
	if err != nil {
		return preview, groupJoinSafeError("could not derive group parameters", err)
	}
	public, err := secret.GetPublicParams()
	if err != nil {
		return preview, groupJoinSafeError("could not derive public group parameters", err)
	}
	if !bytes.Equal(info.PublicKey, public[:]) {
		return preview, groupJoinSafeError("group preview public parameters do not match invite", ErrGroupJoinInvalid)
	}
	title, err := groupJoinAttribute(secret, info.Title, true)
	if err != nil {
		return preview, err
	}
	description := ""
	if len(info.Description) > 0 {
		description, err = groupJoinAttribute(secret, info.Description, false)
		if err != nil {
			return preview, err
		}
	}
	return GroupJoinPreview{Revision: info.Version, Access: AccessControl(info.AddFromInviteLink), PendingAdminApproval: info.PendingAdminApproval, Title: title, Description: description}, nil
}

func groupJoinAttribute(secret libsignalgo.GroupSecretParams, ciphertext []byte, title bool) (string, error) {
	if len(ciphertext) == 0 {
		return "", groupJoinSafeError("group preview is missing a required attribute", ErrGroupJoinInvalid)
	}
	blob, err := decryptGroupPropertyIntoBlob(secret, ciphertext)
	if err != nil {
		return "", groupJoinSafeError("could not decrypt group preview attribute", err)
	}
	var text string
	if title {
		content, ok := blob.Content.(*signalpb.GroupAttributeBlob_Title)
		if !ok {
			return "", groupJoinSafeError("group preview title has invalid content", ErrGroupJoinInvalid)
		}
		text = content.Title
	} else {
		content, ok := blob.Content.(*signalpb.GroupAttributeBlob_DescriptionText)
		if !ok {
			return "", groupJoinSafeError("group preview description has invalid content", ErrGroupJoinInvalid)
		}
		text = content.DescriptionText
	}
	if !utf8.ValidString(text) {
		return "", groupJoinSafeError("group preview attribute has invalid UTF-8", ErrGroupJoinInvalid)
	}
	return text, nil
}

type groupJoinCredential func(context.Context, uuid.UUID) (*libsignalgo.ExpiringProfileKeyCredential, error)

// JoinGroupOnce submits exactly one self join/request based on a fresh preview.
// It does not fetch full state, retry a conflict, update caches, or store keys.
// Callers must verify full membership after a direct join, and may propagate
// GroupContext/Change only when Verified is true. On uncertain or accepted
// follow-up errors, inspect state before considering a new attempt.
func (cli *Client) JoinGroupOnce(ctx context.Context, key types.SerializedGroupMasterKey, password []byte, preview GroupJoinPreview) (GroupJoinOutcome, error) {
	return cli.joinGroupOnce(ctx, key, password, preview, prodServerPublicParams, cli.GetAuthorizationForToday, cli.FetchExpiringProfileKeyCredentialById)
}

func (cli *Client) joinGroupOnce(ctx context.Context, key types.SerializedGroupMasterKey, password []byte, preview GroupJoinPreview, server *libsignalgo.ServerPublicParams, authorize groupJoinAuthorize, credential groupJoinCredential) (outcome GroupJoinOutcome, err error) {
	master, err := groupJoinMasterKey(key, password)
	if err != nil {
		return outcome, err
	}
	if preview.PendingAdminApproval {
		return outcome, ErrGroupJoinPending
	}
	if preview.Access != AccessControl_ANY && preview.Access != AccessControl_ADMINISTRATOR {
		return outcome, ErrGroupJoinInactive
	}
	if preview.Revision == math.MaxUint32 {
		return outcome, groupJoinSafeError("group revision cannot be incremented", ErrGroupJoinInvalid)
	}
	if cli == nil || cli.Store == nil || cli.Store.ACI == uuid.Nil {
		return outcome, groupJoinSafeError("group join requires an account", ErrGroupJoinInvalid)
	}
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	if err = ctx.Err(); err != nil {
		return outcome, groupJoinSafeError("group join canceled before submission", err)
	}
	outcome.Revision = preview.Revision + 1
	secret, err := master.SecretParams()
	if err != nil {
		return outcome, groupJoinSafeError("could not derive group parameters", err)
	}
	own, err := credential(ctx, cli.Store.ACI)
	if err != nil {
		return outcome, groupJoinSafeError("could not obtain own profile credential", err)
	}
	if own == nil {
		return outcome, groupJoinSafeError("own profile credential is unavailable", ErrGroupJoinInvalid)
	}
	presentation, err := secret.CreateExpiringProfileKeyCredentialPresentation(server, *own)
	if err != nil {
		return outcome, groupJoinSafeError("could not prepare own profile presentation", err)
	}
	self := libsignalgo.NewACIServiceID(cli.Store.ACI)
	// Validate the fetched credential belongs to this account before submission.
	expectedID, expectedKey, err := decryptPKeyAndIDorPresentation(ctx, nil, nil, *presentation, secret)
	if err != nil {
		return outcome, groupJoinSafeError("could not validate own profile presentation", err)
	}
	if *expectedID != cli.Store.ACI {
		return outcome, groupJoinSafeError("own profile credential identity does not match account", ErrGroupJoinInvalid)
	}
	requesting := preview.Access == AccessControl_ADMINISTRATOR
	actions := &signalpb.GroupChange_Actions{SourceUserId: self.Bytes(), Version: outcome.Revision}
	if requesting {
		actions.AddMembersPendingAdminApproval = []*signalpb.GroupChange_Actions_AddMemberPendingAdminApprovalAction{{Added: &signalpb.MemberPendingAdminApproval{Presentation: bytes.Clone(*presentation)}}}
	} else {
		actions.AddMembers = []*signalpb.GroupChange_Actions_AddMemberAction{{Added: &signalpb.Member{Presentation: bytes.Clone(*presentation), Role: signalpb.Member_DEFAULT}}}
	}
	body, err := proto.Marshal(actions)
	if err != nil {
		return outcome, groupJoinSafeError("could not encode group join action", err)
	}
	auth, err := authorize(ctx, master)
	if err != nil {
		return outcome, groupJoinSafeError("could not authorize group join", err)
	}
	response, err := groupJoinHTTPRequest(ctx, http.MethodPatch, password, body, auth)
	outcome.Attempted = response.Attempted
	outcome.Accepted = response.Accepted
	if outcome.Attempted {
		outcome.Requesting = requesting
	}
	if err != nil {
		if outcome.Accepted {
			return outcome, groupJoinSafeError("group join accepted, but its response could not be verified; inspect before retrying", err)
		}
		return outcome, err
	}
	changeContext, change, err := verifyGroupJoinResponse(ctx, response.Body, key, master, secret, self, *expectedKey, outcome.Revision, requesting, server)
	if err != nil {
		return outcome, groupJoinSafeError("group join accepted, but its signed response could not be verified; inspect before retrying", err)
	}
	outcome.Verified = true
	outcome.GroupContext = changeContext
	outcome.Change = change
	return outcome, nil
}

// groupJoinFields rejects unknown and unrelated populated protobuf fields rather
// than relying on the ordinary GroupChange.isEmpty check (which omits fields).
func groupJoinFields(message proto.Message, allowed ...protoreflect.Name) bool {
	reflection := message.ProtoReflect()
	if len(reflection.GetUnknown()) > 0 {
		return false
	}
	valid := true
	reflection.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		for _, name := range allowed {
			if field.Name() == name {
				return true
			}
		}
		valid = false
		return false
	})
	return valid
}

func groupJoinIdentityFields(userID, profileKey, presentation []byte) bool {
	// Exact lengths avoid panics when existing crypto helpers convert untrusted
	// slices to fixed arrays. Reject incomplete/contradictory representations.
	if len(userID) == 0 && len(profileKey) == 0 {
		return len(presentation) > 0
	}
	return len(userID) == len(libsignalgo.UUIDCiphertext{}) && len(profileKey) == len(libsignalgo.ProfileKeyCiphertext{}) && len(presentation) == 0
}

func verifyGroupJoinResponse(ctx context.Context, raw []byte, key types.SerializedGroupMasterKey, master libsignalgo.GroupMasterKey, secret libsignalgo.GroupSecretParams, self libsignalgo.ServiceID, profileKey libsignalgo.ProfileKey, revision uint32, requesting bool, server *libsignalgo.ServerPublicParams) (*signalpb.GroupContextV2, *GroupChange, error) {
	invalid := func() (*signalpb.GroupContextV2, *GroupChange, error) { return nil, nil, ErrGroupJoinInvalid }
	response := &signalpb.GroupChangeResponse{}
	if err := proto.Unmarshal(raw, response); err != nil {
		return nil, nil, groupJoinSafeError("could not decode signed group join response", err)
	}
	signed := response.GroupChange
	if signed == nil || len(signed.Actions) == 0 || len(signed.ServerSignature) != len(libsignalgo.NotarySignature{}) || signed.ChangeEpoch > 7 {
		return invalid()
	}
	if !groupJoinFields(signed, "actions", "serverSignature", "changeEpoch") {
		return invalid()
	}
	if err := libsignalgo.ServerPublicParamsVerifySignature(server, signed.Actions, libsignalgo.NotarySignature(signed.ServerSignature)); err != nil {
		return nil, nil, groupJoinSafeError("invalid group join server signature", err)
	}
	actions := &signalpb.GroupChange_Actions{}
	if err := proto.Unmarshal(signed.Actions, actions); err != nil {
		return nil, nil, groupJoinSafeError("could not decode signed group join actions", err)
	}
	groupID, err := master.GroupIdentifier()
	if err != nil {
		return nil, nil, groupJoinSafeError("could not derive group identifier", err)
	}
	if !bytes.Equal(actions.GroupId, groupID[:]) || actions.Version != revision || len(actions.SourceUserId) != len(libsignalgo.UUIDCiphertext{}) {
		return invalid()
	}
	actionField := protoreflect.Name("addMembers")
	if requesting {
		actionField = "addMembersPendingAdminApproval"
	}
	if !groupJoinFields(actions, "sourceUserId", "group_id", "version", actionField) {
		return invalid()
	}
	source, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(actions.SourceUserId))
	if err != nil {
		return nil, nil, groupJoinSafeError("could not decrypt signed group join source", err)
	}
	if source != self {
		return invalid()
	}
	change := &GroupChange{GroupMasterKey: key, SourceServiceID: source, Revision: revision}
	if requesting {
		if len(actions.AddMembersPendingAdminApproval) != 1 {
			return invalid()
		}
		action := actions.AddMembersPendingAdminApproval[0]
		if action == nil || action.Added == nil || !groupJoinFields(action, "added") {
			return invalid()
		}
		member := action.Added
		if !groupJoinFields(member, "userId", "profileKey", "presentation", "timestamp") || !groupJoinIdentityFields(member.UserId, member.ProfileKey, member.Presentation) {
			return invalid()
		}
		decrypted, err := decryptRequestingMember(ctx, member, secret)
		if err != nil {
			return nil, nil, groupJoinSafeError("could not decrypt signed group request", err)
		}
		if decrypted.ACI != self.UUID || decrypted.ProfileKey != profileKey {
			return invalid()
		}
		change.AddRequestingMembers = []*RequestingMember{decrypted}
	} else {
		if len(actions.AddMembers) != 1 {
			return invalid()
		}
		action := actions.AddMembers[0]
		if action == nil || action.Added == nil || !groupJoinFields(action, "added", "joinFromInviteLink") {
			return invalid()
		}
		member := action.Added
		if !groupJoinFields(member, "userId", "profileKey", "presentation", "role", "joinedAtVersion") || !groupJoinIdentityFields(member.UserId, member.ProfileKey, member.Presentation) || member.Role != signalpb.Member_DEFAULT || (member.JoinedAtVersion != 0 && member.JoinedAtVersion != revision) {
			return invalid()
		}
		decrypted, err := decryptMember(ctx, member, secret)
		if err != nil {
			return nil, nil, groupJoinSafeError("could not decrypt signed group member", err)
		}
		if decrypted.ACI != self.UUID || decrypted.ProfileKey != profileKey {
			return invalid()
		}
		change.AddMembers = []*AddMember{{GroupMember: *decrypted, JoinFromInviteLink: action.JoinFromInviteLink}}
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		return nil, nil, groupJoinSafeError("could not encode verified group change", err)
	}
	return &signalpb.GroupContextV2{MasterKey: bytes.Clone(master[:]), Revision: &revision, GroupChange: signedBytes}, change, nil
}
