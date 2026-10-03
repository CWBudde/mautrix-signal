// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

// FetchGroupForAcceptance reads owned fresh full state without reading or
// populating cached group state or endorsements, writing recipients or profile
// keys, persisting master keys, or sending notifications. It retains normal
// authorization credential caching through GetAuthorizationForToday.
func (cli *Client) FetchGroupForAcceptance(ctx context.Context, key types.SerializedGroupMasterKey) (*Group, error) {
	if cli == nil || cli.Store == nil || cli.Store.ACI == uuid.Nil {
		return nil, ErrGroupAcceptanceInvalid
	}
	return cli.fetchGroupForAcceptance(ctx, key, cli.GetAuthorizationForToday)
}

func (cli *Client) fetchGroupForAcceptance(ctx context.Context, key types.SerializedGroupMasterKey, authorize groupJoinAuthorize) (*Group, error) {
	master, err := groupAcceptanceMasterKey(key)
	if err != nil {
		return nil, err
	}
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	if err = ctx.Err(); err != nil {
		return nil, groupJoinSafeError("group acceptance read canceled", err)
	}
	auth, err := authorize(ctx, master)
	if err != nil {
		return nil, groupJoinSafeError("could not authorize group acceptance read", err)
	}
	response, err := groupAcceptanceHTTPRequest(ctx, http.MethodGet, nil, auth)
	if err != nil {
		return nil, err
	}
	parsed := &signalpb.GroupResponse{}
	if err = proto.Unmarshal(response.Body, parsed); err != nil {
		return nil, groupJoinSafeError("could not decode group acceptance state", errors.Join(ErrGroupAcceptanceInvalid, err))
	}
	group, err := decodeGroupForAcceptance(ctx, master, key, parsed.Group)
	if err != nil {
		if !errors.Is(err, ErrGroupAcceptanceTerminated) {
			err = errors.Join(ErrGroupAcceptanceInvalid, err)
		}
		return nil, groupJoinSafeError("could not validate group acceptance state", err)
	}
	return group, nil
}

func decodeGroupForAcceptance(ctx context.Context, master libsignalgo.GroupMasterKey, key types.SerializedGroupMasterKey, wire *signalpb.Group) (*Group, error) {
	if wire == nil {
		return nil, ErrGroupAcceptanceInvalid
	}
	secret, err := master.SecretParams()
	if err != nil {
		return nil, err
	}
	public, err := secret.GetPublicParams()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(wire.PublicKey, public[:]) {
		return nil, ErrGroupAcceptanceInvalid
	}
	if wire.Terminated {
		return nil, ErrGroupAcceptanceTerminated
	}
	id, err := master.GroupIdentifier()
	if err != nil {
		return nil, err
	}
	result := &Group{GroupMasterKey: key, GroupIdentifier: types.BytesToGroupIdentifier(id), Revision: wire.Version, AvatarPath: wire.AvatarUrl, AnnouncementsOnly: wire.AnnouncementsOnly}
	title, err := groupAcceptanceAttribute(secret, wire.Title, "title")
	if err != nil {
		return nil, err
	}
	result.Title = title.GetTitle()
	if len(wire.Description) > 0 {
		description, err := groupAcceptanceAttribute(secret, wire.Description, "description")
		if err != nil {
			return nil, err
		}
		result.Description = description.GetDescriptionText()
	}
	if len(wire.DisappearingMessagesTimer) > 0 {
		timer, err := groupAcceptanceAttribute(secret, wire.DisappearingMessagesTimer, "timer")
		if err != nil {
			return nil, err
		}
		result.DisappearingMessagesDuration = timer.GetDisappearingMessagesDuration()
	}
	for _, member := range wire.Members {
		if member == nil || !groupJoinIdentityFields(member.UserId, member.ProfileKey, member.Presentation) {
			return nil, ErrGroupAcceptanceInvalid
		}
		decoded, err := decryptMember(ctx, member, secret)
		if err != nil {
			return nil, err
		}
		result.Members = append(result.Members, decoded)
	}
	for _, pending := range wire.MembersPendingProfileKey {
		if pending == nil || pending.Member == nil || len(pending.Member.UserId) != len(libsignalgo.UUIDCiphertext{}) || len(pending.AddedByUserId) != len(libsignalgo.UUIDCiphertext{}) {
			return nil, ErrGroupAcceptanceInvalid
		}
		// Pending entries normally have no profile material. If a representation is
		// supplied, validate it completely rather than silently hiding malformed data.
		member := pending.Member
		if len(member.ProfileKey) > 0 || len(member.Presentation) > 0 {
			if !groupJoinIdentityFields(member.UserId, member.ProfileKey, member.Presentation) {
				return nil, ErrGroupAcceptanceInvalid
			}
			if _, _, err = decryptPKeyAndIDorPresentation(ctx, member.UserId, member.ProfileKey, member.Presentation, secret); err != nil {
				return nil, err
			}
		}
		addedBy, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(pending.AddedByUserId))
		if err != nil {
			return nil, err
		}
		if addedBy.Type != libsignalgo.ServiceIDTypeACI {
			return nil, ErrGroupAcceptanceInvalid
		}
		decoded, err := decryptPendingMember(ctx, pending, secret)
		if err != nil {
			return nil, err
		}
		result.PendingMembers = append(result.PendingMembers, decoded)
	}
	for _, requesting := range wire.MembersPendingAdminApproval {
		if requesting == nil || !groupJoinIdentityFields(requesting.UserId, requesting.ProfileKey, requesting.Presentation) {
			return nil, ErrGroupAcceptanceInvalid
		}
		decoded, err := decryptRequestingMember(ctx, requesting, secret)
		if err != nil {
			return nil, err
		}
		result.RequestingMembers = append(result.RequestingMembers, decoded)
	}
	for _, ban := range wire.MembersBanned {
		if ban == nil || len(ban.UserId) != len(libsignalgo.UUIDCiphertext{}) {
			return nil, ErrGroupAcceptanceInvalid
		}
		sid, err := secret.DecryptServiceID(libsignalgo.UUIDCiphertext(ban.UserId))
		if err != nil {
			return nil, err
		}
		result.BannedMembers = append(result.BannedMembers, &BannedMember{ServiceID: sid, Timestamp: ban.Timestamp})
	}
	if wire.AccessControl != nil {
		result.AccessControl = &GroupAccessControl{Members: AccessControl(wire.AccessControl.Members), Attributes: AccessControl(wire.AccessControl.Attributes), AddFromInviteLink: AccessControl(wire.AccessControl.AddFromInviteLink)}
	}
	if len(wire.InviteLinkPassword) > 0 {
		if len(wire.InviteLinkPassword) != 16 {
			return nil, ErrGroupAcceptanceInvalid
		}
		password := InviteLinkPasswordFromBytes(wire.InviteLinkPassword)
		result.InviteLinkPassword = &password
	}
	return result, nil
}

func groupAcceptanceAttribute(secret libsignalgo.GroupSecretParams, raw []byte, kind string) (*signalpb.GroupAttributeBlob, error) {
	// The blob layout needs a tag, nonce and reserved byte. Guard short FFI inputs.
	if len(raw) < 29 {
		return nil, ErrGroupAcceptanceInvalid
	}
	blob, err := decryptGroupPropertyIntoBlob(secret, raw)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "title":
		value, ok := blob.Content.(*signalpb.GroupAttributeBlob_Title)
		if !ok || !utf8.ValidString(value.Title) {
			return nil, ErrGroupAcceptanceInvalid
		}
	case "description":
		value, ok := blob.Content.(*signalpb.GroupAttributeBlob_DescriptionText)
		if !ok || !utf8.ValidString(value.DescriptionText) {
			return nil, ErrGroupAcceptanceInvalid
		}
	case "timer":
		if _, ok := blob.Content.(*signalpb.GroupAttributeBlob_DisappearingMessagesDuration); !ok {
			return nil, ErrGroupAcceptanceInvalid
		}
	default:
		return nil, ErrGroupAcceptanceInvalid
	}
	return blob, nil
}
