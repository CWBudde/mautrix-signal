// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

func (cli *Client) HandleSyncMessageForTest(ctx context.Context, msg *signalpb.SyncMessage, envelope *signalpb.Envelope) bool {
	return cli.handleSyncMessage(ctx, msg, envelope)
}

func (cli *Client) StoreContactSyncForTest(ctx context.Context, data []byte) (*events.ContactList, error) {
	return cli.storeContactSync(ctx, data)
}

func (cli *Client) SeedGroupCacheForTest(group *Group) {
	cli.GroupCache.data[group.GroupIdentifier] = &cachedGroup{Group: group, SendEndorsementCache: &SendEndorsementCache{Expiration: time.Now().Add(time.Hour)}}
}

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

func (cli *Client) IncomingStoryForTest(ctx context.Context, msg *signalpb.StoryMessage, sender uuid.UUID, chat libsignalgo.ServiceID, timestamp, serverTimestamp uint64, blocked bool) bool {
	return cli.incomingStoryMessage(ctx, msg, sender, chat, timestamp, serverTimestamp, blocked)
}

func (cli *Client) HandleDecryptedStoryForTest(ctx context.Context, result DecryptionResult, envelope *signalpb.Envelope, destination libsignalgo.ServiceID) error {
	return cli.handleDecryptedResult(ctx, result, envelope, destination)
}

func SendGroupStoryWithForTest(ctx context.Context, group *Group, story *signalpb.StoryMessage, timestamp uint64, self uuid.UUID, send func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error)) (*GroupStorySendResult, error) {
	return sendGroupStoryWith(ctx, group, story, timestamp, self, send)
}
func MessageWirePolicyForTest(recipient libsignalgo.ServiceID, content *signalpb.Content) (string, bool, libsignalgo.UnidentifiedSenderMessageContentHint) {
	return messageSendPath(recipient, content), isUrgent(content), getContentHint(content)
}
