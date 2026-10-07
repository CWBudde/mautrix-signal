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

func (cli *Client) SenderKeyRecipientsForTest(ctx context.Context, recipients []libsignalgo.ServiceID, sec SendEndorsementCache) ([]libsignalgo.ServiceID, []libsignalgo.ServiceID) {
	devices, _, fallback := cli.getDevicesIDs(ctx, recipients, sec, &GroupMessageSendResult{})
	var selected []libsignalgo.ServiceID
	for id := range devices {
		selected = append(selected, id)
	}
	return selected, fallback
}

func (cli *Client) SendWithSenderKeyForTest(ctx context.Context, gid *libsignalgo.GroupIdentifier, recipients []libsignalgo.ServiceID, sec SendEndorsementCache) error {
	_, err := cli.sendToGroupWithSenderKey(ctx, gid, recipients, sec, &signalpb.Content{}, 123, 0)
	return err
}

func (cli *Client) EncryptionLockHeldForTest() bool {
	if !cli.encryptionLock.TryLock() {
		return true
	}
	cli.encryptionLock.Unlock()
	return false
}

func (cli *Client) EncryptWithSenderKeyForTest(ctx context.Context, recipients []store.SessionAddressTuple, distribution uuid.UUID, cert *libsignalgo.SenderCertificate) ([]byte, error) {
	cli.senderCertificateNoE164 = cert
	address, err := cli.Store.ACIServiceID().Address(uint(cli.Store.DeviceID))
	if err != nil {
		return nil, err
	}
	return cli.encryptWithSenderKey(ctx, &libsignalgo.GroupIdentifier{42}, distribution, address, recipients, &signalpb.Content{})
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
	var afterAck func(context.Context)
	return cli.handleDecryptedResult(ctx, result, envelope, destination, &afterAck)
}

// HandleDecryptedResultForTest also returns the work deferred until the acknowledgement.
func (cli *Client) HandleDecryptedResultForTest(ctx context.Context, result DecryptionResult, envelope *signalpb.Envelope, destination libsignalgo.ServiceID) (func(context.Context), error) {
	var afterAck func(context.Context)
	err := cli.handleDecryptedResult(ctx, result, envelope, destination, &afterAck)
	return afterAck, err
}

func SendGroupStoryWithForTest(ctx context.Context, group *Group, story *signalpb.StoryMessage, timestamp uint64, self uuid.UUID, send func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error)) (*GroupStorySendResult, error) {
	return sendGroupStoryWith(ctx, group, story, timestamp, self, send)
}
func MessageWirePolicyForTest(recipient libsignalgo.ServiceID, content *signalpb.Content) (string, bool, libsignalgo.UnidentifiedSenderMessageContentHint) {
	return messageSendPath(recipient, content), isUrgent(content), getContentHint(content)
}

func SendPrivateStoryWithForTest(ctx context.Context, distribution uuid.UUID, recipients []uuid.UUID, story *signalpb.StoryMessage, timestamp uint64, self uuid.UUID, send func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error)) (*GroupStorySendResult, error) {
	return sendPrivateStoryWith(ctx, distribution, recipients, story, timestamp, self, send)
}
