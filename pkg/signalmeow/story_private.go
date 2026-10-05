// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
)

// SendPrivateStory sends one explicitly expanded distribution-list audience using trusted
// pairwise sessions. A zero distribution UUID identifies My Story. The caller supplies a
// fresh audience; this transport never guesses contacts or edits distribution lists.
// Peer outcomes survive a failed own-device transcript, without resending accepted stories.
func (cli *Client) SendPrivateStory(ctx context.Context, distribution uuid.UUID, recipients []uuid.UUID, story *signalpb.StoryMessage, timestamp uint64) (*GroupStorySendResult, error) {
	if err := checkPrivateStory(story, timestamp, recipients, cli.Store.ACI); err != nil {
		return nil, err
	}
	key, err := cli.ProfileKeyForSignalID(ctx, cli.Store.ACI)
	if err != nil {
		return nil, fmt.Errorf("load story profile key: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: own profile key is missing", ErrInvalidStory)
	}
	owned := proto.Clone(story).(*signalpb.StoryMessage)
	owned.ProfileKey = slices.Clone(key.Slice())
	return sendPrivateStoryWith(ctx, distribution, recipients, owned, timestamp, cli.Store.ACI, func(ctx context.Context, recipient libsignalgo.ServiceID, ts uint64, content *signalpb.Content, groupID *libsignalgo.GroupIdentifier) (bool, error) {
		return cli.sendContent(ctx, recipient, ts, content, 0, true, groupID, nil)
	})
}

func checkPrivateStory(story *signalpb.StoryMessage, timestamp uint64, recipients []uuid.UUID, self uuid.UUID) error {
	if err := checkOutgoingStory(story, timestamp); err != nil {
		return err
	}
	if story.Group != nil || self == uuid.Nil || len(recipients) == 0 {
		return ErrInvalidStory
	}
	for _, recipient := range recipients {
		if recipient == uuid.Nil || recipient == self {
			return ErrInvalidStory
		}
	}
	return nil
}

func sendPrivateStoryWith(ctx context.Context, distribution uuid.UUID, recipients []uuid.UUID, story *signalpb.StoryMessage, timestamp uint64, self uuid.UUID, send func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error)) (*GroupStorySendResult, error) {
	if err := checkPrivateStory(story, timestamp, recipients, self); err != nil {
		return nil, err
	}
	recipients = slices.Clone(recipients)
	slices.SortFunc(recipients, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	recipients = slices.Compact(recipients)
	owned := proto.Clone(story).(*signalpb.StoryMessage)
	content := &signalpb.Content{Content: &signalpb.Content_StoryMessage{StoryMessage: owned}}
	result := &GroupStorySendResult{}
	for _, aci := range recipients {
		recipient := libsignalgo.NewACIServiceID(aci)
		unidentified, err := send(ctx, recipient, timestamp, proto.Clone(content).(*signalpb.Content), nil)
		if err != nil {
			result.FailedToSendTo = append(result.FailedToSendTo, FailedSendResult{Recipient: recipient, Error: err})
		} else {
			result.SuccessfullySentTo = append(result.SuccessfullySentTo, SuccessfulSendResult{Recipient: recipient, Unidentified: unidentified})
		}
	}
	sync := syncMessageFromGroupStory(owned, timestamp, self, result.SuccessfullySentTo)
	sent := sync.GetSyncMessage().GetSent()
	for _, recipient := range recipients {
		sent.StoryMessageRecipients = append(sent.StoryMessageRecipients, &signalpb.SyncMessage_Sent_StoryMessageRecipient{
			DestinationServiceIdBinary: slices.Clone(recipient[:]), DistributionListIds: []string{distribution.String()}, IsAllowedToReply: proto.Bool(owned.GetAllowsReplies()),
		})
	}
	_, result.SyncError = send(ctx, libsignalgo.NewACIServiceID(self), timestamp, sync, nil)
	return result, nil
}
