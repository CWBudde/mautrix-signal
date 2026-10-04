// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

var ErrStoryNotMember = errors.New("not a full member of the story group")
var ErrInvalidStory = errors.New("invalid story")

// GroupStorySendResult preserves peer outcomes separately from the own-device transcript.
// A failed transcript never triggers resubmission of accepted peer stories.
type GroupStorySendResult struct {
	GroupMessageSendResult
	SyncError error
}

// SendGroupStory sends pairwise encrypted stories to full group members and a transcript
// to our other devices. Timestamp must be nonzero, because StoryMessage has no timestamp.
// One retrieved state supplies both the group context and audience. Unlike ordinary group
// messages, this does not use sender keys or group send endorsement tokens.
func (cli *Client) SendGroupStory(ctx context.Context, gid types.GroupIdentifier, story *signalpb.StoryMessage, timestamp uint64) (*GroupStorySendResult, error) {
	if err := checkOutgoingStory(story, timestamp); err != nil {
		return nil, err
	}
	group, _, err := cli.RetrieveGroupByID(ctx, gid, 0)
	if err != nil {
		return nil, err
	}
	if !storyGroupMember(group, cli.Store.ACI) {
		return nil, ErrStoryNotMember
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
	return sendGroupStoryWith(ctx, group, owned, timestamp, cli.Store.ACI, func(ctx context.Context, recipient libsignalgo.ServiceID, ts uint64, content *signalpb.Content, groupID *libsignalgo.GroupIdentifier) (bool, error) {
		return cli.sendContent(ctx, recipient, ts, content, 0, true, groupID, nil)
	})
}

func checkOutgoingStory(story *signalpb.StoryMessage, timestamp uint64) error {
	if story == nil || timestamp == 0 {
		return ErrInvalidStory
	}
	switch a := story.Attachment.(type) {
	case *signalpb.StoryMessage_FileAttachment:
		if a == nil || a.FileAttachment == nil || (!strings.HasPrefix(a.FileAttachment.GetContentType(), "image/") && !strings.HasPrefix(a.FileAttachment.GetContentType(), "video/")) {
			return ErrInvalidStory
		}
	case *signalpb.StoryMessage_TextAttachment:
		if a == nil || a.TextAttachment == nil || strings.TrimSpace(a.TextAttachment.GetText()) == "" {
			return ErrInvalidStory
		}
	default:
		return ErrInvalidStory
	}
	return nil
}

func storyGroupMember(group *Group, self uuid.UUID) bool {
	return group != nil && self != uuid.Nil && slices.ContainsFunc(group.Members, func(member *GroupMember) bool { return member != nil && member.ACI == self })
}

func sendGroupStoryWith(ctx context.Context, group *Group, story *signalpb.StoryMessage, timestamp uint64, self uuid.UUID, send func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error)) (*GroupStorySendResult, error) {
	if err := checkOutgoingStory(story, timestamp); err != nil {
		return nil, err
	}
	if !storyGroupMember(group, self) {
		return nil, ErrStoryNotMember
	}
	gid, err := group.GroupIdentifier.Bytes()
	if err != nil {
		return nil, fmt.Errorf("story group identifier: %w", err)
	}
	owned := proto.Clone(story).(*signalpb.StoryMessage)
	owned.Group = groupMetadataForDataMessage(*group)
	content := &signalpb.Content{Content: &signalpb.Content_StoryMessage{StoryMessage: owned}}
	result := &GroupStorySendResult{}
	for _, member := range group.Members {
		if member == nil || member.ACI == self {
			continue
		}
		recipient := member.UserServiceID()
		unidentified, err := send(ctx, recipient, timestamp, proto.Clone(content).(*signalpb.Content), &gid)
		if err != nil {
			result.FailedToSendTo = append(result.FailedToSendTo, FailedSendResult{Recipient: recipient, Error: err})
		} else {
			result.SuccessfullySentTo = append(result.SuccessfullySentTo, SuccessfulSendResult{Recipient: recipient, Unidentified: unidentified})
		}
	}
	sync := syncMessageFromGroupStory(owned, timestamp, self, result.SuccessfullySentTo)
	_, result.SyncError = send(ctx, libsignalgo.NewACIServiceID(self), timestamp, sync, &gid)
	return result, nil
}

func syncMessageFromGroupStory(story *signalpb.StoryMessage, timestamp uint64, self uuid.UUID, results []SuccessfulSendResult) *signalpb.Content {
	sent := &signalpb.SyncMessage_Sent{StoryMessage: story, Timestamp: proto.Uint64(timestamp), DestinationServiceIdBinary: self[:], IsRecipientUpdate: proto.Bool(false)}
	for _, result := range results {
		sent.UnidentifiedStatus = append(sent.UnidentifiedStatus, &signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{DestinationServiceIdBinary: result.Recipient.Bytes(), Unidentified: proto.Bool(result.Unidentified)})
	}
	return syncSentMessage(sent)
}

func messageSendPath(recipient libsignalgo.ServiceID, content *signalpb.Content) string {
	path := fmt.Sprintf("/v1/messages/%s", recipient)
	if content.GetStoryMessage() != nil {
		path += "?story=true"
	}
	return path
}
