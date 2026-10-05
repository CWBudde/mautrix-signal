package signalmeow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
)

func TestPrivateStorySend(t *testing.T) {
	for _, failPeer := range []bool{false, true} {
		for _, failSync := range []bool{false, true} {
			story := &signalpb.StoryMessage{AllowsReplies: proto.Bool(true), Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("Private")}}}
			before := proto.Clone(story)
			peers := []uuid.UUID{timerACI, timerACI}
			var contents []*signalpb.Content
			failure := errors.New("offline")
			res, err := signalmeow.SendPrivateStoryWithForTest(context.Background(), uuid.Nil, peers, story, 345, timerSelf, func(_ context.Context, recipient libsignalgo.ServiceID, ts uint64, content *signalpb.Content, gid *libsignalgo.GroupIdentifier) (bool, error) {
				if ts != 345 || gid != nil {
					t.Fatal("private story acquired group or wrong timestamp")
				}
				contents = append(contents, proto.Clone(content).(*signalpb.Content))
				if (recipient.UUID == timerSelf && failSync) || (recipient.UUID != timerSelf && failPeer) {
					return false, failure
				}
				return true, nil
			})
			if err != nil || len(contents) != 2 || len(res.FailedToSendTo) != boolInt(failPeer) || len(res.SuccessfullySentTo) != boolInt(!failPeer) || (res.SyncError != nil) != failSync {
				t.Fatalf("result %+v err %v calls %d", res, err, len(contents))
			}
			sent := contents[1].GetSyncMessage().GetSent()
			manifest := sent.GetStoryMessageRecipients()
			if len(manifest) != 1 || manifest[0].GetDistributionListIds()[0] != uuid.Nil.String() || !manifest[0].GetIsAllowedToReply() || string(manifest[0].GetDestinationServiceIdBinary()) != string(timerACI[:]) {
				t.Fatalf("manifest %v", manifest)
			}
			if sent.GetTimestamp() != 345 || sent.GetMessage() != nil || sent.GetExpirationStartTimestamp() != 0 || sent.GetStoryMessage().GetGroup() != nil || !proto.Equal(contents[0].GetStoryMessage(), sent.GetStoryMessage()) || len(sent.GetUnidentifiedStatus()) != boolInt(!failPeer) {
				t.Fatalf("sync %v", sent)
			}
			if !proto.Equal(before, story) {
				t.Fatal("caller modified")
			}
		}
	}
}

func TestPrivateStoryInvalidAudience(t *testing.T) {
	for _, recipients := range [][]uuid.UUID{nil, {uuid.Nil}, {timerSelf}, {timerACI, timerSelf}} {
		_, err := signalmeow.SendPrivateStoryWithForTest(context.Background(), uuid.Nil, recipients, &signalpb.StoryMessage{Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("Private")}}}, 1, timerSelf, func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error) {
			t.Fatal("sent invalid audience")
			return false, nil
		})
		if !errors.Is(err, signalmeow.ErrInvalidStory) {
			t.Fatalf("got %v", err)
		}
	}
}

func TestPrivateStoryPublicEntry(t *testing.T) {
	recipients := &storySendKeys{}
	key := libsignalgo.ProfileKey{}
	recipients.key = &key
	cli := signalmeow.NewClient(&store.Device{DeviceData: store.DeviceData{ACI: timerSelf, DeviceID: 1}, RecipientStore: recipients, ACISessionStore: timerSessions{}}, zerolog.Nop(), func(events.SignalEvent) bool { return true })
	story := &signalpb.StoryMessage{Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("Private")}}}
	res, err := cli.SendPrivateStory(context.Background(), uuid.Nil, []uuid.UUID{timerACI}, story, 123)
	if err != nil || len(res.FailedToSendTo) != 1 || res.SyncError == nil || len(recipients.loads) != 1 || recipients.loads[0] != timerSelf {
		t.Fatalf("result %+v err %v lookups %v", res, err, recipients.loads)
	}
	if len(story.ProfileKey) != 0 {
		t.Fatal("modified caller profile key")
	}
	recipients.key = nil
	_, err = cli.SendPrivateStory(context.Background(), uuid.Nil, []uuid.UUID{timerACI}, story, 123)
	if !errors.Is(err, signalmeow.ErrInvalidStory) {
		t.Fatal(err)
	}
}

func TestPrivateStoryCustomListAndOwnership(t *testing.T) {
	distribution := uuid.MustParse("76543210-1234-4321-8234-123456789abc")
	peers := []uuid.UUID{timerACI}
	story := &signalpb.StoryMessage{AllowsReplies: proto.Bool(false), Attachment: &signalpb.StoryMessage_FileAttachment{FileAttachment: &signalpb.AttachmentPointer{ContentType: proto.String("video/mp4"), Key: []byte{7}}}}
	calls := 0
	_, err := signalmeow.SendPrivateStoryWithForTest(context.Background(), distribution, peers, story, 789, timerSelf, func(_ context.Context, recipient libsignalgo.ServiceID, _ uint64, content *signalpb.Content, _ *libsignalgo.GroupIdentifier) (bool, error) {
		calls++
		if recipient.UUID != timerSelf {
			content.GetStoryMessage().GetFileAttachment().Key[0] = 99
		} else {
			sent := content.GetSyncMessage().GetSent()
			if sent.GetStoryMessageRecipients()[0].GetDistributionListIds()[0] != distribution.String() || sent.GetStoryMessageRecipients()[0].GetIsAllowedToReply() || sent.GetStoryMessage().GetFileAttachment().Key[0] != 7 {
				t.Fatalf("wrong custom transcript: %v", sent)
			}
		}
		return true, nil
	})
	if err != nil || calls != 2 || story.GetFileAttachment().Key[0] != 7 || peers[0] != timerACI {
		t.Fatalf("caller ownership %v", err)
	}
}
