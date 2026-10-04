package signalmeow_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

func storySendGroup() *signalmeow.Group {
	key := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32))
	id, err := key.GroupIdentifier()
	if err != nil {
		panic(err)
	}
	return &signalmeow.Group{GroupIdentifier: types.GroupIdentifier(base64.StdEncoding.EncodeToString(id[:])),
		GroupMasterKey: types.SerializedGroupMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))),
		Revision:       7, Members: []*signalmeow.GroupMember{{ACI: timerSelf}, {ACI: timerACI}},
	}
}

func TestGroupStorySend(t *testing.T) {
	for _, failPeer := range []bool{false, true} {
		for _, failSync := range []bool{false, true} {
			t.Run(base64.StdEncoding.EncodeToString([]byte{boolByte(failPeer), boolByte(failSync)}), func(t *testing.T) {
				group := storySendGroup()
				story := &signalpb.StoryMessage{AllowsReplies: proto.Bool(false), ProfileKey: bytes.Repeat([]byte{9}, 32), Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("Story")}}}
				before := proto.Clone(story)
				var contents []*signalpb.Content
				var recipients []libsignalgo.ServiceID
				failure := errors.New("offline failure")
				res, err := signalmeow.SendGroupStoryWithForTest(context.Background(), group, story, 1234, timerSelf, func(_ context.Context, rcpt libsignalgo.ServiceID, ts uint64, content *signalpb.Content, gid *libsignalgo.GroupIdentifier) (bool, error) {
					if ts != 1234 || gid == nil {
						t.Fatalf("timestamp/context: %d %v", ts, gid)
					}
					contents = append(contents, proto.Clone(content).(*signalpb.Content))
					recipients = append(recipients, rcpt)
					if rcpt.UUID == timerACI && failPeer || rcpt.UUID == timerSelf && failSync {
						return false, failure
					}
					return rcpt.UUID != timerSelf, nil
				})
				if err != nil || res == nil || len(contents) != 2 || recipients[0].UUID != timerACI || recipients[1].UUID != timerSelf {
					t.Fatalf("result: %v %v calls%v", res, err, recipients)
				}
				if (res.SyncError != nil) != failSync || len(res.SuccessfullySentTo) != boolInt(!failPeer) || len(res.FailedToSendTo) != boolInt(failPeer) {
					t.Fatalf("outcome: %+v", res)
				}
				sent := contents[0].GetStoryMessage()
				if sent.GetGroup().GetRevision() != 7 || !bytes.Equal(sent.GetGroup().GetMasterKey(), bytes.Repeat([]byte{42}, 32)) || sent.GetAllowsReplies() {
					t.Fatalf("story: %v", sent)
				}
				sync := contents[1].GetSyncMessage().GetSent()
				if sync.GetTimestamp() != 1234 || !proto.Equal(sync.GetStoryMessage(), sent) || sync.GetMessage() != nil || sync.GetExpirationStartTimestamp() != 0 || len(sync.GetUnidentifiedStatus()) != boolInt(!failPeer) {
					t.Fatalf("sync: %v", sync)
				}
				if !proto.Equal(before, story) {
					t.Fatal("mutated caller story")
				}
			})
		}
	}
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func boolByte(b bool) byte { return byte(boolInt(b)) }

func TestGroupStoryMembership(t *testing.T) {
	group := storySendGroup()
	group.Members = []*signalmeow.GroupMember{{ACI: timerACI}}
	calls := 0
	_, err := signalmeow.SendGroupStoryWithForTest(context.Background(), group, &signalpb.StoryMessage{Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("Story")}}}, 1234, timerSelf, func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error) {
		calls++
		return false, nil
	})
	if !errors.Is(err, signalmeow.ErrStoryNotMember) || calls != 0 {
		t.Fatalf("membership: %v calls%d", err, calls)
	}
}

func TestStoryWirePolicy(t *testing.T) {
	story := &signalpb.Content{Content: &signalpb.Content_StoryMessage{StoryMessage: &signalpb.StoryMessage{}}}
	normal := &signalpb.Content{Content: &signalpb.Content_DataMessage{DataMessage: &signalpb.DataMessage{}}}
	rcpt := libsignalgo.NewACIServiceID(uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	path, urgent, hint := signalmeow.MessageWirePolicyForTest(rcpt, story)
	if path != "/v1/messages/"+rcpt.String()+"?story=true" || urgent || hint != libsignalgo.UnidentifiedSenderMessageContentHintImplicit {
		t.Fatalf("story policy: %s %t %v", path, urgent, hint)
	}
	path, urgent, hint = signalmeow.MessageWirePolicyForTest(rcpt, normal)
	if path != "/v1/messages/"+rcpt.String() || !urgent || hint != libsignalgo.UnidentifiedSenderMessageContentHintResendable {
		t.Fatalf("message policy: %s %t %v", path, urgent, hint)
	}
}

func TestGroupStoryInvalidContent(t *testing.T) {
	for _, story := range []*signalpb.StoryMessage{nil, {}, {Attachment: &signalpb.StoryMessage_TextAttachment{}}, {Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String(" ")}}}, {Attachment: &signalpb.StoryMessage_FileAttachment{FileAttachment: &signalpb.AttachmentPointer{ContentType: proto.String("application/pdf")}}}} {
		calls := 0
		_, err := signalmeow.SendGroupStoryWithForTest(context.Background(), storySendGroup(), story, 1, timerSelf, func(context.Context, libsignalgo.ServiceID, uint64, *signalpb.Content, *libsignalgo.GroupIdentifier) (bool, error) {
			calls++
			return false, nil
		})
		if !errors.Is(err, signalmeow.ErrInvalidStory) || calls != 0 {
			t.Fatalf("invalid story: %v calls%d", err, calls)
		}
	}
}

func TestGroupStorySelfOnlyAndMedia(t *testing.T) {
	group := storySendGroup()
	group.Members = group.Members[:1]
	story := &signalpb.StoryMessage{AllowsReplies: proto.Bool(true), Attachment: &signalpb.StoryMessage_FileAttachment{FileAttachment: &signalpb.AttachmentPointer{ContentType: proto.String("video/mp4"), Key: bytes.Repeat([]byte{7}, 64)}}}
	calls := 0
	res, err := signalmeow.SendGroupStoryWithForTest(context.Background(), group, story, 99, timerSelf, func(_ context.Context, recipient libsignalgo.ServiceID, ts uint64, content *signalpb.Content, _ *libsignalgo.GroupIdentifier) (bool, error) {
		calls++
		sent := content.GetSyncMessage().GetSent()
		if recipient.UUID != timerSelf || ts != 99 || sent.GetTimestamp() != 99 || sent.GetStoryMessage().GetFileAttachment().GetContentType() != "video/mp4" || !sent.GetStoryMessage().GetAllowsReplies() {
			t.Fatalf("self transcript: %v", content)
		}
		return false, nil
	})
	if err != nil || calls != 1 || len(res.SuccessfullySentTo) != 0 || len(res.FailedToSendTo) != 0 || res.SyncError != nil {
		t.Fatalf("self result: %v %v", res, err)
	}
}

type storySendKeys struct {
	store.RecipientStore
	loads []uuid.UUID
	key   *libsignalgo.ProfileKey
}

func (s *storySendKeys) LoadProfileKey(_ context.Context, recipient uuid.UUID) (*libsignalgo.ProfileKey, error) {
	s.loads = append(s.loads, recipient)
	if recipient != timerSelf {
		return nil, errors.New("story must not require peer profile keys")
	}
	return s.key, nil
}

func TestGroupStoryPublicEntry(t *testing.T) {
	group := storySendGroup()
	key := libsignalgo.ProfileKey(bytes.Repeat([]byte{9}, 32))
	keys := &storySendKeys{key: &key}
	device := &store.Device{DeviceData: store.DeviceData{ACI: timerSelf, DeviceID: 1}, RecipientStore: keys, ACISessionStore: timerSessions{}}
	cli := signalmeow.NewClient(device, zerolog.Nop(), func(events.SignalEvent) bool { return true })
	cli.SeedGroupCacheForTest(group)
	story := &signalpb.StoryMessage{Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("Story")}}}
	result, err := cli.SendGroupStory(context.Background(), group.GroupIdentifier, story, 1234)
	if err != nil || result == nil || len(result.FailedToSendTo) != 1 || result.SyncError == nil {
		t.Fatalf("offline peer/sync results: %v %v", result, err)
	}
	if len(keys.loads) != 1 || keys.loads[0] != timerSelf {
		t.Fatalf("profile lookups: %v", keys.loads)
	}
	if story.Group != nil || len(story.ProfileKey) != 0 {
		t.Fatal("public entry mutated caller's story")
	}
	keys.key = nil
	_, err = cli.SendGroupStory(context.Background(), group.GroupIdentifier, story, 1234)
	if !errors.Is(err, signalmeow.ErrInvalidStory) {
		t.Fatalf("missing own profile key: %v", err)
	}
	group.Members = group.Members[1:]
	before := len(keys.loads)
	_, err = cli.SendGroupStory(context.Background(), group.GroupIdentifier, story, 1234)
	if !errors.Is(err, signalmeow.ErrStoryNotMember) || len(keys.loads) != before {
		t.Fatalf("nonmember did work: %v %v", err, keys.loads)
	}
}
