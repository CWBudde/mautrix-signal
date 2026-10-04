package signalmeow_test

import (
	"context"
	"errors"
	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestStoryReceiveHandler(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, synced := range []bool{false, true} {
			t.Run(fmtStoryCase(accepted, synced), func(t *testing.T) {
				self := uuid.MustParse("10000000-0000-0000-0000-000000000001")
				peer := uuid.MustParse("10000000-0000-0000-0000-000000000002")
				sender := peer
				if synced {
					sender = self
				}
				calls := 0
				msg := &signalpb.StoryMessage{Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("story")}}}
				cli := signalmeow.NewClient(&store.Device{DeviceData: store.DeviceData{ACI: self}}, zerolog.Nop(), func(event events.SignalEvent) bool {
					calls++
					story, ok := event.(*events.Story)
					if !ok || story.Info.Sender != sender || story.Info.ChatID != sender.String() || story.Timestamp != 123 || story.Info.ServerTimestamp != 456 || story.Content != msg {
						t.Fatalf("wrong story event: %#v", event)
					}
					return accepted
				})
				var ack bool
				if synced {
					ack = cli.HandleSyncMessageForTest(context.Background(), &signalpb.SyncMessage{Content: &signalpb.SyncMessage_Sent_{Sent: &signalpb.SyncMessage_Sent{Timestamp: proto.Uint64(123), StoryMessage: msg}}}, &signalpb.Envelope{ServerTimestamp: proto.Uint64(456)})
				} else {
					ack = cli.IncomingStoryForTest(context.Background(), msg, sender, libsignalgo.NewACIServiceID(peer), 123, 456, false)
				}
				if ack != accepted || calls != 1 {
					t.Fatalf("ack=%v calls=%d; want %v/1", ack, calls, accepted)
				}
			})
		}
	}
}
func fmtStoryCase(accepted, synced bool) string {
	if synced {
		if accepted {
			return "sync/accepted"
		}
		return "sync/rejected"
	}
	if accepted {
		return "incoming/accepted"
	}
	return "incoming/rejected"
}

type storyGroupStore struct {
	store.GroupStore
	calls int
	err   error
	id    types.GroupIdentifier
}

func (s *storyGroupStore) StoreMasterKey(_ context.Context, id types.GroupIdentifier, _ types.SerializedGroupMasterKey) error {
	s.calls++
	s.id = id
	return s.err
}
func TestStoryReceiveGroupAndBlocked(t *testing.T) {
	sender := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	failure := errors.New("story key store failed")
	for _, tc := range []struct {
		name                   string
		group                  []byte
		blocked                bool
		storeErr               error
		wantAck                bool
		wantEvents, wantStores int
	}{
		{"blocked direct", nil, true, nil, true, 0, 0},
		{"group from blocked sender", make([]byte, 32), true, nil, true, 1, 1},
		{"group storage failure", make([]byte, 32), false, failure, false, 0, 1},
		{"malformed group key", []byte{1}, false, nil, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := &storyGroupStore{err: tc.storeErr}
			calls := 0
			cli := signalmeow.NewClient(&store.Device{GroupStore: groups}, zerolog.Nop(), func(event events.SignalEvent) bool {
				calls++
				story := event.(*events.Story)
				if story.Info.ChatID != string(groups.id) || story.Info.GroupRevision != 7 {
					t.Fatalf("wrong group metadata: %#v", story.Info)
				}
				return true
			})
			msg := &signalpb.StoryMessage{}
			if tc.group != nil {
				msg.Group = &signalpb.GroupContextV2{MasterKey: tc.group, Revision: proto.Uint32(7)}
			}
			ack := cli.IncomingStoryForTest(context.Background(), msg, sender, libsignalgo.NewACIServiceID(sender), 123, 456, tc.blocked)
			if ack != tc.wantAck || calls != tc.wantEvents || groups.calls != tc.wantStores {
				t.Fatalf("ack=%v events=%d stored=%d", ack, calls, groups.calls)
			}
		})
	}
}

type storyRecipients struct {
	store.RecipientStore
	blocked      bool
	profileErr   error
	profileCalls int
}

func (s *storyRecipients) MarkUnregistered(context.Context, libsignalgo.ServiceID, bool) {}
func (s *storyRecipients) IsBlocked(context.Context, uuid.UUID) (bool, error)            { return s.blocked, nil }
func (s *storyRecipients) StoreProfileKey(context.Context, uuid.UUID, libsignalgo.ProfileKey) error {
	s.profileCalls++
	return s.profileErr
}

type storyEventBuffer struct {
	store.EventBuffer
	cleared int
}

func (b *storyEventBuffer) ClearBufferedEventPlaintext(context.Context, [32]byte) error {
	b.cleared++
	return nil
}

func TestStoryDecryptedDispatch(t *testing.T) {
	self := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	peer := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	for _, accepted := range []bool{false, true} {
		calls := 0
		buffer := &storyEventBuffer{}
		device := &store.Device{DeviceData: store.DeviceData{ACI: self}, RecipientStore: &storyRecipients{}, EventBuffer: buffer}
		cli := signalmeow.NewClient(device, zerolog.Nop(), func(event events.SignalEvent) bool {
			calls++
			story, ok := event.(*events.Story)
			if !ok || story.Timestamp != 123 || story.Info.ServerTimestamp != 456 {
				t.Fatalf("wrong dispatch: %#v", event)
			}
			return accepted
		})
		address, err := libsignalgo.NewUUIDAddressFromString(peer.String(), 1)
		joinCheck(t, err)
		content := &signalpb.Content{Content: &signalpb.Content_StoryMessage{StoryMessage: &signalpb.StoryMessage{Attachment: &signalpb.StoryMessage_TextAttachment{TextAttachment: &signalpb.TextAttachment{Text: proto.String("story")}}}}}
		err = cli.HandleDecryptedStoryForTest(context.Background(), signalmeow.DecryptionResult{SenderAddress: address, Content: content, CiphertextHash: new([32]byte{})}, &signalpb.Envelope{ClientTimestamp: proto.Uint64(123), ServerTimestamp: proto.Uint64(456)}, libsignalgo.NewACIServiceID(self))
		if accepted {
			joinCheck(t, err)
			if buffer.cleared != 1 {
				t.Fatal("accepted story not cleared")
			}
		} else if !errors.Is(err, signalmeow.ErrHandlerFailed) || buffer.cleared != 0 {
			t.Fatalf("failed story ack/clear: %v %d", err, buffer.cleared)
		}
		if calls != 1 {
			t.Fatalf("delivered %d stories", calls)
		}
	}
}

func TestStoryProfileKeyFailure(t *testing.T) {
	sender := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	for _, tc := range []struct {
		name           string
		key            []byte
		err            error
		wantAck        bool
		stores, events int
	}{
		{"valid", make([]byte, 32), nil, true, 1, 1},
		{"invalid", []byte{1}, nil, false, 0, 0},
		{"storage failure", make([]byte, 32), errors.New("profile storage failed"), false, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recipients := &storyRecipients{profileErr: tc.err}
			calls := 0
			cli := signalmeow.NewClient(&store.Device{RecipientStore: recipients}, zerolog.Nop(), func(events.SignalEvent) bool { calls++; return true })
			ack := cli.IncomingStoryForTest(context.Background(), &signalpb.StoryMessage{ProfileKey: tc.key}, sender, libsignalgo.NewACIServiceID(sender), 123, 456, false)
			if ack != tc.wantAck || recipients.profileCalls != tc.stores || calls != tc.events {
				t.Fatalf("ack=%v stored=%d events=%d", ack, recipients.profileCalls, calls)
			}
		})
	}
}
