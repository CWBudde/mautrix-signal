// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"context"
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

var errReceiptSendRecorded = errors.New("delivery receipt send recorded")

// receiptRecipients records SendMessage's first store access and makes the send fail at
// the sealed-sender profile key lookup, before any network access.
type receiptRecipients struct {
	storyRecipients
	sends []uuid.UUID
}

func (r *receiptRecipients) LoadAndUpdateRecipient(_ context.Context, aci, _ uuid.UUID, _ store.RecipientUpdaterFunc) (*types.Recipient, error) {
	r.sends = append(r.sends, aci)
	return nil, errReceiptSendRecorded
}

func (r *receiptRecipients) LoadProfileKey(context.Context, uuid.UUID) (*libsignalgo.ProfileKey, error) {
	return nil, errReceiptSendRecorded
}

// The delivery receipt of an accepted message is deferred until the envelope's
// acknowledgement has been queued: the acknowledgement neither waits for its network round
// trip nor depends on its success, and a shutdown that cancels it leaves the message acked.
func TestDeliveryReceiptAfterAck(t *testing.T) {
	self := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	peer := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	for _, accepted := range []bool{false, true} {
		recipients := &receiptRecipients{}
		buffer := &storyEventBuffer{}
		device := &store.Device{DeviceData: store.DeviceData{ACI: self}, RecipientStore: recipients, EventBuffer: buffer}
		cli := signalmeow.NewClient(device, zerolog.Nop(), func(event events.SignalEvent) bool {
			if _, ok := event.(*events.ChatEvent); !ok {
				t.Fatalf("unexpected event %T", event)
			}
			return accepted
		})
		address, err := libsignalgo.NewUUIDAddressFromString(peer.String(), 1)
		joinCheck(t, err)
		content := &signalpb.Content{Content: &signalpb.Content_DataMessage{DataMessage: &signalpb.DataMessage{
			Body: proto.String("hello"), Timestamp: proto.Uint64(123),
		}}}
		afterAck, err := cli.HandleDecryptedResultForTest(context.Background(), signalmeow.DecryptionResult{SenderAddress: address, Content: content, CiphertextHash: new([32]byte{})}, &signalpb.Envelope{ClientTimestamp: proto.Uint64(123), ServerTimestamp: proto.Uint64(456)}, libsignalgo.NewACIServiceID(self))
		if len(recipients.sends) != 0 {
			t.Fatalf("accepted=%v: delivery receipt sent before the acknowledgement", accepted)
		}
		if !accepted {
			if !errors.Is(err, signalmeow.ErrHandlerFailed) || afterAck != nil || buffer.cleared != 0 {
				t.Fatalf("refused message: err=%v deferred=%v cleared=%d", err, afterAck != nil, buffer.cleared)
			}
			continue
		}
		joinCheck(t, err)
		if afterAck == nil || buffer.cleared != 1 {
			t.Fatalf("accepted message: deferred=%v cleared=%d", afterAck != nil, buffer.cleared)
		}
		// A canceled context (shutdown) and a failed send are only logged.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		afterAck(ctx)
		afterAck(context.Background())
		if len(recipients.sends) != 2 || recipients.sends[0] != peer {
			t.Fatalf("delivery receipt sends = %v, want two to %s", recipients.sends, peer)
		}
	}
}
