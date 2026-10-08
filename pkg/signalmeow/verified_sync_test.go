// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"bytes"
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
)

func verifiedFixture(t *testing.T) (*signalpb.Verified, uuid.UUID) {
	t.Helper()
	peer := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	pair, err := libsignalgo.GenerateIdentityKeyPair()
	joinCheck(t, err)
	key, err := pair.GetIdentityKey().Serialize()
	joinCheck(t, err)
	return &signalpb.Verified{DestinationAci: proto.String(peer.String()), IdentityKey: key, State: signalpb.Verified_VERIFIED.Enum()}, peer
}

func verifiedSync(v *signalpb.Verified) *signalpb.SyncMessage {
	return &signalpb.SyncMessage{Content: &signalpb.SyncMessage_Verified{Verified: v}}
}

func TestVerifiedSyncDispatch(t *testing.T) {
	for _, state := range []signalpb.Verified_State{signalpb.Verified_DEFAULT, signalpb.Verified_VERIFIED, signalpb.Verified_UNVERIFIED} {
		for _, binary := range []bool{false, true} {
			v, peer := verifiedFixture(t)
			v.State = state.Enum()
			if binary {
				v.DestinationAci = nil
				v.DestinationAciBinary = peer[:]
			}
			calls := 0
			cli := signalmeow.NewClient(&store.Device{}, zerolog.Nop(), func(raw events.SignalEvent) bool {
				calls++
				got, ok := raw.(*events.IdentityVerification)
				if !ok || got.ACI != peer || got.State != state || !bytes.Equal(got.IdentityKey, v.IdentityKey) {
					t.Fatalf("event = %#v", raw)
				}
				got.IdentityKey[0] = 0
				if v.IdentityKey[0] != 5 {
					t.Fatal("event aliases wire key")
				}
				return false
			})
			if cli.HandleSyncMessageForTest(context.Background(), verifiedSync(v), &signalpb.Envelope{}) || calls != 1 {
				t.Fatalf("handler failure not propagated: calls=%d", calls)
			}
		}
	}
}

func TestVerifiedSyncInvalid(t *testing.T) {
	cases := []struct {
		name   string
		change func(*signalpb.Verified)
	}{
		{"nil", nil},
		{"no destination", func(v *signalpb.Verified) { v.DestinationAci = nil }},
		{"nil uuid", func(v *signalpb.Verified) { v.DestinationAci = proto.String(uuid.Nil.String()) }},
		{"pni", func(v *signalpb.Verified) { v.DestinationAci = proto.String("PNI:" + v.GetDestinationAci()) }},
		{"short binary", func(v *signalpb.Verified) { v.DestinationAciBinary = []byte{1} }},
		{"conflicting destination", func(v *signalpb.Verified) { id := uuid.New(); v.DestinationAciBinary = id[:] }},
		{"nil binary", func(v *signalpb.Verified) { v.DestinationAci = nil; v.DestinationAciBinary = make([]byte, 16) }},
		{"bad prefix", func(v *signalpb.Verified) { v.IdentityKey[0] = 0 }},
		{"bad key", func(v *signalpb.Verified) { v.IdentityKey = []byte{5, 1} }},
		{"key suffix", func(v *signalpb.Verified) { v.IdentityKey = append(v.IdentityKey, 0) }},
		{"no state", func(v *signalpb.Verified) { v.State = nil }},
		{"unknown state", func(v *signalpb.Verified) { v.State = signalpb.Verified_State(99).Enum() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := verifiedFixture(t)
			if tc.change == nil {
				v = nil
			} else {
				tc.change(v)
			}
			calls := 0
			cli := signalmeow.NewClient(&store.Device{}, zerolog.Nop(), func(events.SignalEvent) bool { calls++; return true })
			if !cli.HandleSyncMessageForTest(context.Background(), verifiedSync(v), &signalpb.Envelope{}) || calls != 0 {
				t.Fatalf("invalid update dispatched: calls=%d", calls)
			}
		})
	}
}

func TestVerifiedSyncAuthenticatedAndRedelivery(t *testing.T) {
	self := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	for _, tc := range []struct {
		name                  string
		sender                libsignalgo.ServiceID
		unencrypted, accepted bool
		calls, clears         int
	}{
		{"own failure", libsignalgo.NewACIServiceID(self), false, false, 1, 0}, {"own success", libsignalgo.NewACIServiceID(self), false, true, 1, 1},
		{"foreign spoofed source", libsignalgo.NewACIServiceID(uuid.New()), false, true, 0, 1}, {"own PNI", libsignalgo.NewPNIServiceID(self), false, true, 0, 1},
		{"plaintext", libsignalgo.NewACIServiceID(self), true, true, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := verifiedFixture(t)
			calls := 0
			accepted := tc.accepted
			buffer := &storyEventBuffer{}
			device := &store.Device{DeviceData: store.DeviceData{ACI: self}, RecipientStore: &storyRecipients{}, EventBuffer: buffer}
			cli := signalmeow.NewClient(device, zerolog.Nop(), func(raw events.SignalEvent) bool {
				calls++
				if _, ok := raw.(*events.IdentityVerification); !ok {
					t.Fatalf("event=%T", raw)
				}
				return accepted
			})
			address, err := tc.sender.Address(2)
			joinCheck(t, err)
			result := signalmeow.DecryptionResult{SenderAddress: address, Content: &signalpb.Content{Content: &signalpb.Content_SyncMessage{SyncMessage: verifiedSync(v)}}, CiphertextHash: new([32]byte), Unencrypted: tc.unencrypted}
			// The envelope's claimed source must never authorize a foreign authenticated sender.
			envelope := &signalpb.Envelope{SourceServiceId: proto.String(self.String())}
			after, err := cli.HandleDecryptedResultForTest(context.Background(), result, envelope, libsignalgo.NewACIServiceID(self))
			if after != nil {
				t.Fatal("verification scheduled delivery receipt")
			}
			if calls != tc.calls || buffer.cleared != tc.clears {
				t.Fatalf("calls/clear=%d/%d; want %d/%d", calls, buffer.cleared, tc.calls, tc.clears)
			}
			if tc.calls == 1 && !accepted {
				if !errors.Is(err, signalmeow.ErrHandlerFailed) {
					t.Fatalf("failure=%v", err)
				}
				accepted = true
				_, err = cli.HandleDecryptedResultForTest(context.Background(), result, envelope, libsignalgo.NewACIServiceID(self))
				joinCheck(t, err)
				if calls != 2 || buffer.cleared != 1 {
					t.Fatalf("redelivery calls/clear=%d/%d", calls, buffer.cleared)
				}
			} else {
				joinCheck(t, err)
			}
		})
	}
}
