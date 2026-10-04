// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

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

func TestContactSyncTimers(t *testing.T) {
	device, _, _ := timerDevice(t)
	acis := []uuid.UUID{timerACI, uuid.MustParse("10000000-0000-0000-0000-000000000004"), uuid.MustParse("10000000-0000-0000-0000-000000000005"), uuid.MustParse("10000000-0000-0000-0000-000000000006"), uuid.MustParse("10000000-0000-0000-0000-000000000007")}
	input := []*signalpb.ContactDetails{
		{Name: proto.String("skip missing ACI"), ExpireTimer: proto.Uint32(99), ExpireTimerVersion: proto.Uint32(99)},
		{Aci: proto.String(acis[0].String()), Name: proto.String("absent")},
		{Aci: proto.String(""), Name: proto.String("skip empty ACI")},
		{AciBinary: acis[1][:], Name: proto.String("zero"), ExpireTimer: proto.Uint32(0), ExpireTimerVersion: proto.Uint32(2)},
		{Aci: proto.String(acis[2].String()), Name: proto.String("sixty"), ExpireTimer: proto.Uint32(60), ExpireTimerVersion: proto.Uint32(3)},
		{Aci: proto.String(acis[3].String()), Name: proto.String("seconds only"), ExpireTimer: proto.Uint32(30)},
		{Aci: proto.String(acis[4].String()), Name: proto.String("version only"), ExpireTimerVersion: proto.Uint32(4)},
	}
	var event *events.ContactList
	cli := signalmeow.NewClient(device, zerolog.Nop(), func(evt events.SignalEvent) bool { event = evt.(*events.ContactList); return true })
	raw := contactBytes(t, input...)
	if !cli.HandleSyncMessageForTest(context.Background(), contactSync(timerAttachment(t, raw, false)), &signalpb.Envelope{}) {
		t.Fatal("contact sync rejected")
	}
	if event == nil || len(event.Contacts) != 5 || event.IsFromDB {
		t.Fatalf("contact list=%v", event)
	}
	timers := event.Timers
	if len(timers) != 5 {
		t.Fatalf("contact timer metadata missing: %v", event)
	}
	for i, aci := range acis {
		timer := timers[i]
		if timer.ACI != aci || timer.ACI != event.Contacts[i].ACI {
			t.Fatalf("timer %d has wrong ACI", i)
		}
		seconds, version := timer.ExpireTimer, timer.ExpireTimerVersion
		switch i {
		case 0:
			if seconds != nil || version != nil {
				t.Fatal("absent fields became present")
			}
		case 1:
			if seconds == nil || *seconds != 0 || version == nil || *version != 2 {
				t.Fatal("explicit zero/version2 lost")
			}
		case 2:
			if seconds == nil || *seconds != 60 || version == nil || *version != 3 {
				t.Fatal("sixty/version3 lost")
			}
		case 3:
			if seconds == nil || *seconds != 30 || version != nil {
				t.Fatal("seconds-only presence lost")
			}
		case 4:
			if seconds != nil || version == nil || *version != 4 {
				t.Fatal("version-only presence lost")
			}
		}
	}
	// Different entries must own values instead of aliasing a loop temporary.
	*timers[1].ExpireTimer = 9
	*timers[1].ExpireTimerVersion = 9
	if *timers[2].ExpireTimer != 60 || *timers[2].ExpireTimerVersion != 3 {
		t.Fatal("timer entries share pointer values")
	}
	converted := uuid.MustParse("20000000-0000-0000-0000-000000000001")
	device.RecipientStore = &timerRecipients{convertedACI: converted}
	if !cli.HandleSyncMessageForTest(context.Background(), contactSync(timerAttachment(t, contactBytes(t, input[4]), false)), &signalpb.Envelope{}) {
		t.Fatal("conversion sync rejected")
	}
	if event.Timers[0].ACI != converted {
		t.Fatal("metadata ignored converted recipient ACI")
	}

}

func TestContactSyncTimersTransactionFailure(t *testing.T) {
	device, _, fixture := timerDevice(t)
	second := uuid.MustParse("10000000-0000-0000-0000-000000000008")
	device.RecipientStore = &timerRecipients{RecipientStore: device.RecipientStore, failACI: second}
	calls := 0
	cli := signalmeow.NewClient(device, zerolog.Nop(), func(events.SignalEvent) bool { calls++; return true })
	raw := contactBytes(t, &signalpb.ContactDetails{Aci: proto.String(timerACI.String()), Name: proto.String("first"), ExpireTimer: proto.Uint32(0), ExpireTimerVersion: proto.Uint32(2)}, &signalpb.ContactDetails{Aci: proto.String(second.String()), Name: proto.String("fails"), ExpireTimer: proto.Uint32(60), ExpireTimerVersion: proto.Uint32(3)})
	ack := cli.HandleSyncMessageForTest(context.Background(), contactSync(timerAttachment(t, raw, false)), &signalpb.Envelope{})
	if ack || calls != 0 {
		t.Fatalf("ack=%v events=%d; want false/0", ack, calls)
	}
	list, err := cli.StoreContactSyncForTest(context.Background(), raw)
	if list != nil || !errors.Is(err, errTimerStoreFailure) {
		t.Fatalf("failed transaction returned contact metadata: %v, %v", list, err)
	}
	if fixture == nil {
		contacts, err := device.RecipientStore.LoadAllContacts(context.Background())
		joinCheck(t, err)
		if len(contacts) != 0 {
			t.Fatalf("contact transaction didn't roll back: %v", contacts)
		}
	}
}

type timerSessions struct{ store.SessionStore }

func (timerSessions) AllSessionsForServiceID(context.Context, libsignalgo.ServiceID) ([]store.SessionAddressTuple, error) {
	return nil, errors.New("offline stop before transmission")
}

func TestGroupMessageTimer(t *testing.T) {
	for _, edit := range []bool{false, true} {
		for _, duration := range []uint32{60, 0} {
			name := "ordinary"
			if edit {
				name = "edit"
			}
			if duration == 0 {
				name += "/disabled"
			} else {
				name += "/sixty"
			}
			t.Run(name, func(t *testing.T) {
				key := types.SerializedGroupMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)))
				master := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32))
				id, err := master.GroupIdentifier()
				joinCheck(t, err)
				gid := types.GroupIdentifier(base64.StdEncoding.EncodeToString(id[:]))
				group := &signalmeow.Group{GroupMasterKey: key, GroupIdentifier: gid, Revision: 7, DisappearingMessagesDuration: duration}
				device := &store.Device{DeviceData: store.DeviceData{ACI: timerSelf, DeviceID: 1}, ACISessionStore: timerSessions{}}
				cli := signalmeow.NewClient(device, zerolog.Nop(), func(events.SignalEvent) bool { return true })
				cli.SeedGroupCacheForTest(group)
				message := &signalpb.DataMessage{Body: proto.String("group body"), Timestamp: proto.Uint64(1234), ExpireTimer: proto.Uint32(999), ExpireTimerVersion: proto.Uint32(9), Attachments: []*signalpb.AttachmentPointer{{ContentType: proto.String("image/png")}}, BodyRanges: []*signalpb.BodyRange{{Start: proto.Uint32(0), Length: proto.Uint32(5)}}}
				before := proto.Clone(message).(*signalpb.DataMessage)
				content := &signalpb.Content{Content: &signalpb.Content_DataMessage{DataMessage: message}}
				if edit {
					content.Content = &signalpb.Content_EditMessage{EditMessage: &signalpb.EditMessage{TargetSentTimestamp: proto.Uint64(1000), DataMessage: message}}
				}
				_, err = cli.SendGroupMessage(context.Background(), gid, content)
				joinCheck(t, err)
				msg := content.GetDataMessage()
				if edit {
					msg = content.GetEditMessage().GetDataMessage()
					if content.GetEditMessage().GetTargetSentTimestamp() != 1000 {
						t.Fatal("edit target changed")
					}
				}
				if msg.ExpireTimer == nil || msg.GetExpireTimer() != duration || msg.ExpireTimerVersion != nil || msg.GetGroupV2().GetRevision() != 7 {
					t.Fatalf("group message = %v; want timer%d/revision7/no direct version", msg, duration)
				}
				if !bytes.Equal(msg.GetGroupV2().GetMasterKey(), master[:]) {
					t.Fatal("group key changed")
				}
				group.Revision, group.DisappearingMessagesDuration = 8, 90
				if msg.GetExpireTimer() != duration || msg.GetGroupV2().GetRevision() != 7 {
					t.Fatal("group timer/context aliases mutable group state")
				}
				msg.GroupV2 = nil
				msg.ExpireTimer = before.ExpireTimer
				msg.ExpireTimerVersion = before.ExpireTimerVersion
				if !proto.Equal(msg, before) {
					t.Fatal("group stamping changed body, rich content or timestamp")
				}
				typing := &signalpb.TypingMessage{Timestamp: proto.Uint64(5678), Action: signalpb.TypingMessage_STARTED.Enum()}
				_, err = cli.SendGroupMessage(context.Background(), gid, &signalpb.Content{Content: &signalpb.Content_TypingMessage{TypingMessage: typing}})
				joinCheck(t, err)
				if !bytes.Equal(typing.GetGroupId(), id[:]) || typing.GetTimestamp() != 5678 || typing.GetAction() != signalpb.TypingMessage_STARTED {
					t.Fatalf("typing changed: %v", typing)
				}
			})
		}
	}
}
