// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
)

func TestStorageUpdateHandlerFailure(t *testing.T) {
	device, _, fixture := timerDevice(t)
	emitted := make(chan events.SignalEvent, 1)
	cli := signalmeow.NewClient(device, zerolog.Nop(), func(evt events.SignalEvent) bool { emitted <- evt; return true })
	failure := errors.New("identity update failure")
	calls := 0
	update := &signalmeow.StorageUpdate{Version: 17, NewRecords: []*signalmeow.DecryptedStorageRecord{{StorageRecord: &signalpb.StorageRecord{Record: &signalpb.StorageRecord_Contact{Contact: &signalpb.ContactRecord{Aci: timerACI.String(), E164: "+12025550101", IdentityState: signalpb.ContactRecord_VERIFIED}}}}}}
	cli.StorageUpdateHandler = func(ctx context.Context, got *signalmeow.StorageUpdate) error {
		calls++
		if ctx == nil || got != update || got.Version != 17 {
			t.Fatal("not the fetched update")
		}
		return failure
	}
	if err := cli.ApplyStorage(context.Background(), update); !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("failure=%v, calls=%d", err, calls)
	}
	checkNoPartialContactStorage(t, device, fixture)
	select {
	case <-emitted:
		t.Fatal("failed transaction emitted contacts")
	default:
	}
}

func TestStorageUpdateHandlerIdentityOnly(t *testing.T) {
	device, _, _ := timerDevice(t)
	cli := signalmeow.NewClient(device, zerolog.Nop(), func(events.SignalEvent) bool { return true })
	calls := 0
	cli.StorageUpdateHandler = func(context.Context, *signalmeow.StorageUpdate) error { calls++; return nil }
	joinCheck(t, cli.ApplyStorage(context.Background(), &signalmeow.StorageUpdate{Version: 18}))
	if calls != 1 {
		t.Fatalf("identity-only snapshot calls=%d", calls)
	}
	joinCheck(t, cli.ApplyStorage(context.Background(), nil))
	if calls != 1 {
		t.Fatal("nil update dispatched")
	}
}

func TestStorageUpdateHandlerCommitFailure(t *testing.T) {
	device, _, fixture := timerDevice(t)
	if fixture == nil {
		t.Skip("controlled commit failure requires pure-Go transaction fixture")
	}
	cli := signalmeow.NewClient(device, zerolog.Nop(), func(events.SignalEvent) bool { return true })
	original := &signalpb.AccountRecord{ReadReceipts: true}
	device.AccountRecord = original
	update := &signalmeow.StorageUpdate{Version: 19, NewRecords: []*signalmeow.DecryptedStorageRecord{{StorageRecord: &signalpb.StorageRecord{Record: &signalpb.StorageRecord_Account{Account: &signalpb.AccountRecord{ReadReceipts: false}}}}}}
	failure := errors.New("commit failure")
	device.DeviceStore = storageDeviceWriter{DeviceStore: device.DeviceStore}
	fixture.commitErr = failure
	if err := cli.ApplyStorage(context.Background(), update); !errors.Is(err, failure) {
		t.Fatalf("commit error=%v", err)
	}
	if device.AccountRecord != original {
		t.Fatal("failed commit published settings")
	}
	fixture.commitErr = nil
	joinCheck(t, cli.ApplyStorage(context.Background(), update))
	if device.AccountRecord.GetReadReceipts() {
		t.Fatal("successful retry did not publish settings")
	}
}

// The pure-Go transaction fixture cannot prepare DeviceStore's upsert. Replace only
// that write to reach its controlled commit failure; publication remains production code.
type storageDeviceWriter struct{ store.DeviceStore }

func (storageDeviceWriter) PutDevice(context.Context, *store.DeviceData) error { return nil }
