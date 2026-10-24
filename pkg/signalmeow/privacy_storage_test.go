// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package signalmeow_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

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

var (
	guardedOwnKey     = bytes.Repeat([]byte{0x20}, libsignalgo.ProfileKeyLength)
	conflictingOwnKey = bytes.Repeat([]byte{0x90}, libsignalgo.ProfileKeyLength)
)

// privacyAccount is an imported account whose contact is blocked without profile sharing,
// with read receipts off and its own profile key, all protected at manifest version 5.
type privacyAccount struct {
	t       *testing.T
	db      *refillDB
	cli     *signalmeow.Client
	events  chan events.SignalEvent
	contact uuid.UUID
}

func newPrivacyAccount(t *testing.T) *privacyAccount {
	t.Helper()
	ctx := context.Background()
	aci := uuid.New()
	db := openRefillDB(t, filepath.Join(t.TempDir(), "account.db"), aci)
	key := refillIdentity(t)
	joinCheck(t, db.c.PutDevice(ctx, &store.DeviceData{ACI: aci, PNI: uuid.New(), ACIIdentityKeyPair: key, PNIIdentityKeyPair: key, DeviceID: 2,
		AccountRecord: &signalpb.AccountRecord{ReadReceipts: false, TypingIndicators: true, ProfileKey: guardedOwnKey}}))
	a := &privacyAccount{t: t, db: db, contact: uuid.New()}
	a.open()
	dev := a.cli.Store
	_, err := dev.RecipientStore.LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, func(r *types.Recipient) (bool, error) {
		r.Blocked, r.Whitelisted = true, new(bool)
		return true, nil
	})
	joinCheck(t, err)
	joinCheck(t, dev.RecipientStore.StoreProfileKey(ctx, aci, libsignalgo.ProfileKey(guardedOwnKey)))
	joinCheck(t, dev.PrivacyGuardStore.SeedPrivacyGuards(ctx, []store.PrivacyGuard{
		{Kind: store.PrivacyEntityACI, ID: a.contact, Field: store.PrivacyFieldBlocked, LocalPresent: true, Value: store.PrivacyBool(true), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityACI, ID: a.contact, Field: store.PrivacyFieldWhitelisted, LocalPresent: true, Value: store.PrivacyBool(false), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldReadReceipts, LocalPresent: true, Value: store.PrivacyBool(false), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldOwnProfileKey, LocalPresent: true, Value: guardedOwnKey, Protected: true, ArmedVersion: 5},
	}))
	return a
}

// open (re)loads the device from the database, as a restarted process would.
func (a *privacyAccount) open() {
	// Earlier clients may still deliver asynchronously into their own channel.
	ch := make(chan events.SignalEvent, 16)
	a.events = ch
	a.cli = signalmeow.NewClient(a.db.device(), zerolog.Nop(), func(evt events.SignalEvent) bool { ch <- evt; return true })
}

func (a *privacyAccount) restart() {
	a.db = a.db.reopen()
	a.open()
}

func contactRecord(aci uuid.UUID, blocked, whitelisted bool) *signalmeow.DecryptedStorageRecord {
	return &signalmeow.DecryptedStorageRecord{StorageRecord: &signalpb.StorageRecord{Record: &signalpb.StorageRecord_Contact{
		Contact: &signalpb.ContactRecord{Aci: aci.String(), Blocked: blocked, Whitelisted: whitelisted}}}}
}

func accountRecord(record *signalpb.AccountRecord) *signalmeow.DecryptedStorageRecord {
	return &signalmeow.DecryptedStorageRecord{StorageRecord: &signalpb.StorageRecord{Record: &signalpb.StorageRecord_Account{Account: record}}}
}

// conflicting is a snapshot undoing every imported decision.
func (a *privacyAccount) conflicting(version uint64) *signalmeow.StorageUpdate {
	return &signalmeow.StorageUpdate{Version: version, NewRecords: []*signalmeow.DecryptedStorageRecord{
		contactRecord(a.contact, false, true),
		accountRecord(&signalpb.AccountRecord{ReadReceipts: true, TypingIndicators: false, ProfileKey: conflictingOwnKey}),
	}}
}

// state reads the effective values from SQL, the block cache, the live and the stored account record.
func (a *privacyAccount) state() (blocked, whitelisted, readReceipts, storedReadReceipts bool, ownKey []byte) {
	a.t.Helper()
	ctx := context.Background()
	dev := a.cli.Store
	row, err := dev.RecipientStore.LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, nil)
	joinCheck(a.t, err)
	cached, err := dev.RecipientStore.IsBlocked(ctx, libsignalgo.NewACIServiceID(a.contact))
	joinCheck(a.t, err)
	if cached != row.Blocked {
		a.t.Fatalf("block cache %v disagrees with SQL %v", cached, row.Blocked)
	}
	key, err := dev.RecipientStore.MyProfileKey(ctx)
	joinCheck(a.t, err)
	stored := a.db.device().AccountRecord
	return row.Blocked, row.Whitelisted != nil && *row.Whitelisted, dev.AccountRecord.GetReadReceipts(), stored.GetReadReceipts(), key.Slice()
}

func (a *privacyAccount) checkProtected(step string) {
	a.t.Helper()
	blocked, whitelisted, readReceipts, storedReadReceipts, ownKey := a.state()
	if !blocked || whitelisted || readReceipts || storedReadReceipts || !bytes.Equal(ownKey, guardedOwnKey) {
		a.t.Errorf("%s: blocked=%v whitelisted=%v readReceipts=%v/%v ownKey=%x; want the imported decisions",
			step, blocked, whitelisted, readReceipts, storedReadReceipts, ownKey)
	}
}

func (a *privacyAccount) apply(update *signalmeow.StorageUpdate) {
	a.t.Helper()
	joinCheck(a.t, a.cli.ApplyStorage(context.Background(), update))
}

// TestPrivacyGuardFirstFetch applies a first, conflicting fetch: SQL, the block cache, the
// live and the stored account record keep the imported decisions, while the update handler
// still sees the untouched raw snapshot.
func TestPrivacyGuardFirstFetch(t *testing.T) {
	a := newPrivacyAccount(t)
	update := a.conflicting(6)
	raw := proto.Clone(update.NewRecords[1].StorageRecord).(*signalpb.StorageRecord)
	var handled *signalpb.AccountRecord
	a.cli.StorageUpdateHandler = func(_ context.Context, got *signalmeow.StorageUpdate) error {
		handled = got.NewRecords[1].StorageRecord.GetAccount()
		return nil
	}
	a.apply(update)
	a.checkProtected("first fetch")
	if !proto.Equal(update.NewRecords[1].StorageRecord, raw) || !handled.GetReadReceipts() || !bytes.Equal(handled.GetProfileKey(), conflictingOwnKey) {
		t.Errorf("raw snapshot changed or not handed over: %v", handled)
	}
	if a.cli.Store.AccountRecord.GetTypingIndicators() {
		t.Error("unguarded account field not applied")
	}
	if v, err := a.cli.Store.PrivacyGuardStore.StorageManifestVersion(context.Background()); err != nil || v != 6 {
		t.Errorf("highwater = %d, %v", v, err)
	}
}

// TestPrivacyGuardRestart repeats conflicting and older snapshots after a restart.
func TestPrivacyGuardRestart(t *testing.T) {
	a := newPrivacyAccount(t)
	a.apply(a.conflicting(6))
	a.restart()
	a.checkProtected("restarted")
	for _, version := range []uint64{6, 4, 7} {
		a.apply(a.conflicting(version))
		a.checkProtected("after restart")
	}
}

// TestPrivacyGuardMissingAndFalse: missing records release nothing; a present record's
// omitted proto3 boolean is a false value, which matches and releases the receipts guard.
func TestPrivacyGuardMissingAndFalse(t *testing.T) {
	a := newPrivacyAccount(t)
	a.apply(&signalmeow.StorageUpdate{Version: 6})
	a.apply(&signalmeow.StorageUpdate{Version: 7, NewRecords: []*signalmeow.DecryptedStorageRecord{contactRecord(uuid.New(), false, true)}})
	a.checkProtected("missing records")
	// The contact's omitted Blocked is false, so it doesn't match; the account record without
	// a profile key or receipts matches the receipts guard only.
	a.apply(&signalmeow.StorageUpdate{Version: 8, NewRecords: []*signalmeow.DecryptedStorageRecord{
		contactRecord(a.contact, false, false), accountRecord(&signalpb.AccountRecord{TypingIndicators: true}),
	}})
	blocked, whitelisted, _, _, ownKey := a.state()
	if !blocked || whitelisted || !bytes.Equal(ownKey, guardedOwnKey) {
		t.Errorf("blocked=%v whitelisted=%v ownKey=%x", blocked, whitelisted, ownKey)
	}
	a.apply(&signalmeow.StorageUpdate{Version: 9, NewRecords: []*signalmeow.DecryptedStorageRecord{accountRecord(&signalpb.AccountRecord{ReadReceipts: true})}})
	if _, _, readReceipts, stored, ownKey := a.state(); !readReceipts || !stored || !bytes.Equal(ownKey, guardedOwnKey) {
		t.Errorf("released receipts guard: readReceipts=%v/%v ownKey=%x", readReceipts, stored, ownKey)
	}
}

// TestPrivacyGuardRelease: a strictly newer matching snapshot releases the guards (one
// older than the highwater doesn't), and the next change applies.
func TestPrivacyGuardRelease(t *testing.T) {
	a := newPrivacyAccount(t)
	matching := func(version uint64) *signalmeow.StorageUpdate {
		return &signalmeow.StorageUpdate{Version: version, NewRecords: []*signalmeow.DecryptedStorageRecord{
			contactRecord(a.contact, true, false),
			accountRecord(&signalpb.AccountRecord{ReadReceipts: false, ProfileKey: guardedOwnKey}),
		}}
	}
	a.apply(a.conflicting(10))
	a.apply(matching(8)) // older than the highwater: not observed
	a.apply(a.conflicting(10))
	a.checkProtected("stale match")
	a.apply(matching(11))
	a.checkProtected("aligned")
	a.apply(a.conflicting(12))
	blocked, whitelisted, readReceipts, stored, ownKey := a.state()
	if blocked || !whitelisted || !readReceipts || !stored || !bytes.Equal(ownKey, conflictingOwnKey) {
		t.Errorf("later change: blocked=%v whitelisted=%v readReceipts=%v/%v ownKey=%x", blocked, whitelisted, readReceipts, stored, ownKey)
	}
}

// TestPrivacyGuardRollback fails the transaction of a releasing snapshot: no guard is
// released, no setting, highwater or event is published, and the cache holds no projection.
func TestPrivacyGuardRollback(t *testing.T) {
	a := newPrivacyAccount(t)
	ctx := context.Background()
	failure := errors.New("handler failure")
	a.cli.StorageUpdateHandler = func(context.Context, *signalmeow.StorageUpdate) error { return failure }
	before := a.cli.Store.AccountRecord
	update := &signalmeow.StorageUpdate{Version: 9, NewRecords: []*signalmeow.DecryptedStorageRecord{
		contactRecord(a.contact, true, false), accountRecord(&signalpb.AccountRecord{ReadReceipts: true, TypingIndicators: false}),
	}}
	if err := a.cli.ApplyStorage(ctx, update); !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
	if a.cli.Store.AccountRecord != before {
		t.Error("failed transaction published the account record")
	}
	if v, _ := a.cli.Store.PrivacyGuardStore.StorageManifestVersion(ctx); v != 0 {
		t.Errorf("failed transaction stored highwater %d", v)
	}
	guards, err := a.cli.Store.PrivacyGuardStore.PrivacyGuards(ctx)
	joinCheck(t, err)
	for _, g := range guards {
		if !g.Protected || g.ObservedVersion != 0 {
			t.Errorf("failed transaction changed guard %+v", g)
		}
	}
	a.checkProtected("rolled back")
	select {
	case evt := <-a.events:
		t.Errorf("failed transaction emitted %T", evt)
	default:
	}
}

// TestWhitelistTwoWay: without guards, profile sharing follows storage both ways.
func TestWhitelistTwoWay(t *testing.T) {
	a := newPrivacyAccount(t)
	other := uuid.New()
	for _, want := range []bool{true, false, true} {
		a.apply(&signalmeow.StorageUpdate{Version: 6, NewRecords: []*signalmeow.DecryptedStorageRecord{contactRecord(other, false, want)}})
		row, err := a.cli.Store.RecipientStore.LoadAndUpdateRecipient(context.Background(), other, uuid.Nil, nil)
		joinCheck(t, err)
		if row.Whitelisted == nil || *row.Whitelisted != want {
			t.Errorf("whitelisted = %v, want %v", row.Whitelisted, want)
		}
	}
	// Each change emitted one contact list; an unchanged record is no change.
	for range 3 {
		select {
		case <-a.events:
		case <-time.After(5 * time.Second):
			t.Fatal("change not emitted")
		}
	}
	a.apply(&signalmeow.StorageUpdate{Version: 6, NewRecords: []*signalmeow.DecryptedStorageRecord{contactRecord(other, false, true)}})
	select {
	case evt := <-a.events:
		t.Errorf("unchanged record emitted %v", evt)
	case <-time.After(200 * time.Millisecond):
	}
}
