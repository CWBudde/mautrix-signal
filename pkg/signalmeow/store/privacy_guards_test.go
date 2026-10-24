// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package store_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store/upgrades"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

func ptrKey(k libsignalgo.ProfileKey) *libsignalgo.ProfileKey { return &k }

func boolPtr(v bool) *bool { return &v }

func profileKey(start byte) libsignalgo.ProfileKey {
	var key libsignalgo.ProfileKey
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}

// guardedAccount is an imported account: a blocked ACI contact without profile sharing, a
// blocked PNI-only contact and a protected own profile key, armed at manifest version 5.
type guardedAccount struct {
	db                 *testDB
	dev                *store.Device
	contact, pniOnly   uuid.UUID
	ownKey, foreignKey libsignalgo.ProfileKey
}

func newGuardedAccount(t *testing.T) *guardedAccount {
	t.Helper()
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	a := &guardedAccount{db: db, dev: db.putDevice(uuid.New(), uuid.New()), contact: uuid.New(), pniOnly: uuid.New(),
		ownKey: profileKey(0x20), foreignKey: profileKey(0x60)}
	if _, err := a.dev.RecipientStore.LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, func(r *types.Recipient) (bool, error) {
		r.Blocked, r.Whitelisted = true, boolPtr(false)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.dev.RecipientStore.StoreRecipient(ctx, &types.Recipient{PNI: a.pniOnly, Blocked: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.dev.RecipientStore.StoreProfileKey(ctx, a.dev.ACI, a.ownKey); err != nil {
		t.Fatal(err)
	}
	err := a.dev.PrivacyGuardStore.SeedPrivacyGuards(ctx, []store.PrivacyGuard{
		{Kind: store.PrivacyEntityACI, ID: a.contact, Field: store.PrivacyFieldBlocked, LocalPresent: true, Value: store.PrivacyBool(true), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityACI, ID: a.contact, Field: store.PrivacyFieldWhitelisted, LocalPresent: true, Value: store.PrivacyBool(false), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityPNI, ID: a.pniOnly, Field: store.PrivacyFieldBlocked, LocalPresent: true, Value: store.PrivacyBool(true), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldOwnProfileKey, LocalPresent: true, Value: a.ownKey.Slice(), Protected: true, ArmedVersion: 5},
		{Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldReadReceipts, LocalPresent: true, Value: store.PrivacyBool(false), Protected: true, ArmedVersion: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *guardedAccount) reopen() {
	a.db = a.db.reopen()
	a.dev = a.db.device(a.dev.ACI)
}

// check verifies the protected values in SQL and through the (typed) block cache.
func (a *guardedAccount) check(t *testing.T, step string) {
	t.Helper()
	ctx := context.Background()
	contact, err := a.dev.RecipientStore.LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, nil)
	if err != nil || !contact.Blocked || contact.Whitelisted == nil || *contact.Whitelisted {
		t.Errorf("%s: contact = %+v, %v; want blocked without profile sharing", step, contact, err)
	}
	for _, id := range []libsignalgo.ServiceID{libsignalgo.NewACIServiceID(a.contact), libsignalgo.NewPNIServiceID(a.pniOnly)} {
		for range 2 { // uncached, then cached
			if blocked, err := a.dev.RecipientStore.IsBlocked(ctx, id); err != nil || !blocked {
				t.Errorf("%s: IsBlocked(%s) = %v, %v", step, id, blocked, err)
			}
		}
	}
	if key, err := a.dev.RecipientStore.MyProfileKey(ctx); err != nil || key == nil || *key != a.ownKey {
		t.Errorf("%s: own profile key = %v, %v", step, key, err)
	}
}

// TestPrivacyGuardBypass sends every recipient writer's conflicting value at the guards: none
// replaces a protected value, before or after a restart, and unrelated fields still apply.
func TestPrivacyGuardBypass(t *testing.T) {
	ctx := context.Background()
	a := newGuardedAccount(t)
	a.check(t, "seeded")
	rs := func() store.RecipientStore { return a.dev.RecipientStore }

	writers := map[string]func() error{
		// MessageRequestResponse ACCEPT and an outgoing profile key update whitelist the ACI.
		"acceptRequest": func() error {
			_, err := rs().LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, func(r *types.Recipient) (bool, error) {
				r.Whitelisted, r.NeedsPNISignature = boolPtr(true), false
				return true, nil
			})
			return err
		},
		// A message to our PNI marks the sender as a message request.
		"pniMessage": func() error {
			_, err := rs().LoadAndUpdateRecipient(ctx, uuid.Nil, a.pniOnly, func(r *types.Recipient) (bool, error) {
				r.Whitelisted, r.NeedsPNISignature, r.Blocked = boolPtr(false), true, false
				return true, nil
			})
			return err
		},
		// Sent transcripts, stories and group updates carry our own key through StoreProfileKey.
		"sentTranscriptKey": func() error { return rs().StoreProfileKey(ctx, a.dev.ACI, profileKey(0x90)) },
		"groupKey":          func() error { return rs().StoreProfileKey(ctx, a.dev.ACI, profileKey(0xa0)) },
		"storyKey":          func() error { return rs().StoreProfileKey(ctx, a.dev.ACI, profileKey(0xb0)) },
		// A profile refresh replaces the whole profile, key included.
		"profileRefresh": func() error {
			_, err := rs().LoadAndUpdateRecipient(ctx, a.dev.ACI, uuid.Nil, func(r *types.Recipient) (bool, error) {
				r.Profile = types.Profile{Name: "Refreshed", Key: profileKey(0xc0)}
				return true, nil
			})
			return err
		},
		// Backup import writes blocked and profile sharing through the recipient updater.
		"backupImport": func() error {
			_, err := rs().LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, func(r *types.Recipient) (bool, error) {
				r.Blocked, r.Whitelisted, r.ContactName = false, boolPtr(true), "Imported Name"
				return true, nil
			})
			return err
		},
		// A plain row write, and a merge of the PNI-only row into an ACI row.
		"storeRecipient": func() error {
			return rs().StoreRecipient(ctx, &types.Recipient{ACI: a.contact, Blocked: false, Whitelisted: boolPtr(true), ContactName: "Imported Name"})
		},
	}
	for name, write := range writers {
		if err := write(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a.check(t, name)
	}
	contact, _ := rs().LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, nil)
	if contact.ContactName != "Imported Name" {
		t.Errorf("unrelated field not applied: %q", contact.ContactName)
	}
	self, _ := rs().LoadAndUpdateRecipient(ctx, a.dev.ACI, uuid.Nil, nil)
	if self.Profile.Name != "Refreshed" {
		t.Errorf("unrelated profile field not applied: %+v", self.Profile)
	}
	// Other users' profile keys are not protected.
	other := uuid.New()
	if err := rs().StoreProfileKey(ctx, other, a.foreignKey); err != nil {
		t.Fatal(err)
	}
	if key, err := rs().LoadProfileKey(ctx, other); err != nil || key == nil || *key != a.foreignKey {
		t.Errorf("foreign profile key = %v, %v", key, err)
	}

	a.reopen()
	a.check(t, "reopened")
	if err := writers["acceptRequest"](); err != nil {
		t.Fatal(err)
	}
	a.check(t, "reopened write")

	// Merging the guarded PNI-only row with a newly learned ACI keeps the PNI guard.
	merged := uuid.New()
	if err := rs().StoreRecipient(ctx, &types.Recipient{ACI: merged}); err != nil {
		t.Fatal(err)
	}
	row, err := rs().LoadAndUpdateRecipient(ctx, merged, a.pniOnly, func(r *types.Recipient) (bool, error) {
		r.Blocked = false
		return true, nil
	})
	if err != nil || !row.Blocked {
		t.Errorf("merged row = %+v, %v; want blocked", row, err)
	}
	if blocked, err := rs().IsBlocked(ctx, libsignalgo.NewACIServiceID(merged)); err != nil || !blocked {
		t.Errorf("merged ACI blocked = %v, %v", blocked, err)
	}
}

// TestPrivacyGuardRelease checks the release rule: only a strictly newer snapshot with a
// present, valid, matching value releases a guard; then later writes apply.
func TestPrivacyGuardRelease(t *testing.T) {
	ctx := context.Background()
	a := newGuardedAccount(t)
	guards := a.dev.PrivacyGuardStore
	blocked := func(present bool, value []byte, version uint64) bool {
		t.Helper()
		released, err := guards.ObservePrivacyRemote(ctx, store.PrivacyEntityACI, a.contact, store.PrivacyFieldBlocked, present, value, version)
		if err != nil {
			t.Fatal(err)
		}
		return released
	}
	for name, observe := range map[string]func() bool{
		"conflicting newer": func() bool { return blocked(true, store.PrivacyBool(false), 9) },
		"matching armed":    func() bool { return blocked(true, store.PrivacyBool(true), 5) },
		"matching older":    func() bool { return blocked(true, store.PrivacyBool(true), 4) },
		"missing newer":     func() bool { return blocked(false, nil, 9) },
		"invalid newer":     func() bool { return blocked(true, []byte{7}, 9) },
	} {
		if observe() {
			t.Errorf("%s released the guard", name)
		}
		a.check(t, name)
	}
	// Unknown enums and absent keys never release account guards.
	for field, value := range map[store.PrivacyField][]byte{
		store.PrivacyFieldOwnProfileKey:          nil,
		store.PrivacyFieldPhoneNumberSharingMode: {9},
	} {
		if released, err := guards.ObservePrivacyRemote(ctx, store.PrivacyEntityAccount, uuid.Nil, field, value != nil, value, 9); err != nil || released {
			t.Errorf("%s: released = %v, %v", field, released, err)
		}
	}
	// No guard, no effect.
	if released, err := guards.ObservePrivacyRemote(ctx, store.PrivacyEntityACI, uuid.New(), store.PrivacyFieldBlocked, true, store.PrivacyBool(true), 9); err != nil || released {
		t.Errorf("unguarded: released = %v, %v", released, err)
	}

	a.reopen()
	guards = a.dev.PrivacyGuardStore
	if !blocked(true, store.PrivacyBool(true), 6) {
		t.Fatal("strictly newer matching snapshot did not release")
	}
	if _, err := a.dev.RecipientStore.LoadAndUpdateRecipient(ctx, a.contact, uuid.Nil, func(r *types.Recipient) (bool, error) {
		r.Blocked = false
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.dev.RecipientStore.IsBlocked(ctx, libsignalgo.NewACIServiceID(a.contact)); got {
		t.Error("released guard still applied")
	}
	all, err := guards.PrivacyGuards(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range all {
		if g.Kind == store.PrivacyEntityACI && g.ID == a.contact && g.Field == store.PrivacyFieldBlocked {
			if g.Protected || !g.RemotePresent || !bytes.Equal(g.RemoteValue, store.PrivacyBool(true)) || g.ObservedVersion != 9 {
				t.Errorf("released guard = %+v", g)
			}
		}
	}

	// A local command re-arms the existing guard at the stored highwater; unguarded users
	// get no guard.
	if err := guards.AdvanceStorageManifestVersion(ctx, 12); err != nil {
		t.Fatal(err)
	}
	if err := guards.AdvanceStorageManifestVersion(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if v, err := guards.StorageManifestVersion(ctx); err != nil || v != 12 {
		t.Fatalf("highwater = %d, %v", v, err)
	}
	if _, err := a.dev.SetRecipientBlocked(ctx, libsignalgo.NewACIServiceID(a.contact), true); err != nil {
		t.Fatal(err)
	}
	if blocked(true, store.PrivacyBool(true), 12) {
		t.Error("re-armed guard released by the snapshot it was armed at")
	}
	a.check(t, "re-armed")
	stranger := uuid.New()
	if _, err := a.dev.SetRecipientBlocked(ctx, libsignalgo.NewACIServiceID(stranger), true); err != nil {
		t.Fatal(err)
	}
	if rearmed, err := guards.RearmPrivacyGuard(ctx, store.PrivacyEntityACI, stranger, store.PrivacyFieldBlocked, store.PrivacyBool(false)); err != nil || rearmed {
		t.Errorf("rearm without guard = %v, %v", rearmed, err)
	}
	if got, _ := a.dev.RecipientStore.IsBlocked(ctx, libsignalgo.NewACIServiceID(stranger)); !got {
		t.Error("local block of an unguarded user not stored")
	}
}

func TestPrivacyGuardSeedRefusals(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	guards := db.putDevice(uuid.New(), uuid.New()).PrivacyGuardStore
	id := uuid.New()
	for name, g := range map[string]store.PrivacyGuard{
		"unknown kind":       {Kind: "e164", ID: id, Field: store.PrivacyFieldBlocked, Value: store.PrivacyBool(true)},
		"group":              {Kind: "group", ID: id, Field: store.PrivacyFieldBlocked, Value: store.PrivacyBool(true)},
		"account with ID":    {Kind: store.PrivacyEntityAccount, ID: id, Field: store.PrivacyFieldReadReceipts, Value: store.PrivacyBool(true)},
		"account blocked":    {Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldBlocked, Value: store.PrivacyBool(true)},
		"ACI setting":        {Kind: store.PrivacyEntityACI, ID: id, Field: store.PrivacyFieldReadReceipts, Value: store.PrivacyBool(true)},
		"nil ACI":            {Kind: store.PrivacyEntityACI, Field: store.PrivacyFieldBlocked, Value: store.PrivacyBool(true)},
		"bool value":         {Kind: store.PrivacyEntityACI, ID: id, Field: store.PrivacyFieldBlocked, Value: []byte{2}},
		"empty value":        {Kind: store.PrivacyEntityPNI, ID: id, Field: store.PrivacyFieldWhitelisted},
		"short profile key":  {Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldOwnProfileKey, Value: make([]byte, 31)},
		"unknown enum":       {Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldPhoneNumberSharingMode, Value: []byte{3}},
		"unknown field":      {Kind: store.PrivacyEntityAccount, Field: "username", Value: store.PrivacyBool(true)},
		"long sharing value": {Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldPhoneNumberSharingMode, Value: []byte{1, 0}},
	} {
		if err := guards.SeedPrivacyGuards(ctx, []store.PrivacyGuard{g}); !errors.Is(err, store.ErrPrivacyGuardInvalid) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if all, _ := guards.PrivacyGuards(ctx); len(all) != 0 {
		t.Fatalf("refused seeds stored %d guards", len(all))
	}
	ok := store.PrivacyGuard{Kind: store.PrivacyEntityAccount, Field: store.PrivacyFieldPhoneNumberSharingMode,
		Value: store.PrivacySharingMode(signalpb.AccountRecord_NOBODY), Protected: true}
	if err := guards.SeedPrivacyGuards(ctx, []store.PrivacyGuard{ok}); err != nil {
		t.Fatal(err)
	}
	if err := guards.SeedPrivacyGuards(ctx, []store.PrivacyGuard{ok}); !errors.Is(err, store.ErrPrivacyGuardsExist) {
		t.Errorf("second seed error = %v", err)
	}
}

// TestTypedBlocking keeps an ACI and a PNI with the same UUID bytes apart, in SQL and in the
// block cache, and persists the blocked state of PNI-only rows.
func TestTypedBlocking(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	dev := db.putDevice(uuid.New(), uuid.New())
	shared := uuid.New()
	aci, pni := libsignalgo.NewACIServiceID(shared), libsignalgo.NewPNIServiceID(shared)
	if err := dev.RecipientStore.StoreRecipient(ctx, &types.Recipient{PNI: shared, Blocked: true, Whitelisted: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got, err := dev.RecipientStore.IsBlocked(ctx, pni); err != nil || !got {
			t.Fatalf("PNI blocked = %v, %v", got, err)
		}
		if got, err := dev.RecipientStore.IsBlocked(ctx, aci); err != nil || got {
			t.Fatalf("ACI with the PNI's bytes blocked = %v, %v", got, err)
		}
	}
	if got, err := dev.RecipientStore.IsBlocked(ctx, libsignalgo.NewPNIServiceID(uuid.New())); err != nil || got {
		t.Fatalf("unknown PNI blocked = %v, %v", got, err)
	}
	db = db.reopen()
	dev = db.device(dev.ACI)
	row, err := dev.RecipientStore.LoadAndUpdateRecipient(ctx, uuid.Nil, shared, nil)
	if err != nil || !row.Blocked || row.Whitelisted == nil || *row.Whitelisted {
		t.Fatalf("reopened PNI-only row = %+v, %v", row, err)
	}
	// Unblocking the PNI through the typed local command leaves the ACI alone.
	if _, err := dev.SetRecipientBlocked(ctx, aci, true); err != nil {
		t.Fatal(err)
	}
	if _, err := dev.SetRecipientBlocked(ctx, pni, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := dev.RecipientStore.IsBlocked(ctx, pni); got {
		t.Error("PNI still blocked")
	}
	if got, _ := dev.RecipientStore.IsBlocked(ctx, aci); !got {
		t.Error("ACI unblocked with the PNI")
	}
}

func TestPrivacyGuardProjectAccountRecord(t *testing.T) {
	ctx := context.Background()
	a := newGuardedAccount(t)
	raw := &signalpb.AccountRecord{ReadReceipts: true, TypingIndicators: true, ProfileKey: ptrKey(profileKey(0x90)).Slice(), GivenName: "Remote"}
	projected, err := a.dev.PrivacyGuardStore.ProjectAccountRecord(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if projected.ReadReceipts || !projected.TypingIndicators || !bytes.Equal(projected.ProfileKey, a.ownKey.Slice()) || projected.GivenName != "Remote" {
		t.Errorf("projection = %v", projected)
	}
	if !raw.ReadReceipts || !bytes.Equal(raw.ProfileKey, ptrKey(profileKey(0x90)).Slice()) {
		t.Error("projection modified the raw record")
	}
	values := store.AccountPrivacyValues(&signalpb.AccountRecord{PhoneNumberSharingMode: 7})
	if _, ok := values[store.PrivacyFieldPhoneNumberSharingMode]; ok {
		t.Error("unknown sharing mode reported as present")
	}
	if _, ok := values[store.PrivacyFieldOwnProfileKey]; ok {
		t.Error("absent profile key reported as present")
	}
	if !bytes.Equal(values[store.PrivacyFieldReadReceipts], store.PrivacyBool(false)) {
		t.Error("omitted proto3 bool is not a false value")
	}
}

func TestPrivacyGuardSchemaFloor(t *testing.T) {
	ctx := context.Background()
	db := openV27(t)
	aci := uuid.New()
	db.putLegacyDevice(aci, uuid.New())
	v29 := db.root.Child("signalmeow_version", upgrades.Table[:29], dbutil.NoopLogger)
	if err := v29.Upgrade(ctx); err != nil {
		t.Fatalf("upgrade to v29: %v", err)
	}
	if err := db.c.Upgrade(ctx); err != nil {
		t.Fatalf("upgrade to v30: %v", err)
	}
	if v, c := db.version(); v != 30 || c != 30 {
		t.Fatalf("migrated version = %d/%d, want 30/30", v, c)
	}
	dev := db.device(aci)
	if all, err := dev.PrivacyGuardStore.PrivacyGuards(ctx); err != nil || len(all) != 0 {
		t.Fatalf("migrated guards = %v, %v", all, err)
	}
	if v, err := dev.PrivacyGuardStore.StorageManifestVersion(ctx); err != nil || v != 0 {
		t.Fatalf("migrated highwater = %d, %v", v, err)
	}
	// A v29 binary would apply storage over the guards, so it must refuse the database.
	if err := v29.Upgrade(ctx); !errors.Is(err, dbutil.ErrUnsupportedDatabaseVersion) {
		t.Fatalf("v29 reader error = %v, want ErrUnsupportedDatabaseVersion", err)
	}
}
