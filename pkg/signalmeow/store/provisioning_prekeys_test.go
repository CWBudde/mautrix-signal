// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
)

type linkInput struct {
	data *store.DeviceData
	keys store.ProvisioningPreKeys
}

func newLinkInput(t *testing.T, aci, pni uuid.UUID, password string) linkInput {
	t.Helper()
	aciKey, pniKey := identityKeyPair(t), identityKeyPair(t)
	return linkInput{
		data: &store.DeviceData{
			ACIIdentityKeyPair: aciKey, PNIIdentityKeyPair: pniKey, ACI: aci, PNI: pni,
			ACIRegistrationID: 1, PNIRegistrationID: 2, DeviceID: 3, Number: "+4915100000000", Password: password,
		},
		keys: store.ProvisioningPreKeys{
			ACISigned: signedKey(t, 1, aciKey), PNISigned: signedKey(t, 1, pniKey),
			ACILastResort: kyberKey(t, 1, aciKey), PNILastResort: kyberKey(t, 1, pniKey),
		},
	}
}

func provisionedState() store.PreKeyAllocatorState {
	return store.PreKeyAllocatorState{NextEC: 1, NextSigned: 2, NextKyber: 2, ActiveSigned: ptr(1), ActiveLastResort: ptr(1)}
}

func assertProvisioned(t *testing.T, dev *store.Device) {
	t.Helper()
	ctx := context.Background()
	for _, pks := range []store.PreKeyStore{dev.ACIPreKeyStore, dev.PNIPreKeyStore} {
		assertState(t, pks, provisionedState())
		assertCounts(t, pks, 0, 0)
		if rec, err := pks.LoadSignedPreKey(ctx, 1); err != nil || rec == nil {
			t.Fatalf("%s signed prekey 1 missing: %v", pks.GetServiceID(), err)
		}
		if lr, err := pks.IsKyberPreKeyLastResort(ctx, 1); err != nil || !lr {
			t.Fatalf("%s last-resort prekey 1 = %v, %v", pks.GetServiceID(), lr, err)
		}
	}
}

// oldAccount links an account and then gives it the state a running client accumulates:
// an EC key, a session and advanced allocator positions.
func oldAccount(t *testing.T, db *testDB) (aci, oldPNI uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	aci, oldPNI = uuid.New(), uuid.New()
	in := newLinkInput(t, aci, oldPNI, "old-password")
	dev, err := db.c.StoreProvisionedDevice(ctx, in.data, in.keys)
	if err != nil {
		t.Fatalf("initial link: %v", err)
	}
	if err := dev.ACIPreKeyStore.StorePreKey(ctx, 0, ecKey(t, 41)); err != nil {
		t.Fatal(err)
	}
	db.exec(`INSERT INTO signalmeow_sessions (account_id, service_id, their_service_id, their_device_id, record) VALUES ($1, $2, $3, 1, $4)`,
		aci.String(), dev.ACIServiceID().String(), uuid.NewString(), []byte{1})
	return aci, oldPNI
}

func assertOldAccount(t *testing.T, db *testDB, aci, oldPNI uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	dev := db.device(aci)
	if dev.PNI != oldPNI || dev.Password != "old-password" {
		t.Fatalf("credentials replaced: PNI %s password %q", dev.PNI, dev.Password)
	}
	if rec, err := dev.ACIPreKeyStore.LoadPreKey(ctx, 41); err != nil || rec == nil {
		t.Fatalf("old EC key lost: %v", err)
	}
	var sessions int
	if err := db.root.QueryRow(ctx, "SELECT COUNT(*) FROM signalmeow_sessions WHERE account_id=$1", aci.String()).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("old sessions = %d, %v", sessions, err)
	}
	want := provisionedState()
	want.NextEC = 42
	assertState(t, dev.ACIPreKeyStore, want)
	assertState(t, dev.PNIPreKeyStore, provisionedState())
}

func TestProvisionedPreKeyAllocators(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	aci := uuid.New()
	in := newLinkInput(t, aci, uuid.New(), "password")
	dev, err := db.c.StoreProvisionedDevice(ctx, in.data, in.keys)
	if err != nil || dev == nil {
		t.Fatalf("store provisioned device = %v, %v", dev, err)
	}
	db = db.reopen()
	assertProvisioned(t, db.device(aci))

	// Relinking with a changed PNI replaces the old credentials, keys, sessions and scopes.
	db2 := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	aci, oldPNI := oldAccount(t, db2)
	newPNI := uuid.New()
	relink := newLinkInput(t, aci, newPNI, "new-password")
	dev, err = db2.c.StoreProvisionedDevice(ctx, relink.data, relink.keys)
	if err != nil {
		t.Fatalf("relink: %v", err)
	}
	if dev.PNI != newPNI || dev.Password != "new-password" {
		t.Fatalf("relinked device has PNI %s password %q", dev.PNI, dev.Password)
	}
	assertProvisioned(t, dev)
	if rec, _ := dev.ACIPreKeyStore.LoadPreKey(ctx, 41); rec != nil {
		t.Fatal("old EC key survived relink")
	}
	if n := db2.allocatorRows("service_id=$1", libsignalgo.NewPNIServiceID(oldPNI).String()); n != 0 {
		t.Fatalf("old PNI scope kept %d allocator rows", n)
	}
	var sessions int
	if err := db2.root.QueryRow(ctx, "SELECT COUNT(*) FROM signalmeow_sessions WHERE account_id=$1", aci.String()).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions after relink = %d, %v", sessions, err)
	}
}

func TestProvisionedPreKeyRollback(t *testing.T) {
	ctx := context.Background()
	for name, trigger := range map[string]string{
		"clear":     `CREATE TRIGGER fail_link BEFORE DELETE ON signalmeow_sessions BEGIN SELECT RAISE(ABORT, 'injected'); END`,
		"key write": `CREATE TRIGGER fail_link BEFORE INSERT ON signalmeow_kyber_pre_keys BEGIN SELECT RAISE(ABORT, 'injected'); END`,
		"seed":      `CREATE TRIGGER fail_link BEFORE INSERT ON signalmeow_prekey_allocators BEGIN SELECT RAISE(ABORT, 'injected'); END`,
	} {
		t.Run(name, func(t *testing.T) {
			db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
			aci, oldPNI := oldAccount(t, db)
			db.exec(trigger)
			relink := newLinkInput(t, aci, uuid.New(), "new-password")
			dev, err := db.c.StoreProvisionedDevice(ctx, relink.data, relink.keys)
			if err == nil || dev != nil {
				t.Fatalf("failing relink = %v, %v", dev, err)
			}
			db.exec("DROP TRIGGER fail_link")
			assertOldAccount(t, db, aci, oldPNI)
		})
	}

	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	valid := newLinkInput(t, uuid.New(), uuid.New(), "password")
	wrongID := valid.keys
	wrongID.PNILastResort = kyberKey(t, 2, valid.data.PNIIdentityKeyPair)
	missing := valid.keys
	missing.ACISigned = nil
	for name, keys := range map[string]store.ProvisioningPreKeys{"wrong ID": wrongID, "missing": missing} {
		if _, err := db.c.StoreProvisionedDevice(ctx, valid.data, keys); !errors.Is(err, store.ErrPreKeyAllocatorInvalid) {
			t.Errorf("%s keys: %v", name, err)
		}
	}
	if dev, err := db.c.DeviceByACI(ctx, valid.data.ACI); err != nil || dev != nil {
		t.Fatalf("rejected keys still stored a device: %v, %v", dev, err)
	}

	err := db.root.DoTxn(ctx, nil, func(ctx context.Context) error {
		_, err := db.c.StoreProvisionedDevice(ctx, valid.data, valid.keys)
		return err
	})
	if !errors.Is(err, store.ErrProvisioningInTransaction) {
		t.Fatalf("provisioning in transaction = %v", err)
	}
}
