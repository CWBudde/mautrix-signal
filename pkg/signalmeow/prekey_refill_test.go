// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package signalmeow_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
)

type refillDB struct {
	t    *testing.T
	path string
	root *dbutil.Database
	c    *store.Container
	aci  uuid.UUID
}

func openRefillDB(t *testing.T, path string, aci uuid.UUID) *refillDB {
	t.Helper()
	root, err := dbutil.NewWithDialect(refillSQLiteDSN(path, 5000), refillSQLiteDriver)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	c := store.NewStore(root, dbutil.NoopLogger)
	if err := c.Upgrade(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &refillDB{t: t, path: path, root: root, c: c, aci: aci}
}

func (db *refillDB) reopen() *refillDB {
	db.t.Helper()
	if err := db.root.Close(); err != nil {
		db.t.Fatal(err)
	}
	return openRefillDB(db.t, db.path, db.aci)
}

func (db *refillDB) exec(query string) {
	db.t.Helper()
	if _, err := db.root.Exec(context.Background(), query); err != nil {
		db.t.Fatalf("exec %q: %v", query, err)
	}
}

func (db *refillDB) device() *store.Device {
	db.t.Helper()
	device, err := db.c.DeviceByACI(context.Background(), db.aci)
	if err != nil || device == nil {
		db.t.Fatalf("load device: %v", err)
	}
	return device
}

func (db *refillDB) client() *signalmeow.Client {
	return &signalmeow.Client{Store: db.device()}
}

// newRefillDevice links a device through the real provisioning store path and moves both
// scopes' Kyber counters past a retained last-resort key with a higher ID.
func newRefillDevice(t *testing.T) *refillDB {
	t.Helper()
	ctx := context.Background()
	aci, pni := uuid.New(), uuid.New()
	db := openRefillDB(t, filepath.Join(t.TempDir(), "account.db"), aci)
	aciKey, pniKey := refillIdentity(t), refillIdentity(t)
	_, err := db.c.StoreProvisionedDevice(ctx, &store.DeviceData{
		ACIIdentityKeyPair: aciKey, PNIIdentityKeyPair: pniKey, ACI: aci, PNI: pni,
		DeviceID: 2, Password: "password",
	}, store.ProvisioningPreKeys{
		ACISigned:     signalmeow.GenerateSignedPreKey(1, aciKey),
		PNISigned:     signalmeow.GenerateSignedPreKey(1, pniKey),
		ACILastResort: signalmeow.GenerateKyberPreKeys(1, 1, aciKey)[0],
		PNILastResort: signalmeow.GenerateKyberPreKeys(1, 1, pniKey)[0],
	})
	if err != nil {
		t.Fatalf("store provisioned device: %v", err)
	}
	return db
}

func refillIdentity(t *testing.T) *libsignalgo.IdentityKeyPair {
	t.Helper()
	ikp, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return ikp
}

func scopes(device *store.Device) []store.PreKeyStore {
	return []store.PreKeyStore{device.ACIPreKeyStore, device.PNIPreKeyStore}
}

func refillState(t *testing.T, pks store.PreKeyStore) store.PreKeyAllocatorState {
	t.Helper()
	state, err := pks.PreKeyAllocatorState(context.Background())
	if err != nil {
		t.Fatalf("%s state: %v", pks.GetServiceID(), err)
	}
	return state
}

func refillCounts(t *testing.T, pks store.PreKeyStore) (uint32, uint32) {
	t.Helper()
	ec, kyber, err := pks.PreKeyCounts(context.Background())
	if err != nil {
		t.Fatalf("%s counts: %v", pks.GetServiceID(), err)
	}
	return ec, kyber
}

func ecIDs(t *testing.T, pks store.PreKeyStore) (lo, hi uint32) {
	t.Helper()
	keys, err := pks.AllPreKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return idRange(t, len(keys), func(i int) (uint32, error) { return keys[i].GetID() })
}

func kyberIDs(t *testing.T, pks store.PreKeyStore) (lo, hi uint32) {
	t.Helper()
	keys, err := pks.AllNormalKyberPreKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return idRange(t, len(keys), func(i int) (uint32, error) { return keys[i].GetID() })
}

func idRange(t *testing.T, n int, id func(int) (uint32, error)) (lo, hi uint32) {
	t.Helper()
	if n == 0 {
		t.Fatal("no keys")
	}
	lo, hi = ^uint32(0), 0
	for i := range n {
		v, err := id(i)
		if err != nil {
			t.Fatal(err)
		}
		lo, hi = min(lo, v), max(hi, v)
	}
	return lo, hi
}

func TestPreKeyRefillDurableRanges(t *testing.T) {
	ctx := context.Background()
	db := newRefillDevice(t)
	cli := db.client()
	for _, pks := range scopes(cli.Store) {
		upload, err := cli.GenerateAndSaveNextPreKeyBatch(ctx, pks, 0)
		if err != nil || !upload {
			t.Fatalf("%s EC refill = %v, %v", pks.GetServiceID(), upload, err)
		}
		upload, err = cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, pks, 0)
		if err != nil || !upload {
			t.Fatalf("%s Kyber refill = %v, %v", pks.GetServiceID(), upload, err)
		}
		if ec, kyber := refillCounts(t, pks); ec != signalmeow.PREKEY_BATCH_SIZE || kyber != signalmeow.PREKEY_BATCH_SIZE {
			t.Fatalf("%s counts after refill = %d/%d", pks.GetServiceID(), ec, kyber)
		}
		// EC starts at the provisioned next ID 1; Kyber continues after last-resort ID 1.
		if lo, hi := ecIDs(t, pks); lo != 1 || hi != 100 {
			t.Fatalf("%s EC IDs [%d,%d], want [1,100]", pks.GetServiceID(), lo, hi)
		}
		if lo, hi := kyberIDs(t, pks); lo != 2 || hi != 101 {
			t.Fatalf("%s Kyber IDs [%d,%d], want [2,101]", pks.GetServiceID(), lo, hi)
		}
		// Consume the highest and then all ordinary keys.
		if err := pks.RemovePreKey(ctx, 100); err != nil {
			t.Fatal(err)
		}
		if err := pks.MarkKyberPreKeyUsed(ctx, 101); err != nil {
			t.Fatal(err)
		}
	}
	if err := cli.Store.ClearDeviceKeys(ctx); err != nil {
		t.Fatal(err)
	}

	db = db.reopen()
	cli = db.client()
	for _, pks := range scopes(cli.Store) {
		if _, err := cli.GenerateAndSaveNextPreKeyBatch(ctx, pks, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, pks, 0); err != nil {
			t.Fatal(err)
		}
		if lo, hi := ecIDs(t, pks); lo != 101 || hi != 200 {
			t.Fatalf("%s EC IDs after depletion [%d,%d], want [101,200]", pks.GetServiceID(), lo, hi)
		}
		if lo, hi := kyberIDs(t, pks); lo != 102 || hi != 201 {
			t.Fatalf("%s Kyber IDs after depletion [%d,%d], want [102,201]", pks.GetServiceID(), lo, hi)
		}
	}

	// Existing server-count thresholds: full store, healthy server → nothing to do; server
	// above the store → reupload without generating; low server with full store → reupload.
	pks := cli.Store.ACIPreKeyStore
	for _, tc := range []struct {
		server int
		upload bool
	}{{60, false}, {120, true}, {10, true}} {
		upload, err := cli.GenerateAndSaveNextPreKeyBatch(ctx, pks, tc.server)
		if err != nil || upload != tc.upload {
			t.Fatalf("server count %d: upload = %v, %v; want %v", tc.server, upload, err, tc.upload)
		}
	}
	if ec, _ := refillCounts(t, pks); ec != signalmeow.PREKEY_BATCH_SIZE {
		t.Fatalf("threshold checks generated keys: count %d", ec)
	}
	if state := refillState(t, pks); state.NextEC != 201 {
		t.Fatalf("threshold checks reserved IDs: next %d", state.NextEC)
	}
}

func TestPreKeyRefillFailureAfterReservation(t *testing.T) {
	ctx := context.Background()
	db := newRefillDevice(t)
	cli := db.client()
	pks := cli.Store.ACIPreKeyStore

	// The 51st record write fails after the batch [1,100] was reserved.
	db.exec(`CREATE TRIGGER fail_record BEFORE INSERT ON signalmeow_pre_keys WHEN NEW.is_signed=false AND NEW.key_id > 50
		BEGIN SELECT RAISE(ABORT, 'injected record failure'); END`)
	if _, err := cli.GenerateAndSaveNextPreKeyBatch(ctx, pks, 0); err == nil {
		t.Fatal("refill with failing record write succeeded")
	}
	db.exec("DROP TRIGGER fail_record")
	if ec, _ := refillCounts(t, pks); ec != 50 {
		t.Fatalf("partial refill kept %d keys, want 50", ec)
	}
	if _, err := cli.GenerateAndSaveNextPreKeyBatch(ctx, pks, 0); err != nil {
		t.Fatal(err)
	}
	keys, err := pks.AllPreKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		id, _ := key.GetID()
		if id > 50 && id <= 100 {
			t.Fatalf("ID %d of the interrupted reservation was reused", id)
		}
	}
	if lo, hi := ecIDs(t, pks); lo != 1 || hi != 150 {
		t.Fatalf("EC IDs [%d,%d], want [1,150] with gap (50,100]", lo, hi)
	}

	// A failed reservation generates and stores nothing.
	db.exec(`CREATE TRIGGER fail_reserve BEFORE UPDATE ON signalmeow_prekey_allocators
		BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END`)
	pni := cli.Store.PNIPreKeyStore
	if _, err := cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, pni, 0); err == nil {
		t.Fatal("refill with failing reservation succeeded")
	}
	db.exec("DROP TRIGGER fail_reserve")
	if _, kyber := refillCounts(t, pni); kyber != 0 {
		t.Fatalf("failed reservation stored %d Kyber keys", kyber)
	}
	if state := refillState(t, pni); state.NextKyber != 2 {
		t.Fatalf("failed reservation moved Kyber next to %d", state.NextKyber)
	}
}

func TestPreKeyRefillOrdinaryKyberCounts(t *testing.T) {
	ctx := context.Background()
	db := newRefillDevice(t)
	cli := db.client()
	pks := cli.Store.ACIPreKeyStore
	if _, err := cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, pks, 0); err != nil {
		t.Fatal(err)
	}
	if err := pks.MarkKyberPreKeyUsed(ctx, 101); err != nil {
		t.Fatal(err)
	}
	// 99 ordinary keys plus the retained last-resort key: the batch is one key short.
	if _, kyber := refillCounts(t, pks); kyber != 99 {
		t.Fatalf("ordinary Kyber count = %d, want 99", kyber)
	}
	upload, err := cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, pks, 0)
	if err != nil || !upload {
		t.Fatalf("refill = %v, %v", upload, err)
	}
	if _, kyber := refillCounts(t, pks); kyber != 100 {
		t.Fatalf("ordinary Kyber count after refill = %d, want 100", kyber)
	}
	if state := refillState(t, pks); state.NextKyber != 103 {
		t.Fatalf("Kyber next = %d, want 103", state.NextKyber)
	}
}

func TestPreKeyRefillActiveReferences(t *testing.T) {
	ctx := context.Background()
	db := newRefillDevice(t)
	cli := db.client()
	for _, pks := range scopes(cli.Store) {
		if _, err := cli.RefillPreKeysForTest(ctx, pks, 0, 0); err != nil {
			t.Fatal(err)
		}
		state := refillState(t, pks)
		if state.ActiveSigned == nil || *state.ActiveSigned != 1 || state.ActiveLastResort == nil || *state.ActiveLastResort != 1 {
			t.Fatalf("%s active references changed by refill: %+v", pks.GetServiceID(), state)
		}
		// Using the last-resort key retains it; using an ordinary key deletes it.
		if err := pks.MarkKyberPreKeyUsed(ctx, 1); err != nil {
			t.Fatal(err)
		}
		if rec, err := pks.LoadKyberPreKey(ctx, 1); err != nil || rec == nil {
			t.Fatalf("%s last-resort key not retained: %v", pks.GetServiceID(), err)
		}
		if err := pks.MarkKyberPreKeyUsed(ctx, 2); err != nil {
			t.Fatal(err)
		}
		if rec, _ := pks.LoadKyberPreKey(ctx, 2); rec != nil {
			t.Fatalf("%s ordinary Kyber key not deleted", pks.GetServiceID())
		}
	}
}

func TestPreKeyRefillKindIsolation(t *testing.T) {
	ctx := context.Background()
	db := newRefillDevice(t)
	cli := db.client()
	pks := cli.Store.ACIPreKeyStore
	// Exhaust EC: a wide legacy write moves the position beyond the source range.
	if err := pks.StorePreKey(ctx, 0x1000000, signalmeow.GeneratePreKeys(0x1000000, 1)[0]); err != nil {
		t.Fatal(err)
	}
	if err := pks.RemovePreKey(ctx, 0x1000000); err != nil {
		t.Fatal(err)
	}
	upload, err := cli.RefillPreKeysForTest(ctx, pks, 0, 0)
	if !errors.Is(err, store.ErrPreKeyAllocatorExhausted) {
		t.Fatalf("refill error = %v, want exhaustion", err)
	}
	if !upload {
		t.Fatal("exhausted EC kept the Kyber batch from being uploaded")
	}
	if ec, kyber := refillCounts(t, pks); ec != 0 || kyber != signalmeow.PREKEY_BATCH_SIZE {
		t.Fatalf("counts = %d/%d, want 0/%d", ec, kyber, signalmeow.PREKEY_BATCH_SIZE)
	}
}
