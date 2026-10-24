// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package store_test

import (
	"context"
	_ "embed"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store/upgrades"
)

//go:embed testdata/schema-v27.sql
var schemaV27 string

var errInjected = errors.New("injected failure")

const failAllocatorUpdateTrigger = `
CREATE TRIGGER fail_allocator_update BEFORE UPDATE ON signalmeow_prekey_allocators
BEGIN SELECT RAISE(ABORT, 'injected allocator failure'); END`

type testDB struct {
	t    *testing.T
	path string
	root *dbutil.Database
	c    *store.Container
}

// openDB opens (and upgrades) a file-backed account database with go-signal's options.
func openDB(t *testing.T, path string) *testDB {
	t.Helper()
	return openDBWithBusyTimeout(t, path, 5000, true)
}

func openDBWithBusyTimeout(t *testing.T, path string, busyTimeoutMS int, upgrade bool) *testDB {
	t.Helper()
	root, err := dbutil.NewWithDialect(testSQLiteDSN(path, busyTimeoutMS), testSQLiteDriver)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	c := store.NewStore(root, dbutil.NoopLogger)
	if upgrade {
		if err := c.Upgrade(context.Background()); err != nil {
			t.Fatalf("upgrade: %v", err)
		}
	}
	return &testDB{t: t, path: path, root: root, c: c}
}

func (db *testDB) reopen() *testDB {
	db.t.Helper()
	if err := db.root.Close(); err != nil {
		db.t.Fatalf("close: %v", err)
	}
	return openDB(db.t, db.path)
}

func (db *testDB) exec(query string, args ...any) {
	db.t.Helper()
	if _, err := db.root.Exec(context.Background(), query, args...); err != nil {
		db.t.Fatalf("exec %q: %v", query, err)
	}
}

func (db *testDB) version() (version, compat int) {
	db.t.Helper()
	err := db.root.QueryRow(context.Background(), "SELECT version, compat FROM signalmeow_version").Scan(&version, &compat)
	if err != nil {
		db.t.Fatalf("read version: %v", err)
	}
	return version, compat
}

func (db *testDB) allocatorRows(where string, args ...any) int {
	db.t.Helper()
	var n int
	err := db.root.QueryRow(context.Background(), "SELECT COUNT(*) FROM signalmeow_prekey_allocators WHERE "+where, args...).Scan(&n)
	if err != nil {
		db.t.Fatalf("count allocator rows: %v", err)
	}
	return n
}

func identityKeyPair(t *testing.T) *libsignalgo.IdentityKeyPair {
	t.Helper()
	ikp, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate identity key pair: %v", err)
	}
	return ikp
}

// putDevice stores a device row only, as plain PutDevice does: no allocator state.
func (db *testDB) putDevice(aci, pni uuid.UUID) *store.Device {
	db.t.Helper()
	ctx := context.Background()
	err := db.c.PutDevice(ctx, &store.DeviceData{
		ACIIdentityKeyPair: identityKeyPair(db.t),
		PNIIdentityKeyPair: identityKeyPair(db.t),
		ACIRegistrationID:  1,
		PNIRegistrationID:  2,
		ACI:                aci,
		PNI:                pni,
		DeviceID:           2,
		Number:             "+4915100000000",
		Password:           "password",
	})
	if err != nil {
		db.t.Fatalf("put device: %v", err)
	}
	return db.device(aci)
}

// putLegacyDevice stores a device row with the columns of an older schema, before upgrading.
func (db *testDB) putLegacyDevice(aci, pni uuid.UUID) {
	db.t.Helper()
	aciKey, err := identityKeyPair(db.t).Serialize()
	if err != nil {
		db.t.Fatal(err)
	}
	pniKey, err := identityKeyPair(db.t).Serialize()
	if err != nil {
		db.t.Fatal(err)
	}
	db.exec(`INSERT INTO signalmeow_device (aci_uuid, aci_identity_key_pair, registration_id, pni_uuid,
		pni_identity_key_pair, pni_registration_id, device_id, number, password) VALUES ($1, $2, 1, $3, $4, 2, 2, '+4915100000000', 'password')`,
		aci, aciKey, pni, pniKey)
}

func (db *testDB) device(aci uuid.UUID) *store.Device {
	db.t.Helper()
	device, err := db.c.DeviceByACI(context.Background(), aci)
	if err != nil || device == nil {
		db.t.Fatalf("load device %s: %v", aci, err)
	}
	return device
}

func (db *testDB) seed(device *store.Device, serviceID libsignalgo.ServiceID, state store.PreKeyAllocatorState) {
	db.t.Helper()
	err := device.DoDecryptionTxn(context.Background(), func(ctx context.Context) error {
		return db.c.SeedPreKeyAllocator(ctx, device.ACI, serviceID, state)
	})
	if err != nil {
		db.t.Fatalf("seed %s: %v", serviceID, err)
	}
}

func ecKey(t *testing.T, id uint32) *libsignalgo.PreKeyRecord {
	t.Helper()
	return signalmeow.GeneratePreKeys(id, 1)[0]
}

func signedKey(t *testing.T, id uint32, ikp *libsignalgo.IdentityKeyPair) *libsignalgo.SignedPreKeyRecord {
	t.Helper()
	return signalmeow.GenerateSignedPreKey(id, ikp)
}

func kyberKey(t *testing.T, id uint32, ikp *libsignalgo.IdentityKeyPair) *libsignalgo.KyberPreKeyRecord {
	t.Helper()
	return signalmeow.GenerateKyberPreKeys(id, 1, ikp)[0]
}

func ptr(v uint32) *uint32 { return &v }

func mustState(t *testing.T, pks store.PreKeyStore) store.PreKeyAllocatorState {
	t.Helper()
	state, err := pks.PreKeyAllocatorState(context.Background())
	if err != nil {
		t.Fatalf("allocator state %s: %v", pks.GetServiceID(), err)
	}
	return state
}

func refString(ref *uint32) string {
	if ref == nil {
		return "nil"
	}
	return strconv.FormatUint(uint64(*ref), 10)
}

func assertState(t *testing.T, pks store.PreKeyStore, want store.PreKeyAllocatorState) {
	t.Helper()
	got := mustState(t, pks)
	if got.NextEC != want.NextEC || got.NextSigned != want.NextSigned || got.NextKyber != want.NextKyber ||
		refString(got.ActiveSigned) != refString(want.ActiveSigned) ||
		refString(got.ActiveLastResort) != refString(want.ActiveLastResort) {
		t.Fatalf("%s state = next %d/%d/%d active %s/%s, want next %d/%d/%d active %s/%s", pks.GetServiceID(),
			got.NextEC, got.NextSigned, got.NextKyber, refString(got.ActiveSigned), refString(got.ActiveLastResort),
			want.NextEC, want.NextSigned, want.NextKyber, refString(want.ActiveSigned), refString(want.ActiveLastResort))
	}
}

func assertCounts(t *testing.T, pks store.PreKeyStore, wantEC, wantKyber uint32) {
	t.Helper()
	ec, kyber, err := pks.PreKeyCounts(context.Background())
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if ec != wantEC || kyber != wantKyber {
		t.Fatalf("%s counts = %d/%d, want %d/%d", pks.GetServiceID(), ec, kyber, wantEC, wantKyber)
	}
}

func reserve(t *testing.T, pks store.PreKeyStore, kind store.PreKeyKind, count uint32) uint32 {
	t.Helper()
	start, err := pks.ReservePreKeyIDs(context.Background(), kind, count)
	if err != nil {
		t.Fatalf("reserve %s %d: %v", kind, count, err)
	}
	return start
}

func assertReserveFails(t *testing.T, ctx context.Context, pks store.PreKeyStore, kind store.PreKeyKind, count uint32, want error) {
	t.Helper()
	start, err := pks.ReservePreKeyIDs(ctx, kind, count)
	if err == nil || (want != nil && !errors.Is(err, want)) {
		t.Fatalf("reserve %s %d = %d, %v; want %v", kind, count, start, err, want)
	}
	if start != 0 {
		t.Fatalf("failed reservation returned start %d", start)
	}
}

// legacy v27 fixture -------------------------------------------------------------------------

type legacyKey struct {
	table     string // "ec", "signed", "kyber", "lr"
	serviceID string
	id        int64
}

func insertLegacy(db *testDB, account uuid.UUID, keys ...legacyKey) {
	db.t.Helper()
	for _, k := range keys {
		switch k.table {
		case "ec", "signed":
			db.exec(`INSERT INTO signalmeow_pre_keys (account_id, service_id, key_id, is_signed, key_pair) VALUES ($1, $2, $3, $4, $5)`,
				account.String(), k.serviceID, k.id, k.table == "signed", []byte{1})
		default:
			db.exec(`INSERT INTO signalmeow_kyber_pre_keys (account_id, service_id, key_id, key_pair, is_last_resort) VALUES ($1, $2, $3, $4, $5)`,
				account.String(), k.serviceID, k.id, []byte{1}, k.table == "lr")
		}
	}
}

func openV27(t *testing.T) *testDB {
	t.Helper()
	db := openDBWithBusyTimeout(t, filepath.Join(t.TempDir(), "account.db"), 5000, false)
	db.exec(schemaV27)
	return db
}

func TestPreKeyAllocatorMigration(t *testing.T) {
	ctx := context.Background()
	db := openV27(t)
	if v, c := db.version(); v != 27 || c != 13 {
		t.Fatalf("fixture version = %d/%d, want 27/13", v, c)
	}

	sparse, sparsePNI := uuid.New(), uuid.New()
	ambiguous, ambiguousPNI := uuid.New(), uuid.New()
	noPNI := uuid.New()
	orphanPNI := libsignalgo.NewPNIServiceID(uuid.New()).String()
	db.putLegacyDevice(sparse, sparsePNI)
	db.putLegacyDevice(ambiguous, ambiguousPNI)
	db.putLegacyDevice(noPNI, uuid.Nil)

	sparseACI := libsignalgo.NewACIServiceID(sparse).String()
	insertLegacy(db, sparse,
		legacyKey{"ec", sparseACI, 3}, legacyKey{"ec", sparseACI, 7},
		legacyKey{"signed", sparseACI, 11},
		legacyKey{"kyber", sparseACI, 17}, legacyKey{"lr", sparseACI, 23},
		legacyKey{"ec", orphanPNI, 99},
	)
	ambiguousACI := libsignalgo.NewACIServiceID(ambiguous).String()
	insertLegacy(db, ambiguous,
		legacyKey{"signed", ambiguousACI, 4}, legacyKey{"signed", ambiguousACI, 5},
		legacyKey{"lr", ambiguousACI, 8}, legacyKey{"lr", ambiguousACI, 9},
		legacyKey{"ec", ambiguousACI, 0x1000000}, // legacy ID outside the source range
	)

	if err := db.c.Upgrade(ctx); err != nil {
		t.Fatalf("upgrade v27: %v", err)
	}
	if v, c := db.version(); v != 30 || c != 30 {
		t.Fatalf("migrated version = %d/%d, want 30/30", v, c)
	}

	dev := db.device(sparse)
	assertState(t, dev.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 8, NextSigned: 12, NextKyber: 24, ActiveSigned: ptr(11), ActiveLastResort: ptr(23)})
	assertCounts(t, dev.ACIPreKeyStore, 2, 1)
	// The empty PNI scope keeps the legacy MAX+1 fallback of 1, with no active keys.
	assertState(t, dev.PNIPreKeyStore, store.PreKeyAllocatorState{NextEC: 1, NextSigned: 1, NextKyber: 1})
	assertCounts(t, dev.PNIPreKeyStore, 0, 0)
	if n := db.allocatorRows("service_id=$1", orphanPNI); n != 0 {
		t.Fatalf("orphaned scope got %d allocator rows", n)
	}
	if n := db.allocatorRows("account_id=$1", noPNI.String()); n != 3 {
		t.Fatalf("device without PNI got %d allocator rows, want 3 (ACI only)", n)
	}

	amb := db.device(ambiguous)
	// Several signed/LR candidates: the active key is unknown, so no reference is fabricated.
	assertState(t, amb.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 0x1000001, NextSigned: 6, NextKyber: 10})
	if _, next, err := amb.ACIPreKeyStore.GetNextPreKeyID(ctx); err != nil || next != 0x1000001 {
		t.Fatalf("GetNextPreKeyID beyond source range = %d, %v; want 0x1000001 (not truncated)", next, err)
	}
	assertReserveFails(t, ctx, amb.ACIPreKeyStore, store.PreKeyEC, 1, store.ErrPreKeyAllocatorExhausted)

	// Deleting keys never moves or deletes allocator positions, which also survive reopening.
	if err := dev.ACIPreKeyStore.RemovePreKey(ctx, 7); err != nil {
		t.Fatalf("remove prekey: %v", err)
	}
	if err := dev.ClearDeviceKeys(ctx); err != nil {
		t.Fatalf("clear keys: %v", err)
	}
	db = db.reopen()
	dev = db.device(sparse)
	assertState(t, dev.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 8, NextSigned: 12, NextKyber: 24, ActiveSigned: ptr(11), ActiveLastResort: ptr(23)})
	assertCounts(t, dev.ACIPreKeyStore, 0, 0)
	if start := reserve(t, dev.ACIPreKeyStore, store.PreKeyEC, 5); start != 8 {
		t.Fatalf("reservation after depletion started at %d, want 8", start)
	}
}

func TestPreKeyAllocatorSchemaFloor(t *testing.T) {
	ctx := context.Background()
	fresh := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	if v, c := fresh.version(); v != 30 || c != 30 {
		t.Fatalf("fresh version = %d/%d, want 30/30", v, c)
	}

	migrated := openV27(t)
	aci := uuid.New()
	migrated.putLegacyDevice(aci, uuid.New())
	if err := migrated.c.Upgrade(ctx); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if v, c := migrated.version(); v != 30 || c != 30 {
		t.Fatalf("migrated version = %d/%d, want 30/30", v, c)
	}

	// A v27 binary (its upgrade table ends at v27) must refuse the database before touching keys.
	for name, db := range map[string]*testDB{"fresh": fresh, "migrated": migrated} {
		old := db.root.Child("signalmeow_version", upgrades.Table[:27], dbutil.NoopLogger)
		if err := old.Upgrade(ctx); !errors.Is(err, dbutil.ErrUnsupportedDatabaseVersion) {
			t.Fatalf("%s: v27 reader error = %v, want ErrUnsupportedDatabaseVersion", name, err)
		}
	}
	if v, c := migrated.version(); v != 30 || c != 30 {
		t.Fatalf("version after refused downgrade = %d/%d", v, c)
	}
}

func TestPreKeyAllocatorSeedTransaction(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	aci, pni := uuid.New(), uuid.New()
	dev := db.putDevice(aci, pni)

	state := store.PreKeyAllocatorState{NextEC: 6, NextSigned: 4, NextKyber: 11, ActiveSigned: ptr(3), ActiveLastResort: ptr(9)}
	err := dev.DoDecryptionTxn(ctx, func(ctx context.Context) error {
		pks := dev.ACIPreKeyStore
		if err := pks.StorePreKey(ctx, 5, ecKey(t, 5)); err != nil {
			return err
		}
		if err := pks.StoreSignedPreKey(ctx, 3, signedKey(t, 3, dev.ACIIdentityKeyPair)); err != nil {
			return err
		}
		if err := pks.StoreLastResortKyberPreKey(ctx, 9, kyberKey(t, 9, dev.ACIIdentityKeyPair)); err != nil {
			return err
		}
		if err := pks.StoreKyberPreKey(ctx, 10, kyberKey(t, 10, dev.ACIIdentityKeyPair)); err != nil {
			return err
		}
		return db.c.SeedPreKeyAllocator(ctx, aci, dev.ACIServiceID(), state)
	})
	if err != nil {
		t.Fatalf("seed transaction: %v", err)
	}
	db = db.reopen()
	dev = db.device(aci)
	assertState(t, dev.ACIPreKeyStore, state)
	assertCounts(t, dev.ACIPreKeyStore, 1, 1)
	if rec, err := dev.ACIPreKeyStore.LoadKyberPreKey(ctx, 9); err != nil || rec == nil {
		t.Fatalf("seeded LR record missing: %v", err)
	}

	// Snapshots hand out independent pointers.
	first := mustState(t, dev.ACIPreKeyStore)
	*first.ActiveSigned = 77
	assertState(t, dev.ACIPreKeyStore, state)

	// Rollback of the enclosing transaction persists neither records nor metadata.
	err = dev.DoDecryptionTxn(ctx, func(ctx context.Context) error {
		if err := dev.PNIPreKeyStore.StorePreKey(ctx, 1, ecKey(t, 1)); err != nil {
			return err
		}
		if err := db.c.SeedPreKeyAllocator(ctx, aci, dev.PNIServiceID(), store.PreKeyAllocatorState{NextEC: 2, NextSigned: 1, NextKyber: 1}); err != nil {
			return err
		}
		return errInjected
	})
	if !errors.Is(err, errInjected) {
		t.Fatalf("rolled back seed = %v", err)
	}
	if _, err := dev.PNIPreKeyStore.PreKeyAllocatorState(ctx); !errors.Is(err, store.ErrPreKeyAllocatorUninitialized) {
		t.Fatalf("PNI state after rollback = %v, want uninitialized", err)
	}
	if rec, _ := dev.PNIPreKeyStore.LoadPreKey(ctx, 1); rec != nil {
		t.Fatal("PNI record survived rollback")
	}

	if err := db.c.SeedPreKeyAllocator(ctx, aci, dev.PNIServiceID(), store.PreKeyAllocatorState{}); !errors.Is(err, store.ErrPreKeyTransactionRequired) {
		t.Fatalf("seed outside transaction = %v", err)
	}

	other := db.putDevice(uuid.New(), uuid.New())
	if err := other.DoDecryptionTxn(ctx, func(ctx context.Context) error {
		if err := other.ACIPreKeyStore.StorePreKey(ctx, 5, ecKey(t, 5)); err != nil {
			return err
		}
		if err := other.ACIPreKeyStore.StoreKyberPreKey(ctx, 10, kyberKey(t, 10, other.ACIIdentityKeyPair)); err != nil {
			return err
		}
		return other.ACIPreKeyStore.StoreSignedPreKey(ctx, 2, signedKey(t, 2, other.ACIIdentityKeyPair))
	}); err != nil {
		t.Fatalf("store other records: %v", err)
	}
	rejected := map[string]struct {
		account   uuid.UUID
		serviceID libsignalgo.ServiceID
		state     store.PreKeyAllocatorState
		want      error
	}{
		"duplicate":          {aci, dev.ACIServiceID(), state, store.ErrPreKeyAllocatorExists},
		"foreign ACI":        {other.ACI, libsignalgo.NewACIServiceID(uuid.New()), store.PreKeyAllocatorState{NextEC: 6, NextKyber: 11, NextSigned: 3}, store.ErrPreKeyAllocatorInvalid},
		"foreign PNI":        {other.ACI, libsignalgo.NewPNIServiceID(uuid.New()), store.PreKeyAllocatorState{}, store.ErrPreKeyAllocatorInvalid},
		"other device's PNI": {other.ACI, dev.PNIServiceID(), store.PreKeyAllocatorState{}, store.ErrPreKeyAllocatorInvalid},
		"unknown account":    {uuid.New(), libsignalgo.NewACIServiceID(uuid.New()), store.PreKeyAllocatorState{}, store.ErrPreKeyAllocatorInvalid},
		"EC next at max":     {other.ACI, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 5, NextSigned: 3, NextKyber: 11}, store.ErrPreKeyAllocatorInvalid},
		"signed next at max": {other.ACI, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 6, NextSigned: 2, NextKyber: 11}, store.ErrPreKeyAllocatorInvalid},
		"kyber next below":   {other.ACI, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 6, NextSigned: 3, NextKyber: 9}, store.ErrPreKeyAllocatorInvalid},
		"missing signed":     {other.ACI, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 6, NextSigned: 3, NextKyber: 11, ActiveSigned: ptr(1)}, store.ErrPreKeyAllocatorInvalid},
		"LR is ordinary":     {other.ACI, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 6, NextSigned: 3, NextKyber: 11, ActiveLastResort: ptr(10)}, store.ErrPreKeyAllocatorInvalid},
		"above limit":        {other.ACI, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: store.PreKeyIDLimit + 1, NextSigned: 3, NextKyber: 11}, store.ErrPreKeyAllocatorInvalid},
	}
	for name, tc := range rejected {
		err := other.DoDecryptionTxn(ctx, func(ctx context.Context) error {
			return db.c.SeedPreKeyAllocator(ctx, tc.account, tc.serviceID, tc.state)
		})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: seed = %v, want %v", name, err, tc.want)
		}
	}
	if _, err := other.ACIPreKeyStore.PreKeyAllocatorState(ctx); !errors.Is(err, store.ErrPreKeyAllocatorUninitialized) {
		t.Fatalf("rejected seeds left state: %v", err)
	}

	// Empty kinds may start at zero; absent active references are valid even with retained
	// signed records, as in Java.
	db.seed(other, other.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 6, NextSigned: 3, NextKyber: 11})
	db.seed(other, other.PNIServiceID(), store.PreKeyAllocatorState{})
	assertState(t, other.PNIPreKeyStore, store.PreKeyAllocatorState{})
	if start := reserve(t, other.PNIPreKeyStore, store.PreKeyEC, 3); start != 0 {
		t.Fatalf("zero-start reservation = %d", start)
	}
}

func TestPreKeyAllocatorDirectWrites(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	dev := db.putDevice(uuid.New(), uuid.New())
	pks := dev.ACIPreKeyStore
	ikp := dev.ACIIdentityKeyPair
	db.seed(dev, dev.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 1, NextSigned: 1, NextKyber: 1})

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pks.StorePreKey(ctx, 50, ecKey(t, 50)))
	must(pks.StorePreKey(ctx, 20, ecKey(t, 20)))
	must(pks.StoreSignedPreKey(ctx, 30, signedKey(t, 30, ikp)))
	must(pks.StoreKyberPreKey(ctx, 40, kyberKey(t, 40, ikp)))
	must(pks.StoreLastResortKyberPreKey(ctx, 60, kyberKey(t, 60, ikp)))
	must(pks.StoreKyberPreKey(ctx, 45, kyberKey(t, 45, ikp)))
	// Writes above the watermark advance it to id+1; lower writes never rewind; Kyber is shared.
	assertState(t, pks, store.PreKeyAllocatorState{NextEC: 51, NextSigned: 31, NextKyber: 61})

	// An injected SQL failure in the allocator update rolls the record back as well.
	db.exec(failAllocatorUpdateTrigger)
	if err := pks.StorePreKey(ctx, 70, ecKey(t, 70)); err == nil {
		t.Fatal("store with failing allocator update succeeded")
	}
	db.exec("DROP TRIGGER fail_allocator_update")
	if rec, _ := pks.LoadPreKey(ctx, 70); rec != nil {
		t.Fatal("record survived failed allocator update")
	}

	// Enclosing-transaction rollback restores both.
	err := dev.DoDecryptionTxn(ctx, func(ctx context.Context) error {
		if err := pks.StorePreKey(ctx, 80, ecKey(t, 80)); err != nil {
			return err
		}
		return errInjected
	})
	if !errors.Is(err, errInjected) {
		t.Fatalf("rollback = %v", err)
	}
	if rec, _ := pks.LoadPreKey(ctx, 80); rec != nil {
		t.Fatal("record survived rollback")
	}
	assertState(t, pks, store.PreKeyAllocatorState{NextEC: 51, NextSigned: 31, NextKyber: 61})

	// Wide legacy writes are not truncated and stop further allocation.
	must(pks.StorePreKey(ctx, 0x1000000, ecKey(t, 0x1000000)))
	assertState(t, pks, store.PreKeyAllocatorState{NextEC: 0x1000001, NextSigned: 31, NextKyber: 61})
	assertReserveFails(t, ctx, pks, store.PreKeyEC, 1, store.ErrPreKeyAllocatorExhausted)

	// Writes without metadata do not create it.
	must(dev.PNIPreKeyStore.StorePreKey(ctx, 5, ecKey(t, 5)))
	if _, err := dev.PNIPreKeyStore.PreKeyAllocatorState(ctx); !errors.Is(err, store.ErrPreKeyAllocatorUninitialized) {
		t.Fatalf("PNI state after write without metadata = %v", err)
	}
	if _, _, err := dev.PNIPreKeyStore.GetNextPreKeyID(ctx); !errors.Is(err, store.ErrPreKeyAllocatorUninitialized) {
		t.Fatalf("GetNextPreKeyID without metadata = %v", err)
	}
	assertCounts(t, dev.PNIPreKeyStore, 1, 0)
}

func TestPreKeyAllocatorReservations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "account.db")
	db := openDB(t, path)
	same := uuid.New()
	a := db.putDevice(same, same) // ACI and PNI share the UUID; scopes stay separate
	b := db.putDevice(uuid.New(), uuid.New())
	db.seed(a, a.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 100, NextSigned: 200, NextKyber: 300})
	db.seed(a, a.PNIServiceID(), store.PreKeyAllocatorState{NextEC: 1000, NextSigned: 2000, NextKyber: 3000})
	db.seed(b, b.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 7, NextSigned: 8, NextKyber: 9})

	for _, tc := range []struct {
		pks   store.PreKeyStore
		kind  store.PreKeyKind
		count uint32
		want  uint32
	}{
		{a.ACIPreKeyStore, store.PreKeyEC, 100, 100},
		{a.ACIPreKeyStore, store.PreKeyEC, 1, 200},
		{a.ACIPreKeyStore, store.PreKeySigned, 1, 200},
		{a.ACIPreKeyStore, store.PreKeyKyber, 100, 300},
		{a.PNIPreKeyStore, store.PreKeyEC, 10, 1000},
		{a.PNIPreKeyStore, store.PreKeyKyber, 10, 3000},
		{b.ACIPreKeyStore, store.PreKeyEC, 10, 7},
	} {
		if start := reserve(t, tc.pks, tc.kind, tc.count); start != tc.want {
			t.Fatalf("%s %s reservation start = %d, want %d", tc.pks.GetServiceID(), tc.kind, start, tc.want)
		}
	}
	assertState(t, a.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 201, NextSigned: 201, NextKyber: 400})
	assertState(t, a.PNIPreKeyStore, store.PreKeyAllocatorState{NextEC: 1010, NextSigned: 2000, NextKyber: 3010})
	assertState(t, b.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 17, NextSigned: 8, NextKyber: 9})

	// Depleted store: positions continue, never MAX+1 of what remains.
	if err := b.ACIPreKeyStore.StorePreKey(ctx, 7, ecKey(t, 7)); err != nil {
		t.Fatal(err)
	}
	if err := b.ClearDeviceKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if start := reserve(t, b.ACIPreKeyStore, store.PreKeyEC, 1); start != 17 {
		t.Fatalf("depleted reservation start = %d, want 17", start)
	}

	// Two database handles reserving concurrently get disjoint ranges.
	db2 := openDB(t, path)
	stores := []store.PreKeyStore{a.ACIPreKeyStore, db2.device(same).ACIPreKeyStore}
	type span struct{ start, end uint32 }
	var (
		mu    sync.Mutex
		spans []span
		wg    sync.WaitGroup
	)
	errs := make(chan error, 40)
	for i := range 40 {
		wg.Add(1)
		go func(pks store.PreKeyStore) {
			defer wg.Done()
			start, err := pks.ReservePreKeyIDs(ctx, store.PreKeyEC, 10)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			spans = append(spans, span{start, start + 10})
			mu.Unlock()
		}(stores[i%2])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent reservation: %v", err)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			t.Fatalf("overlapping ranges %v and %v", spans[i-1], spans[i])
		}
	}
	if spans[0].start != 201 || spans[len(spans)-1].end != 601 {
		t.Fatalf("concurrent ranges cover [%d,%d), want [201,601)", spans[0].start, spans[len(spans)-1].end)
	}

	// Restart keeps positions.
	db = db.reopen()
	a = db.device(same)
	assertState(t, a.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 601, NextSigned: 201, NextKyber: 400})

	// Failures return no range and consume nothing.
	unseeded := db.putDevice(uuid.New(), uuid.New())
	assertReserveFails(t, ctx, unseeded.ACIPreKeyStore, store.PreKeyEC, 1, store.ErrPreKeyAllocatorUninitialized)
	assertReserveFails(t, ctx, a.ACIPreKeyStore, store.PreKeyKind("x"), 1, store.ErrPreKeyAllocatorInvalid)
	assertReserveFails(t, ctx, a.ACIPreKeyStore, store.PreKeyEC, 0, store.ErrPreKeyAllocatorInvalid)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	assertReserveFails(t, canceled, a.ACIPreKeyStore, store.PreKeyEC, 1, context.Canceled)
	db.exec(failAllocatorUpdateTrigger)
	assertReserveFails(t, ctx, a.ACIPreKeyStore, store.PreKeyEC, 1, nil)
	db.exec("DROP TRIGGER fail_allocator_update")
	assertState(t, a.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 601, NextSigned: 201, NextKyber: 400})

	// A transaction held by a foreign handle surfaces as a bounded busy error, not a hang.
	db3 := openDBWithBusyTimeout(t, path, 100, true)
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- db3.root.DoTxn(ctx, nil, func(ctx context.Context) error {
			if _, err := db3.root.Exec(ctx, "UPDATE signalmeow_prekey_allocators SET next_id=next_id WHERE kind='ec'"); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	quick := openDBWithBusyTimeout(t, path, 100, false)
	assertReserveFails(t, ctx, quick.device(same).ACIPreKeyStore, store.PreKeyEC, 1, nil)
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("foreign transaction: %v", err)
	}
	assertState(t, a.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 601, NextSigned: 201, NextKyber: 400})
}

func TestPreKeyAllocatorExhaustion(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	dev := db.putDevice(uuid.New(), uuid.New())
	db.seed(dev, dev.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 0xfffffe, NextSigned: 1, NextKyber: 0xfffff0})
	pks := dev.ACIPreKeyStore

	if start := reserve(t, pks, store.PreKeyEC, 1); start != 0xfffffe {
		t.Fatalf("final ID reservation = %#x", start)
	}
	assertState(t, pks, store.PreKeyAllocatorState{NextEC: 0xffffff, NextSigned: 1, NextKyber: 0xfffff0})
	if _, next, err := pks.GetNextPreKeyID(ctx); err != nil || next != 0xffffff {
		t.Fatalf("GetNextPreKeyID at limit = %#x, %v", next, err)
	}
	assertReserveFails(t, ctx, pks, store.PreKeyEC, 1, store.ErrPreKeyAllocatorExhausted)
	// A batch crossing the limit fails atomically.
	assertReserveFails(t, ctx, pks, store.PreKeyKyber, 100, store.ErrPreKeyAllocatorExhausted)
	assertState(t, pks, store.PreKeyAllocatorState{NextEC: 0xffffff, NextSigned: 1, NextKyber: 0xfffff0})
	if start := reserve(t, pks, store.PreKeyKyber, 15); start != 0xfffff0 {
		t.Fatalf("exact final Kyber batch = %#x", start)
	}
}

func TestPreKeyAllocatorOuterTransaction(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	dev := db.putDevice(uuid.New(), uuid.New())
	db.seed(dev, dev.ACIServiceID(), store.PreKeyAllocatorState{NextEC: 10, NextSigned: 1, NextKyber: 1})

	err := dev.DoDecryptionTxn(ctx, func(ctx context.Context) error {
		assertReserveFails(t, ctx, dev.ACIPreKeyStore, store.PreKeyEC, 5, store.ErrPreKeyReservationInTransaction)
		return errInjected
	})
	if !errors.Is(err, errInjected) {
		t.Fatalf("outer transaction = %v", err)
	}
	assertState(t, dev.ACIPreKeyStore, store.PreKeyAllocatorState{NextEC: 10, NextSigned: 1, NextKyber: 1})
	if start := reserve(t, dev.ACIPreKeyStore, store.PreKeyEC, 5); start != 10 {
		t.Fatalf("reservation after rejected outer attempt = %d", start)
	}
}
