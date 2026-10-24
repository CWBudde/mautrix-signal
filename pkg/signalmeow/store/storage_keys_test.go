// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package store_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store/upgrades"
)

// Java vectors from signal-cli's key models (go-signal: scripts/generate-account-import-fixtures.sh
// --storage-keys, internal/signal/accountimport/testdata/java-storage-keys/vectors.json).
const (
	javaPool          = "gosignalstoragekeyvectors0123456789abcdefghijklmnopqrstuvwxyz012"
	javaPoolMaster    = "W8PWfUAYDqzJ/H2aD2E30DAFmUvBaWYOsMcjufiuxQQ="
	javaPoolStorage   = "e+2iFZlwIhofS0jem5XaBTc3+pMTZFHcXdyxVdM/2SE="
	javaPinMaster     = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	javaPinStorage    = "2f0j7pnBSK2Hn2JgkpcTnmo29BWxrXedI8aHsfptNtk="
	javaDerivedStored = "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8="
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStorageServiceKeyJavaVectors(t *testing.T) {
	master, err := libsignalgo.AccountEntropyPool(javaPool).DeriveSVRKey()
	if err != nil || !bytes.Equal(master, b64(t, javaPoolMaster)) {
		t.Fatalf("pool master key = %x, %v", master, err)
	}
	for name, tc := range map[string]struct {
		device store.DeviceData
		want   string
	}{
		"pool":         {store.DeviceData{AccountEntropyPool: javaPool}, javaPoolStorage},
		"pool+master":  {store.DeviceData{AccountEntropyPool: javaPool, MasterKey: b64(t, javaPoolMaster)}, javaPoolStorage},
		"pin master":   {store.DeviceData{MasterKey: b64(t, javaPinMaster)}, javaPinStorage},
		"derived only": {store.DeviceData{DerivedStorageKey: b64(t, javaDerivedStored)}, javaDerivedStored},
		"derived+pin":  {store.DeviceData{DerivedStorageKey: b64(t, javaPinStorage), MasterKey: b64(t, javaPinMaster)}, javaPinStorage},
	} {
		got, err := tc.device.ResolveStorageServiceKey()
		if err != nil || !bytes.Equal(got[:], b64(t, tc.want)) {
			t.Errorf("%s: resolved %x, %v; want %s", name, got, err, tc.want)
		}
	}
}

func TestStorageServiceKeyResolveRefusals(t *testing.T) {
	derived := b64(t, javaDerivedStored)
	for name, tc := range map[string]struct {
		device store.DeviceData
		want   error
	}{
		"nothing":             {store.DeviceData{}, store.ErrStorageServiceKeyUnknown},
		"short derived":       {store.DeviceData{DerivedStorageKey: derived[:31]}, store.ErrStorageServiceKeyInvalid},
		"empty derived":       {store.DeviceData{DerivedStorageKey: []byte{}}, store.ErrStorageServiceKeyInvalid},
		"long master":         {store.DeviceData{MasterKey: append(b64(t, javaPinMaster), 0)}, store.ErrStorageServiceKeyInvalid},
		"invalid pool":        {store.DeviceData{AccountEntropyPool: "short"}, store.ErrStorageServiceKeyInvalid},
		"derived vs master":   {store.DeviceData{DerivedStorageKey: derived, MasterKey: b64(t, javaPinMaster)}, store.ErrStorageServiceKeyConflict},
		"derived vs pool":     {store.DeviceData{DerivedStorageKey: derived, AccountEntropyPool: javaPool}, store.ErrStorageServiceKeyConflict},
		"master vs pool":      {store.DeviceData{MasterKey: b64(t, javaPinMaster), AccountEntropyPool: javaPool}, store.ErrStorageServiceKeyConflict},
		"derived master form": {store.DeviceData{DerivedStorageKey: b64(t, javaPinMaster), MasterKey: b64(t, javaPinMaster)}, store.ErrStorageServiceKeyConflict},
	} {
		if _, err := tc.device.ResolveStorageServiceKey(); !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", name, err, tc.want)
		}
	}
}

func TestStorageServiceKeySync(t *testing.T) {
	pinMaster, pinStorage, derived := b64(t, javaPinMaster), b64(t, javaPinStorage), b64(t, javaDerivedStored)
	resolve := func(d store.DeviceData) []byte {
		t.Helper()
		key, err := d.ResolveStorageServiceKey()
		if err != nil {
			t.Fatalf("resolve after sync: %v", err)
		}
		return key[:]
	}

	// A pool supersedes a derived key and an older master key; its master key is stored.
	old := store.DeviceData{DerivedStorageKey: derived, MasterKey: pinMaster}
	got, changed, err := store.ApplyStorageKeySync(old, javaPool, derived)
	if err != nil || !changed || got.DerivedStorageKey != nil || !bytes.Equal(got.MasterKey, b64(t, javaPoolMaster)) ||
		got.AccountEntropyPool != javaPool || !bytes.Equal(resolve(got), b64(t, javaPoolStorage)) {
		t.Fatalf("pool sync = %+v, %v, %v", got, changed, err)
	}
	if !bytes.Equal(old.DerivedStorageKey, derived) || !bytes.Equal(old.MasterKey, pinMaster) {
		t.Fatal("pool sync modified its input")
	}
	if _, changed, err := store.ApplyStorageKeySync(got, javaPool, nil); err != nil || changed {
		t.Fatalf("repeated pool sync changed = %v, %v", changed, err)
	}

	// A legacy derived key that disagrees replaces the stale forms; it is never re-derived.
	got, changed, err = store.ApplyStorageKeySync(store.DeviceData{AccountEntropyPool: javaPool, MasterKey: b64(t, javaPoolMaster)}, "", derived)
	if err != nil || !changed || got.MasterKey != nil || got.AccountEntropyPool != "" || !bytes.Equal(resolve(got), derived) {
		t.Fatalf("legacy sync = %+v, %v, %v", got, changed, err)
	}
	// One that agrees keeps the master key it was derived from.
	got, changed, err = store.ApplyStorageKeySync(store.DeviceData{MasterKey: pinMaster}, "", pinStorage)
	if err != nil || !changed || !bytes.Equal(got.MasterKey, pinMaster) || !bytes.Equal(resolve(got), pinStorage) {
		t.Fatalf("agreeing legacy sync = %+v, %v, %v", got, changed, err)
	}
	if _, changed, err := store.ApplyStorageKeySync(got, "", pinStorage); err != nil || changed {
		t.Fatalf("repeated legacy sync changed = %v, %v", changed, err)
	}

	// Invalid or empty updates leave the device alone.
	for name, tc := range map[string]struct {
		aep libsignalgo.AccountEntropyPool
		key []byte
		err error
	}{
		"empty":       {"", nil, nil},
		"bad pool":    {"short", nil, store.ErrStorageServiceKeyInvalid},
		"short key":   {"", derived[:16], store.ErrStorageServiceKeyInvalid},
		"empty key":   {"", []byte{}, store.ErrStorageServiceKeyInvalid},
		"bad pool+ok": {"short", derived, store.ErrStorageServiceKeyInvalid},
	} {
		in := store.DeviceData{MasterKey: pinMaster}
		got, changed, err := store.ApplyStorageKeySync(in, tc.aep, tc.key)
		if !errors.Is(err, tc.err) || changed || !bytes.Equal(got.MasterKey, pinMaster) || got.DerivedStorageKey != nil {
			t.Errorf("%s: %+v, %v, %v", name, got, changed, err)
		}
	}
}

func TestStorageServiceKeyPersistence(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, filepath.Join(t.TempDir(), "account.db"))
	dev := db.putDevice(uuid.New(), uuid.New())
	if dev.DerivedStorageKey != nil {
		t.Fatalf("new device derived key = %x", dev.DerivedStorageKey)
	}
	dev.DerivedStorageKey = b64(t, javaDerivedStored)
	if err := db.c.PutDevice(ctx, &dev.DeviceData); err != nil {
		t.Fatal(err)
	}
	db = db.reopen()
	dev = db.device(dev.ACI)
	if key, err := dev.ResolveStorageServiceKey(); err != nil || !bytes.Equal(key[:], b64(t, javaDerivedStored)) || dev.MasterKey != nil {
		t.Fatalf("reopened derived-only device = %x, %v (master %x)", key, err, dev.MasterKey)
	}

	dev.DerivedStorageKey = []byte{}
	if err := db.c.PutDevice(ctx, &dev.DeviceData); err != nil {
		t.Fatal(err)
	}
	if got := db.reopen().device(dev.ACI).DerivedStorageKey; got != nil {
		t.Fatalf("empty derived key reopened as %x, want nil", got)
	}
}

func TestStorageServiceKeySchemaFloor(t *testing.T) {
	ctx := context.Background()
	db := openV27(t)
	aci := uuid.New()
	db.putLegacyDevice(aci, uuid.New())
	v28 := db.root.Child("signalmeow_version", upgrades.Table[:28], dbutil.NoopLogger)
	if err := v28.Upgrade(ctx); err != nil {
		t.Fatalf("upgrade to v28: %v", err)
	}
	if v, c := db.version(); v != 28 || c != 28 {
		t.Fatalf("intermediate version = %d/%d, want 28/28", v, c)
	}
	if err := db.root.Child("signalmeow_version", upgrades.Table[:29], dbutil.NoopLogger).Upgrade(ctx); err != nil {
		t.Fatalf("upgrade to v29: %v", err)
	}
	if v, c := db.version(); v != 29 || c != 29 {
		t.Fatalf("migrated version = %d/%d, want 29/29", v, c)
	}
	if dev := db.device(aci); dev.DerivedStorageKey != nil {
		t.Fatalf("migrated derived key = %x", dev.DerivedStorageKey)
	}
	// A v28 binary cannot see the derived key, so it must refuse the database.
	if err := v28.Upgrade(ctx); !errors.Is(err, dbutil.ErrUnsupportedDatabaseVersion) {
		t.Fatalf("v28 reader error = %v, want ErrUnsupportedDatabaseVersion", err)
	}
}
