// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo || libsignal_go

package signalmeow_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
)

// Java vectors from signal-cli's key models (go-signal: scripts/generate-account-import-fixtures.sh
// --storage-keys, internal/signal/accountimport/testdata/java-storage-keys/vectors.json).
var javaStorageVectors = []struct {
	name, storageKey, manifestKey, itemKey string
}{
	{"accountEntropyPool", "e+2iFZlwIhofS0jem5XaBTc3+pMTZFHcXdyxVdM/2SE=", "Au6j/kg3VCQTds8sQofY16GwUpvEcofmkZT7DDKPa/Q=", "SmbjZkd3PGIseQwW49w9b3L6w576ahfmpaWfW1JYJSs="},
	{"pinMasterKey", "2f0j7pnBSK2Hn2JgkpcTnmo29BWxrXedI8aHsfptNtk=", "1yi6/EPZvZcsXboXDswvLFPwAKsNNHjnsmXSvwn1Zq4=", "59qhqyIVCZAZNsEEn57giNdoQNa44yH+ynL/ZVUKO/A="},
	{"derivedStorageKey", "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=", "hCFneY6N7/w4pg7oZsRHm5oBZCV/EpMIAko27XoR09Y=", "SBNEQpwErJr2ZPdgXTzbzWNMg4g9YE0Q90Kxjw4JZfg="},
}

const (
	javaStoragePool     = "gosignalstoragekeyvectors0123456789abcdefghijklmnopqrstuvwxyz012"
	javaStorageManifest = 7
	javaStorageItemID   = "QEFCQ0RFRkdISUpLTE1OTw=="
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStorageKeyJavaDerivations(t *testing.T) {
	for _, v := range javaStorageVectors {
		key := store.StorageServiceKey(mustB64(t, v.storageKey))
		if got := signalmeow.DeriveStorageManifestKeyForTest(key, javaStorageManifest); !bytes.Equal(got, mustB64(t, v.manifestKey)) {
			t.Errorf("%s: manifest key = %x", v.name, got)
		}
		if got := signalmeow.DeriveLegacyStorageItemKeyForTest(key, mustB64(t, javaStorageItemID)); !bytes.Equal(got, mustB64(t, v.itemKey)) {
			t.Errorf("%s: item key = %x", v.name, got)
		}
	}
}

// keysSync builds a SyncMessage.Keys as it arrives on the wire, optionally with the legacy
// derived storageService field (1) that the generated schema reserves.
func keysSync(t *testing.T, aep string, legacy []byte) *signalpb.SyncMessage {
	t.Helper()
	keys := &signalpb.SyncMessage_Keys{}
	if aep != "" {
		keys.AccountEntropyPool = proto.String(aep)
	}
	raw, err := proto.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != nil {
		raw = protowire.AppendBytes(protowire.AppendTag(raw, 1, protowire.BytesType), legacy)
	}
	decoded := &signalpb.SyncMessage_Keys{}
	if err := proto.Unmarshal(raw, decoded); err != nil {
		t.Fatal(err)
	}
	return &signalpb.SyncMessage{Content: &signalpb.SyncMessage_Keys_{Keys: decoded}}
}

type keysClient struct {
	db    *refillDB
	cli   *signalmeow.Client
	syncs int
}

func newKeysClient(t *testing.T, db *refillDB) *keysClient {
	t.Helper()
	k := &keysClient{db: db}
	k.cli = signalmeow.NewClient(db.device(), zerolog.Nop(), func(events.SignalEvent) bool { return true })
	k.cli.SetStorageSyncHookForTest(func(context.Context) { k.syncs++ })
	return k
}

func (k *keysClient) handle(t *testing.T, msg *signalpb.SyncMessage) bool {
	t.Helper()
	return k.cli.HandleSyncMessageForTest(context.Background(), msg, &signalpb.Envelope{})
}

func resolved(t *testing.T, d *store.Device) []byte {
	t.Helper()
	key, err := d.ResolveStorageServiceKey()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return key[:]
}

func TestStorageKeySyncPersistsAcrossRestart(t *testing.T) {
	db := newRefillDevice(t)
	k := newKeysClient(t, db)
	if !k.cli.NeedsStorageKeysForTest() {
		t.Fatal("new linked device without keys must request them")
	}

	// Legacy derived-only update: stored as the derived form, never re-derived.
	derived := mustB64(t, javaStorageVectors[2].storageKey)
	if !k.handle(t, keysSync(t, "", derived)) || k.syncs != 1 || k.cli.NeedsStorageKeysForTest() {
		t.Fatalf("legacy keys sync: syncs=%d", k.syncs)
	}
	db = db.reopen()
	dev := db.device()
	if !bytes.Equal(resolved(t, dev), derived) || dev.MasterKey != nil || dev.AccountEntropyPool != "" {
		t.Fatalf("restarted derived-only device: %x master=%x pool=%q", resolved(t, dev), dev.MasterKey, dev.AccountEntropyPool)
	}

	// A pool from the primary supersedes the derived key, in memory and after restart.
	k = newKeysClient(t, db)
	if !k.handle(t, keysSync(t, javaStoragePool, derived)) || k.syncs != 1 {
		t.Fatalf("pool keys sync: syncs=%d", k.syncs)
	}
	want := mustB64(t, javaStorageVectors[0].storageKey)
	if !bytes.Equal(resolved(t, k.cli.Store), want) || k.cli.Store.DerivedStorageKey != nil {
		t.Fatalf("in-memory device after pool sync: %x derived=%x", resolved(t, k.cli.Store), k.cli.Store.DerivedStorageKey)
	}
	dev = db.reopen().device()
	if !bytes.Equal(resolved(t, dev), want) || dev.DerivedStorageKey != nil || string(dev.AccountEntropyPool) != javaStoragePool {
		t.Fatalf("restarted device after pool sync: %x derived=%x", resolved(t, dev), dev.DerivedStorageKey)
	}

	// An unchanged repeat is not written again but still starts a storage sync.
	if !k.handle(t, keysSync(t, javaStoragePool, nil)) || k.syncs != 2 {
		t.Fatalf("repeated keys sync: syncs=%d", k.syncs)
	}
}

func TestStorageKeySyncRefusals(t *testing.T) {
	db := newRefillDevice(t)
	for name, msg := range map[string]*signalpb.SyncMessage{
		"empty":          keysSync(t, "", nil),
		"invalid pool":   keysSync(t, "short", nil),
		"short legacy":   keysSync(t, "", []byte{1, 2, 3}),
		"wrong wiretype": {Content: &signalpb.SyncMessage_Keys_{Keys: unknownKeys(t, protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 7))}},
		"truncated":      {Content: &signalpb.SyncMessage_Keys_{Keys: unknownKeys(t, protowire.AppendTag(nil, 1, protowire.BytesType))}},
	} {
		k := newKeysClient(t, db)
		if !k.handle(t, msg) || k.syncs != 0 || !k.cli.NeedsStorageKeysForTest() {
			t.Errorf("%s: syncs=%d needs=%v", name, k.syncs, k.cli.NeedsStorageKeysForTest())
		}
		if dev := db.device(); dev.MasterKey != nil || dev.DerivedStorageKey != nil || dev.AccountEntropyPool != "" {
			t.Errorf("%s: device changed", name)
		}
	}

	// A malformed legacy field does not block a valid pool in the same message.
	k := newKeysClient(t, db)
	keys := unknownKeys(t, protowire.AppendTag(nil, 1, protowire.BytesType))
	keys.AccountEntropyPool = proto.String(javaStoragePool)
	if !k.handle(t, &signalpb.SyncMessage{Content: &signalpb.SyncMessage_Keys_{Keys: keys}}) || k.syncs != 1 {
		t.Fatalf("pool with malformed legacy field: syncs=%d", k.syncs)
	}
}

func unknownKeys(t *testing.T, unknown []byte) *signalpb.SyncMessage_Keys {
	t.Helper()
	keys := &signalpb.SyncMessage_Keys{}
	keys.ProtoReflect().SetUnknown(unknown)
	return keys
}

var errDeviceWrite = errors.New("injected device write failure")

type failingDeviceStore struct{ store.DeviceStore }

func (failingDeviceStore) PutDevice(context.Context, *store.DeviceData) error { return errDeviceWrite }

func TestStorageKeySyncPersistenceFailure(t *testing.T) {
	db := newRefillDevice(t)
	k := newKeysClient(t, db)
	k.cli.Store.DeviceStore = failingDeviceStore{k.cli.Store.DeviceStore}
	if k.handle(t, keysSync(t, javaStoragePool, nil)) {
		t.Fatal("failed persistence must fail the handler so the message is redelivered")
	}
	if k.syncs != 0 || !k.cli.NeedsStorageKeysForTest() || k.cli.Store.AccountEntropyPool != "" || k.cli.Store.MasterKey != nil {
		t.Fatalf("failed persistence changed the in-memory device: syncs=%d", k.syncs)
	}
	if dev := db.device(); dev.AccountEntropyPool != "" || dev.MasterKey != nil {
		t.Fatal("failed persistence changed the stored device")
	}
}

func TestStorageKeyConnectRequest(t *testing.T) {
	db := newRefillDevice(t)
	dev := db.device()
	for name, tc := range map[string]struct {
		change func(*store.Device)
		needs  bool
	}{
		"unknown":  {func(*store.Device) {}, true},
		"derived":  {func(d *store.Device) { d.DerivedStorageKey = mustB64(t, javaStorageVectors[2].storageKey) }, false},
		"pool":     {func(d *store.Device) { d.AccountEntropyPool = javaStoragePool }, false},
		"conflict": {func(d *store.Device) { d.AccountEntropyPool = javaStoragePool; d.DerivedStorageKey = make([]byte, 32) }, true},
		"invalid":  {func(d *store.Device) { d.MasterKey = []byte{1} }, true},
	} {
		d := store.Device{DeviceData: dev.DeviceData}
		tc.change(&d)
		cli := signalmeow.NewClient(&d, zerolog.Nop(), nil)
		if cli.NeedsStorageKeysForTest() != tc.needs || cli.HasStorageServiceKey() == tc.needs {
			t.Errorf("%s: needs keys = %v, want %v", name, cli.NeedsStorageKeysForTest(), tc.needs)
		}
	}
}
