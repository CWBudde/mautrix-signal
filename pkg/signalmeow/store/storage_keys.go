// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
)

// StorageServiceKeyLen is the length of the storage service key and of the account master key
// it is derived from.
const StorageServiceKeyLen = 32

// StorageServiceKey is a derived storage service key. Its own type keeps master keys, which
// share the length, from being passed where the derived key is expected.
type StorageServiceKey [StorageServiceKeyLen]byte

var (
	ErrStorageServiceKeyUnknown  = errors.New("storage service key is unknown")
	ErrStorageServiceKeyInvalid  = errors.New("invalid storage service key material")
	ErrStorageServiceKeyConflict = errors.New("storage service key forms disagree")
)

// DeriveStorageServiceKey derives the storage service key from an account master key
// (HMAC-SHA256 over "Storage Service Encryption").
func DeriveStorageServiceKey(masterKey []byte) (StorageServiceKey, error) {
	var key StorageServiceKey
	if len(masterKey) != StorageServiceKeyLen {
		return key, fmt.Errorf("%w: master key has %d bytes", ErrStorageServiceKeyInvalid, len(masterKey))
	}
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte("Storage Service Encryption"))
	copy(key[:], h.Sum(nil))
	return key, nil
}

// ResolveStorageServiceKey returns the storage service key of the device. It uses a stored
// derived key as is and derives one from the master key or the account entropy pool. Every
// form that is present must be valid and lead to the same key; a master key must also match
// the pool's. Nothing present means ErrStorageServiceKeyUnknown. A derived key is never
// derived again and never turned into a master key.
func (d *DeviceData) ResolveStorageServiceKey() (StorageServiceKey, error) {
	var resolved StorageServiceKey
	found := false
	agree := func(form string, key StorageServiceKey) error {
		if !found {
			resolved, found = key, true
		} else if !hmac.Equal(resolved[:], key[:]) {
			return fmt.Errorf("%w: %s", ErrStorageServiceKeyConflict, form)
		}
		return nil
	}
	if d.DerivedStorageKey != nil {
		if len(d.DerivedStorageKey) != StorageServiceKeyLen {
			return resolved, fmt.Errorf("%w: derived key has %d bytes", ErrStorageServiceKeyInvalid, len(d.DerivedStorageKey))
		}
		resolved, found = StorageServiceKey(d.DerivedStorageKey), true
	}
	if d.MasterKey != nil {
		key, err := DeriveStorageServiceKey(d.MasterKey)
		if err != nil {
			return StorageServiceKey{}, err
		}
		if err := agree("master key", key); err != nil {
			return StorageServiceKey{}, err
		}
	}
	if d.AccountEntropyPool != "" {
		master, err := d.AccountEntropyPool.DeriveSVRKey()
		if err != nil {
			return StorageServiceKey{}, fmt.Errorf("%w: account entropy pool: %w", ErrStorageServiceKeyInvalid, err)
		}
		if d.MasterKey != nil && !hmac.Equal(master, d.MasterKey) {
			return StorageServiceKey{}, fmt.Errorf("%w: account entropy pool and master key", ErrStorageServiceKeyConflict)
		}
		key, err := DeriveStorageServiceKey(master)
		if err != nil {
			return StorageServiceKey{}, err
		}
		if err := agree("account entropy pool", key); err != nil {
			return StorageServiceKey{}, err
		}
	}
	if !found {
		return resolved, ErrStorageServiceKeyUnknown
	}
	return resolved, nil
}

// ApplyStorageKeySync returns the device's key forms after an authenticated SyncMessage.Keys
// update, following signal-cli: an account entropy pool supersedes every older form (its
// master key is stored alongside), otherwise a legacy derived storage service key replaces
// the derived form and clears a master key or pool that no longer leads to it. An update
// without either changes nothing. The input is not modified; changed reports whether any key
// form differs.
func ApplyStorageKeySync(d DeviceData, aep libsignalgo.AccountEntropyPool, storageKey []byte) (updated DeviceData, changed bool, err error) {
	before := d
	switch {
	case aep != "":
		master, err := aep.DeriveSVRKey()
		if err != nil {
			return before, false, fmt.Errorf("%w: account entropy pool: %w", ErrStorageServiceKeyInvalid, err)
		}
		d.AccountEntropyPool, d.MasterKey, d.DerivedStorageKey = aep, master, nil
	case storageKey != nil:
		if len(storageKey) != StorageServiceKeyLen {
			return before, false, fmt.Errorf("%w: derived key has %d bytes", ErrStorageServiceKeyInvalid, len(storageKey))
		}
		d.DerivedStorageKey = bytes.Clone(storageKey)
		if resolved, err := d.ResolveStorageServiceKey(); err != nil || !hmac.Equal(resolved[:], storageKey) {
			d.MasterKey, d.AccountEntropyPool = nil, ""
		}
	default:
		return before, false, nil
	}
	changed = before.AccountEntropyPool != d.AccountEntropyPool || !sameKey(before.MasterKey, d.MasterKey) ||
		!sameKey(before.DerivedStorageKey, d.DerivedStorageKey)
	return d, changed, nil
}

func sameKey(a, b []byte) bool { return (a == nil) == (b == nil) && bytes.Equal(a, b) }
