// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
)

// ErrProvisioningInTransaction is returned when StoreProvisionedDevice runs inside a caller's
// transaction, which would keep its replacement from committing on its own.
var ErrProvisioningInTransaction = errors.New("provisioned device must not be stored inside a transaction")

// ProvisioningPreKeys are the fixed ID 1 signed and last-resort Kyber prekeys that a linked
// device registers with the server.
type ProvisioningPreKeys struct {
	ACISigned, PNISigned         *libsignalgo.SignedPreKeyRecord
	ACILastResort, PNILastResort *libsignalgo.KyberPreKeyRecord
}

const deleteAllocatorsQuery = `DELETE FROM signalmeow_prekey_allocators WHERE account_id=$1`

// provisionedPreKeyState is the allocator state of each scope after provisioning: signed and
// last-resort ID 1 are active, the next IDs follow them, and EC keys start at 1.
func provisionedPreKeyState() PreKeyAllocatorState {
	one := func() *uint32 { id := uint32(1); return &id }
	return PreKeyAllocatorState{NextEC: 1, NextSigned: 2, NextKyber: 2, ActiveSigned: one(), ActiveLastResort: one()}
}

func (k ProvisioningPreKeys) validate() error {
	return errors.Join(
		checkProvisioningPreKey("ACI signed", k.ACISigned),
		checkProvisioningPreKey("PNI signed", k.PNISigned),
		checkProvisioningPreKey("ACI last-resort", k.ACILastResort),
		checkProvisioningPreKey("PNI last-resort", k.PNILastResort),
	)
}

func checkProvisioningPreKey[R interface {
	comparable
	GetID() (uint32, error)
}](name string, record R) error {
	var missing R
	if record == missing {
		return fmt.Errorf("%w: missing %s prekey", ErrPreKeyAllocatorInvalid, name)
	}
	id, err := record.GetID()
	if err != nil {
		return fmt.Errorf("%w: %s prekey: %w", ErrPreKeyAllocatorInvalid, name, err)
	} else if id != 1 {
		return fmt.Errorf("%w: %s prekey has ID %d, want 1", ErrPreKeyAllocatorInvalid, name, id)
	}
	return nil
}

// StoreProvisionedDevice stores the credentials of a newly linked device and replaces any
// previous protocol state of the account in one transaction: it clears old prekeys, sessions
// and allocators, stores the local identities and the fixed provisioning prekeys, and seeds
// both allocator scopes. On error nothing changed. This is the explicit credential-replacement
// boundary, not a general reset API. It is local only: the server already registered the
// device, so a failure means the device has to be linked again.
func (c *Container) StoreProvisionedDevice(ctx context.Context, data *DeviceData, keys ProvisioningPreKeys) (*Device, error) {
	if inTransaction(ctx, c.db) {
		return nil, ErrProvisioningInTransaction
	} else if data == nil {
		return nil, fmt.Errorf("%w: missing device data", ErrPreKeyAllocatorInvalid)
	} else if err := keys.validate(); err != nil {
		return nil, err
	}
	var device *Device
	err := c.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		if err := c.PutDevice(ctx, data); err != nil {
			return fmt.Errorf("failed to store device: %w", err)
		}
		dev, err := c.DeviceByACI(ctx, data.ACI)
		if err != nil {
			return fmt.Errorf("failed to load device: %w", err)
		} else if dev == nil {
			return fmt.Errorf("stored device %s not found", data.ACI)
		}
		if err := dev.ClearDeviceKeys(ctx); err != nil {
			return fmt.Errorf("failed to clear old keys and sessions: %w", err)
		}
		if _, err := c.db.Exec(ctx, deleteAllocatorsQuery, data.ACI); err != nil {
			return fmt.Errorf("failed to clear old prekey allocators: %w", err)
		}
		for _, serviceID := range []struct {
			name string
			save func() (bool, error)
		}{
			{"ACI", func() (bool, error) {
				return dev.IdentityKeyStore.SaveIdentityKey(ctx, dev.ACIServiceID(), dev.ACIIdentityKeyPair.GetIdentityKey())
			}},
			{"PNI", func() (bool, error) {
				return dev.IdentityKeyStore.SaveIdentityKey(ctx, dev.PNIServiceID(), dev.PNIIdentityKeyPair.GetIdentityKey())
			}},
		} {
			if _, err := serviceID.save(); err != nil {
				return fmt.Errorf("failed to save %s identity key: %w", serviceID.name, err)
			}
		}
		for _, scope := range []struct {
			pks        PreKeyStore
			signed     *libsignalgo.SignedPreKeyRecord
			lastResort *libsignalgo.KyberPreKeyRecord
		}{
			{dev.ACIPreKeyStore, keys.ACISigned, keys.ACILastResort},
			{dev.PNIPreKeyStore, keys.PNISigned, keys.PNILastResort},
		} {
			serviceID := scope.pks.GetServiceID()
			if err := scope.pks.StoreSignedPreKey(ctx, 1, scope.signed); err != nil {
				return fmt.Errorf("failed to store %s signed prekey: %w", serviceID, err)
			}
			if err := scope.pks.StoreLastResortKyberPreKey(ctx, 1, scope.lastResort); err != nil {
				return fmt.Errorf("failed to store %s last-resort prekey: %w", serviceID, err)
			}
			if err := c.SeedPreKeyAllocator(ctx, data.ACI, serviceID, provisionedPreKeyState()); err != nil {
				return fmt.Errorf("failed to seed %s prekey allocator: %w", serviceID, err)
			}
		}
		device = dev
		return nil
	})
	if err != nil {
		return nil, err
	}
	return device, nil
}
