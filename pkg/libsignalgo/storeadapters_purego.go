//go:build purego

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2026 Christian Budde
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package libsignalgo

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/session"
	"github.com/cwbudde/libsignal-go/stores"
)

// Adapters from the libsignalgo store interfaces to libsignal-go's. They take
// the place of the cgo build's callbacks and behave like them: an error from a
// store reaches the caller unchanged (see callbackError), a missing pre-key is
// an invalid key identifier, and identities are looked up by the service ID in
// the address name.

var errNoIdentityKeyPair = errors.New("identity key store returned no identity key pair")

func storeErr(err error) error {
	if err == nil {
		return nil
	}
	return callbackError{err}
}

func errInvalidKeyID(kind string, id uint32) error {
	return &SignalError{Code: ErrorCodeInvalidKeyIdentifier, Message: "invalid " + kind + " ID " + strconv.FormatUint(uint64(id), 10)}
}

// serviceIDOf returns the service ID named by an address, as the cgo callbacks
// do with Address.NameServiceID.
func serviceIDOf(addr address.ProtocolAddress) (ServiceID, error) {
	id, err := ServiceIDFromString(addr.Name())
	if err != nil {
		return ServiceID{}, callbackError{err}
	}
	return id, nil
}

type sessionStoreAdapter struct{ store SessionStore }

var _ session.Store = sessionStoreAdapter{}

func (a sessionStoreAdapter) LoadSession(ctx context.Context, addr address.ProtocolAddress) (*session.SessionRecord, error) {
	record, err := a.store.LoadSession(ctx, wrapAddress(addr))
	if err != nil || record == nil {
		return nil, storeErr(err)
	}
	return record.record, nil
}

func (a sessionStoreAdapter) StoreSession(ctx context.Context, addr address.ProtocolAddress, record *session.SessionRecord) error {
	return storeErr(a.store.StoreSession(ctx, wrapAddress(addr), wrapSessionRecord(record)))
}

type identityStoreAdapter struct{ store IdentityKeyStore }

var _ stores.IdentityKeyStore = identityStoreAdapter{}

func (a identityStoreAdapter) GetIdentityKeyPair(ctx context.Context) (curve.KeyPair, error) {
	kp, err := a.store.GetIdentityKeyPair(ctx)
	if err != nil {
		return curve.KeyPair{}, storeErr(err)
	}
	if kp == nil {
		return curve.KeyPair{}, callbackError{errNoIdentityKeyPair}
	}
	return kp.curveKeyPair(), nil
}

func (a identityStoreAdapter) GetLocalRegistrationID(ctx context.Context) (uint32, error) {
	id, err := a.store.GetLocalRegistrationID(ctx)
	return id, storeErr(err)
}

func (a identityStoreAdapter) SaveIdentity(ctx context.Context, addr address.ProtocolAddress, key curve.PublicKey) (stores.IdentityChange, error) {
	serviceID, err := serviceIDOf(addr)
	if err != nil {
		return stores.NewOrUnchanged, err
	}
	replaced, err := a.store.SaveIdentityKey(ctx, serviceID, &IdentityKey{wrapPublicKey(key)})
	if err != nil {
		return stores.NewOrUnchanged, storeErr(err)
	}
	return stores.IdentityChangeFromReplaced(replaced), nil
}

func (a identityStoreAdapter) IsTrustedIdentity(ctx context.Context, addr address.ProtocolAddress, key curve.PublicKey, direction stores.Direction) (bool, error) {
	serviceID, err := serviceIDOf(addr)
	if err != nil {
		return false, err
	}
	dir := SignalDirectionSending
	if direction == stores.Receiving {
		dir = SignalDirectionReceiving
	}
	trusted, err := a.store.IsTrustedIdentity(ctx, serviceID, &IdentityKey{wrapPublicKey(key)}, dir)
	return trusted, storeErr(err)
}

func (a identityStoreAdapter) GetIdentity(ctx context.Context, addr address.ProtocolAddress) (curve.PublicKey, bool, error) {
	serviceID, err := serviceIDOf(addr)
	if err != nil {
		return curve.PublicKey{}, false, err
	}
	key, err := a.store.GetIdentityKey(ctx, serviceID)
	if err != nil || key == nil {
		return curve.PublicKey{}, false, storeErr(err)
	}
	return key.publicKey.key, true, nil
}

type preKeyStoreAdapter struct{ store PreKeyStore }

var _ stores.PreKeyStore = preKeyStoreAdapter{}

func (a preKeyStoreAdapter) GetPreKey(ctx context.Context, id uint32) ([]byte, error) {
	record, err := a.store.LoadPreKey(ctx, id)
	if err != nil {
		return nil, storeErr(err)
	}
	if record == nil {
		return nil, errInvalidKeyID("pre-key", id)
	}
	return record.Serialize()
}

func (a preKeyStoreAdapter) SavePreKey(ctx context.Context, id uint32, serialized []byte) error {
	record, err := DeserializePreKeyRecord(serialized)
	if err != nil {
		return err
	}
	return storeErr(a.store.StorePreKey(ctx, id, record))
}

func (a preKeyStoreAdapter) RemovePreKey(ctx context.Context, id uint32) error {
	return storeErr(a.store.RemovePreKey(ctx, id))
}

type signedPreKeyStoreAdapter struct{ store SignedPreKeyStore }

var _ stores.SignedPreKeyStore = signedPreKeyStoreAdapter{}

func (a signedPreKeyStoreAdapter) GetSignedPreKey(ctx context.Context, id uint32) ([]byte, error) {
	record, err := a.store.LoadSignedPreKey(ctx, id)
	if err != nil {
		return nil, storeErr(err)
	}
	if record == nil {
		return nil, errInvalidKeyID("signed pre-key", id)
	}
	return record.Serialize()
}

func (a signedPreKeyStoreAdapter) SaveSignedPreKey(ctx context.Context, id uint32, serialized []byte) error {
	record, err := DeserializeSignedPreKeyRecord(serialized)
	if err != nil {
		return err
	}
	return storeErr(a.store.StoreSignedPreKey(ctx, id, record))
}

type kyberPreKeyStoreAdapter struct{ store KyberPreKeyStore }

var _ stores.KyberPreKeyStore = kyberPreKeyStoreAdapter{}

func (a kyberPreKeyStoreAdapter) GetKyberPreKey(ctx context.Context, id uint32) ([]byte, error) {
	record, err := a.store.LoadKyberPreKey(ctx, id)
	if err != nil {
		return nil, storeErr(err)
	}
	if record == nil {
		return nil, errInvalidKeyID("Kyber pre-key", id)
	}
	return record.Serialize()
}

func (a kyberPreKeyStoreAdapter) SaveKyberPreKey(ctx context.Context, id uint32, serialized []byte) error {
	record, err := DeserializeKyberPreKeyRecord(serialized)
	if err != nil {
		return err
	}
	return storeErr(a.store.StoreKyberPreKey(ctx, id, record))
}

// MarkKyberPreKeyUsed passes on only the Kyber pre-key id, as the cgo build
// does; the store decides what to do with a used key.
func (a kyberPreKeyStoreAdapter) MarkKyberPreKeyUsed(ctx context.Context, id uint32, _ uint32, _ curve.PublicKey) error {
	return storeErr(a.store.MarkKyberPreKeyUsed(ctx, id))
}

type senderKeyStoreAdapter struct{ store SenderKeyStore }

var _ stores.SenderKeyStore = senderKeyStoreAdapter{}

func (a senderKeyStoreAdapter) LoadSenderKey(ctx context.Context, sender address.ProtocolAddress, distributionID [16]byte) ([]byte, error) {
	record, err := a.store.LoadSenderKey(ctx, wrapAddress(sender), uuid.UUID(distributionID))
	if err != nil || record == nil {
		return nil, storeErr(err)
	}
	return record.Serialize()
}

func (a senderKeyStoreAdapter) StoreSenderKey(ctx context.Context, sender address.ProtocolAddress, distributionID [16]byte, serialized []byte) error {
	record, err := DeserializeSenderKeyRecord(serialized)
	if err != nil {
		return err
	}
	return storeErr(a.store.StoreSenderKey(ctx, wrapAddress(sender), uuid.UUID(distributionID), record))
}
