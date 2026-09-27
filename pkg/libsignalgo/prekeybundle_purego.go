//go:build libsignal_go

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
// Copyright (C) 2025 Tulir Asokan
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
	"crypto/rand"
	"time"

	"github.com/cwbudde/libsignal-go/session"
)

func ProcessPreKeyBundle(ctx context.Context, bundle *PreKeyBundle, forAddress, localAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore) error {
	err := session.ProcessPreKeyBundle(ctx, rand.Reader, forAddress.addr, bundle.bundle,
		sessionStoreAdapter{sessionStore}, identityStoreAdapter{identityStore},
		session.WithLocalAddress(localAddress.addr), session.WithClock(time.Now))
	return wrapError(err)
}

type PreKeyBundle struct {
	nc     noCopy
	bundle *session.PreKeyBundle
}

func NewPreKeyBundle(
	registrationID uint32,
	deviceID uint32,
	preKeyID uint32,
	preKey *PublicKey,
	signedPreKeyID uint32,
	signedPreKey *PublicKey,
	signedPreKeySignature []byte,
	kyberPreKeyID uint32,
	kyberPreKey *KyberPublicKey,
	kyberPreKeySignature []byte,
	identityKey *IdentityKey,
) (*PreKeyBundle, error) {
	if kyberPreKey == nil {
		return nil, &SignalError{Code: ErrorCodeNullParameter, Message: "missing Kyber pre-key"}
	}
	params := session.PreKeyBundleParams{
		RegistrationID:  registrationID,
		DeviceID:        deviceID,
		SignedPreKeyID:  signedPreKeyID,
		SignedPreKey:    signedPreKey.key,
		SignedPreKeySig: signedPreKeySignature,
		KyberPreKeyID:   kyberPreKeyID,
		KyberPreKey:     kyberPreKey.key,
		KyberPreKeySig:  kyberPreKeySignature,
		IdentityKey:     identityKey.publicKey.key,
	}
	// The cgo build passes a missing one-time pre-key as a null key with id
	// u32::MAX; libsignal then requires both or neither.
	switch {
	case preKey != nil && preKeyID != ^uint32(0):
		id, key := preKeyID, preKey.key
		params.PreKeyID, params.PreKey = &id, &key
	case preKey != nil:
		return nil, errInvalidArgument("Must supply both or neither of prekey and prekey_id")
	}
	b, err := session.NewPreKeyBundle(params)
	if err != nil {
		return nil, wrapError(err)
	}
	return &PreKeyBundle{bundle: b}, nil
}

func (pkb *PreKeyBundle) Clone() (*PreKeyBundle, error) {
	return &PreKeyBundle{bundle: pkb.bundle}, nil
}

func (pkb *PreKeyBundle) Destroy() error {
	return nil
}

func (pkb *PreKeyBundle) CancelFinalizer() {}

func (pkb *PreKeyBundle) GetIdentityKey() (*IdentityKey, error) {
	return &IdentityKey{wrapPublicKey(pkb.bundle.IdentityKey())}, nil
}
