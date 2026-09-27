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

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/session"
)

func DecryptPreKey(ctx context.Context, preKeyMessage *PreKeyMessage, fromAddress, localAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, kyberPreKeyStore KyberPreKeyStore) ([]byte, error) {
	plaintext, err := session.MessageDecryptPreKey(ctx, preKeyMessage.msg, fromAddress.addr, localAddress.addr,
		sessionStoreAdapter{sessionStore}, identityStoreAdapter{identityStore}, preKeyStoreAdapter{preKeyStore},
		signedPreKeyStoreAdapter{signedPreKeyStore}, kyberPreKeyStoreAdapter{kyberPreKeyStore}, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return plaintext, nil
}

type PreKeyRecord struct {
	nc     noCopy
	record *session.PreKeyRecord
}

func wrapPreKeyRecord(record *session.PreKeyRecord) *PreKeyRecord {
	return &PreKeyRecord{record: record}
}

func NewPreKeyRecord(id uint32, publicKey *PublicKey, privateKey *PrivateKey) (*PreKeyRecord, error) {
	return wrapPreKeyRecord(session.NewPreKeyRecord(id, curve.NewKeyPair(publicKey.key, privateKey.key))), nil
}

func NewPreKeyRecordFromPrivateKey(id uint32, privateKey *PrivateKey) (*PreKeyRecord, error) {
	pub, err := privateKey.GetPublicKey()
	if err != nil {
		return nil, err
	}
	return NewPreKeyRecord(id, pub, privateKey)
}

func DeserializePreKeyRecord(serialized []byte) (*PreKeyRecord, error) {
	record, err := session.DeserializePreKeyRecord(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPreKeyRecord(record), nil
}

func (pkr *PreKeyRecord) Clone() (*PreKeyRecord, error) {
	return wrapPreKeyRecord(pkr.record), nil
}

func (pkr *PreKeyRecord) Destroy() error {
	return nil
}

func (pkr *PreKeyRecord) CancelFinalizer() {}

func (pkr *PreKeyRecord) Serialize() ([]byte, error) {
	serialized, err := pkr.record.Serialize()
	return serialized, wrapError(err)
}

func (pkr *PreKeyRecord) GetID() (uint32, error) {
	return pkr.record.ID(), nil
}

func (pkr *PreKeyRecord) GetPublicKey() (*PublicKey, error) {
	key, err := pkr.record.PublicKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPublicKey(key), nil
}

func (pkr *PreKeyRecord) GetPrivateKey() (*PrivateKey, error) {
	key, err := pkr.record.PrivateKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPrivateKey(key), nil
}
