//go:build libsignal_go

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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
	"crypto/rand"
	"time"

	"github.com/cwbudde/libsignal-go/kem"
	"github.com/cwbudde/libsignal-go/session"
)

type KyberPreKeyRecord struct {
	nc     noCopy
	record *session.KyberPreKeyRecord
}

type KyberKeyPair struct {
	nc  noCopy
	key kem.KeyPair
}

type KyberPublicKey struct {
	nc  noCopy
	key kem.PublicKey
}

type KyberSecretKey struct {
	nc  noCopy
	key kem.SecretKey
}

func (kp *KyberKeyPair) Destroy() error {
	return nil
}

func (kp *KyberKeyPair) CancelFinalizer() {}

func (k *KyberPublicKey) Destroy() error {
	return nil
}

func (k *KyberPublicKey) CancelFinalizer() {}

func (k *KyberSecretKey) Destroy() error {
	return nil
}

func (k *KyberSecretKey) CancelFinalizer() {}

func wrapKyberPreKeyRecord(record *session.KyberPreKeyRecord) *KyberPreKeyRecord {
	return &KyberPreKeyRecord{record: record}
}

func (kp *KyberKeyPair) GetPublicKey() (*KyberPublicKey, error) {
	return &KyberPublicKey{key: kp.key.PublicKey}, nil
}

func (kp *KyberPublicKey) Serialize() ([]byte, error) {
	return kp.key.Serialize(), nil
}

func DeserializeKyberPublicKey(serialized []byte) (*KyberPublicKey, error) {
	key, err := kem.DeserializePublicKey(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return &KyberPublicKey{key: key}, nil
}

func NewKyberPreKeyRecord(id uint32, timestamp time.Time, keyPair *KyberKeyPair, signature []byte) (*KyberPreKeyRecord, error) {
	return wrapKyberPreKeyRecord(session.NewKyberPreKeyRecord(id, timestamp, keyPair.key, signature)), nil
}

func DeserializeKyberPreKeyRecord(serialized []byte) (*KyberPreKeyRecord, error) {
	record, err := session.DeserializeKyberPreKeyRecord(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapKyberPreKeyRecord(record), nil
}

func (kpkr *KyberPreKeyRecord) Clone() (*KyberPreKeyRecord, error) {
	return wrapKyberPreKeyRecord(kpkr.record), nil
}

func (kpkr *KyberPreKeyRecord) Destroy() error {
	return nil
}

func (kpkr *KyberPreKeyRecord) CancelFinalizer() {}

func (kpkr *KyberPreKeyRecord) Serialize() ([]byte, error) {
	serialized, err := kpkr.record.Serialize()
	return serialized, wrapError(err)
}

func (kpkr *KyberPreKeyRecord) GetSignature() ([]byte, error) {
	return kpkr.record.Signature(), nil
}

func (kpkr *KyberPreKeyRecord) GetID() (uint32, error) {
	return kpkr.record.ID(), nil
}

func (kpkr *KyberPreKeyRecord) GetTimestamp() (time.Time, error) {
	return kpkr.record.Timestamp(), nil
}

func (kpkr *KyberPreKeyRecord) GetPublicKey() (*KyberPublicKey, error) {
	key, err := kpkr.record.PublicKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return &KyberPublicKey{key: key}, nil
}

func (kpkr *KyberPreKeyRecord) GetSecretKey() (*KyberSecretKey, error) {
	key, err := kpkr.record.SecretKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return &KyberSecretKey{key: key}, nil
}

func KyberKeyPairGenerate() (*KyberKeyPair, error) {
	key, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return &KyberKeyPair{key: key}, nil
}
