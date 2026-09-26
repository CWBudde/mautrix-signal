//go:build purego

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
	"time"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/session"
)

type SignedPreKeyRecord struct {
	nc     noCopy
	record *session.SignedPreKeyRecord
}

func wrapSignedPreKeyRecord(record *session.SignedPreKeyRecord) *SignedPreKeyRecord {
	return &SignedPreKeyRecord{record: record}
}

func NewSignedPreKeyRecord(id uint32, timestamp time.Time, publicKey *PublicKey, privateKey *PrivateKey, signature []byte) (*SignedPreKeyRecord, error) {
	kp := curve.NewKeyPair(publicKey.key, privateKey.key)
	return wrapSignedPreKeyRecord(session.NewSignedPreKeyRecord(id, timestamp, kp, signature)), nil
}

func NewSignedPreKeyRecordFromPrivateKey(id uint32, timestamp time.Time, privateKey *PrivateKey, signature []byte) (*SignedPreKeyRecord, error) {
	pub, err := privateKey.GetPublicKey()
	if err != nil {
		return nil, err
	}
	return NewSignedPreKeyRecord(id, timestamp, pub, privateKey, signature)
}

func DeserializeSignedPreKeyRecord(serialized []byte) (*SignedPreKeyRecord, error) {
	record, err := session.DeserializeSignedPreKeyRecord(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapSignedPreKeyRecord(record), nil
}

func (spkr *SignedPreKeyRecord) Clone() (*SignedPreKeyRecord, error) {
	return wrapSignedPreKeyRecord(spkr.record), nil
}

func (spkr *SignedPreKeyRecord) Destroy() error {
	return nil
}

func (spkr *SignedPreKeyRecord) CancelFinalizer() {}

func (spkr *SignedPreKeyRecord) Serialize() ([]byte, error) {
	serialized, err := spkr.record.Serialize()
	return serialized, wrapError(err)
}

func (spkr *SignedPreKeyRecord) GetSignature() ([]byte, error) {
	return spkr.record.Signature(), nil
}

func (spkr *SignedPreKeyRecord) GetID() (uint32, error) {
	return spkr.record.ID(), nil
}

func (spkr *SignedPreKeyRecord) GetTimestamp() (time.Time, error) {
	return spkr.record.Timestamp(), nil
}

func (spkr *SignedPreKeyRecord) GetPublicKey() (*PublicKey, error) {
	key, err := spkr.record.PublicKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPublicKey(key), nil
}

func (spkr *SignedPreKeyRecord) GetPrivateKey() (*PrivateKey, error) {
	key, err := spkr.record.PrivateKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPrivateKey(key), nil
}
