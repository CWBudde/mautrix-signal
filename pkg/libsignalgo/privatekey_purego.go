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
	"crypto/rand"

	"github.com/cwbudde/libsignal-go/curve"
)

type PrivateKey struct {
	nc  noCopy
	key curve.PrivateKey
}

func wrapPrivateKey(key curve.PrivateKey) *PrivateKey {
	return &PrivateKey{key: key}
}

func GeneratePrivateKey() (*PrivateKey, error) {
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPrivateKey(kp.PrivateKey), nil
}

func DeserializePrivateKey(keyData []byte) (*PrivateKey, error) {
	key, err := curve.DeserializePrivateKey(keyData)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPrivateKey(key), nil
}

func (pk *PrivateKey) Clone() (*PrivateKey, error) {
	return wrapPrivateKey(pk.key), nil
}

func (pk *PrivateKey) Destroy() error {
	return nil
}

func (pk *PrivateKey) CancelFinalizer() {}

func (pk *PrivateKey) GetPublicKey() (*PublicKey, error) {
	pub, err := pk.key.PublicKey()
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPublicKey(pub), nil
}

func (pk *PrivateKey) Serialize() ([]byte, error) {
	return pk.key.Serialize(), nil
}

func (pk *PrivateKey) Sign(message []byte) ([]byte, error) {
	sig, err := pk.key.CalculateSignature(rand.Reader, message)
	if err != nil {
		return nil, wrapError(err)
	}
	return sig, nil
}

func (pk *PrivateKey) Agree(publicKey *PublicKey) ([]byte, error) {
	shared, err := pk.key.CalculateAgreement(publicKey.key)
	if err != nil {
		return nil, wrapError(err)
	}
	return shared, nil
}

// keyPair returns the curve key pair of pk.
func (pk *PrivateKey) keyPair() (curve.KeyPair, error) {
	kp, err := curve.KeyPairFromPrivateKey(pk.key)
	if err != nil {
		return curve.KeyPair{}, wrapError(err)
	}
	return kp, nil
}
