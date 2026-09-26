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
	"github.com/cwbudde/libsignal-go/curve"
)

type PublicKey struct {
	nc  noCopy
	key curve.PublicKey
}

func wrapPublicKey(key curve.PublicKey) *PublicKey {
	return &PublicKey{key: key}
}

func (pk *PublicKey) Clone() (*PublicKey, error) {
	return wrapPublicKey(pk.key), nil
}

func DeserializePublicKey(keyData []byte) (*PublicKey, error) {
	key, err := curve.DeserializePublicKey(keyData)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPublicKey(key), nil
}

func (pk *PublicKey) Serialize() ([]byte, error) {
	return pk.key.Serialize(), nil
}

func (k *PublicKey) Destroy() error {
	return nil
}

func (k *PublicKey) CancelFinalizer() {}

func (k *PublicKey) Equal(other *PublicKey) (bool, error) {
	return k.key.Equal(other.key), nil
}

func (k *PublicKey) Bytes() ([]byte, error) {
	return k.key.PublicKeyBytes(), nil
}

func (k *PublicKey) Verify(message, signature []byte) (bool, error) {
	return k.key.VerifySignature(signature, message), nil
}
