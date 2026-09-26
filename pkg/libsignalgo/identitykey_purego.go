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
	"crypto/rand"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/identity"
)

type IdentityKey struct {
	publicKey *PublicKey
}

func NewIdentityKeyFromPublicKey(publicKey *PublicKey) (*IdentityKey, error) {
	return &IdentityKey{publicKey: publicKey}, nil
}

func NewIdentityKeyFromBytes(bytes []byte) (*IdentityKey, error) {
	publicKey, err := DeserializePublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return &IdentityKey{publicKey: publicKey}, nil
}

func (i *IdentityKey) TrySerialize() []byte {
	if i == nil {
		return nil
	}
	serialized, err := i.Serialize()
	if err != nil {
		return nil
	}
	return serialized
}

func (i *IdentityKey) Serialize() ([]byte, error) {
	return i.publicKey.Serialize()
}

func DeserializeIdentityKey(bytes []byte) (*IdentityKey, error) {
	publicKey, err := DeserializePublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return &IdentityKey{publicKey: publicKey}, nil
}

func (i *IdentityKey) VerifyAlternateIdentity(other *IdentityKey, signature []byte) (bool, error) {
	return identity.VerifyAlternateIdentity(i.publicKey.key, other.publicKey.key, signature), nil
}

func (i *IdentityKey) Equal(other *IdentityKey) (bool, error) {
	return i.publicKey.Equal(other.publicKey)
}

type IdentityKeyPair struct {
	publicKey  *PublicKey
	privateKey *PrivateKey
}

func (i *IdentityKeyPair) GetPublicKey() *PublicKey {
	return i.publicKey
}

func (i *IdentityKeyPair) GetPrivateKey() *PrivateKey {
	return i.privateKey
}

func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		return nil, err
	}
	return &IdentityKeyPair{publicKey: publicKey, privateKey: privateKey}, nil
}

func DeserializeIdentityKeyPair(bytes []byte) (*IdentityKeyPair, error) {
	kp, err := identity.DeserializeKeyPair(bytes)
	if err != nil {
		return nil, wrapError(err)
	}
	return &IdentityKeyPair{publicKey: wrapPublicKey(kp.PublicKey), privateKey: wrapPrivateKey(kp.PrivateKey)}, nil
}

func NewIdentityKeyPair(publicKey *PublicKey, privateKey *PrivateKey) (*IdentityKeyPair, error) {
	return &IdentityKeyPair{publicKey: publicKey, privateKey: privateKey}, nil
}

func (i *IdentityKeyPair) Serialize() ([]byte, error) {
	return identity.SerializeKeyPair(i.curveKeyPair()), nil
}

func (i *IdentityKeyPair) GetIdentityKey() *IdentityKey {
	return &IdentityKey{publicKey: i.publicKey}
}

func (i *IdentityKeyPair) SignAlternateIdentity(other *IdentityKey) ([]byte, error) {
	sig, err := identity.SignAlternateIdentity(i.privateKey.key, other.publicKey.key, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return sig, nil
}

// curveKeyPair returns the identity key pair as libsignal-go uses it.
func (i *IdentityKeyPair) curveKeyPair() curve.KeyPair {
	return curve.NewKeyPair(i.publicKey.key, i.privateKey.key)
}
