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
	"encoding/base64"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"github.com/google/uuid"
)

const RandomnessLength = 32

type Randomness = fixedArray32

func GenerateRandomness() Randomness {
	var r Randomness
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}
	return r
}

const GroupMasterKeyLength = 32

const GroupIdentifierLength = 32

const GroupSecretParamsLength = 289

type GroupMasterKey [GroupMasterKeyLength]byte

type GroupSecretParams [GroupSecretParamsLength]byte

type GroupPublicParams = fixedArray97

type GroupIdentifier [GroupIdentifierLength]byte

func (gid *GroupIdentifier) String() string {
	if gid == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(gid[:])
}

type UUIDCiphertext = fixedArray65

type ProfileKeyCiphertext = fixedArray65

func GenerateGroupSecretParams() (GroupSecretParams, error) {
	return GenerateGroupSecretParamsWithRandomness(GenerateRandomness())
}

func (gmk GroupMasterKey) GroupIdentifier() (*GroupIdentifier, error) {
	g := zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey(gmk))
	id := GroupIdentifier(g.Public().Identifier())
	return &id, nil
}

func (gmk GroupMasterKey) SecretParams() (GroupSecretParams, error) {
	return DeriveGroupSecretParamsFromMasterKey(gmk)
}

func GenerateGroupSecretParamsWithRandomness(randomness Randomness) (GroupSecretParams, error) {
	return GroupSecretParams(zkgroup.GenerateGroupSecretParams([32]byte(randomness)).Bytes()), nil
}

func DeriveGroupSecretParamsFromMasterKey(groupMasterKey GroupMasterKey) (GroupSecretParams, error) {
	return GroupSecretParams(zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey(groupMasterKey)).Bytes()), nil
}

func (gsp *GroupSecretParams) GetPublicParams() (*GroupPublicParams, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	p := GroupPublicParams(g.Public().Bytes())
	return &p, nil
}

func GetGroupIdentifier(groupPublicParams GroupPublicParams) (*GroupIdentifier, error) {
	g, e := zkgroup.ParseGroupPublicParams(groupPublicParams[:])
	if e != nil {
		return nil, zkError(e)
	}
	id := GroupIdentifier(g.Identifier())
	return &id, nil
}

func (gsp *GroupSecretParams) DecryptBlobWithPadding(blob []byte) ([]byte, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	b, e := g.DecryptBlob(blob)
	return b, zkError(e)
}

func (gsp *GroupSecretParams) EncryptBlobWithPaddingDeterministic(randomness Randomness, plaintext []byte, padding_len uint32) ([]byte, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	b, e := g.EncryptBlob([32]byte(randomness), plaintext, padding_len)
	return b, zkError(e)
}

func (gsp *GroupSecretParams) DecryptServiceID(ciphertextServiceID UUIDCiphertext) (ServiceID, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return ServiceID{}, zkError(e)
	}
	c, e := zkgroup.ParseUUIDCiphertext(ciphertextServiceID[:])
	if e != nil {
		return ServiceID{}, zkError(e)
	}
	id, e := g.DecryptServiceID(c)
	if e != nil {
		return ServiceID{}, zkError(e)
	}
	return ServiceIDFromBytes(id.ServiceIDBinary())
}

func (gsp *GroupSecretParams) EncryptServiceID(serviceID ServiceID) (*UUIDCiphertext, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	id, e := address.ParseServiceIDBinary(serviceID.Bytes())
	if e != nil {
		return nil, wrapError(e)
	}
	c := UUIDCiphertext(g.EncryptServiceID(id).Bytes())
	return &c, nil
}

func (gsp *GroupSecretParams) DecryptProfileKey(ciphertextProfileKey ProfileKeyCiphertext, u uuid.UUID) (*ProfileKey, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	c, e := zkgroup.ParseProfileKeyCiphertext(ciphertextProfileKey[:])
	if e != nil {
		return nil, zkError(e)
	}
	k, e := g.DecryptProfileKey(c, [16]byte(u))
	if e != nil {
		return nil, zkError(e)
	}
	key := ProfileKey(k)
	return &key, nil
}

func (gsp *GroupSecretParams) EncryptProfileKey(profileKey ProfileKey, u uuid.UUID) (*ProfileKeyCiphertext, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	c := ProfileKeyCiphertext(g.EncryptProfileKey(zkgroup.ProfileKey(profileKey), [16]byte(u)).Bytes())
	return &c, nil
}

func (gsp *GroupSecretParams) CreateExpiringProfileKeyCredentialPresentation(spp *ServerPublicParams, credential ExpiringProfileKeyCredential) (*ProfileKeyCredentialPresentation, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	c, e := zkgroup.ParseExpiringProfileKeyCredential(credential[:])
	if e != nil {
		return nil, zkError(e)
	}
	p, e := spp.inner.CreateExpiringProfileKeyCredentialPresentation([32]byte(GenerateRandomness()), g, c)
	if e != nil {
		return nil, zkError(e)
	}
	out := ProfileKeyCredentialPresentation(p.Bytes())
	return &out, nil
}

func (gsp *GroupSecretParams) GetMasterKey() (*GroupMasterKey, error) {
	g, e := zkgroup.ParseGroupSecretParams(gsp[:])
	if e != nil {
		return nil, zkError(e)
	}
	k := GroupMasterKey(g.MasterKey())
	return &k, nil
}
