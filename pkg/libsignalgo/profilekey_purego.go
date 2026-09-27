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
	"crypto/aes"
	"encoding/base64"
	"errors"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"github.com/google/uuid"
)

const ProfileKeyLength = 32
const AccessKeyLength = 16
const ProfileKeyVersionLength = 64

type ProfileKey [ProfileKeyLength]byte
type ProfileKeyCommitment = fixedArray97
type ProfileKeyVersion [ProfileKeyVersionLength]byte
type AccessKey [AccessKeyLength]byte

func DeserializeProfileKey(bytes []byte) (*ProfileKey, error) {
	if len(bytes) == 0 {
		return nil, nil
	} else if len(bytes) != ProfileKeyLength {
		return nil, errors.New("invalid profile key length")
	}
	key := ProfileKey(bytes)
	return &key, nil
}

var blankProfileKey ProfileKey

func (pk *ProfileKey) IsEmpty() bool {
	return pk == nil || *pk == blankProfileKey
}

func (pv *ProfileKeyVersion) String() string {
	return string(pv[:])
}

func (pk *ProfileKey) Slice() []byte {
	if pk.IsEmpty() {
		return nil
	}
	return pk[:]
}

func (ak *AccessKey) Xor(other *AccessKey) *AccessKey {
	if ak == nil {
		return other
	} else if other == nil {
		return ak
	}
	var result AccessKey
	for i := 0; i < AccessKeyLength; i++ {
		result[i] = ak[i] ^ other[i]
	}
	return &result
}

func (ak *AccessKey) String() string {
	return base64.StdEncoding.EncodeToString(ak[:])
}

func (pk *ProfileKey) GetCommitment(u uuid.UUID) (*ProfileKeyCommitment, error) {
	c := ProfileKeyCommitment(zkgroup.ProfileKey(*pk).Commitment([16]byte(u)))
	return &c, nil
}

func (pk *ProfileKey) GetProfileKeyVersion(u uuid.UUID) (*ProfileKeyVersion, error) {
	v := ProfileKeyVersion(zkgroup.ProfileKey(*pk).Version([16]byte(u)))
	return &v, nil
}

// DeriveAccessKey derives the unidentified access key: AES-256 under the
// profile key of the block 0...02 (ProfileKey::derive_access_key, which
// explains why this equals the original AES-GCM definition).
func (pk *ProfileKey) DeriveAccessKey() (*AccessKey, error) {
	block, err := aes.NewCipher(pk[:])
	if err != nil {
		return nil, errInvalidArgument("%v", err)
	}
	var in, out AccessKey
	in[AccessKeyLength-1] = 2
	block.Encrypt(out[:], in[:])
	return &out, nil
}

const ExpiringProfileKeyCredentialResponseLength = 497

type ProfileKeyCredentialRequestContext [473]byte

type ProfileKeyCredentialRequest = fixedArray329

type ProfileKeyCredentialResponse []byte

type ProfileKeyCredentialPresentation []byte

type ExpiringProfileKeyCredential = fixedArray153

type ExpiringProfileKeyCredentialResponse = fixedArray497

func CreateProfileKeyCredentialRequestContext(serverPublicParams *ServerPublicParams, u uuid.UUID, profileKey ProfileKey) (*ProfileKeyCredentialRequestContext, error) {
	c, e := serverPublicParams.inner.CreateProfileKeyCredentialRequestContext([32]byte(GenerateRandomness()), [16]byte(u), zkgroup.ProfileKey(profileKey))
	if e != nil {
		return nil, zkError(e)
	}
	out := ProfileKeyCredentialRequestContext(c.Bytes())
	return &out, nil
}

func (p *ProfileKeyCredentialRequestContext) ProfileKeyCredentialRequestContextGetRequest() (*ProfileKeyCredentialRequest, error) {
	c, e := zkgroup.ParseProfileKeyCredentialRequestContext(p[:])
	if e != nil {
		return nil, zkError(e)
	}
	r := ProfileKeyCredentialRequest(c.Request().Bytes())
	return &r, nil
}

func NewExpiringProfileKeyCredentialResponse(b []byte) (*ExpiringProfileKeyCredentialResponse, error) {
	c, e := zkgroup.ParseExpiringProfileKeyCredentialResponse(b)
	if e != nil {
		return nil, zkError(e)
	}
	out := ExpiringProfileKeyCredentialResponse(c.Bytes())
	return &out, nil
}

func ReceiveExpiringProfileKeyCredential(spp *ServerPublicParams, requestContext *ProfileKeyCredentialRequestContext, response *ExpiringProfileKeyCredentialResponse, currentTimeInSeconds uint64) (*ExpiringProfileKeyCredential, error) {
	c, e := zkgroup.ParseProfileKeyCredentialRequestContext(requestContext[:])
	if e != nil {
		return nil, zkError(e)
	}
	r, e := zkgroup.ParseExpiringProfileKeyCredentialResponse(response[:])
	if e != nil {
		return nil, zkError(e)
	}
	v, e := spp.inner.ReceiveExpiringProfileKeyCredential(c, r, currentTimeInSeconds)
	if e != nil {
		return nil, zkError(e)
	}
	out := ExpiringProfileKeyCredential(v.Bytes())
	return &out, nil
}

func (a ProfileKeyCredentialPresentation) CheckValidContents() error {
	_, e := zkgroup.ParseProfileKeyCredentialPresentation(a)
	return zkError(e)
}

func (a ProfileKeyCredentialPresentation) UUIDCiphertext() (UUIDCiphertext, error) {
	p, e := zkgroup.ParseProfileKeyCredentialPresentation(a)
	if e != nil {
		return UUIDCiphertext{}, zkError(e)
	}
	return UUIDCiphertext(p.UUIDCiphertext().Bytes()), nil
}

func (a ProfileKeyCredentialPresentation) ProfileKeyCiphertext() (ProfileKeyCiphertext, error) {
	p, e := zkgroup.ParseProfileKeyCredentialPresentation(a)
	if e != nil {
		return ProfileKeyCiphertext{}, zkError(e)
	}
	return ProfileKeyCiphertext(p.ProfileKeyCiphertext().Bytes()), nil
}
