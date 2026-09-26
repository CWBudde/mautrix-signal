//go:build purego

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
	"github.com/cwbudde/libsignal-go/zkgroup"
	"github.com/google/uuid"
)

// type AuthCredential [181]byte
// type AuthCredentialResponse [361]byte
const AuthCredentialWithPniLength = 265

const AuthCredentialWithPniResponseLength = 425

type AuthCredentialWithPni [AuthCredentialWithPniLength]byte

type AuthCredentialWithPniResponse [AuthCredentialWithPniResponseLength]byte

type AuthCredentialPresentation []byte

func (ac *AuthCredentialWithPni) Slice() []byte {
	if ac == nil {
		return nil
	}
	return ac[:]
}

func ReceiveAuthCredentialWithPni(
	serverPublicParams *ServerPublicParams,
	aci uuid.UUID,
	pni uuid.UUID,
	redemptionTime uint64,
	authCredResponse AuthCredentialWithPniResponse,
) (*AuthCredentialWithPni, error) {
	r, e := zkgroup.ParseAuthCredentialWithPniResponse(authCredResponse[:])
	if e != nil {
		return nil, zkError(e)
	}
	c, e := serverPublicParams.inner.ReceiveAuthCredentialWithPni([16]byte(aci), [16]byte(pni), redemptionTime, r)
	if e != nil {
		return nil, zkError(e)
	}
	out := AuthCredentialWithPni(c.Bytes())
	return &out, nil
}

func NewAuthCredentialWithPniResponse(b []byte) (*AuthCredentialWithPniResponse, error) {
	r, e := zkgroup.ParseAuthCredentialWithPniResponse(b)
	if e != nil {
		return nil, zkError(e)
	}
	out := AuthCredentialWithPniResponse(r.Bytes())
	return &out, nil
}

func CreateAuthCredentialWithPniPresentation(
	serverPublicParams *ServerPublicParams,
	randomness Randomness,
	groupSecretParams GroupSecretParams,
	authCredWithPni AuthCredentialWithPni,
) (*AuthCredentialPresentation, error) {
	g, e := zkgroup.ParseGroupSecretParams(groupSecretParams[:])
	if e != nil {
		return nil, zkError(e)
	}
	c, e := zkgroup.ParseAuthCredentialWithPni(authCredWithPni[:])
	if e != nil {
		return nil, zkError(e)
	}
	p, e := serverPublicParams.inner.CreateAuthCredentialPresentation([32]byte(randomness), g, c)
	if e != nil {
		return nil, zkError(e)
	}
	out := AuthCredentialPresentation(p.Bytes())
	return &out, nil
}
