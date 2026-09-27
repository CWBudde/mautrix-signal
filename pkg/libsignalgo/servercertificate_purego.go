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

	"github.com/cwbudde/libsignal-go/sealedsender"
)

type ServerCertificate struct {
	nc   noCopy
	cert *sealedsender.ServerCertificate
}

func wrapServerCertificate(cert *sealedsender.ServerCertificate) *ServerCertificate {
	return &ServerCertificate{cert: cert}
}

// NewServerCertificate should only be used for testing (at least according to
// the Swift bindings).
func NewServerCertificate(keyID uint32, publicKey *PublicKey, trustRoot *PrivateKey) (*ServerCertificate, error) {
	cert, err := sealedsender.NewServerCertificate(keyID, publicKey.key, trustRoot.key, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapServerCertificate(cert), nil
}

func DeserializeServerCertificate(serialized []byte) (*ServerCertificate, error) {
	cert, err := sealedsender.DeserializeServerCertificate(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapServerCertificate(cert), nil
}

func (sc *ServerCertificate) Clone() (*ServerCertificate, error) {
	return wrapServerCertificate(sc.cert), nil
}

func (sc *ServerCertificate) Destroy() error {
	return nil
}

func (sc *ServerCertificate) CancelFinalizer() {}

func (sc *ServerCertificate) Serialize() ([]byte, error) {
	return sc.cert.Serialized(), nil
}

func (sc *ServerCertificate) GetCertificate() ([]byte, error) {
	return sc.cert.Certificate(), nil
}

func (sc *ServerCertificate) GetSignature() ([]byte, error) {
	return sc.cert.Signature(), nil
}

func (sc *ServerCertificate) GetKeyID() (uint32, error) {
	return sc.cert.KeyID(), nil
}

func (sc *ServerCertificate) GetKey() (*PublicKey, error) {
	return wrapPublicKey(sc.cert.PublicKey()), nil
}
