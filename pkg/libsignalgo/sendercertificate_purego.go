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
	"time"

	"github.com/google/uuid"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/sealedsender"
)

type SenderCertificate struct {
	nc   noCopy
	cert *sealedsender.SenderCertificate
}

func wrapSenderCertificate(cert *sealedsender.SenderCertificate) *SenderCertificate {
	return &SenderCertificate{cert: cert}
}

// NewSenderCertificate should only be used for testing (at least according to
// the Swift bindings).
func NewSenderCertificate(sender *SealedSenderAddress, publicKey *PublicKey, expiration time.Time, signerCertificate *ServerCertificate, signerKey *PrivateKey) (*SenderCertificate, error) {
	if _, err := address.NewDeviceID(sender.DeviceID); err != nil {
		return nil, errInvalidArgument("%v", err)
	}
	// The cgo build always passes the E164, so an empty one is kept as empty.
	e164 := sender.E164
	cert, err := sealedsender.NewSenderCertificate(sender.UUID.String(), &e164, publicKey.key, sender.DeviceID,
		expiration, signerCertificate.cert, signerKey.key, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapSenderCertificate(cert), nil
}

func DeserializeSenderCertificate(serialized []byte) (*SenderCertificate, error) {
	cert, err := sealedsender.DeserializeSenderCertificate(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapSenderCertificate(cert), nil
}

func (sc *SenderCertificate) Clone() (*SenderCertificate, error) {
	return wrapSenderCertificate(sc.cert), nil
}

func (sc *SenderCertificate) Destroy() error {
	return nil
}

func (sc *SenderCertificate) CancelFinalizer() {}

func (sc *SenderCertificate) Serialize() ([]byte, error) {
	return sc.cert.Serialized(), nil
}

func (sc *SenderCertificate) GetCertificate() ([]byte, error) {
	return sc.cert.Certificate(), nil
}

func (sc *SenderCertificate) GetSignature() ([]byte, error) {
	return sc.cert.Signature(), nil
}

func (sc *SenderCertificate) GetSenderUUID() (uuid.UUID, error) {
	return uuid.Parse(sc.cert.SenderUUID())
}

func (sc *SenderCertificate) GetSenderE164() (string, error) {
	e164, _ := sc.cert.SenderE164()
	return e164, nil
}

func (sc *SenderCertificate) GetExpiration() (time.Time, error) {
	return time.UnixMilli(sc.cert.Expiration().UnixMilli()), nil
}

func (sc *SenderCertificate) GetDeviceID() (uint32, error) {
	return sc.cert.SenderDeviceID(), nil
}

func (sc *SenderCertificate) GetKey() (*PublicKey, error) {
	return wrapPublicKey(sc.cert.Key()), nil
}

func (sc *SenderCertificate) Validate(trustRoots []*PublicKey, ts time.Time) (bool, error) {
	roots := make([]curve.PublicKey, len(trustRoots))
	for i, root := range trustRoots {
		roots[i] = root.key
	}
	valid, err := sc.cert.ValidateWithTrustRoots(roots, sealedsender.WithClock(time.UnixMilli(ts.UnixMilli())))
	if err != nil {
		return false, wrapError(err)
	}
	return valid, nil
}

func (sc *SenderCertificate) GetServerCertificate() (*ServerCertificate, error) {
	signer, err := sc.cert.ResolvedSigner()
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapServerCertificate(signer), nil
}
