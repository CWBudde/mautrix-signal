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
	"github.com/cwbudde/libsignal-go/fingerprint"
)

type FingerprintVersion uint32

const (
	FingerprintVersionV1 FingerprintVersion = 1
	FingerprintVersionV2 FingerprintVersion = 2
)

type Fingerprint struct {
	nc noCopy
	fp *fingerprint.Fingerprint
}

func NewFingerprint(iterations, version FingerprintVersion, localIdentifier []byte, localKey *PublicKey, remoteIdentifier []byte, remoteKey *PublicKey) (*Fingerprint, error) {
	fp, err := fingerprint.New(uint32(version), uint32(iterations), localIdentifier, localKey.key, remoteIdentifier, remoteKey.key)
	if err != nil {
		return nil, wrapError(err)
	}
	return &Fingerprint{fp: fp}, nil
}

func (f *Fingerprint) Clone() (*Fingerprint, error) {
	return &Fingerprint{fp: f.fp}, nil
}

func (f *Fingerprint) Destroy() error {
	return nil
}

func (f *Fingerprint) ScannableEncoding() ([]byte, error) {
	out, err := f.fp.Scannable.Serialize()
	if err != nil {
		return nil, wrapError(err)
	}
	return out, nil
}

func (f *Fingerprint) DisplayString() (string, error) {
	return f.fp.DisplayString(), nil
}

func (f *Fingerprint) Compare(fingerprint1, fingerprint2 []byte) (bool, error) {
	scannable, err := fingerprint.DeserializeScannableFingerprint(fingerprint1)
	if err != nil {
		return false, wrapError(err)
	}
	same, err := scannable.Compare(fingerprint2)
	if err != nil {
		return false, wrapError(err)
	}
	return same, nil
}
