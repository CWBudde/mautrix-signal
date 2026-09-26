//go:build purego

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
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
	"crypto/hkdf"
	"crypto/sha256"
)

func HKDFDerive(outputLength int, inputKeyMaterial, salt, info []byte) ([]byte, error) {
	out, err := hkdf.Key(sha256.New, inputKeyMaterial, salt, string(info), outputLength)
	if err != nil {
		return nil, errInvalidArgument("HKDF: %v", err)
	}
	return out, nil
}
