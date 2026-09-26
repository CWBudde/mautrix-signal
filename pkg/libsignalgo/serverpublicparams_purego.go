//go:build purego

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
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
	"bytes"
	"fmt"
)

// ServerPublicParams holds the serialized zkgroup server parameters. Parsing them is part of the
// zkgroup port (go-signal PLAN.md 8.3); until then only the length is checked.
type ServerPublicParams struct {
	serialized []byte
}

type NotarySignature = fixedArray64

const ServerPublicParamsLength = 673

// DeserializeServerPublicParams must succeed for the embedded production parameters, which
// signalmeow deserializes at init.
func DeserializeServerPublicParams(params []byte) (*ServerPublicParams, error) {
	if len(params) != ServerPublicParamsLength {
		return nil, fmt.Errorf("invalid server public params length: %d (expected %d)", len(params), ServerPublicParamsLength)
	}
	return &ServerPublicParams{serialized: bytes.Clone(params)}, nil
}

func ServerPublicParamsVerifySignature(
	serverPublicParams *ServerPublicParams,
	messageBytes []byte,
	NotarySignature NotarySignature,
) error {
	return ErrNotImplemented
}
