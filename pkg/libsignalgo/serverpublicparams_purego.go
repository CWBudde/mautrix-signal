//go:build libsignal_go

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
	"github.com/cwbudde/libsignal-go/zkgroup"
)

// ServerPublicParams holds validated zkgroup server parameters.
type ServerPublicParams struct {
	inner *zkgroup.ServerPublicParams
}

type NotarySignature = fixedArray64

const ServerPublicParamsLength = 673

// DeserializeServerPublicParams must succeed for the embedded production parameters, which
// signalmeow deserializes at init.
func DeserializeServerPublicParams(params []byte) (*ServerPublicParams, error) {
	p, err := zkgroup.ParseServerPublicParams(params)
	if err != nil {
		return nil, zkError(err)
	}
	return &ServerPublicParams{inner: p}, nil
}

func ServerPublicParamsVerifySignature(
	serverPublicParams *ServerPublicParams,
	messageBytes []byte,
	NotarySignature NotarySignature,
) error {
	if serverPublicParams == nil {
		return errInvalidArgument("nil server params")
	}
	return zkError(serverPublicParams.inner.VerifySignature(messageBytes, zkgroup.NotarySignature(NotarySignature)))
}
