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
	"errors"
	"time"

	"github.com/cwbudde/libsignal-go/attest/enclave"
)

// SGXClientState is an attested Noise connection to an SGX enclave (CDSI).
type SGXClientState struct {
	nc    noCopy
	state *enclave.SGXClientState
}

func NewCDS2ClientState(mrenclave, attestationMessage []byte, currentTime time.Time) (*SGXClientState, error) {
	s, err := enclave.NewCDS2ClientState(mrenclave, attestationMessage, currentTime)
	if err != nil {
		return nil, sgxError(err)
	}
	return &SGXClientState{state: s}, nil
}

// Destroy drops the connection state; later calls fail with InvalidState.
func (cds *SGXClientState) Destroy() error {
	cds.state = nil
	return nil
}

func (cds *SGXClientState) InitialRequest() ([]byte, error) {
	if cds.state == nil {
		return nil, sgxError(enclave.ErrInvalidState)
	}
	b, err := cds.state.InitialRequest()
	return b, sgxError(err)
}

func (cds *SGXClientState) CompleteHandshake(handshakeReceived []byte) error {
	if cds.state == nil {
		return sgxError(enclave.ErrInvalidState)
	}
	return sgxError(cds.state.CompleteHandshake(handshakeReceived))
}

func (cds *SGXClientState) EstablishedSend(plaintext []byte) ([]byte, error) {
	if cds.state == nil {
		return nil, sgxError(enclave.ErrInvalidState)
	}
	b, err := cds.state.EstablishedSend(plaintext)
	if err != nil {
		return nil, sgxError(err)
	}
	return b, nil
}

func (cds *SGXClientState) EstablishedReceive(ciphertext []byte) ([]byte, error) {
	if cds.state == nil {
		return nil, sgxError(enclave.ErrInvalidState)
	}
	b, err := cds.state.EstablishedRecv(ciphertext)
	if err != nil {
		return nil, sgxError(err)
	}
	return b, nil
}

// sgxError maps an attest/enclave error to the code the cgo build reports
// (libsignal v0.102.2 bridge/shared/types/src/ffi/error.rs, IntoFfiError for
// attest::enclave::Error).
func sgxError(err error) error {
	if err == nil {
		return nil
	}
	code := ErrorCodeInvalidMessage // AttestationError, NoiseHandshakeError, NoiseError
	switch {
	case errors.Is(err, enclave.ErrInvalidState):
		code = ErrorCodeInvalidState
	case errors.Is(err, enclave.ErrAttestationData):
		code = ErrorCodeInvalidAttestationData
	}
	return &SignalError{Code: code, Message: "SGX operation failed: " + err.Error()}
}
