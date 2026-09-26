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
	"errors"

	"github.com/cwbudde/libsignal-go/attest/hsmenclave"
)

// HSMEnclaveClient is the bridge's HsmEnclaveClient on libsignal-go's
// attest/hsmenclave. A nil client means InvalidConnectionState: destroyed,
// or after a failed or repeated CompleteHandshake.
type HSMEnclaveClient struct {
	nc     noCopy
	client *hsmenclave.Client
}

// hsmErrorCodes maps attest/hsmenclave's errors to the codes of
// IntoFfiError for HsmEnclaveError (rust/bridge/shared/types/src/ffi/error.rs).
var hsmErrorCodes = []struct {
	err  error
	code ErrorCode
}{
	{hsmenclave.ErrCommunication, ErrorCodeInvalidMessage},
	{hsmenclave.ErrHandshake, ErrorCodeInvalidMessage},
	{hsmenclave.ErrTrustedCode, ErrorCodeUntrustedIdentity},
	{hsmenclave.ErrInvalidPublicKey, ErrorCodeInvalidKey},
	{hsmenclave.ErrInvalidCodeHash, ErrorCodeInvalidArgument},
	{hsmenclave.ErrInvalidState, ErrorCodeInvalidState},
}

func hsmError(err error) error {
	if err == nil {
		return nil
	}
	for _, e := range hsmErrorCodes {
		if errors.Is(err, e.err) {
			return &SignalError{Code: e.code, Message: "HSM enclave operation failed: " + err.Error()}
		}
	}
	return &SignalError{Code: ErrorCodeUnknownError, Message: "HSM enclave operation failed: " + err.Error()}
}

func NewHSMEnclaveClient(trustedPublicKey, trustedCodeHashes []byte) (*HSMEnclaveClient, error) {
	client, err := hsmenclave.NewClient(trustedPublicKey, trustedCodeHashes)
	if err != nil {
		return nil, hsmError(err)
	}
	return &HSMEnclaveClient{client: client}, nil
}

// Destroy drops the client's state; later calls fail with InvalidState.
func (hsm *HSMEnclaveClient) Destroy() error {
	hsm.client = nil
	return nil
}

func (hsm *HSMEnclaveClient) InitialRequest() ([]byte, error) {
	if hsm.client == nil {
		return nil, hsmError(hsmenclave.ErrInvalidState)
	}
	req, err := hsm.client.InitialRequest()
	return req, hsmError(err)
}

// CompleteHandshake finishes the handshake. Like upstream's, which replaces
// the state before checking it, any call that fails leaves the client
// unusable, including one on an established connection.
func (hsm *HSMEnclaveClient) CompleteHandshake(handshakeReceived []byte) error {
	client := hsm.client
	if client == nil {
		return hsmError(hsmenclave.ErrInvalidState)
	}
	if err := client.CompleteHandshake(handshakeReceived); err != nil {
		hsm.client = nil
		return hsmError(err)
	}
	return nil
}

func (hsm *HSMEnclaveClient) EstablishedSend(plaintext []byte) ([]byte, error) {
	if hsm.client == nil {
		return nil, hsmError(hsmenclave.ErrInvalidState)
	}
	ct, err := hsm.client.EstablishedSend(plaintext)
	return ct, hsmError(err)
}

func (hsm *HSMEnclaveClient) EstablishedReceive(ciphertext []byte) ([]byte, error) {
	if hsm.client == nil {
		return nil, hsmError(hsmenclave.ErrInvalidState)
	}
	pt, err := hsm.client.EstablishedRecv(ciphertext)
	return pt, hsmError(err)
}
