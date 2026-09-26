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
	"github.com/cwbudde/libsignal-go/aes256gcmsiv"
)

type AES256_GCM_SIV struct {
	nc     noCopy
	cipher *aes256gcmsiv.Cipher
}

func NewAES256_GCM_SIV(key []byte) (*AES256_GCM_SIV, error) {
	c, err := aes256gcmsiv.New(key)
	if err != nil {
		return nil, &SignalError{Code: ErrorCodeInvalidArgument, Message: err.Error()}
	}
	return &AES256_GCM_SIV{cipher: c}, nil
}

func (aes *AES256_GCM_SIV) Destroy() error {
	return nil
}

func (aes *AES256_GCM_SIV) Encrypt(plaintext, nonce, associatedData []byte) ([]byte, error) {
	out, err := aes.cipher.Encrypt(plaintext, nonce, associatedData)
	if err != nil {
		return nil, &SignalError{Code: ErrorCodeInvalidArgument, Message: err.Error()}
	}
	return out, nil
}

func (aes *AES256_GCM_SIV) Decrypt(ciphertext, nonce, associatedData []byte) ([]byte, error) {
	out, err := aes.cipher.Decrypt(ciphertext, nonce, associatedData)
	if err != nil {
		return nil, &SignalError{Code: ErrorCodeInvalidMessage, Message: err.Error()}
	}
	return out, nil
}
