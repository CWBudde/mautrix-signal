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
	"github.com/cwbudde/libsignal-go/protocol"
)

type PlaintextContent struct {
	nc      noCopy
	content *protocol.PlaintextContent
}

func PlaintextContentFromDecryptionErrorMessage(message *DecryptionErrorMessage) (*PlaintextContent, error) {
	content, err := protocol.NewPlaintextContentFromDecryptionError(message.msg)
	if err != nil {
		return nil, wrapError(err)
	}
	return &PlaintextContent{content: content}, nil
}

func DeserializePlaintextContent(plaintextContentBytes []byte) (*PlaintextContent, error) {
	content, err := protocol.DeserializePlaintextContent(plaintextContentBytes)
	if err != nil {
		return nil, wrapError(err)
	}
	return &PlaintextContent{content: content}, nil
}

func (pc *PlaintextContent) Clone() (*PlaintextContent, error) {
	return &PlaintextContent{content: pc.content}, nil
}

func (pc *PlaintextContent) Destroy() error {
	return nil
}

func (pc *PlaintextContent) CancelFinalizer() {}

func (pc *PlaintextContent) Serialize() ([]byte, error) {
	return pc.content.Serialized(), nil
}

func (pc *PlaintextContent) GetBody() ([]byte, error) {
	return pc.content.Body(), nil
}
