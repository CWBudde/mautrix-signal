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

type CiphertextMessageType uint8

const (
	CiphertextMessageTypeWhisper   CiphertextMessageType = 2
	CiphertextMessageTypePreKey    CiphertextMessageType = 3
	CiphertextMessageTypeSenderKey CiphertextMessageType = 7
	CiphertextMessageTypePlaintext CiphertextMessageType = 8
)

// CiphertextMessage keeps the type and wire form of a message, which is all
// that callers and sealed sender need from it.
type CiphertextMessage struct {
	nc         noCopy
	msgType    CiphertextMessageType
	serialized []byte
}

func newCiphertextMessage(msgType CiphertextMessageType, serialized []byte) *CiphertextMessage {
	return &CiphertextMessage{msgType: msgType, serialized: serialized}
}

func NewCiphertextMessage(plaintext *PlaintextContent) (*CiphertextMessage, error) {
	return newCiphertextMessage(CiphertextMessageTypePlaintext, plaintext.content.Serialized()), nil
}

func (c *CiphertextMessage) Destroy() error {
	return nil
}

func (c *CiphertextMessage) CancelFinalizer() {}

func (c *CiphertextMessage) Serialize() ([]byte, error) {
	return append([]byte(nil), c.serialized...), nil
}

func (c *CiphertextMessage) MessageType() (CiphertextMessageType, error) {
	return c.msgType, nil
}
