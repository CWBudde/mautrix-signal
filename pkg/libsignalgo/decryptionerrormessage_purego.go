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

import (
	"github.com/cwbudde/libsignal-go/protocol"
)

type DecryptionErrorMessage struct {
	nc  noCopy
	msg *protocol.DecryptionErrorMessage
}

func wrapDecryptionErrorMessage(msg *protocol.DecryptionErrorMessage) *DecryptionErrorMessage {
	return &DecryptionErrorMessage{msg: msg}
}

func DeserializeDecryptionErrorMessage(messageBytes []byte) (*DecryptionErrorMessage, error) {
	msg, err := protocol.DeserializeDecryptionErrorMessage(messageBytes)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapDecryptionErrorMessage(msg), nil
}

func DecryptionErrorMessageForOriginalMessage(originalBytes []byte, originalType CiphertextMessageType, originalTs uint64, originalSenderDeviceID uint) (*DecryptionErrorMessage, error) {
	msg, err := protocol.DecryptionErrorMessageForOriginal(originalBytes, uint8(originalType), originalTs, uint32(originalSenderDeviceID))
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapDecryptionErrorMessage(msg), nil
}

func DecryptionErrorMessageFromSerializedContent(serialized []byte) (*DecryptionErrorMessage, error) {
	msg, err := protocol.ExtractDecryptionErrorMessageFromSerializedContent(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapDecryptionErrorMessage(msg), nil
}

func (dem *DecryptionErrorMessage) Clone() (*DecryptionErrorMessage, error) {
	return wrapDecryptionErrorMessage(dem.msg), nil
}

func (dem *DecryptionErrorMessage) Destroy() error {
	return nil
}

func (dem *DecryptionErrorMessage) CancelFinalizer() {}

func (dem *DecryptionErrorMessage) Serialize() ([]byte, error) {
	return dem.msg.Serialized(), nil
}

func (dem *DecryptionErrorMessage) GetTimestamp() (uint64, error) {
	return dem.msg.Timestamp(), nil
}

func (dem *DecryptionErrorMessage) GetDeviceID() (uint32, error) {
	return dem.msg.DeviceID(), nil
}

func (dem *DecryptionErrorMessage) GetRatchetKey() (*PublicKey, error) {
	key := dem.msg.RatchetKey()
	if key == nil {
		return nil, nil
	}
	return wrapPublicKey(*key), nil
}
