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

type PreKeyMessage struct {
	nc  noCopy
	msg *protocol.PreKeySignalMessage
}

func DeserializePreKeyMessage(serialized []byte) (*PreKeyMessage, error) {
	msg, err := protocol.DeserializePreKeySignalMessage(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return &PreKeyMessage{msg: msg}, nil
}

func (m *PreKeyMessage) Clone() (*PreKeyMessage, error) {
	return &PreKeyMessage{msg: m.msg}, nil
}

func (m *PreKeyMessage) Destroy() error {
	return nil
}

func (m *PreKeyMessage) CancelFinalizer() {}

func (m *PreKeyMessage) Serialize() ([]byte, error) {
	return m.msg.Serialize(), nil
}

func (m *PreKeyMessage) GetVersion() (uint32, error) {
	return uint32(m.msg.MessageVersion()), nil
}

func (m *PreKeyMessage) GetRegistrationID() (uint32, error) {
	return m.msg.RegistrationID(), nil
}

func (m *PreKeyMessage) GetPreKeyID() (*uint32, error) {
	return m.msg.PreKeyID(), nil
}

func (m *PreKeyMessage) GetSignedPreKeyID() (uint32, error) {
	return m.msg.SignedPreKeyID(), nil
}

func (m *PreKeyMessage) GetBaseKey() (*PublicKey, error) {
	return wrapPublicKey(m.msg.BaseKey()), nil
}

func (m *PreKeyMessage) GetIdentityKey() (*IdentityKey, error) {
	return &IdentityKey{wrapPublicKey(m.msg.IdentityKey())}, nil
}

func (m *PreKeyMessage) GetSignalMessage() (*Message, error) {
	return wrapMessage(m.msg.Message()), nil
}
