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
	"context"
	"crypto/rand"
	"time"

	"github.com/cwbudde/libsignal-go/protocol"
	"github.com/cwbudde/libsignal-go/session"
)

func Encrypt(ctx context.Context, plaintext []byte, forAddress, localAddress *Address, sessionStore SessionStore, identityKeyStore IdentityKeyStore) (*CiphertextMessage, error) {
	signal, preKey, err := session.MessageEncrypt(ctx, plaintext, forAddress.addr, localAddress.addr,
		sessionStoreAdapter{sessionStore}, identityStoreAdapter{identityKeyStore}, time.Now(), rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	if preKey != nil {
		return newCiphertextMessage(CiphertextMessageTypePreKey, preKey.Serialize()), nil
	}
	return newCiphertextMessage(CiphertextMessageTypeWhisper, signal.Serialize()), nil
}

func Decrypt(ctx context.Context, message *Message, fromAddress, localAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore) ([]byte, error) {
	plaintext, err := session.MessageDecryptSignal(ctx, message.msg, fromAddress.addr, localAddress.addr,
		sessionStoreAdapter{sessionStore}, identityStoreAdapter{identityStore}, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return plaintext, nil
}

type Message struct {
	nc  noCopy
	msg *protocol.SignalMessage
}

func wrapMessage(msg *protocol.SignalMessage) *Message {
	return &Message{msg: msg}
}

func DeserializeMessage(serialized []byte) (*Message, error) {
	msg, err := protocol.DeserializeSignalMessage(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapMessage(msg), nil
}

func (m *Message) Clone() (*Message, error) {
	return wrapMessage(m.msg), nil
}

func (m *Message) Destroy() error {
	return nil
}

func (m *Message) CancelFinalizer() {}

func (m *Message) GetBody() ([]byte, error) {
	return m.msg.Body(), nil
}

func (m *Message) Serialize() ([]byte, error) {
	return m.msg.Serialize(), nil
}

func (m *Message) GetMessageVersion() (uint32, error) {
	return uint32(m.msg.MessageVersion()), nil
}

func (m *Message) GetCounter() (uint32, error) {
	return m.msg.Counter(), nil
}
