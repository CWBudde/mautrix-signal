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
	"context"
	"crypto/rand"

	"github.com/google/uuid"

	"github.com/cwbudde/libsignal-go/groups"
	"github.com/cwbudde/libsignal-go/protocol"
)

func ProcessSenderKeyDistributionMessage(ctx context.Context, message *SenderKeyDistributionMessage, fromSender *Address, store SenderKeyStore) error {
	return wrapError(groups.ProcessSenderKeyDistributionMessage(ctx, fromSender.addr, message.msg, senderKeyStoreAdapter{store}))
}

type SenderKeyDistributionMessage struct {
	nc  noCopy
	msg *protocol.SenderKeyDistributionMessage
}

func NewSenderKeyDistributionMessage(ctx context.Context, sender *Address, distributionID uuid.UUID, store SenderKeyStore) (*SenderKeyDistributionMessage, error) {
	msg, err := groups.CreateSenderKeyDistributionMessage(ctx, sender.addr, distributionID, senderKeyStoreAdapter{store}, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return &SenderKeyDistributionMessage{msg: msg}, nil
}

func DeserializeSenderKeyDistributionMessage(serialized []byte) (*SenderKeyDistributionMessage, error) {
	msg, err := protocol.DeserializeSenderKeyDistributionMessage(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return &SenderKeyDistributionMessage{msg: msg}, nil
}

func (sc *SenderKeyDistributionMessage) Destroy() error {
	return nil
}

func (sc *SenderKeyDistributionMessage) CancelFinalizer() {}

func (sc *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	return sc.msg.Serialized(), nil
}

func (sc *SenderKeyDistributionMessage) Process(ctx context.Context, sender *Address, store SenderKeyStore) error {
	return ProcessSenderKeyDistributionMessage(ctx, sc, sender, store)
}
