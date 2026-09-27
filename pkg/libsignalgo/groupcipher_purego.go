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
)

func GroupEncrypt(ctx context.Context, ptext []byte, sender *Address, distributionID uuid.UUID, store SenderKeyStore) (*CiphertextMessage, error) {
	msg, err := groups.Encrypt(ctx, sender.addr, distributionID, ptext, senderKeyStoreAdapter{store}, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return newCiphertextMessage(CiphertextMessageTypeSenderKey, msg.Serialized()), nil
}

func GroupDecrypt(ctx context.Context, ctext []byte, sender *Address, store SenderKeyStore) ([]byte, error) {
	plaintext, err := groups.Decrypt(ctx, sender.addr, ctext, senderKeyStoreAdapter{store})
	if err != nil {
		return nil, wrapError(err)
	}
	return plaintext, nil
}
