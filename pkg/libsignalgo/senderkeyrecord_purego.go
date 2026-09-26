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
	"github.com/cwbudde/libsignal-go/groups"
)

type SenderKeyRecord struct {
	nc     noCopy
	record *groups.SenderKeyRecord
}

func DeserializeSenderKeyRecord(serialized []byte) (*SenderKeyRecord, error) {
	record, err := groups.DeserializeSenderKeyRecord(serialized)
	if err != nil {
		return nil, &SignalError{Code: ErrorCodeInvalidSenderKeySession, Message: err.Error()}
	}
	return &SenderKeyRecord{record: record}, nil
}

func (skr *SenderKeyRecord) Serialize() ([]byte, error) {
	serialized, err := skr.record.Serialize()
	return serialized, wrapError(err)
}

func (skr *SenderKeyRecord) Clone() (*SenderKeyRecord, error) {
	serialized, err := skr.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializeSenderKeyRecord(serialized)
}

func (skr *SenderKeyRecord) Destroy() error {
	return nil
}

func (skr *SenderKeyRecord) CancelFinalizer() {}
