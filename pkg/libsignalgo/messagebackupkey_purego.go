//go:build libsignal_go

// mautrix-signal - A Matrix-signal puppeting bridge.
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
	"github.com/cwbudde/libsignal-go/accountkeys"
)

type MessageBackupKey struct {
	nc      noCopy
	hmacKey [MessageBackupKeyBytesLength]byte
	aesKey  [MessageBackupKeyBytesLength]byte
}

const MessageBackupKeyBytesLength = 32

type messageBackupKeyBytes = fixedArray32

func MessageBackupKeyFromAccountEntropyPool(aep AccountEntropyPool, aci ServiceID) (*MessageBackupKey, error) {
	pool, err := aep.parse()
	if err != nil {
		return nil, err
	}
	backupKey := BackupKey(accountkeys.DeriveBackupKey(pool))
	backupID, err := backupKey.DeriveBackupID(aci)
	if err != nil {
		return nil, err
	}
	return MessageBackupKeyFromBackupKeyAndID(&backupKey, backupID)
}

func MessageBackupKeyFromBackupKeyAndID(backupKey *BackupKey, backupID *BackupID) (*MessageBackupKey, error) {
	hmacKey, aesKey := backupKey.key().DeriveMessageBackupKey(accountkeys.BackupID(*backupID))
	return &MessageBackupKey{hmacKey: hmacKey, aesKey: aesKey}, nil
}

func (bk *MessageBackupKey) Destroy() error {
	return nil
}

func (bk *MessageBackupKey) GetHMACKey() ([MessageBackupKeyBytesLength]byte, error) {
	return bk.hmacKey, nil
}

func (bk *MessageBackupKey) GetAESKey() ([MessageBackupKeyBytesLength]byte, error) {
	return bk.aesKey, nil
}
