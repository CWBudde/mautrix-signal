//go:build purego

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
	"go.mau.fi/util/random"

	"github.com/cwbudde/libsignal-go/accountkeys"
	"github.com/cwbudde/libsignal-go/address"
)

const BackupKeyLength = 32

type BackupKey [BackupKeyLength]byte

func (bk *BackupKey) Slice() []byte {
	if bk == nil {
		return nil
	}
	return bk[:]
}

const BackupIDLength = 16

type BackupID = fixedArray16
type BackupMetadataKey = fixedArray32
type BackupMediaID = fixedArray15
type BackupMediaKey = fixedArray64

func GenerateRandomBackupKey() *BackupKey {
	return (*BackupKey)(random.Bytes(BackupKeyLength))
}

func BytesToBackupKey(bytes []byte) *BackupKey {
	if len(bytes) != BackupKeyLength {
		return nil
	}
	return (*BackupKey)(bytes)
}

func (bk *BackupKey) key() accountkeys.BackupKey {
	return accountkeys.BackupKey(*bk)
}

// aciOf converts an ACI to libsignal-go's service ID; the backup derivations
// take only ACIs.
func aciOf(aci ServiceID) (address.ServiceID, error) {
	if aci.Type != ServiceIDTypeACI {
		return address.ServiceID{}, errInvalidArgument("expected an ACI, got %s", aci)
	}
	return address.NewACI(aci.UUID), nil
}

func (bk *BackupKey) DeriveBackupID(aci ServiceID) (*BackupID, error) {
	id, err := aciOf(aci)
	if err != nil {
		return nil, err
	}
	out := BackupID(bk.key().DeriveBackupID(id))
	return &out, nil
}

func (bk *BackupKey) DeriveECKey(aci ServiceID) (*PrivateKey, error) {
	id, err := aciOf(aci)
	if err != nil {
		return nil, err
	}
	key, err := bk.key().DeriveECKey(id)
	if err != nil {
		return nil, wrapError(err)
	}
	return wrapPrivateKey(key), nil
}

func (bk *BackupKey) DeriveLocalBackupMetadataKey() (*BackupMetadataKey, error) {
	out := BackupMetadataKey(bk.key().DeriveLocalBackupMetadataKey())
	return &out, nil
}

func (bk *BackupKey) DeriveMediaID(mediaName string) (*BackupMediaID, error) {
	out := BackupMediaID(bk.key().DeriveMediaID(mediaName))
	return &out, nil
}

func (bk *BackupKey) DeriveMediaEncryptionKey(mediaID *BackupMediaID) (*BackupMediaKey, error) {
	out := BackupMediaKey(bk.key().DeriveMediaEncryptionKeyData(*mediaID))
	return &out, nil
}

func (bk *BackupKey) DeriveThumbnailTransitEncryptionKey(mediaID *BackupMediaID) (*BackupMediaKey, error) {
	out := BackupMediaKey(bk.key().DeriveThumbnailTransitEncryptionKeyData(*mediaID))
	return &out, nil
}
