// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2026 Christian Budde
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

package libsignalgo_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

// The derivations test holds the deterministic helpers (account entropy pool,
// backup keys, access keys, decryption error messages) to known answers that
// the cgo build recorded:
//
//	LIBSIGNALGO_WRITE_FIXTURE=1 go test -run TestDerivations ./pkg/libsignalgo/   # cgo
//
// Both builds then have to reproduce every value byte for byte.

const (
	derivAEP        = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"
	derivMediaName  = "media-name"
	derivDEMTime    = 1_700_000_000_123
	derivDEMDevice  = 2
	derivFixtureKey = "cgo"
)

var derivACI = libsignalgo.NewACIServiceID(uuid.MustParse(crossAliceACI))

func derivFixturePath() string {
	return filepath.Join("testdata", "derivations_"+derivFixtureKey+".json")
}

func TestDerivations(t *testing.T) {
	got := computeDerivations(t)
	if os.Getenv("LIBSIGNALGO_WRITE_FIXTURE") != "" {
		require.Equal(t, derivFixtureKey, testBackend, "the known answers come from the cgo build")
		raw, err := json.MarshalIndent(got, "", "\t")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(derivFixturePath(), append(raw, '\n'), 0o644))
	}

	raw, err := os.ReadFile(derivFixturePath())
	require.NoError(t, err)
	var want map[string][]byte
	require.NoError(t, json.Unmarshal(raw, &want))
	require.Equal(t, sortedKeys(want), sortedKeys(got))
	for _, name := range sortedKeys(want) {
		require.Equal(t, want[name], got[name], name)
	}
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func computeDerivations(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	deriveBackupKeys(t, out)
	deriveAccessKeys(t, out)
	deriveDecryptionErrors(t, out)
	return out
}

func deriveBackupKeys(t *testing.T, out map[string][]byte) {
	t.Helper()
	aep := libsignalgo.AccountEntropyPool(derivAEP)
	svrKey, err := aep.DeriveSVRKey()
	require.NoError(t, err)
	out["aep_svr_key"] = svrKey
	backupKeyBytes, err := aep.DeriveBackupKey()
	require.NoError(t, err)
	out["aep_backup_key"] = backupKeyBytes

	fromAEP, err := libsignalgo.MessageBackupKeyFromAccountEntropyPool(aep, derivACI)
	require.NoError(t, err)
	hmacKey, err := fromAEP.GetHMACKey()
	require.NoError(t, err)
	aesKey, err := fromAEP.GetAESKey()
	require.NoError(t, err)
	out["message_backup_key_aep_hmac"] = hmacKey[:]
	out["message_backup_key_aep_aes"] = aesKey[:]

	backupKey := libsignalgo.BytesToBackupKey(backupKeyBytes)
	require.NotNil(t, backupKey)
	backupID, err := backupKey.DeriveBackupID(derivACI)
	require.NoError(t, err)
	out["backup_id"] = backupID[:]
	ecKey, err := backupKey.DeriveECKey(derivACI)
	require.NoError(t, err)
	ecPub, err := ecKey.GetPublicKey()
	require.NoError(t, err)
	out["backup_ec_public_key"] = mustSerialize(t, ecPub)
	metadataKey, err := backupKey.DeriveLocalBackupMetadataKey()
	require.NoError(t, err)
	out["backup_local_metadata_key"] = metadataKey[:]
	mediaID, err := backupKey.DeriveMediaID(derivMediaName)
	require.NoError(t, err)
	out["backup_media_id"] = mediaID[:]
	mediaKey, err := backupKey.DeriveMediaEncryptionKey(mediaID)
	require.NoError(t, err)
	out["backup_media_key"] = mediaKey[:]
	thumbKey, err := backupKey.DeriveThumbnailTransitEncryptionKey(mediaID)
	require.NoError(t, err)
	out["backup_thumbnail_key"] = thumbKey[:]

	fromKeyAndID, err := libsignalgo.MessageBackupKeyFromBackupKeyAndID(backupKey, backupID)
	require.NoError(t, err)
	hmacKey, err = fromKeyAndID.GetHMACKey()
	require.NoError(t, err)
	aesKey, err = fromKeyAndID.GetAESKey()
	require.NoError(t, err)
	out["message_backup_key_id_hmac"] = hmacKey[:]
	out["message_backup_key_id_aes"] = aesKey[:]
}

func deriveAccessKeys(t *testing.T, out map[string][]byte) {
	t.Helper()
	profileKeyBytes := make([]byte, libsignalgo.ProfileKeyLength)
	for i := range profileKeyBytes {
		profileKeyBytes[i] = byte(0xa0 + i)
	}
	profileKey, err := libsignalgo.DeserializeProfileKey(profileKeyBytes)
	require.NoError(t, err)
	require.Equal(t, profileKeyBytes, profileKey.Slice())
	accessKey, err := profileKey.DeriveAccessKey()
	require.NoError(t, err)
	out["access_key"] = accessKey[:]

	var other libsignalgo.AccessKey
	for i := range other {
		other[i] = byte(i * 17)
	}
	out["access_key_xor"] = accessKey.Xor(&other)[:]
}

func deriveDecryptionErrors(t *testing.T, out map[string][]byte) {
	t.Helper()
	// A pre-key message recorded by the cgo build, so the ratchet key the
	// DEM picks out of it is fixed too.
	raw, err := os.ReadFile(crossFixturePath("cgo"))
	require.NoError(t, err)
	var cross crossFixture
	require.NoError(t, json.Unmarshal(raw, &cross))
	require.NotEmpty(t, cross.PreKeyMessages)

	dem, err := libsignalgo.DecryptionErrorMessageForOriginalMessage(cross.PreKeyMessages[0],
		libsignalgo.CiphertextMessageTypePreKey, derivDEMTime, derivDEMDevice)
	require.NoError(t, err)
	demBytes := mustSerialize(t, dem)
	out["dem"] = demBytes
	timestamp, err := dem.GetTimestamp()
	require.NoError(t, err)
	require.EqualValues(t, derivDEMTime, timestamp)
	deviceID, err := dem.GetDeviceID()
	require.NoError(t, err)
	require.EqualValues(t, derivDEMDevice, deviceID)
	ratchetKey, err := dem.GetRatchetKey()
	require.NoError(t, err)
	require.NotNil(t, ratchetKey)
	out["dem_ratchet_key"] = mustSerialize(t, ratchetKey)

	parsed, err := libsignalgo.DeserializeDecryptionErrorMessage(demBytes)
	require.NoError(t, err)
	require.Equal(t, demBytes, mustSerialize(t, parsed))
	cloned, err := dem.Clone()
	require.NoError(t, err)
	require.Equal(t, demBytes, mustSerialize(t, cloned))

	content, err := libsignalgo.PlaintextContentFromDecryptionErrorMessage(dem)
	require.NoError(t, err)
	contentBytes := mustSerialize(t, content)
	out["plaintext_content"] = contentBytes
	body, err := content.GetBody()
	require.NoError(t, err)
	out["plaintext_content_body"] = body

	parsedContent, err := libsignalgo.DeserializePlaintextContent(contentBytes)
	require.NoError(t, err)
	require.Equal(t, contentBytes, mustSerialize(t, parsedContent))
	clonedContent, err := content.Clone()
	require.NoError(t, err)
	require.Equal(t, contentBytes, mustSerialize(t, clonedContent))

	extracted, err := libsignalgo.DecryptionErrorMessageFromSerializedContent(body)
	require.NoError(t, err)
	require.Equal(t, demBytes, mustSerialize(t, extracted))
}
