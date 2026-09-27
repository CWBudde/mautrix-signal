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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

// The cross-backend test checks that state written by one backend (cgo or
// purego) keeps working with the other: records and messages from the fixture
// of each backend are loaded, decrypted and continued. The fixtures come from
// the generating half of the test:
//
//	LIBSIGNALGO_WRITE_FIXTURE=1 go test -run TestCrossBackend ./pkg/libsignalgo/                        # cgo
//	LIBSIGNALGO_WRITE_FIXTURE=1 CGO_ENABLED=0 go test -tags libsignal_go -run TestCrossBackend ./pkg/libsignalgo/

const (
	crossAliceACI       = "9d0652a3-dcc3-4d11-975f-74d61598733f"
	crossBobACI         = "6838237d-02f6-4098-b110-698253d15961"
	crossPreKeyID       = 4570
	crossSignedPreKeyID = 3006
	crossKyberPreKeyID  = 8008
)

var (
	crossDistributionID = uuid.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")
	crossPreKeyTime     = time.UnixMilli(1_700_000_000_000)
	crossCertExpiry     = time.UnixMilli(4_102_444_800_000) // 2100
)

type crossFixture struct {
	Backend string `json:"backend"`

	AliceIdentity       []byte `json:"alice_identity"`
	AliceRegistrationID uint32 `json:"alice_registration_id"`
	AliceSession        []byte `json:"alice_session"`
	BobIdentity         []byte `json:"bob_identity"`
	BobRegistrationID   uint32 `json:"bob_registration_id"`
	BobPreKey           []byte `json:"bob_pre_key"`
	BobSignedPreKey     []byte `json:"bob_signed_pre_key"`
	BobKyberPreKey      []byte `json:"bob_kyber_pre_key"`

	// Alice's first messages to Bob, pre-key messages until he answers; the
	// last one travels sealed.
	PreKeyMessages [][]byte `json:"pre_key_messages"`
	TrustRoot      []byte   `json:"trust_root"`
	Sealed         []byte   `json:"sealed"`

	SKDM         []byte `json:"skdm"`
	GroupMessage []byte `json:"group_message"`
}

func crossFixturePath(backend string) string {
	return filepath.Join("testdata", "crossbackend_"+backend+".json")
}

func crossAddress(t *testing.T, aci string, device uint) *libsignalgo.Address {
	t.Helper()
	addr, err := libsignalgo.NewUUIDAddressFromString(aci, device)
	require.NoError(t, err)
	return addr
}

func mustSerialize(t *testing.T, s interface{ Serialize() ([]byte, error) }) []byte {
	t.Helper()
	b, err := s.Serialize()
	require.NoError(t, err)
	return b
}

func TestCrossBackend(t *testing.T) {
	if os.Getenv("LIBSIGNALGO_WRITE_FIXTURE") != "" {
		writeCrossFixture(t)
	}
	for _, backend := range []string{"cgo", "purego"} {
		t.Run("from "+backend, func(t *testing.T) {
			raw, err := os.ReadFile(crossFixturePath(backend))
			require.NoError(t, err)
			var f crossFixture
			require.NoError(t, json.Unmarshal(raw, &f))
			require.Equal(t, backend, f.Backend)
			checkCrossFixture(t, &f)
		})
	}
}

// writeCrossFixture records a conversation made with this build's backend.
func writeCrossFixture(t *testing.T) {
	ctx := context.Background()
	aliceAddr := crossAddress(t, crossAliceACI, 1)
	bobAddr := crossAddress(t, crossBobACI, 1)
	alice := NewInMemorySignalProtocolStore()
	bob := NewInMemorySignalProtocolStore()

	f := crossFixture{
		Backend:             testBackend,
		AliceIdentity:       mustSerialize(t, alice.identityKeyPair),
		AliceRegistrationID: alice.registrationID,
		BobIdentity:         mustSerialize(t, bob.identityKeyPair),
		BobRegistrationID:   bob.registrationID,
	}

	// Bob's pre-keys and the bundle Alice fetches.
	preKey, err := libsignalgo.GeneratePrivateKey()
	require.NoError(t, err)
	preKeyPub, err := preKey.GetPublicKey()
	require.NoError(t, err)
	signedPreKey, err := libsignalgo.GeneratePrivateKey()
	require.NoError(t, err)
	signedPreKeyPub, err := signedPreKey.GetPublicKey()
	require.NoError(t, err)
	signedSig, err := bob.identityKeyPair.GetPrivateKey().Sign(mustSerialize(t, signedPreKeyPub))
	require.NoError(t, err)
	kyber, err := libsignalgo.KyberKeyPairGenerate()
	require.NoError(t, err)
	kyberPub, err := kyber.GetPublicKey()
	require.NoError(t, err)
	kyberSig, err := bob.identityKeyPair.GetPrivateKey().Sign(mustSerialize(t, kyberPub))
	require.NoError(t, err)

	preKeyRecord, err := libsignalgo.NewPreKeyRecordFromPrivateKey(crossPreKeyID, preKey)
	require.NoError(t, err)
	signedRecord, err := libsignalgo.NewSignedPreKeyRecordFromPrivateKey(crossSignedPreKeyID, crossPreKeyTime, signedPreKey, signedSig)
	require.NoError(t, err)
	kyberRecord, err := libsignalgo.NewKyberPreKeyRecord(crossKyberPreKeyID, crossPreKeyTime, kyber, kyberSig)
	require.NoError(t, err)
	f.BobPreKey = mustSerialize(t, preKeyRecord)
	f.BobSignedPreKey = mustSerialize(t, signedRecord)
	f.BobKyberPreKey = mustSerialize(t, kyberRecord)

	bundle, err := libsignalgo.NewPreKeyBundle(bob.registrationID, 1, crossPreKeyID, preKeyPub,
		crossSignedPreKeyID, signedPreKeyPub, signedSig, crossKyberPreKeyID, kyberPub, kyberSig,
		bob.identityKeyPair.GetIdentityKey())
	require.NoError(t, err)
	require.NoError(t, libsignalgo.ProcessPreKeyBundle(ctx, bundle, bobAddr, aliceAddr, alice, alice))

	for _, text := range []string{"one", "two"} {
		msg, err := libsignalgo.Encrypt(ctx, []byte(text), bobAddr, aliceAddr, alice, alice)
		require.NoError(t, err)
		msgType, err := msg.MessageType()
		require.NoError(t, err)
		require.Equal(t, libsignalgo.CiphertextMessageTypePreKey, msgType)
		f.PreKeyMessages = append(f.PreKeyMessages, mustSerialize(t, msg))
	}

	// The last message travels sealed.
	trustRoot, err := libsignalgo.GenerateIdentityKeyPair()
	require.NoError(t, err)
	server, err := libsignalgo.GenerateIdentityKeyPair()
	require.NoError(t, err)
	serverCert, err := libsignalgo.NewServerCertificate(1, server.GetPublicKey(), trustRoot.GetPrivateKey())
	require.NoError(t, err)
	senderCert, err := libsignalgo.NewSenderCertificate(
		libsignalgo.NewSealedSenderAddress("+14151111111", uuid.MustParse(crossAliceACI), 1),
		alice.identityKeyPair.GetPublicKey(), crossCertExpiry, serverCert, server.GetPrivateKey())
	require.NoError(t, err)
	f.TrustRoot = mustSerialize(t, trustRoot.GetPublicKey())
	sealedMsg, err := libsignalgo.Encrypt(ctx, []byte("sealed"), bobAddr, aliceAddr, alice, alice)
	require.NoError(t, err)
	usmc, err := libsignalgo.NewUnidentifiedSenderMessageContent(sealedMsg, senderCert,
		libsignalgo.UnidentifiedSenderMessageContentHintResendable, nil)
	require.NoError(t, err)
	f.Sealed, err = libsignalgo.SealedSenderEncrypt(ctx, usmc, bobAddr, alice)
	require.NoError(t, err)

	aliceSession, err := alice.LoadSession(ctx, bobAddr)
	require.NoError(t, err)
	f.AliceSession = mustSerialize(t, aliceSession)

	skdm, err := libsignalgo.NewSenderKeyDistributionMessage(ctx, aliceAddr, crossDistributionID, alice)
	require.NoError(t, err)
	f.SKDM = mustSerialize(t, skdm)
	groupMsg, err := libsignalgo.GroupEncrypt(ctx, []byte("group"), aliceAddr, crossDistributionID, alice)
	require.NoError(t, err)
	f.GroupMessage = mustSerialize(t, groupMsg)

	raw, err := json.MarshalIndent(&f, "", "\t")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(crossFixturePath(testBackend), append(raw, '\n'), 0o644))
}

// checkCrossFixture continues the recorded conversation with this build's
// backend.
func checkCrossFixture(t *testing.T, f *crossFixture) {
	ctx := context.Background()
	aliceAddr := crossAddress(t, crossAliceACI, 1)
	bobAddr := crossAddress(t, crossBobACI, 1)

	// Every stored record loads and serializes back to the same bytes, so a
	// database written by either backend reads and writes the same.
	bob := NewInMemorySignalProtocolStore()
	var err error
	bob.identityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(f.BobIdentity)
	require.NoError(t, err)
	require.Equal(t, f.BobIdentity, mustSerialize(t, bob.identityKeyPair))
	bob.registrationID = f.BobRegistrationID
	preKey, err := libsignalgo.DeserializePreKeyRecord(f.BobPreKey)
	require.NoError(t, err)
	require.Equal(t, f.BobPreKey, mustSerialize(t, preKey))
	require.NoError(t, bob.StorePreKey(ctx, crossPreKeyID, preKey))
	signed, err := libsignalgo.DeserializeSignedPreKeyRecord(f.BobSignedPreKey)
	require.NoError(t, err)
	require.Equal(t, f.BobSignedPreKey, mustSerialize(t, signed))
	ts, err := signed.GetTimestamp()
	require.NoError(t, err)
	require.True(t, ts.Equal(crossPreKeyTime))
	require.NoError(t, bob.StoreSignedPreKey(ctx, crossSignedPreKeyID, signed))
	kyber, err := libsignalgo.DeserializeKyberPreKeyRecord(f.BobKyberPreKey)
	require.NoError(t, err)
	require.Equal(t, f.BobKyberPreKey, mustSerialize(t, kyber))
	require.NoError(t, bob.StoreKyberPreKey(ctx, crossKyberPreKeyID, kyber))

	decryptPreKey := func(serialized []byte, want string) {
		t.Helper()
		msg, err := libsignalgo.DeserializePreKeyMessage(serialized)
		require.NoError(t, err)
		plain, err := libsignalgo.DecryptPreKey(ctx, msg, aliceAddr, bobAddr, bob, bob, bob, bob, bob)
		require.NoError(t, err)
		require.Equal(t, want, string(plain))
	}
	// Out of order: both belong to the one session.
	decryptPreKey(f.PreKeyMessages[1], "two")
	decryptPreKey(f.PreKeyMessages[0], "one")

	usmc, err := libsignalgo.SealedSenderDecryptToUSMC(ctx, f.Sealed, bob)
	require.NoError(t, err)
	cert, err := usmc.GetSenderCertificate()
	require.NoError(t, err)
	sender, err := cert.GetSenderUUID()
	require.NoError(t, err)
	require.Equal(t, crossAliceACI, sender.String())
	trustRoot, err := libsignalgo.DeserializePublicKey(f.TrustRoot)
	require.NoError(t, err)
	valid, err := cert.Validate([]*libsignalgo.PublicKey{trustRoot}, crossPreKeyTime)
	require.NoError(t, err)
	require.True(t, valid)
	hint, err := usmc.GetContentHint()
	require.NoError(t, err)
	require.Equal(t, libsignalgo.UnidentifiedSenderMessageContentHintResendable, hint)
	contents, err := usmc.GetContents()
	require.NoError(t, err)
	decryptPreKey(contents, "sealed")

	// Alice continues from her stored session.
	alice := NewInMemorySignalProtocolStore()
	alice.identityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(f.AliceIdentity)
	require.NoError(t, err)
	alice.registrationID = f.AliceRegistrationID
	aliceSession, err := libsignalgo.DeserializeSessionRecord(f.AliceSession)
	require.NoError(t, err)
	require.Equal(t, f.AliceSession, mustSerialize(t, aliceSession))
	require.NoError(t, alice.StoreSession(ctx, bobAddr, aliceSession))

	reply, err := libsignalgo.Encrypt(ctx, []byte("reply"), aliceAddr, bobAddr, bob, bob)
	require.NoError(t, err)
	replyType, err := reply.MessageType()
	require.NoError(t, err)
	require.Equal(t, libsignalgo.CiphertextMessageTypeWhisper, replyType)
	replyMsg, err := libsignalgo.DeserializeMessage(mustSerialize(t, reply))
	require.NoError(t, err)
	plain, err := libsignalgo.Decrypt(ctx, replyMsg, bobAddr, aliceAddr, alice, alice)
	require.NoError(t, err)
	require.Equal(t, "reply", string(plain))

	next, err := libsignalgo.Encrypt(ctx, []byte("acknowledged"), bobAddr, aliceAddr, alice, alice)
	require.NoError(t, err)
	nextType, err := next.MessageType()
	require.NoError(t, err)
	require.Equal(t, libsignalgo.CiphertextMessageTypeWhisper, nextType, "Alice's session should be acknowledged")
	nextMsg, err := libsignalgo.DeserializeMessage(mustSerialize(t, next))
	require.NoError(t, err)
	plain, err = libsignalgo.Decrypt(ctx, nextMsg, aliceAddr, bobAddr, bob, bob)
	require.NoError(t, err)
	require.Equal(t, "acknowledged", string(plain))

	skdm, err := libsignalgo.DeserializeSenderKeyDistributionMessage(f.SKDM)
	require.NoError(t, err)
	require.NoError(t, libsignalgo.ProcessSenderKeyDistributionMessage(ctx, skdm, aliceAddr, bob))
	plain, err = libsignalgo.GroupDecrypt(ctx, f.GroupMessage, aliceAddr, bob)
	require.NoError(t, err)
	require.Equal(t, "group", string(plain))
	senderKey, err := bob.LoadSenderKey(ctx, aliceAddr, crossDistributionID)
	require.NoError(t, err)
	roundTrip, err := libsignalgo.DeserializeSenderKeyRecord(mustSerialize(t, senderKey))
	require.NoError(t, err)
	require.Equal(t, mustSerialize(t, senderKey), mustSerialize(t, roundTrip), fmt.Sprintf("sender key record from %s", f.Backend))
}
