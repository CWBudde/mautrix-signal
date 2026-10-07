// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

var errTrustRead = errors.New("identity store unavailable")
var errStopDistribution = errors.New("stop before distribution transport")

type senderTrustStore struct {
	libsignalgo.IdentityKeyStore
	key              *libsignalgo.IdentityKey
	trusted          bool
	getErr, trustErr error
	checked          []libsignalgo.ServiceID
	blocked          libsignalgo.ServiceID
	pair             *libsignalgo.IdentityKeyPair
}

func (s *senderTrustStore) GetIdentityKeyPair(context.Context) (*libsignalgo.IdentityKeyPair, error) {
	return s.pair, nil
}
func (s *senderTrustStore) GetLocalRegistrationID(context.Context) (uint32, error) { return 42, nil }
func (s *senderTrustStore) SaveIdentityKey(context.Context, libsignalgo.ServiceID, *libsignalgo.IdentityKey) (bool, error) {
	return false, nil
}

func (s *senderTrustStore) GetIdentityKey(context.Context, libsignalgo.ServiceID) (*libsignalgo.IdentityKey, error) {
	return s.key, s.getErr
}

func (s *senderTrustStore) IsTrustedIdentity(_ context.Context, id libsignalgo.ServiceID, key *libsignalgo.IdentityKey, direction libsignalgo.SignalDirection) (bool, error) {
	equal, err := key.Equal(s.key)
	if err != nil || !equal || direction != libsignalgo.SignalDirectionSending {
		return false, errors.New("wrong identity or direction")
	}
	s.checked = append(s.checked, id)
	return s.trusted && id != s.blocked, s.trustErr
}

type senderProfiles struct{ store.RecipientStore }

func (senderProfiles) LoadProfileKey(context.Context, uuid.UUID) (*libsignalgo.ProfileKey, error) {
	key := libsignalgo.ProfileKey{42}
	return &key, nil
}

type senderSessions struct {
	store.SessionStore
	record *libsignalgo.SessionRecord
}

func (s *senderSessions) LoadSession(context.Context, *libsignalgo.Address) (*libsignalgo.SessionRecord, error) {
	return s.record, nil
}
func (s *senderSessions) StoreSession(_ context.Context, _ *libsignalgo.Address, record *libsignalgo.SessionRecord) error {
	s.record = record
	return nil
}
func (senderSessions) AllSessionsForServiceID(_ context.Context, id libsignalgo.ServiceID) ([]store.SessionAddressTuple, error) {
	return []store.SessionAddressTuple{{ServiceID: id, DeviceID: 1}}, nil
}

func senderTrustClient(t *testing.T, identities *senderTrustStore) (*signalmeow.Client, libsignalgo.ServiceID, signalmeow.SendEndorsementCache) {
	t.Helper()
	pair, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identities.key = pair.GetIdentityKey()
	peer := libsignalgo.NewACIServiceID(uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	cli := &signalmeow.Client{Store: &store.Device{
		DeviceData:       store.DeviceData{ACI: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), DeviceID: 1},
		ACIIdentityStore: identities, ACISessionStore: &senderSessions{}, RecipientStore: senderProfiles{},
	}}
	sec := signalmeow.SendEndorsementCache{MemberEndorsements: map[libsignalgo.ServiceID]libsignalgo.GroupSendEndorsement{peer: nil}}
	return cli, peer, sec
}

type encryptionSenderStore struct {
	store.SenderKeyStore
	record *libsignalgo.SenderKeyRecord
}

func (s *encryptionSenderStore) LoadSenderKey(context.Context, *libsignalgo.Address, uuid.UUID) (*libsignalgo.SenderKeyRecord, error) {
	return s.record, nil
}
func (s *encryptionSenderStore) StoreSenderKey(_ context.Context, _ *libsignalgo.Address, _ uuid.UUID, record *libsignalgo.SenderKeyRecord) error {
	s.record = record
	return nil
}

// Selection can finish before receive replaces an identity. The final envelope
// lookup must check the actual key returned to crypto, even with a cached session.
func TestSenderKeyTrustEncryption(t *testing.T) {
	s := &senderTrustStore{trusted: true}
	cli, peer, sec := senderTrustClient(t, s)
	var err error
	s.pair, err = libsignalgo.GenerateIdentityKeyPair()
	require.NoError(t, err)
	remotePair, err := libsignalgo.GenerateIdentityKeyPair()
	require.NoError(t, err)
	s.key = remotePair.GetIdentityKey()
	remote, err := peer.Address(1)
	require.NoError(t, err)
	local, err := cli.Store.ACIServiceID().Address(1)
	require.NoError(t, err)
	pre, err := libsignalgo.GeneratePrivateKey()
	require.NoError(t, err)
	prePub, err := pre.GetPublicKey()
	require.NoError(t, err)
	signed, err := libsignalgo.GeneratePrivateKey()
	require.NoError(t, err)
	signedPub, err := signed.GetPublicKey()
	require.NoError(t, err)
	signedRaw, err := signedPub.Serialize()
	require.NoError(t, err)
	signature, err := remotePair.GetPrivateKey().Sign(signedRaw)
	require.NoError(t, err)
	kyber, err := libsignalgo.KyberKeyPairGenerate()
	require.NoError(t, err)
	kyberPub, err := kyber.GetPublicKey()
	require.NoError(t, err)
	kyberRaw, err := kyberPub.Serialize()
	require.NoError(t, err)
	kyberSig, err := remotePair.GetPrivateKey().Sign(kyberRaw)
	require.NoError(t, err)
	bundle, err := libsignalgo.NewPreKeyBundle(77, 1, 1, prePub, 2, signedPub, signature, 3, kyberPub, kyberSig, s.key)
	require.NoError(t, err)
	require.NoError(t, libsignalgo.ProcessPreKeyBundle(t.Context(), bundle, remote, local, cli.Store.ACISessionStore, s))
	session := cli.Store.ACISessionStore.(*senderSessions).record
	sender := &encryptionSenderStore{}
	cli.Store.SenderKeyStore = sender
	distribution := uuid.New()
	_, err = libsignalgo.NewSenderKeyDistributionMessage(t.Context(), local, distribution, sender)
	require.NoError(t, err)
	root, err := libsignalgo.GenerateIdentityKeyPair()
	require.NoError(t, err)
	serverCert, err := libsignalgo.NewServerCertificate(1, root.GetPublicKey(), root.GetPrivateKey())
	require.NoError(t, err)
	cert, err := libsignalgo.NewSenderCertificate(libsignalgo.NewSealedSenderAddress("", cli.Store.ACI, 1), s.pair.GetPublicKey(), time.Now().Add(72*time.Hour), serverCert, root.GetPrivateKey())
	require.NoError(t, err)
	tuples := []store.SessionAddressTuple{{ServiceID: peer, DeviceID: 1, Address: remote, Record: session}}
	ciphertext, err := cli.EncryptWithSenderKeyForTest(t.Context(), tuples, distribution, cert)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	selected, _ := cli.SenderKeyRecipientsForTest(t.Context(), []libsignalgo.ServiceID{peer}, sec)
	require.Equal(t, []libsignalgo.ServiceID{peer}, selected)
	// Receive changes the key after selection, leaving an established session.
	changed, err := libsignalgo.GenerateIdentityKeyPair()
	require.NoError(t, err)
	s.key, s.trusted = changed.GetIdentityKey(), false
	ciphertext, err = cli.EncryptWithSenderKeyForTest(t.Context(), tuples, distribution, cert)
	require.ErrorIs(t, err, libsignalgo.ErrorCodeUntrustedIdentity)
	require.Empty(t, ciphertext)
	// Trusting the replacement permits the same group operation again.
	s.trusted = true
	ciphertext, err = cli.EncryptWithSenderKeyForTest(t.Context(), tuples, distribution, cert)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
}

// Removing the trust gate promotes a changed-key peer with an existing session
// to multi-recipient encryption, which itself does not consult identity trust.
func TestSenderKeyTrustSelection(t *testing.T) {
	for _, name := range []string{"trusted", "untrusted", "missing", "read-error", "trust-error"} {
		t.Run(name, func(t *testing.T) {
			s := &senderTrustStore{trusted: true}
			cli, peer, sec := senderTrustClient(t, s)
			switch name {
			case "untrusted":
				s.trusted = false
			case "missing":
				s.key = nil
			case "read-error":
				s.getErr = errTrustRead
			case "trust-error":
				s.trustErr = errTrustRead
			}
			selected, fallback := cli.SenderKeyRecipientsForTest(t.Context(), []libsignalgo.ServiceID{cli.Store.ACIServiceID(), peer}, sec)
			if name == "trusted" {
				if len(selected) != 1 || selected[0] != peer || len(fallback) != 0 {
					t.Fatalf("selected %v fallback %v", selected, fallback)
				}
			} else if len(selected) != 0 || !slices.Equal(fallback, []libsignalgo.ServiceID{peer}) {
				t.Fatalf("unsafe selection %v fallback %v", selected, fallback)
			}
			if name != "missing" && name != "read-error" && !slices.Equal(s.checked, []libsignalgo.ServiceID{peer}) {
				t.Fatalf("trust checks %v", s.checked)
			}
		})
	}
}

type senderRotationStore struct {
	store.SenderKeyStore
	info              *store.SenderKeyInfo
	deleted           bool
	oldDistribution   uuid.UUID
	putErr, deleteErr error
}

func (s *senderRotationStore) GetSenderKeyInfo(context.Context, types.GroupIdentifier) (*store.SenderKeyInfo, error) {
	copyInfo := *s.info
	copyInfo.SharedWith = maps.Clone(s.info.SharedWith)
	return &copyInfo, nil
}

func (s *senderRotationStore) PutSenderKeyInfo(_ context.Context, _ types.GroupIdentifier, info *store.SenderKeyInfo) error {
	if s.putErr != nil {
		return s.putErr
	}
	copyInfo := *info
	copyInfo.SharedWith = maps.Clone(info.SharedWith)
	s.info = &copyInfo
	return nil
}
func (s *senderRotationStore) DeleteSenderKey(_ context.Context, _ *libsignalgo.Address, id uuid.UUID) error {
	if id != s.oldDistribution {
		return errors.New("wrong distribution deleted")
	}
	s.deleted = true
	return s.deleteErr
}
func (s *senderRotationStore) LoadSenderKey(context.Context, *libsignalgo.Address, uuid.UUID) (*libsignalgo.SenderKeyRecord, error) {
	return nil, errStopDistribution
}

// A peer who already holds the key must be excluded and force key regeneration;
// its old sharing entry must not authorize retries with the regenerated key.
func TestSenderKeyTrustRotation(t *testing.T) {
	s := &senderTrustStore{trusted: true}
	cli, blocked, sec := senderTrustClient(t, s)
	trusted := libsignalgo.NewACIServiceID(uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"))
	sec.MemberEndorsements[trusted] = nil
	s.blocked = blocked
	sender := &senderRotationStore{info: &store.SenderKeyInfo{DistributionID: uuid.New(), CreatedAt: time.Now(), SharedWith: map[libsignalgo.ServiceID][]int{blocked: {1}, trusted: {1}}}}
	sender.oldDistribution = sender.info.DistributionID
	cli.Store.SenderKeyStore = sender
	err := cli.SendWithSenderKeyForTest(t.Context(), &libsignalgo.GroupIdentifier{42}, []libsignalgo.ServiceID{blocked, trusted}, sec)
	if !errors.Is(err, errStopDistribution) {
		t.Fatalf("did not reach redistribution: %v", err)
	}
	if !sender.deleted {
		t.Fatal("key held by untrusted peer was reused")
	}
	if len(sender.info.SharedWith) != 0 {
		t.Fatalf("stale sharing entries after reset: %v", sender.info.SharedWith)
	}
	if sender.info.DistributionID == sender.oldDistribution {
		t.Fatal("rotated key reused old distribution authorization")
	}
}

func TestSenderKeyTrustRotationWriteFailures(t *testing.T) {
	for _, stage := range []string{"metadata", "old-key"} {
		t.Run(stage, func(t *testing.T) {
			s := &senderTrustStore{trusted: true}
			cli, blocked, sec := senderTrustClient(t, s)
			trusted := libsignalgo.NewACIServiceID(uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"))
			sec.MemberEndorsements[trusted] = nil
			s.blocked = blocked
			oldID := uuid.New()
			sender := &senderRotationStore{oldDistribution: oldID, info: &store.SenderKeyInfo{DistributionID: oldID, CreatedAt: time.Now(), SharedWith: map[libsignalgo.ServiceID][]int{blocked: {1}, trusted: {1}}}}
			if stage == "metadata" {
				sender.putErr = errTrustRead
			} else {
				sender.deleteErr = errTrustRead
			}
			cli.Store.SenderKeyStore = sender
			err := cli.SendWithSenderKeyForTest(t.Context(), &libsignalgo.GroupIdentifier{42}, []libsignalgo.ServiceID{blocked, trusted}, sec)
			require.ErrorIs(t, err, errTrustRead)
			if stage == "metadata" {
				require.False(t, sender.deleted, "old key must survive failed metadata update")
				require.Equal(t, oldID, sender.info.DistributionID)
			} else {
				require.True(t, sender.deleted)
				require.NotEqual(t, oldID, sender.info.DistributionID)
				require.Empty(t, sender.info.SharedWith, "old holders must not authorize the new distribution")
			}
		})
	}
}

type fallbackLockSessions struct {
	store.SessionStore
	cli   *signalmeow.Client
	calls int
	held  bool
}

func (s *fallbackLockSessions) AllSessionsForServiceID(_ context.Context, id libsignalgo.ServiceID) ([]store.SessionAddressTuple, error) {
	s.calls++
	if s.calls == 1 {
		return []store.SessionAddressTuple{{ServiceID: id, DeviceID: 1}}, nil
	}
	s.held = s.cli.EncryptionLockHeldForTest()
	return nil, errStopDistribution
}

// Excluding every peer uses pairwise encryption. Its session lookup must still
// hold the encryption mutex, rather than inheriting a stale "already locked" flag.
func TestSenderKeyTrustFallbackLock(t *testing.T) {
	s := &senderTrustStore{trusted: false}
	cli, peer, sec := senderTrustClient(t, s)
	sessions := &fallbackLockSessions{cli: cli}
	cli.Store.ACISessionStore = sessions
	err := cli.SendWithSenderKeyForTest(t.Context(), &libsignalgo.GroupIdentifier{42}, []libsignalgo.ServiceID{peer}, sec)
	if !errors.Is(err, errStopDistribution) || sessions.calls != 2 {
		t.Fatalf("fallback did not reach pairwise session lookup: calls %d err %v", sessions.calls, err)
	}
	if !sessions.held {
		t.Fatal("pairwise fallback accesses sessions without encryption lock")
	}
}
