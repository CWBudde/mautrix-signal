// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
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
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/cwbudde/libsignal-go/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
)

var nullHash = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func getKeyBytes(t *testing.T) []byte {
	validKey, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	keyBytes, err := validKey.GetPublicKey().Bytes()
	assert.NoError(t, err)
	return keyBytes
}

// From HsmEnclaveTests.swift:testCreateClient
// From HsmEnclaveTests.swift:testCreateClientFailsWithNoHashes
func TestCreateHSMClient(t *testing.T) {
	setupLogging()
	hashes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	t.Run("Succeeds with hashes", func(t *testing.T) {
		client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), hashes)
		assert.NoError(t, err)

		initialMessage, err := client.InitialRequest()
		assert.NoError(t, err)
		assert.Len(t, initialMessage, 112)
	})

	t.Run("Fails with no hashes", func(t *testing.T) {
		_, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), []byte{})
		assert.Error(t, err)
	})
}

// From HsmEnclaveTests.swift:testCompleteHandshakeWithoutInitialRequest
func TestHSMCompleteHandshakeWithoutInitialRequest(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	assert.NoError(t, err)
	err = client.CompleteHandshake([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

// From HsmEnclaveTests.swift:testEstablishedSendFailsPriorToEstablishment
func TestHSMEstablishedSendFailsPriorToEstablishment(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	assert.NoError(t, err)
	_, err = client.EstablishedSend([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

// From HsmEnclaveTests.swift:testEstablishedRecvFailsPriorToEstablishment
func TestHSMEstablishedReceiveFailsPriorToEstablishment(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	assert.NoError(t, err)
	_, err = client.EstablishedReceive([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

// hsmCode checks that err is a *SignalError with the given code. Both builds
// must report the codes of rust/bridge/shared/types/src/ffi/error.rs
// (IntoFfiError for HsmEnclaveError).
func hsmCode(t *testing.T, err error, want libsignalgo.ErrorCode) {
	t.Helper()
	var signalErr *libsignalgo.SignalError
	if assert.True(t, errors.As(err, &signalErr), "err = %v, want a *SignalError", err) {
		assert.Equal(t, want, signalErr.Code, "err = %v", err)
	}
}

func hsmHash(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// hsmServer is the HSM side of the Noise NK handshake: it reads the client's
// initial request, checks that it carries the trusted code hashes and
// answers with codeHash.
func hsmServer(t *testing.T, key *ecdh.PrivateKey, initial, wantHashes, codeHash []byte) ([]byte, *noise.Transport) {
	t.Helper()
	hs, err := noise.NewResponder(noise.NK, key.Bytes(), nil)
	require.NoError(t, err)
	payload, err := hs.ReadMessage(initial)
	require.NoError(t, err)
	require.Equal(t, wantHashes, payload)
	reply, err := hs.WriteMessage(codeHash)
	require.NoError(t, err)
	tr, err := hs.Transport()
	require.NoError(t, err)
	return reply, tr
}

// hsmClient creates a client for key trusting hashes and returns it with its
// initial request.
func hsmClient(t *testing.T, key *ecdh.PrivateKey, hashes []byte) (*libsignalgo.HSMEnclaveClient, []byte) {
	t.Helper()
	client, err := libsignalgo.NewHSMEnclaveClient(key.PublicKey().Bytes(), hashes)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Destroy()) })
	initial, err := client.InitialRequest()
	require.NoError(t, err)
	return client, initial
}

// hsmUnusable checks that every call fails with InvalidState, as after a
// failed handshake.
func hsmUnusable(t *testing.T, client *libsignalgo.HSMEnclaveClient, reply []byte) {
	t.Helper()
	_, err := client.InitialRequest()
	hsmCode(t, err, libsignalgo.ErrorCodeInvalidState)
	hsmCode(t, client.CompleteHandshake(reply), libsignalgo.ErrorCodeInvalidState)
	_, err = client.EstablishedSend([]byte{1})
	hsmCode(t, err, libsignalgo.ErrorCodeInvalidState)
	_, err = client.EstablishedReceive([]byte{1})
	hsmCode(t, err, libsignalgo.ErrorCodeInvalidState)
}

func TestHSMNewClientErrors(t *testing.T) {
	setupLogging()
	pub := getKeyBytes(t)
	for _, tc := range []struct {
		name        string
		pub, hashes []byte
		want        libsignalgo.ErrorCode
	}{
		{"short key", pub[:31], nullHash, libsignalgo.ErrorCodeInvalidKey},
		{"long key", append(bytes.Clone(pub), 0), nullHash, libsignalgo.ErrorCodeInvalidKey},
		{"no key", nil, nullHash, libsignalgo.ErrorCodeInvalidKey},
		{"no hashes", pub, nil, libsignalgo.ErrorCodeInvalidArgument},
		{"partial hash", pub, nullHash[:31], libsignalgo.ErrorCodeInvalidArgument},
		{"hash and a byte", pub, append(bytes.Clone(nullHash), 0), libsignalgo.ErrorCodeInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := libsignalgo.NewHSMEnclaveClient(tc.pub, tc.hashes)
			assert.Nil(t, client)
			hsmCode(t, err, tc.want)
		})
	}
}

func TestHSMWrongStateCodes(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	require.NoError(t, err)
	_, err = client.EstablishedSend([]byte{1})
	hsmCode(t, err, libsignalgo.ErrorCodeInvalidState)
	_, err = client.EstablishedReceive([]byte{1})
	hsmCode(t, err, libsignalgo.ErrorCodeInvalidState)
	// Garbage is not the HSM's handshake reply: the handshake fails and
	// leaves the client unusable.
	hsmCode(t, client.CompleteHandshake([]byte{1, 2, 3}), libsignalgo.ErrorCodeInvalidMessage)
	hsmUnusable(t, client, []byte{1, 2, 3})
	assert.NoError(t, client.Destroy())
}

// TestHSMHandshake runs the whole protocol against a Go Noise NK responder:
// the handshake with each trusted hash as the HSM's, then messages both ways.
func TestHSMHandshake(t *testing.T) {
	setupLogging()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	trusted := slices.Concat(hsmHash(1), hsmHash(2), hsmHash(3))
	for i := range 3 {
		client, initial := hsmClient(t, key, trusted)
		assert.Len(t, initial, 48+len(trusted))
		again, err := client.InitialRequest()
		require.NoError(t, err)
		assert.Equal(t, initial, again)

		reply, srv := hsmServer(t, key, initial, trusted, hsmHash(byte(i+1)))
		require.NoError(t, client.CompleteHandshake(reply))

		_, err = client.InitialRequest()
		hsmCode(t, err, libsignalgo.ErrorCodeInvalidState)

		// Long enough to take two Noise messages.
		long := bytes.Repeat([]byte("hsm!"), noise.MaxPayloadSize/2)
		ct, err := client.EstablishedSend(long)
		require.NoError(t, err)
		got, err := srv.Recv(ct)
		require.NoError(t, err)
		assert.Equal(t, long, got)

		ct, err = srv.Send([]byte("reply"))
		require.NoError(t, err)
		got, err = client.EstablishedReceive(ct)
		require.NoError(t, err)
		assert.Equal(t, []byte("reply"), got)

		// Replayed: the nonce no longer matches.
		_, err = client.EstablishedReceive(ct)
		hsmCode(t, err, libsignalgo.ErrorCodeInvalidMessage)
		// Upstream keeps the connection after a failed receive.
		ct, err = srv.Send([]byte("more"))
		require.NoError(t, err)
		got, err = client.EstablishedReceive(ct)
		require.NoError(t, err)
		assert.Equal(t, []byte("more"), got)

		// Upstream's complete_handshake drops the state before checking it,
		// so a second call ends the connection too.
		hsmCode(t, client.CompleteHandshake(reply), libsignalgo.ErrorCodeInvalidState)
		hsmUnusable(t, client, reply)
	}
}

// TestHSMHandshakeRejected checks the HSM's replies the client refuses: its
// code hash must be exactly one of the trusted ones.
func TestHSMHandshakeRejected(t *testing.T) {
	setupLogging()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	trusted := slices.Concat(hsmHash(1), hsmHash(2))
	for _, tc := range []struct {
		name    string
		payload []byte
		want    libsignalgo.ErrorCode
	}{
		{"untrusted", hsmHash(9), libsignalgo.ErrorCodeUntrustedIdentity},
		{"empty", nil, libsignalgo.ErrorCodeUntrustedIdentity},
		{"short", hsmHash(1)[:31], libsignalgo.ErrorCodeUntrustedIdentity},
		{"long", append(hsmHash(1), 0), libsignalgo.ErrorCodeInvalidMessage},
		{"two hashes", trusted, libsignalgo.ErrorCodeInvalidMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, initial := hsmClient(t, key, trusted)
			reply, _ := hsmServer(t, key, initial, trusted, tc.payload)
			hsmCode(t, client.CompleteHandshake(reply), tc.want)
			hsmUnusable(t, client, reply)
		})
	}

	t.Run("tampered", func(t *testing.T) {
		client, initial := hsmClient(t, key, trusted)
		reply, _ := hsmServer(t, key, initial, trusted, hsmHash(1))
		reply[len(reply)-1] ^= 1
		hsmCode(t, client.CompleteHandshake(reply), libsignalgo.ErrorCodeInvalidMessage)
		hsmUnusable(t, client, reply)
	})

	t.Run("wrong server key", func(t *testing.T) {
		other, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, initial := hsmClient(t, key, trusted)
		hs, err := noise.NewResponder(noise.NK, other.Bytes(), nil)
		require.NoError(t, err)
		_, err = hs.ReadMessage(initial)
		assert.ErrorIs(t, err, noise.ErrDecrypt)
	})
}
