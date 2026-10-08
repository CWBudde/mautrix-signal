// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"bytes"

	"github.com/google/uuid"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
)

// handleVerificationSync runs only after handleDecryptedResult authenticates the own ACI.
// Malformed updates are ignored; valid updates propagate persistence refusal to ACK handling.
func (cli *Client) handleVerificationSync(msg *signalpb.Verified) bool {
	if msg == nil || msg.State == nil {
		return true
	}
	switch *msg.State {
	case signalpb.Verified_DEFAULT, signalpb.Verified_VERIFIED, signalpb.Verified_UNVERIFIED:
	default:
		return true
	}
	var aci uuid.UUID
	if text := msg.GetDestinationAci(); text != "" {
		if len(text) != 36 {
			return true
		}
		parsed, err := uuid.Parse(text)
		if err != nil || parsed == uuid.Nil {
			return true
		}
		aci = parsed
	}
	if binary := msg.GetDestinationAciBinary(); len(binary) > 0 {
		parsed, err := uuid.FromBytes(binary)
		if err != nil || parsed == uuid.Nil || aci != uuid.Nil && aci != parsed {
			return true
		}
		aci = parsed
	}
	if aci == uuid.Nil || aci == cli.Store.ACI {
		return true
	}
	// Canonical serialized Curve25519 identity keys are exactly a type byte plus 32 bytes.
	if len(msg.IdentityKey) != 33 || msg.IdentityKey[0] != 5 {
		return true
	}
	key, err := libsignalgo.DeserializeIdentityKey(msg.IdentityKey)
	if err != nil {
		return true
	}
	serialized, err := key.Serialize()
	if err != nil || !bytes.Equal(serialized, msg.IdentityKey) {
		return true
	}
	return cli.handleEvent(&events.IdentityVerification{ACI: aci, IdentityKey: bytes.Clone(serialized), State: *msg.State})
}
