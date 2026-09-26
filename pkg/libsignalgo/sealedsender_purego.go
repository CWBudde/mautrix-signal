//go:build purego

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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
	"fmt"

	"github.com/google/uuid"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/sealedsender"
)

type SealedSenderAddress struct {
	E164     string
	UUID     uuid.UUID
	DeviceID uint32
}

func NewSealedSenderAddress(e164 string, uuid uuid.UUID, deviceID uint32) *SealedSenderAddress {
	return &SealedSenderAddress{
		E164:     e164,
		UUID:     uuid,
		DeviceID: deviceID,
	}
}

func SealedSenderEncryptPlaintext(
	ctx context.Context,
	message []byte,
	contentHint UnidentifiedSenderMessageContentHint,
	forAddress, localAddress *Address,
	fromSenderCert *SenderCertificate,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	groupID *GroupIdentifier,
) ([]byte, error) {
	ciphertextMessage, err := Encrypt(ctx, message, forAddress, localAddress, sessionStore, identityStore)
	if err != nil {
		return nil, err
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		ciphertextMessage,
		fromSenderCert,
		contentHint,
		groupID,
	)
	if err != nil {
		return nil, err
	}
	return SealedSenderEncrypt(ctx, usmc, forAddress, identityStore)
}

func SealedSenderEncrypt(ctx context.Context, usmc *UnidentifiedSenderMessageContent, forRecipient *Address, identityStore IdentityKeyStore) ([]byte, error) {
	store := identityStoreAdapter{identityStore}
	ourIdentity, err := store.GetIdentityKeyPair(ctx)
	if err != nil {
		return nil, wrapError(err)
	}
	theirIdentity, ok, err := store.GetIdentity(ctx, forRecipient.addr)
	if err != nil {
		return nil, wrapError(err)
	}
	if !ok {
		return nil, &SignalError{Code: ErrorCodeSessionNotFound, Message: "no identity key for " + forRecipient.addr.String()}
	}
	sealed, err := sealedsender.SealV1(usmc.usmc, ourIdentity, theirIdentity, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return sealed, nil
}

type SessionAddressTuple struct {
	ServiceID ServiceID
	DeviceID  int
	Address   *Address
	Record    *SessionRecord
}

// validRegistrationIDMask: valid registration IDs fit in 14 bits.
const validRegistrationIDMask = 0x3FFF

// SealedSenderMultiRecipientEncrypt encrypts usmc for all recipients at once
// (sealed sender v2). Consecutive recipients with the same address name form
// one recipient with several devices; its identity key comes from the identity
// store, each device's registration ID from its session.
func SealedSenderMultiRecipientEncrypt(
	ctx context.Context,
	usmc *UnidentifiedSenderMessageContent,
	recipients []SessionAddressTuple,
	identityStore IdentityKeyStore,
) ([]byte, error) {
	store := identityStoreAdapter{identityStore}
	ourIdentity, err := store.GetIdentityKeyPair(ctx)
	if err != nil {
		return nil, wrapError(err)
	}
	sealRecipients := make([]sealedsender.SealV2Recipient, 0, len(recipients))
	for i, recipient := range recipients {
		addr := recipient.Address.addr
		serviceID, err := address.ParseServiceIDString(addr.Name())
		if err != nil {
			return nil, errInvalidArgument("multi-recipient sealed sender requires recipients' ServiceId (not %s)", addr.Name())
		}
		r := sealedsender.SealV2Recipient{ServiceID: serviceID, DeviceID: addr.DeviceID().Value()}
		if i > 0 && recipients[i-1].Address.addr.Name() == addr.Name() {
			r.IdentityKey = sealRecipients[i-1].IdentityKey
		} else {
			key, ok, err := store.GetIdentity(ctx, addr)
			if err != nil {
				return nil, wrapError(err)
			}
			if !ok {
				return nil, &SignalError{Code: ErrorCodeSessionNotFound, Message: "no identity key for " + addr.String()}
			}
			r.IdentityKey = key
		}
		record := recipient.Record.record
		if !record.HasCurrentState() {
			return nil, &SignalError{Code: ErrorCodeInvalidState, Message: fmt.Sprintf(
				"cannot get registration ID from session with %s (maybe it was recently archived)", addr)}
		}
		r.RegistrationID = record.CurrentState().RemoteRegistrationID()
		if r.RegistrationID&validRegistrationIDMask != r.RegistrationID {
			return nil, &SignalError{Code: ErrorCodeInvalidRegistrationId, Message: fmt.Sprintf(
				"session for %s has invalid registration ID %#x", addr, r.RegistrationID)}
		}
		sealRecipients = append(sealRecipients, r)
	}
	sent, err := sealedsender.SealV2(usmc.usmc, sealRecipients, ourIdentity, rand.Reader)
	if err != nil {
		return nil, wrapError(err)
	}
	return sent.Serialized(), nil
}

type SealedSenderResult struct {
	Message []byte
	Sender  SealedSenderAddress
}

func SealedSenderDecryptToUSMC(
	ctx context.Context,
	ciphertext []byte,
	identityStore IdentityKeyStore,
) (*UnidentifiedSenderMessageContent, error) {
	ourIdentity, err := identityStoreAdapter{identityStore}.GetIdentityKeyPair(ctx)
	if err != nil {
		return nil, wrapError(err)
	}
	usmc, err := sealedsender.DecryptToUSMC(ciphertext, ourIdentity)
	if err != nil {
		return nil, wrapError(err)
	}
	return &UnidentifiedSenderMessageContent{usmc: usmc}, nil
}

type UnidentifiedSenderMessageContentHint uint32

const (
	UnidentifiedSenderMessageContentHintDefault    UnidentifiedSenderMessageContentHint = 0
	UnidentifiedSenderMessageContentHintResendable UnidentifiedSenderMessageContentHint = 1
	UnidentifiedSenderMessageContentHintImplicit   UnidentifiedSenderMessageContentHint = 2
)

func (hint UnidentifiedSenderMessageContentHint) String() string {
	switch hint {
	case UnidentifiedSenderMessageContentHintDefault:
		return "Default"
	case UnidentifiedSenderMessageContentHintResendable:
		return "Resendable"
	case UnidentifiedSenderMessageContentHintImplicit:
		return "Implicit"
	default:
		return fmt.Sprintf("Unknown(%d)", hint)
	}
}

type UnidentifiedSenderMessageContent struct {
	nc   noCopy
	usmc *sealedsender.UnidentifiedSenderMessageContent
}

func NewUnidentifiedSenderMessageContent(message *CiphertextMessage, senderCertificate *SenderCertificate, contentHint UnidentifiedSenderMessageContentHint, groupID *GroupIdentifier) (*UnidentifiedSenderMessageContent, error) {
	var groupIDBytes []byte
	if groupID != nil {
		groupIDBytes = groupID[:]
	}
	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(uint8(message.msgType), senderCertificate.cert,
		message.serialized, sealedsender.ContentHint(contentHint), groupIDBytes)
	if err != nil {
		return nil, wrapError(err)
	}
	return &UnidentifiedSenderMessageContent{usmc: usmc}, nil
}

func DeserializeUnidentifiedSenderMessageContent(serialized []byte) (*UnidentifiedSenderMessageContent, error) {
	usmc, err := sealedsender.DeserializeUnidentifiedSenderMessageContent(serialized)
	if err != nil {
		return nil, wrapError(err)
	}
	return &UnidentifiedSenderMessageContent{usmc: usmc}, nil
}

func (usmc *UnidentifiedSenderMessageContent) Destroy() error {
	return nil
}

func (usmc *UnidentifiedSenderMessageContent) CancelFinalizer() {}

func (usmc *UnidentifiedSenderMessageContent) Serialize() ([]byte, error) {
	return usmc.usmc.Serialized(), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContents() ([]byte, error) {
	return usmc.usmc.Contents(), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetGroupID() (*GroupIdentifier, error) {
	bytes, _ := usmc.usmc.GroupID()
	if len(bytes) == 0 {
		return nil, nil
	} else if len(bytes) != GroupIdentifierLength {
		return nil, fmt.Errorf("unexpected group ID length: %d", len(bytes))
	}
	return (*GroupIdentifier)(bytes), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetSenderCertificate() (*SenderCertificate, error) {
	return wrapSenderCertificate(usmc.usmc.Sender()), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetMessageType() (CiphertextMessageType, error) {
	return CiphertextMessageType(usmc.usmc.MessageType()), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContentHint() (UnidentifiedSenderMessageContentHint, error) {
	return UnidentifiedSenderMessageContentHint(usmc.usmc.ContentHint()), nil
}
