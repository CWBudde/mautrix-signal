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
	"time"

	"github.com/cwbudde/libsignal-go/session"
)

type SessionRecord struct {
	nc     noCopy
	record *session.SessionRecord
}

func wrapSessionRecord(record *session.SessionRecord) *SessionRecord {
	return &SessionRecord{record: record}
}

func DeserializeSessionRecord(serialized []byte) (*SessionRecord, error) {
	record, err := session.DeserializeSessionRecord(serialized)
	if err != nil {
		return nil, &SignalError{Code: ErrorCodeInvalidSession, Message: err.Error()}
	}
	return wrapSessionRecord(record), nil
}

func (sr *SessionRecord) Clone() (*SessionRecord, error) {
	return wrapSessionRecord(sr.record.Clone()), nil
}

func (sr *SessionRecord) Destroy() error {
	return nil
}

func (sr *SessionRecord) CancelFinalizer() {}

func (sr *SessionRecord) ArchiveCurrentState() error {
	return wrapError(sr.record.ArchiveCurrentState())
}

func (sr *SessionRecord) CurrentRatchetKeyMatches(key *PublicKey) (bool, error) {
	if sr == nil || key == nil {
		return false, nil
	}
	if !sr.record.HasCurrentState() {
		return false, nil
	}
	ratchetKey, err := sr.record.CurrentState().SenderRatchetKey()
	if err != nil {
		return false, &SignalError{Code: ErrorCodeInvalidSession, Message: err.Error()}
	}
	return ratchetKey.Equal(key.key), nil
}

func (sr *SessionRecord) HasCurrentState() (bool, error) {
	return sr.record.HasUsableSenderChain(time.Now()), nil
}

func (sr *SessionRecord) Serialize() ([]byte, error) {
	serialized, err := sr.record.Serialize()
	return serialized, wrapError(err)
}

func (sr *SessionRecord) GetLocalRegistrationID() (uint32, error) {
	if !sr.record.HasCurrentState() {
		return 0, errNoCurrentSession()
	}
	return sr.record.CurrentState().LocalRegistrationID(), nil
}

func (sr *SessionRecord) GetRemoteRegistrationID() (uint32, error) {
	if !sr.record.HasCurrentState() {
		return 0, errNoCurrentSession()
	}
	return sr.record.CurrentState().RemoteRegistrationID(), nil
}

func errNoCurrentSession() error {
	return &SignalError{Code: ErrorCodeSessionNotFound, Message: "session record has no current session"}
}
