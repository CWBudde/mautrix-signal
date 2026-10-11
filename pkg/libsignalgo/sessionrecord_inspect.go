//go:build cgo || libsignal_go

package libsignalgo

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/proto"
	"github.com/cwbudde/libsignal-go/spqr"
	"google.golang.org/protobuf/encoding/protowire"
	googleproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	ErrMalformedSessionRecord   = errors.New("malformed serialized session record")
	ErrUnsupportedSessionRecord = errors.New("unsupported serialized session record")
	ErrSessionRecordLimit       = errors.New("serialized session record exceeds limit")
)

type SessionRecordInspection struct {
	Current  *SessionStateInspection
	Archived []SessionStateInspection
}

type SessionStateInspection struct {
	Version, LocalRegistrationID, RemoteRegistrationID uint32
	LocalIdentityPublic, RemoteIdentityPublic          []byte
	SenderChainPresent                                 bool
	ReceiverChainCount, SkippedMessageKeyCount         int
	PendingPreKey                                      *PendingPreKeyInspection
	PendingKyberID                                     *uint32
	PQRatchet                                          PQRatchetInspection
}

type PendingPreKeyInspection struct {
	PreKeyID         *uint32
	SignedPreKeyID   int32
	TimestampSeconds uint64
}

type PQRatchetInspection struct {
	Present     bool
	Version     uint32
	Negotiating bool
	MinVersion  uint32
}

// InspectSessionRecord reports structural current/archive metadata without
// changing input bytes, checking time-dependent sender usability or comparing
// historical remote identities against an account's current trust store.
// Inspection establishes supported encoding, not cryptographic authenticity or
// exchange compatibility. On failure no partial metadata is returned.
func InspectSessionRecord(raw []byte) (SessionRecordInspection, error) {
	var record proto.RecordStructure
	if err := inspectSessionDecode(raw, &record); err != nil {
		return SessionRecordInspection{}, err
	}
	if len(record.PreviousSessions) > 40 {
		return SessionRecordInspection{}, fmt.Errorf("%w: archives", ErrSessionRecordLimit)
	}
	var result SessionRecordInspection
	if record.CurrentSession != nil {
		current, err := inspectSessionState(record.CurrentSession)
		if err != nil {
			return SessionRecordInspection{}, fmt.Errorf("current state: %w", err)
		}
		result.Current = &current
	}
	for i, raw := range record.PreviousSessions {
		var previous proto.SessionStructure
		if err := inspectSessionDecode(raw, &previous); err != nil {
			return SessionRecordInspection{}, fmt.Errorf("archive %d: %w", i, err)
		}
		state, err := inspectSessionState(&previous)
		if err != nil {
			return SessionRecordInspection{}, fmt.Errorf("archive %d: %w", i, err)
		}
		result.Archived = append(result.Archived, state)
	}
	return result, nil
}

func inspectSessionDecode(raw []byte, msg googleproto.Message) error {
	if len(raw) > 1<<20 {
		return ErrSessionRecordLimit
	}
	if err := inspectSessionWire(raw, msg.ProtoReflect().Descriptor(), 0); err != nil {
		return err
	}
	if err := (googleproto.UnmarshalOptions{RecursionLimit: 64}).Unmarshal(raw, msg); err != nil {
		return fmt.Errorf("%w: protobuf", ErrMalformedSessionRecord)
	}
	return nil
}

// Decode every wire occurrence, including superseded oneof/message values.
func inspectSessionWire(raw []byte, md protoreflect.MessageDescriptor, depth int) error {
	if depth > 64 {
		return ErrSessionRecordLimit
	}
	for len(raw) != 0 {
		number, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return ErrMalformedSessionRecord
		}
		raw = raw[n:]
		fd := md.Fields().ByNumber(protoreflect.FieldNumber(number))
		if fd == nil {
			return fmt.Errorf("%w: unknown field", ErrUnsupportedSessionRecord)
		}
		expected := protowire.VarintType
		if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.BytesKind {
			expected = protowire.BytesType
		}
		if kind != expected {
			return fmt.Errorf("%w: wire type", ErrMalformedSessionRecord)
		}
		consumed := protowire.ConsumeFieldValue(number, kind, raw)
		if consumed < 0 {
			return ErrMalformedSessionRecord
		}
		if md.FullName() == (&proto.SessionStructure{}).ProtoReflect().Descriptor().FullName() {
			if number == 1 {
				value, _ := protowire.ConsumeVarint(raw)
				if value != 3 && value != 4 {
					return fmt.Errorf("%w: session version", ErrUnsupportedSessionRecord)
				}
			}
			if number == 15 {
				inner, _ := protowire.ConsumeBytes(raw)
				if err := inspectSessionPQ(inner); err != nil {
					return err
				}
			}
		}
		if fd.Kind() == protoreflect.Int32Kind {
			value, _ := protowire.ConsumeVarint(raw)
			if uint64(int64(int32(value))) != value {
				return fmt.Errorf("%w: signed scalar overflow", ErrMalformedSessionRecord)
			}
		}
		if fd.Kind() == protoreflect.Uint32Kind {
			value, _ := protowire.ConsumeVarint(raw)
			if value > 1<<32-1 {
				return fmt.Errorf("%w: scalar overflow", ErrMalformedSessionRecord)
			}
		}
		if fd.Kind() == protoreflect.MessageKind {
			inner, count := protowire.ConsumeBytes(raw)
			if count < 0 {
				return ErrMalformedSessionRecord
			}
			if err := inspectSessionWire(inner, fd.Message(), depth+1); err != nil {
				return err
			}
		}
		raw = raw[consumed:]
	}
	return nil
}

func inspectSessionPQ(raw []byte) error {
	if err := spqr.ValidateState(raw); err != nil {
		category := ErrMalformedSessionRecord
		if errors.Is(err, spqr.ErrUnsupportedState) {
			category = ErrUnsupportedSessionRecord
		}
		if errors.Is(err, spqr.ErrStateLimit) {
			category = ErrSessionRecordLimit
		}
		return fmt.Errorf("%w: PQ state", category)
	}
	return nil
}

func inspectSessionState(st *proto.SessionStructure) (SessionStateInspection, error) {
	var result SessionStateInspection
	if st.SessionVersion != 3 && st.SessionVersion != 4 {
		return result, fmt.Errorf("%w: session version", ErrUnsupportedSessionRecord)
	}
	if st.LocalRegistrationId == 0 || st.RemoteRegistrationId == 0 || len(st.RootKey) != 32 || !inspectSessionPublic(st.LocalIdentityPublic) || !inspectSessionPublic(st.RemoteIdentityPublic) || !inspectSessionPublic(st.AliceBaseKey) {
		return result, fmt.Errorf("%w: identity or state metadata", ErrMalformedSessionRecord)
	}
	if len(st.ReceiverChains) > 5 {
		return result, fmt.Errorf("%w: receiver chains", ErrSessionRecordLimit)
	}
	if err := inspectSessionPQ(st.PqRatchetState); err != nil {
		return result, err
	}
	status, err := spqr.Negotiation(st.PqRatchetState)
	if err != nil {
		return result, fmt.Errorf("%w: PQ metadata", ErrMalformedSessionRecord)
	}
	result = SessionStateInspection{
		Version: st.SessionVersion, LocalRegistrationID: st.LocalRegistrationId, RemoteRegistrationID: st.RemoteRegistrationId,
		LocalIdentityPublic: bytes.Clone(st.LocalIdentityPublic), RemoteIdentityPublic: bytes.Clone(st.RemoteIdentityPublic),
		SenderChainPresent: st.SenderChain != nil, ReceiverChainCount: len(st.ReceiverChains),
		PQRatchet: PQRatchetInspection{Present: len(st.PqRatchetState) != 0, Version: uint32(status.Version), Negotiating: status.Negotiating, MinVersion: uint32(status.MinVersion)},
	}
	if st.SenderChain != nil {
		if err := inspectSessionChain(st.SenderChain, true); err != nil {
			return SessionStateInspection{}, err
		}
	}
	for _, chain := range st.ReceiverChains {
		if err := inspectSessionChain(chain, false); err != nil {
			return SessionStateInspection{}, err
		}
		result.SkippedMessageKeyCount += len(chain.MessageKeys)
	}
	if p := st.PendingPreKey; p != nil {
		if !inspectSessionPublic(p.BaseKey) {
			return SessionStateInspection{}, fmt.Errorf("%w: pending base key", ErrMalformedSessionRecord)
		}
		result.PendingPreKey = &PendingPreKeyInspection{SignedPreKeyID: p.SignedPreKeyId, TimestampSeconds: p.Timestamp}
		if p.PreKeyId != nil {
			result.PendingPreKey.PreKeyID = new(*p.PreKeyId)
		}
	}
	if p := st.PendingKyberPreKey; p != nil {
		if len(p.Ciphertext) != 1569 {
			return SessionStateInspection{}, fmt.Errorf("%w: pending Kyber ciphertext", ErrMalformedSessionRecord)
		}
		if p.Ciphertext[0] != 0x08 {
			return SessionStateInspection{}, fmt.Errorf("%w: pending Kyber type", ErrUnsupportedSessionRecord)
		}
		result.PendingKyberID = new(p.PreKeyId)
	}
	return result, nil
}

func inspectSessionPublic(raw []byte) bool {
	if len(raw) != curve.SerializedPublicKeyLength {
		return false
	}
	_, err := curve.DeserializePublicKey(raw)
	return err == nil
}

func inspectSessionChain(c *proto.SessionStructure_Chain, sender bool) error {
	if c == nil || !inspectSessionPublic(c.SenderRatchetKey) || c.ChainKey == nil || len(c.ChainKey.Key) != 32 {
		return fmt.Errorf("%w: chain metadata", ErrMalformedSessionRecord)
	}
	if sender && len(c.SenderRatchetKeyPrivate) != 32 {
		return fmt.Errorf("%w: sender ratchet key", ErrMalformedSessionRecord)
	}
	if len(c.MessageKeys) > 2000 {
		return fmt.Errorf("%w: skipped keys", ErrSessionRecordLimit)
	}
	for _, key := range c.MessageKeys {
		if key == nil || (len(key.Seed) != 32 && !(len(key.Seed) == 0 && len(key.CipherKey) == 32 && len(key.MacKey) == 32 && len(key.Iv) == 16)) {
			return fmt.Errorf("%w: skipped key encoding", ErrMalformedSessionRecord)
		}
	}
	return nil
}
