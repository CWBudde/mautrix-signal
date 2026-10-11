//go:build cgo || libsignal_go

package libsignalgo_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/cwbudde/libsignal-go/proto"
	"github.com/cwbudde/libsignal-go/spqr"
	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	googleproto "google.golang.org/protobuf/proto"
)

func inspectionState() *proto.SessionStructure {
	public := append([]byte{5}, bytes.Repeat([]byte{0x42}, 32)...)
	return &proto.SessionStructure{
		SessionVersion: 4, LocalRegistrationId: 123, RemoteRegistrationId: 456,
		LocalIdentityPublic: bytes.Clone(public), RemoteIdentityPublic: bytes.Clone(public),
		RootKey: bytes.Repeat([]byte{1}, 32), AliceBaseKey: bytes.Clone(public),
	}
}

func inspectionMarshal(t *testing.T, msg googleproto.Message) []byte {
	t.Helper()
	raw, err := googleproto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func inspectionRecord(t *testing.T, state *proto.SessionStructure) []byte {
	t.Helper()
	return inspectionMarshal(t, &proto.RecordStructure{CurrentSession: state})
}

func TestInspectSessionRecordCurrentAndArchived(t *testing.T) {
	current, previous := inspectionState(), inspectionState()
	previous.RemoteRegistrationId = 789
	previous.RemoteIdentityPublic[1] = 0x24
	raw := inspectionMarshal(t, &proto.RecordStructure{CurrentSession: current, PreviousSessions: [][]byte{inspectionMarshal(t, previous)}})
	got, err := libsignalgo.InspectSessionRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Current == nil || got.Current.Version != 4 || got.Current.LocalRegistrationID != 123 || got.Current.RemoteRegistrationID != 456 || len(got.Archived) != 1 || got.Archived[0].RemoteRegistrationID != 789 || got.Archived[0].RemoteIdentityPublic[1] != 0x24 {
		t.Fatal("metadata differs")
	}
	if !bytes.Equal(got.Current.LocalIdentityPublic, current.LocalIdentityPublic) {
		t.Fatal("identity differs")
	}
}

func TestInspectSessionRecordArchivedOnly(t *testing.T) {
	raw := inspectionMarshal(t, &proto.RecordStructure{PreviousSessions: [][]byte{inspectionMarshal(t, inspectionState())}})
	got, err := libsignalgo.InspectSessionRecord(raw)
	if err != nil || got.Current != nil || len(got.Archived) != 1 || got.Archived[0].SenderChainPresent {
		t.Fatal("archive-only metadata", err)
	}
	got, err = libsignalgo.InspectSessionRecord(nil)
	if err != nil || got.Current != nil || len(got.Archived) != 0 {
		t.Fatal("empty record", err)
	}
}

func TestInspectSessionRecordPendingMetadata(t *testing.T) {
	for _, present := range []bool{false, true} {
		st := inspectionState()
		st.PendingPreKey = &proto.SessionStructure_PendingPreKey{SignedPreKeyId: -1, BaseKey: st.AliceBaseKey, Timestamp: 1_700_000_000}
		if present {
			st.PendingPreKey.PreKeyId = new(uint32)
		}
		st.PendingKyberPreKey = &proto.SessionStructure_PendingKyberPreKey{Ciphertext: make([]byte, 1568)}
		got, err := libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
		if err != nil {
			t.Fatal(err)
		}
		p := got.Current.PendingPreKey
		if p == nil || (p.PreKeyID != nil) != present || p.TimestampSeconds != 1_700_000_000 || p.SignedPreKeyID != -1 || got.Current.PendingKyberID == nil || *got.Current.PendingKyberID != 0 {
			t.Fatal("pending metadata differs")
		}
	}
}

func TestInspectSessionRecordUnknownEncoding(t *testing.T) {
	for _, name := range []string{"root", "current", "archive", "chain", "pending", "PQ", "version"} {
		t.Run(name, func(t *testing.T) {
			st := inspectionState()
			r := &proto.RecordStructure{CurrentSession: st}
			unknown := []byte{0xf8, 0x07, 0x01}
			switch name {
			case "root":
				r.ProtoReflect().SetUnknown(unknown)
			case "current":
				st.ProtoReflect().SetUnknown(unknown)
			case "archive":
				old := inspectionState()
				old.ProtoReflect().SetUnknown(unknown)
				r.PreviousSessions = [][]byte{inspectionMarshal(t, old)}
			case "chain":
				st.SenderChain = &proto.SessionStructure_Chain{}
				st.SenderChain.ProtoReflect().SetUnknown(unknown)
			case "pending":
				st.PendingPreKey = &proto.SessionStructure_PendingPreKey{}
				st.PendingPreKey.ProtoReflect().SetUnknown(unknown)
			case "PQ":
				st.PqRatchetState = unknown
			case "version":
				st.SessionVersion = 99
			}
			got, err := libsignalgo.InspectSessionRecord(inspectionMarshal(t, r))
			if !errors.Is(err, libsignalgo.ErrUnsupportedSessionRecord) || !reflect.DeepEqual(got, libsignalgo.SessionRecordInspection{}) {
				t.Fatal("unsupported encoding accepted", err)
			}
		})
	}
}

func TestInspectSessionRecordMalformedArchive(t *testing.T) {
	raw := inspectionMarshal(t, &proto.RecordStructure{CurrentSession: inspectionState(), PreviousSessions: [][]byte{{0x0a, 0xff}}})
	if _, err := libsignalgo.InspectSessionRecord(raw); !errors.Is(err, libsignalgo.ErrMalformedSessionRecord) {
		t.Fatal(err)
	}
	st := inspectionState()
	st.LocalIdentityPublic = []byte{5}
	if _, err := libsignalgo.InspectSessionRecord(inspectionRecord(t, st)); !errors.Is(err, libsignalgo.ErrMalformedSessionRecord) {
		t.Fatal("bad identity accepted", err)
	}
}

func TestInspectSessionRecordLimits(t *testing.T) {
	for _, count := range []int{40, 41} {
		r := &proto.RecordStructure{}
		for range count {
			r.PreviousSessions = append(r.PreviousSessions, inspectionMarshal(t, inspectionState()))
		}
		_, err := libsignalgo.InspectSessionRecord(inspectionMarshal(t, r))
		if (count == 40 && err != nil) || (count == 41 && !errors.Is(err, libsignalgo.ErrSessionRecordLimit)) {
			t.Fatal("archive limit", err)
		}
	}
	for _, count := range []int{5, 6} {
		st := inspectionState()
		for range count {
			st.ReceiverChains = append(st.ReceiverChains, &proto.SessionStructure_Chain{SenderRatchetKey: st.AliceBaseKey, ChainKey: &proto.SessionStructure_Chain_ChainKey{Key: make([]byte, 32)}})
		}
		_, err := libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
		if (count == 5 && err != nil) || (count == 6 && !errors.Is(err, libsignalgo.ErrSessionRecordLimit)) {
			t.Fatal("chain limit", err)
		}
	}
	for _, count := range []int{2000, 2001} {
		st := inspectionState()
		chain := &proto.SessionStructure_Chain{SenderRatchetKey: st.AliceBaseKey, ChainKey: &proto.SessionStructure_Chain_ChainKey{Key: make([]byte, 32)}}
		for i := range count {
			chain.MessageKeys = append(chain.MessageKeys, &proto.SessionStructure_Chain_MessageKey{Index: uint32(i), Seed: make([]byte, 32)})
		}
		st.ReceiverChains = []*proto.SessionStructure_Chain{chain}
		_, err := libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
		if (count == 2000 && err != nil) || (count == 2001 && !errors.Is(err, libsignalgo.ErrSessionRecordLimit)) {
			t.Fatal("skipped key limit", err)
		}
	}
	if _, err := libsignalgo.InspectSessionRecord(make([]byte, (1<<20)+1)); !errors.Is(err, libsignalgo.ErrSessionRecordLimit) {
		t.Fatal(err)
	}
}

func TestInspectSessionRecordPQRatchet(t *testing.T) {
	st := inspectionState()
	var err error
	st.PqRatchetState, err = spqr.InitialState(spqr.Params{Version: proto.Version_V_1, MinVersion: proto.Version_V_0, AuthKey: make([]byte, 32), ChainParams: &proto.ChainParams{}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
	if err != nil || !got.Current.PQRatchet.Present || got.Current.PQRatchet.Version != 1 || !got.Current.PQRatchet.Negotiating || got.Current.PQRatchet.MinVersion != 0 {
		t.Fatal("PQ metadata differs", err)
	}
	st.PqRatchetState = nil
	got, err = libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
	if err != nil || got.Current.PQRatchet.Present || got.Current.PQRatchet.Version != 0 {
		t.Fatal("empty PQ metadata differs", err)
	}
	// Hand-built supported storage shapes pin classification; exchanges use genuine Java fixtures.
	pq := &proto.PqRatchetState{Chain: &proto.Chain{
		Params: &proto.ChainParams{}, NextRoot: make([]byte, 32),
		Links: []*proto.Chain_Epoch{{Send: &proto.Chain_Epoch_EpochDirection{Next: make([]byte, 32)}, Recv: &proto.Chain_Epoch_EpochDirection{Next: make([]byte, 32)}}},
	}}
	st.PqRatchetState = inspectionMarshal(t, pq)
	got, err = libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
	if err != nil || !got.Current.PQRatchet.Present || got.Current.PQRatchet.Version != 0 || got.Current.PQRatchet.Negotiating {
		t.Fatal("negotiated V0 metadata differs", err)
	}
	pq.Inner = &proto.PqRatchetState_V1{V1: &proto.V1State{InnerState: &proto.V1State_KeysUnsampled{KeysUnsampled: &proto.V1State_Chunked_KeysUnsampled{Uc: &proto.V1State_Unchunked_KeysUnsampled{Epoch: 1, Auth: &proto.Authenticator{RootKey: make([]byte, 32), MacKey: make([]byte, 32)}}}}}}
	st.PqRatchetState = inspectionMarshal(t, pq)
	got, err = libsignalgo.InspectSessionRecord(inspectionRecord(t, st))
	if err != nil || !got.Current.PQRatchet.Present || got.Current.PQRatchet.Version != 1 || got.Current.PQRatchet.Negotiating {
		t.Fatal("active V1 metadata differs", err)
	}
}

func TestInspectSessionRecordNonMutation(t *testing.T) {
	raw := inspectionRecord(t, inspectionState())
	before := sha256.Sum256(raw)
	got, err := libsignalgo.InspectSessionRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	got.Current.LocalIdentityPublic[1] ^= 1
	again, err := libsignalgo.InspectSessionRecord(raw)
	if err != nil || sha256.Sum256(raw) != before || again.Current.LocalIdentityPublic[1] != 0x42 {
		t.Fatal("inspection aliases input", err)
	}
}
