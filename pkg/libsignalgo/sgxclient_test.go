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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

// The fixtures are upstream libsignal v0.102.2 rust/attest/tests/data (via
// libsignal-go attest/dcap/testdata):
//
//   - cds2_test_cdsi.*: a recorded CDSI staging ClientHandshakeStart, its
//     MRENCLAVE and the time it was recorded (big-endian Unix seconds). It
//     attests in production builds, but the enclave's Noise key is unknown,
//     so the handshake can't be completed offline.
//   - cds2_test.*: the 2022 CDS2 test attestation (evidence, endorsements,
//     MRENCLAVE and the enclave's Noise private key). Its TCB evaluation data
//     number is 12, which upstream accepts only in test-util builds, so both
//     production builds must reject it.

func readSGXTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type cdsiFixture struct {
	mrenclave, msg []byte
	now            time.Time
}

func loadCDSIFixture(t *testing.T) cdsiFixture {
	t.Helper()
	ts := readSGXTestdata(t, "cds2_test_cdsi.timestamp")
	return cdsiFixture{
		mrenclave: readSGXTestdata(t, "cds2_test_cdsi.mrenclave"),
		msg:       readSGXTestdata(t, "cds2_test_cdsi.handshakestart"),
		now:       time.Unix(int64(binary.BigEndian.Uint64(ts)), 0),
	}
}

func (c cdsiFixture) newState(t *testing.T) *libsignalgo.SGXClientState {
	t.Helper()
	s, err := libsignalgo.NewCDS2ClientState(c.mrenclave, c.msg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Destroy() })
	return s
}

// wantSGXCode checks that err carries the error code the cgo build reports
// (bridge/shared/types/src/ffi/error.rs, IntoFfiError for enclave::Error).
func wantSGXCode(t *testing.T, err error, want libsignalgo.ErrorCode) {
	t.Helper()
	var code libsignalgo.ErrorCode
	if !errors.As(err, &code) {
		t.Fatalf("err = %v, want error code %d", err, want)
	}
	if code != want {
		t.Fatalf("err = %v: code %d, want %d", err, code, want)
	}
}

// wantSGXUnusable checks that every call on s fails with InvalidState.
func wantSGXUnusable(t *testing.T, s *libsignalgo.SGXClientState) {
	t.Helper()
	_, err := s.InitialRequest()
	wantSGXCode(t, err, libsignalgo.ErrorCodeInvalidState)
	wantSGXCode(t, s.CompleteHandshake(make([]byte, 48)), libsignalgo.ErrorCodeInvalidState)
	_, err = s.EstablishedSend([]byte("x"))
	wantSGXCode(t, err, libsignalgo.ErrorCodeInvalidState)
	_, err = s.EstablishedReceive(make([]byte, 17))
	wantSGXCode(t, err, libsignalgo.ErrorCodeInvalidState)
}

func TestCDS2ClientState(t *testing.T) {
	c := loadCDSIFixture(t)
	s := c.newState(t)

	initial, err := s.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	// CDS2 is Noise NKhfs: e (32), the encrypted ML-KEM-1024 key (1568 + 16)
	// and the empty payload's tag (16).
	if want := 32 + 1568 + 16 + 16; len(initial) != want {
		t.Fatalf("initial request is %d bytes, want %d", len(initial), want)
	}
	again, err := s.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initial, again) {
		t.Fatal("InitialRequest changed")
	}
	// A second state uses a fresh ephemeral key.
	other, err := c.newState(t).InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(initial, other) {
		t.Fatal("two states sent the same initial request")
	}

	// Nothing is established before the handshake completes.
	_, err = s.EstablishedSend([]byte("x"))
	wantSGXCode(t, err, libsignalgo.ErrorCodeInvalidState)
	_, err = s.EstablishedReceive(make([]byte, 17))
	wantSGXCode(t, err, libsignalgo.ErrorCodeInvalidState)
	if _, err := s.InitialRequest(); err != nil {
		t.Fatalf("InitialRequest after a wrong-state call: %v", err)
	}
}

func TestCDS2ClientStateFailedHandshake(t *testing.T) {
	c := loadCDSIFixture(t)
	for _, tc := range []struct {
		name  string
		reply func(initial []byte) []byte
	}{
		{"empty", func([]byte) []byte { return nil }},
		{"garbage", func([]byte) []byte { return make([]byte, 48+1568+16) }},
		{"short", func([]byte) []byte { return make([]byte, 47) }},
		{"echo", func(initial []byte) []byte { return initial }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := c.newState(t)
			initial, err := s.InitialRequest()
			if err != nil {
				t.Fatal(err)
			}
			wantSGXCode(t, s.CompleteHandshake(tc.reply(initial)), libsignalgo.ErrorCodeInvalidMessage)
			// A failed handshake leaves the state unusable.
			wantSGXUnusable(t, s)
		})
	}
}

func TestCDS2ClientStateRejected(t *testing.T) {
	c := loadCDSIFixture(t)
	flipped := bytes.Clone(c.mrenclave)
	flipped[0] ^= 1
	// CDSI prod accepts the same advisories as the recorded staging enclave,
	// so only the MRENCLAVE comparison rejects it. (An unknown MRENCLAVE is
	// rejected earlier, for the advisories it doesn't accept.)
	cdsiProd, err := hex.DecodeString("15637fa1e54fe655176d3df1a9f94b87c01ed377acaa570682dc5d72c95ef07b")
	if err != nil {
		t.Fatal(err)
	}

	cds2Test := protowire.AppendTag(nil, 2, protowire.BytesType)
	cds2Test = protowire.AppendBytes(cds2Test, readSGXTestdata(t, "cds2_test.evidence"))
	cds2Test = protowire.AppendTag(cds2Test, 3, protowire.BytesType)
	cds2Test = protowire.AppendBytes(cds2Test, readSGXTestdata(t, "cds2_test.endorsements"))
	cds2TestMrenclave, err := hex.DecodeString(string(bytes.TrimSpace(readSGXTestdata(t, "cds2_test.mrenclave"))))
	if err != nil {
		t.Fatal(err)
	}
	// Within the validity of the cds2_test collateral.
	cds2TestTime := time.UnixMilli(1655857680000)

	for _, tc := range []struct {
		name      string
		mrenclave []byte
		msg       []byte
		now       time.Time
		want      libsignalgo.ErrorCode
	}{
		{"other_enclave", cdsiProd, c.msg, c.now, libsignalgo.ErrorCodeInvalidMessage},
		{"unknown_mrenclave", flipped, c.msg, c.now, libsignalgo.ErrorCodeInvalidMessage},
		{"short_mrenclave", c.mrenclave[:31], c.msg, c.now, libsignalgo.ErrorCodeInvalidAttestationData},
		{"expired", c.mrenclave, c.msg, c.now.AddDate(2, 0, 0), libsignalgo.ErrorCodeInvalidMessage},
		{"not_yet_valid", c.mrenclave, c.msg, c.now.AddDate(-2, 0, 0), libsignalgo.ErrorCodeInvalidMessage},
		{"malformed", c.mrenclave, []byte{0xff}, c.now, libsignalgo.ErrorCodeInvalidAttestationData},
		{"truncated", c.mrenclave, c.msg[:len(c.msg)-1], c.now, libsignalgo.ErrorCodeInvalidAttestationData},
		{"empty", c.mrenclave, nil, c.now, libsignalgo.ErrorCodeInvalidAttestationData},
		{"tampered_evidence", c.mrenclave, tamper(c.msg, 1000), c.now, libsignalgo.ErrorCodeInvalidMessage},
		// Evaluation data number 12 is accepted only by test builds.
		{"cds2_test_very_expired", cds2TestMrenclave, cds2Test, cds2TestTime, libsignalgo.ErrorCodeInvalidMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := libsignalgo.NewCDS2ClientState(tc.mrenclave, tc.msg, tc.now)
			if err == nil {
				_ = s.Destroy()
			}
			wantSGXCode(t, err, tc.want)
		})
	}
}

func tamper(b []byte, i int) []byte {
	b = bytes.Clone(b)
	b[i] ^= 1
	return b
}
