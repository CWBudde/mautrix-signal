// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package libsignalgo_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"github.com/google/uuid"
	"github.com/gtank/ristretto255"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

func groupSendCheck(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func groupSendBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	groupSendCheck(t, e)
	return b
}

// The public parameters and fixed artifacts originate from the pinned Rust
// oracle. Receipt uses a fresh expiry and the independently tested generic
// issuance primitive so the same test exercises the CGO and purego shims daily.
type groupSendFixture struct {
	Params struct {
		Seed       string   `json:"seed"`
		MasterKey  string   `json:"master_key"`
		Members    []string `json:"members"`
		Expiration uint64   `json:"expiration"`
	} `json:"params"`
	Result struct {
		Server       string   `json:"server"`
		Response     string   `json:"response"`
		Endorsements []string `json:"endorsements"`
		Combined     string   `json:"combined"`
		Token        string   `json:"token"`
		FullToken    string   `json:"full_token"`
	} `json:"result"`
}

func groupSendLoad(t *testing.T) groupSendFixture {
	t.Helper()
	fixture := os.Getenv("GROUP_SEND_TEST_FIXTURE")
	if fixture == "" {
		fixture = "testdata/group-send.json"
	}
	b, e := os.ReadFile(fixture)
	groupSendCheck(t, e)
	var f groupSendFixture
	groupSendCheck(t, json.Unmarshal(b, &f))
	return f
}
func groupSendFresh(t *testing.T, ids []libsignalgo.ServiceID, g *libsignalgo.GroupSecretParams, seed [32]byte) (libsignalgo.GroupSendEndorsementsResponse, *zkcredential.ServerDerivedKeyPair, time.Time) {
	t.Helper()
	expiry := time.Now().UTC().Truncate(24 * time.Hour).Add(48 * time.Hour)
	sho := poksho.NewShoHmacSha256([]byte("20240215_Signal_GroupSendEndorsement"))
	sho.AbsorbAndRatchet(binary.BigEndian.AppendUint64(nil, uint64(expiry.Unix())))
	key := zkcredential.GenerateServerRootKeyPair(seed).DeriveKey(sho)
	type entry struct {
		p    *ristretto255.Element
		sort []byte
	}
	entries := make([]entry, len(ids))
	for i, id := range ids {
		c, e := g.EncryptServiceID(id)
		groupSendCheck(t, e)
		p, e := ristretto255.NewIdentityElement().SetCanonicalBytes(c[1:33])
		groupSendCheck(t, e)
		entries[i] = entry{p, ristretto255.NewIdentityElement().Add(p, p).Bytes()}
	}
	slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare(a.sort, b.sort) })
	points := make([]*ristretto255.Element, len(ids))
	for i, e := range entries {
		points[i] = e.p
	}
	response, e := zkcredential.IssueEndorsements(points, key, [32]byte{42})
	groupSendCheck(t, e)
	return binary.LittleEndian.AppendUint64(append([]byte{0}, response.Bytes()...), uint64(expiry.Unix())), key, expiry
}
func groupSendVerify(t *testing.T, key *zkcredential.ServerDerivedKeyPair, token libsignalgo.GroupSendFullToken, ids []libsignalgo.ServiceID) {
	t.Helper()
	groupSendCheck(t, token.CheckValidContents())
	sum := ristretto255.NewIdentityElement()
	for _, id := range ids {
		parsed, e := address.ParseServiceIDFixedWidthBinary(*id.FixedBytes())
		groupSendCheck(t, e)
		sum.Add(sum, zkcrypto.NewUID(parsed).Points()[0])
	}
	groupSendCheck(t, key.VerifyToken(sum, token[9:len(token)-8]))
}
func TestGroupSendEndorsementShim(t *testing.T) {
	f := groupSendLoad(t)
	g, e := libsignalgo.GroupMasterKey(groupSendBytes(t, f.Params.MasterKey)).SecretParams()
	groupSendCheck(t, e)
	spp, e := libsignalgo.DeserializeServerPublicParams(groupSendBytes(t, f.Result.Server))
	groupSendCheck(t, e)
	var ids []libsignalgo.ServiceID
	for _, v := range f.Params.Members {
		b := groupSendBytes(t, v)
		ids = append(ids, libsignalgo.ServiceID{Type: libsignalgo.ServiceIDType(b[0]), UUID: uuid.UUID(b[1:])})
	}
	var endorsements []libsignalgo.GroupSendEndorsement
	for _, v := range f.Result.Endorsements {
		endorsements = append(endorsements, groupSendBytes(t, v))
	}
	combined, e := libsignalgo.GroupSendEndorsementCombine(endorsements[1:]...)
	groupSendCheck(t, e)
	if !bytes.Equal(combined, groupSendBytes(t, f.Result.Combined)) {
		t.Fatal("Rust combined differs")
	}
	token, e := combined.ToToken(&g)
	groupSendCheck(t, e)
	if !bytes.Equal(token, groupSendBytes(t, f.Result.Token)) {
		t.Fatal("Rust token differs")
	}
	full, e := token.ToFullToken(time.Unix(int64(f.Params.Expiration), 0))
	groupSendCheck(t, e)
	if !bytes.Equal(full, groupSendBytes(t, f.Result.FullToken)) {
		t.Fatal("Rust full token differs")
	}
	response, key, expiry := groupSendFresh(t, ids, &g, [32]byte(groupSendBytes(t, f.Params.Seed)))
	groupSendCheck(t, response.CheckValidContents())
	gotExpiry, e := response.GetExpiration()
	groupSendCheck(t, e)
	if !gotExpiry.Equal(expiry) {
		t.Fatal("response expiry differs")
	}
	// All positions of localUser must be excluded from the combined token, while
	// the map retains that user's individual endorsement (Rust bridge contract).
	for local := range ids {
		combined, received, e := response.ReceiveWithServiceIDs(ids, ids[local], &g, spp)
		groupSendCheck(t, e)
		if len(received) != len(ids) {
			t.Fatal("member map incomplete")
		}
		others := append(slices.Clone(ids[:local]), ids[local+1:]...)
		full, e := combined.ToFullToken(&g, expiry)
		groupSendCheck(t, e)
		groupSendVerify(t, key, full, others)
		gotExpiry, e = full.GetExpiration()
		groupSendCheck(t, e)
		if !gotExpiry.Equal(expiry) {
			t.Fatal("token expiry differs")
		}
		individual, e := received[ids[local]].ToFullToken(&g, expiry)
		groupSendCheck(t, e)
		groupSendVerify(t, key, individual, ids[local:local+1])
	}
	combined, received, e := response.ReceiveWithServiceIDs(ids, ids[0], &g, spp)
	groupSendCheck(t, e)
	removed, e := combined.Remove(received[ids[1]])
	groupSendCheck(t, e)
	full, e = removed.ToFullToken(&g, expiry)
	groupSendCheck(t, e)
	groupSendVerify(t, key, full, ids[2:])
	response[len(response)/2] ^= 1
	if _, _, e = response.ReceiveWithServiceIDs(ids, ids[0], &g, spp); e == nil {
		t.Fatal("accepted tampered response")
	}
}
