// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

var acceptancePNI = uuid.MustParse("00000000-0000-0000-0000-000000000002")

func acceptanceGroup(t *testing.T) *signalpb.GroupResponse {
	t.Helper()
	info := joinPreviewProto(t)
	f := loadJoinFixture(t)
	editor, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(f.self))
	joinCheck(t, err)
	g := &signalpb.Group{PublicKey: bytes.Clone(info.PublicKey), Title: bytes.Clone(info.Title), Description: bytes.Clone(info.Description), Version: 7, AccessControl: &signalpb.AccessControl{Members: signalpb.AccessControl_ADMINISTRATOR}}
	for _, sid := range []libsignalgo.ServiceID{libsignalgo.NewACIServiceID(f.self), libsignalgo.NewPNIServiceID(acceptancePNI)} {
		id, err := f.secret.EncryptServiceID(sid)
		joinCheck(t, err)
		g.MembersPendingProfileKey = append(g.MembersPendingProfileKey, &signalpb.MemberPendingProfileKey{Member: &signalpb.Member{UserId: id[:], Role: signalpb.Member_DEFAULT}, AddedByUserId: bytes.Clone(editor[:]), Timestamp: 1234})
	}
	presentation, err := f.secret.CreateExpiringProfileKeyCredentialPresentation(f.server, *f.credential)
	joinCheck(t, err)
	cipher, err := presentation.UUIDCiphertext()
	joinCheck(t, err)
	profile, err := presentation.ProfileKeyCiphertext()
	joinCheck(t, err)
	g.Members = []*signalpb.Member{{UserId: bytes.Clone(cipher[:]), ProfileKey: bytes.Clone(profile[:]), Role: signalpb.Member_ADMINISTRATOR, JoinedAtVersion: 3}}
	g.MembersPendingAdminApproval = []*signalpb.MemberPendingAdminApproval{{UserId: bytes.Clone(cipher[:]), ProfileKey: bytes.Clone(profile[:]), Timestamp: 12345}}
	g.MembersBanned = []*signalpb.MemberBanned{{UserId: bytes.Clone(editor[:]), Timestamp: 42}}
	g.InviteLinkPassword = bytes.Repeat([]byte{9}, 16)
	blob, err := proto.Marshal(&signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_DisappearingMessagesDuration{DisappearingMessagesDuration: 60}})
	joinCheck(t, err)
	g.DisappearingMessagesTimer, err = f.secret.EncryptBlobWithPaddingDeterministic(libsignalgo.Randomness{1}, blob, 0)
	joinCheck(t, err)
	g.AnnouncementsOnly = true
	return &signalpb.GroupResponse{Group: g}
}

func TestGroupAcceptanceRead(t *testing.T) {
	fixture := acceptanceGroup(t)
	raw, err := proto.Marshal(fixture)
	joinCheck(t, err)
	bodies := []*joinBody{}
	calls := 0
	joinHTTP(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodGet || req.URL.String() != "https://storage.signal.org/v2/groups/" || req.GetBody != nil {
			t.Fatal("wrong acceptance read request")
		}
		if u, p, ok := req.BasicAuth(); !ok || u != "test-user" || p != "test-auth" {
			t.Fatal("missing auth")
		}
		b := &joinBody{Reader: bytes.NewReader(raw)}
		bodies = append(bodies, b)
		return joinResponse(200, b), nil
	})
	// The injected client has no stores/cache: any write or cached read would fail.
	first, err := signalmeow.FetchGroupForAcceptanceForTest(context.Background(), joinKey())
	joinCheck(t, err)
	first.PendingMembers[0].Role = 99
	first.Title = "mutated"
	second, err := signalmeow.FetchGroupForAcceptanceForTest(context.Background(), joinKey())
	joinCheck(t, err)
	f := loadJoinFixture(t)
	if calls != 2 || first == second || second.Revision != 7 || second.Title != "Test group" || second.Description != "A group" || len(second.PendingMembers) != 2 || second.PendingMembers[0].ServiceID != libsignalgo.NewACIServiceID(f.self) || second.PendingMembers[1].ServiceID != libsignalgo.NewPNIServiceID(acceptancePNI) || second.PendingMembers[0].Role != signalmeow.GroupMember_DEFAULT || len(second.Members) != 1 || second.Members[0].ACI != f.self || second.Members[0].Role != signalmeow.GroupMember_ADMINISTRATOR || len(second.RequestingMembers) != 1 || second.RequestingMembers[0].ACI != f.self || len(second.BannedMembers) != 1 || second.DisappearingMessagesDuration != 60 || !second.AnnouncementsOnly || second.InviteLinkPassword == nil {
		t.Fatal("read lost fresh owned full-state data")
	}
	for _, b := range bodies {
		if !b.closed {
			t.Fatal("body not closed")
		}
	}
}

func TestGroupAcceptanceReadMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupResponse, *http.Response)
		want   error
	}{
		{"missing group", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group = nil }, nil},
		{"missing nested pending", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.MembersPendingProfileKey[0].Member = nil }, nil},
		{"short pending ID", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.MembersPendingProfileKey[0].Member.UserId = []byte{1}
		}, nil},
		{"short added by", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.MembersPendingProfileKey[0].AddedByUserId = []byte{1}
		}, nil},
		{"short member ID", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.Members = []*signalpb.Member{{UserId: []byte{1}, ProfileKey: []byte{1}}}
		}, nil},
		{"short profile", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.Members = []*signalpb.Member{{UserId: g.Group.MembersPendingProfileKey[0].Member.UserId, ProfileKey: []byte{1}}}
		}, nil},
		{"malformed presentation", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.Members = []*signalpb.Member{{Presentation: []byte{1}}}
		}, nil},
		{"request ciphertext", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.MembersPendingAdminApproval = []*signalpb.MemberPendingAdminApproval{{UserId: []byte{1}, ProfileKey: []byte{1}}}
		}, nil},
		{"ban ciphertext", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.MembersBanned = []*signalpb.MemberBanned{{UserId: []byte{1}}}
		}, nil},
		{"invalid member ciphertext", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.Members[0].UserId = make([]byte, len(libsignalgo.UUIDCiphertext{}))
		}, nil},
		{"invalid pending ciphertext", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.MembersPendingProfileKey[0].Member.UserId = make([]byte, len(libsignalgo.UUIDCiphertext{}))
		}, nil},
		{"invalid profile ciphertext", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.Members[0].ProfileKey = make([]byte, len(libsignalgo.ProfileKeyCiphertext{}))
		}, nil},
		{"short pending profile ciphertext", func(g *signalpb.GroupResponse, _ *http.Response) {
			g.Group.MembersPendingProfileKey[0].Member.ProfileKey = []byte{1}
		}, nil},
		{"corrupt authenticated title", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.Title[0] ^= 1 }, nil},
		{"wrong public", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.PublicKey[1] ^= 1 }, nil},
		{"short public", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.PublicKey = []byte{1} }, nil},
		{"missing title", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.Title = nil }, nil},
		{"corrupt title", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.Title = []byte{1} }, nil},
		{"wrong title", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.Title = g.Group.Description }, nil},
		{"corrupt description", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.Description = []byte{1} }, nil},
		{"corrupt timer", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.DisappearingMessagesTimer = []byte{1} }, nil},
		{"wrong timer", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.DisappearingMessagesTimer = g.Group.Title }, nil},
		{"invite password", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.InviteLinkPassword = []byte{1} }, nil},
		{"missing timestamp", func(_ *signalpb.GroupResponse, r *http.Response) { r.Header.Del("X-Signal-Timestamp") }, nil},
		{"bad timestamp", func(_ *signalpb.GroupResponse, r *http.Response) { r.Header.Set("X-Signal-Timestamp", "secret") }, nil},
		{"overflow timestamp", func(_ *signalpb.GroupResponse, r *http.Response) {
			r.Header.Set("X-Signal-Timestamp", "18446744073709551616")
		}, nil},
		{"forbidden", func(_ *signalpb.GroupResponse, r *http.Response) { r.StatusCode = 403 }, signalmeow.AuthorizationFailedError},
		{"terminated", func(_ *signalpb.GroupResponse, r *http.Response) { r.StatusCode = 423 }, signalmeow.ErrGroupAcceptanceTerminated},
		{"terminated state", func(g *signalpb.GroupResponse, _ *http.Response) { g.Group.Terminated = true }, signalmeow.ErrGroupAcceptanceTerminated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := acceptanceGroup(t)
			res := joinResponse(200, nil)
			tc.modify(g, res)
			raw, err := proto.Marshal(g)
			joinCheck(t, err)
			b := &joinBody{Reader: bytes.NewReader(raw)}
			res.Body = b
			joinHTTP(t, func(*http.Request) (*http.Response, error) { return res, nil })
			got, err := signalmeow.FetchGroupForAcceptanceForTest(context.Background(), joinKey())
			if err == nil || got != nil || !b.closed || errors.Is(err, signalmeow.ErrGroupAcceptanceUncertain) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid read accepted or leaked: %v", err)
			}
			if tc.want == nil && !errors.Is(err, signalmeow.ErrGroupAcceptanceInvalid) {
				t.Fatalf("malformed state lost invalid sentinel: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("lost sentinel: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"oversized", strings.NewReader(strings.Repeat("x", (1<<20)+1))}, {"empty", bytes.NewReader(nil)}, {"failed", joinFailReader{errors.New("secret reader failure")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &joinBody{Reader: tc.reader}
			joinHTTP(t, func(*http.Request) (*http.Response, error) { return joinResponse(200, b), nil })
			_, err := signalmeow.FetchGroupForAcceptanceForTest(context.Background(), joinKey())
			if err == nil || !b.closed || errors.Is(err, signalmeow.ErrGroupAcceptanceUncertain) || strings.Contains(err.Error(), "secret") {
				t.Fatal("invalid read outcome")
			}
		})
	}
}

func TestGroupAcceptanceReadPreflight(t *testing.T) {
	calls := 0
	joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected") })
	for _, key := range []types.SerializedGroupMasterKey{"secret", "AQ=="} {
		_, err := signalmeow.FetchGroupForAcceptanceForTest(context.Background(), key)
		if err == nil || calls != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid key submitted or leaked")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := signalmeow.FetchGroupForAcceptanceForTest(ctx, joinKey())
	if calls != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read submitted")
	}
	for _, cli := range []*signalmeow.Client{nil, {}} {
		if _, err = cli.FetchGroupForAcceptance(context.Background(), joinKey()); err == nil {
			t.Fatal("missing account read")
		}
	}
}
func TestGroupAcceptanceReadUnknownMetadata(t *testing.T) {
	fixture := acceptanceGroup(t)
	fixture.Group.ProtoReflect().SetUnknown([]byte{0xf8, 7, 1})
	raw, err := proto.Marshal(fixture)
	joinCheck(t, err)
	joinHTTP(t, func(*http.Request) (*http.Response, error) {
		return joinResponse(200, io.NopCloser(bytes.NewReader(raw))), nil
	})
	group, err := signalmeow.FetchGroupForAcceptanceForTest(context.Background(), joinKey())
	joinCheck(t, err)
	if group.Title != "Test group" || len(group.PendingMembers) != 2 {
		t.Fatal("unrelated metadata hid authorization fields")
	}
}

func TestGroupAcceptanceReadMissingIdentity(t *testing.T) {
	cli := &signalmeow.Client{Store: &store.Device{}}
	_, err := cli.FetchGroupForAcceptance(context.Background(), joinKey())
	if !errors.Is(err, signalmeow.ErrGroupAcceptanceInvalid) {
		t.Fatal("missing selected account identity did not fail locally")
	}
}
