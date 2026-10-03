// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

// Catches password-bearing URLs, unauthenticated previews, unbound parameters,
// invalid timestamps/attributes, and treating disabled links as cancellation bans.
func TestGroupJoinRequestPreview(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupJoinInfo, *http.Response)
		bad    bool
	}{
		{"pending", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.PendingAdminApproval = true }, false},
		{"not pending", func(*signalpb.GroupJoinInfo, *http.Response) {}, false},
		{"disabled pending", func(g *signalpb.GroupJoinInfo, _ *http.Response) {
			g.AddFromInviteLink = signalpb.AccessControl_UNSATISFIABLE
			g.PendingAdminApproval = true
		}, false},
		{"optional description", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Description = nil }, false},
		{"wrong public", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.PublicKey[0] ^= 1 }, true},
		{"missing public", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.PublicKey = nil }, true},
		{"missing title", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Title = nil }, true},
		{"corrupt title", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Title = []byte{1} }, true},
		{"wrong title", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Title = g.Description }, true},
		{"wrong description", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Description = g.Title }, true},
		{"missing timestamp", func(_ *signalpb.GroupJoinInfo, r *http.Response) { r.Header.Del("X-Signal-Timestamp") }, true},
		{"malformed timestamp", func(_ *signalpb.GroupJoinInfo, r *http.Response) { r.Header.Set("X-Signal-Timestamp", "secret") }, true},
		{"negative timestamp", func(_ *signalpb.GroupJoinInfo, r *http.Response) { r.Header.Set("X-Signal-Timestamp", "-1") }, true},
		{"timestamp overflow", func(_ *signalpb.GroupJoinInfo, r *http.Response) {
			r.Header.Set("X-Signal-Timestamp", "18446744073709551616")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := joinPreviewProto(t)
			response := joinResponse(http.StatusOK, nil)
			tc.modify(info, response)
			raw, err := proto.Marshal(info)
			joinCheck(t, err)
			body := &joinBody{Reader: bytes.NewReader(raw)}
			response.Body = body
			calls := 0
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.URL.String() != "https://storage.signal.org/v2/groups/join/" || req.GetBody != nil {
					t.Fatal("preview requires exact password-free GET")
				}
				user, pass, ok := req.BasicAuth()
				if !ok || user != "test-user" || pass != "test-auth" {
					t.Fatal("missing group authentication")
				}
				return response, nil
			})
			preview, err := signalmeow.PreviewGroupJoinRequestForTest(context.Background(), joinKey())
			if tc.bad {
				if !errors.Is(err, signalmeow.ErrGroupCancellationInvalid) {
					t.Fatalf("expected invalid preview: %v", err)
				}
			} else {
				joinCheck(t, err)
				if preview.Title != "Test group" || preview.Revision != 7 || preview.Access != signalmeow.AccessControl(info.AddFromInviteLink) || preview.PendingAdminApproval != info.PendingAdminApproval {
					t.Fatal("lost authenticated preview fields")
				}
				if (len(info.Description) == 0 && preview.Description != "") || (len(info.Description) != 0 && preview.Description != "A group") {
					t.Fatal("lost description")
				}
			}
			if calls != 1 || !body.closed {
				t.Fatal("preview replayed or body leaked")
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("preview leaked secret")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"empty", strings.NewReader("")}, {"malformed", bytes.NewReader([]byte{255})}, {"oversized", strings.NewReader(strings.Repeat("x", (1<<20)+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &joinBody{Reader: tc.reader}
			joinHTTP(t, func(*http.Request) (*http.Response, error) { return joinResponse(200, body), nil })
			_, err := signalmeow.PreviewGroupJoinRequestForTest(context.Background(), joinKey())
			if !errors.Is(err, signalmeow.ErrGroupCancellationInvalid) || !body.closed {
				t.Fatal("invalid preview body accepted or leaked")
			}
		})
	}
	for _, status := range []int{403, 404, 423} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			joinHTTP(t, func(*http.Request) (*http.Response, error) {
				return joinResponse(status, io.NopCloser(strings.NewReader("secret"))), nil
			})
			_, err := signalmeow.PreviewGroupJoinRequestForTest(context.Background(), joinKey())
			var want error = signalmeow.AuthorizationFailedError
			if status == 404 {
				want = signalmeow.NotFoundError
			}
			if status == 423 {
				want = signalmeow.ErrGroupCancellationTerminated
			}
			if !errors.Is(err, want) {
				t.Fatalf("refusal cannot prove absence: %v", err)
			}
		})
	}
	t.Run("invalid account or key", func(t *testing.T) {
		for _, cli := range []*signalmeow.Client{nil, {}} {
			for _, key := range []types.SerializedGroupMasterKey{joinKey(), "bad", "AQ=="} {
				_, err := cli.PreviewGroupJoinRequest(context.Background(), key)
				if !errors.Is(err, signalmeow.ErrGroupCancellationInvalid) {
					t.Fatal("invalid account/key accepted")
				}
			}
		}
	})
}

func cancellationRun(ctx context.Context, f joinFixture, revision uint32) (signalmeow.GroupJoinRequestCancelOutcome, error) {
	return signalmeow.GroupJoinRequestCancellationOnceForTest(ctx, joinKey(), revision, f.self, f.server, nil)
}

func cancellationResponseActions(t *testing.T, f joinFixture, actions *signalpb.GroupChange_Actions) *signalpb.GroupChange_Actions {
	t.Helper()
	actions = proto.Clone(actions).(*signalpb.GroupChange_Actions)
	id, err := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32)).GroupIdentifier()
	joinCheck(t, err)
	actions.GroupId = bytes.Clone(id[:])
	source, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(f.self))
	joinCheck(t, err)
	actions.SourceUserId = bytes.Clone(source[:])
	return actions
}

// Catches a generic mutation, wrong account/kind, profile/full-state fetch,
// password/query use, retries, missing signed verification, or retained aliases.
func TestGroupJoinRequestCancellationWire(t *testing.T) {
	f := loadJoinFixture(t)
	calls := 0
	var signed []byte
	body := &joinBody{}
	joinHTTP(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPatch || req.URL.String() != "https://storage.signal.org/v2/groups/" || req.GetBody != nil {
			t.Fatal("wrong one-shot cancellation endpoint")
		}
		user, pass, ok := req.BasicAuth()
		if !ok || user != "test-user" || pass != "test-auth" {
			t.Fatal("missing group authentication")
		}
		actions := acceptanceRequest(t, req)
		acceptanceOnlyFields(t, actions, "sourceUserId", "version", "deleteMembersPendingAdminApproval")
		if actions.Version != 8 || !bytes.Equal(actions.SourceUserId, f.self[:]) || len(actions.DeleteMembersPendingAdminApproval) != 1 {
			t.Fatal("wrong own ACI cancellation metadata")
		}
		deletion := actions.DeleteMembersPendingAdminApproval[0]
		acceptanceOnlyFields(t, deletion, "deletedUserId")
		if len(deletion.DeletedUserId) != len(libsignalgo.UUIDCiphertext{}) {
			t.Fatal("deletion must encrypt own ACI")
		}
		self, err := f.secret.DecryptServiceID(libsignalgo.UUIDCiphertext(deletion.DeletedUserId))
		joinCheck(t, err)
		if self != libsignalgo.NewACIServiceID(f.self) {
			t.Fatal("wrong encrypted identity")
		}
		signed = f.signed(t, cancellationResponseActions(t, f, actions), 7)
		body.Reader = bytes.NewReader(signed)
		response := joinResponse(200, body)
		response.Header.Del("X-Signal-Timestamp") // PATCH needs no preview timestamp.
		return response, nil
	})
	out, err := cancellationRun(context.Background(), f, 7)
	joinCheck(t, err)
	if calls != 1 || !body.closed || !out.Attempted || !out.Accepted || !out.Verified || out.Revision != 8 || out.GroupContext == nil || out.Change == nil {
		t.Fatal("wrong verified cancellation outcome")
	}
	if out.GroupContext.GetRevision() != 8 || !bytes.Equal(out.GroupContext.MasterKey, bytes.Repeat([]byte{42}, 32)) || out.Change.GroupMasterKey != joinKey() || out.Change.Revision != 8 || out.Change.SourceServiceID != libsignalgo.NewACIServiceID(f.self) || len(out.Change.DeleteRequestingMembers) != 1 || *out.Change.DeleteRequestingMembers[0] != f.self {
		t.Fatal("verified context/change lost binding")
	}
	retained := bytes.Clone(out.GroupContext.GroupChange)
	for i := range signed {
		signed[i] ^= 255
	}
	if !bytes.Equal(retained, out.GroupContext.GroupChange) {
		t.Fatal("context aliases transport body")
	}
}

// Catches accepting a valid signature over a different group, revision, source,
// deletion identity/kind, unsupported epoch, or unrelated/unknown signed fields.
func TestGroupJoinRequestCancellationResponseBinding(t *testing.T) {
	f := loadJoinFixture(t)
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupChange_Actions)
		epoch  uint32
		valid  bool
	}{
		{"epoch zero", func(*signalpb.GroupChange_Actions) {}, 0, true},
		{"epoch seven", func(*signalpb.GroupChange_Actions) {}, 7, true},
		{"epoch eight", func(*signalpb.GroupChange_Actions) {}, 8, false},
		{"wrong group", func(a *signalpb.GroupChange_Actions) { a.GroupId[0] ^= 1 }, 7, false},
		{"missing group", func(a *signalpb.GroupChange_Actions) { a.GroupId = nil }, 7, false},
		{"wrong revision", func(a *signalpb.GroupChange_Actions) { a.Version++ }, 7, false},
		{"wrong source", func(a *signalpb.GroupChange_Actions) {
			id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(acceptancePNI))
			joinCheck(t, err)
			a.SourceUserId = id[:]
		}, 7, false},
		{"PNI source same UUID", func(a *signalpb.GroupChange_Actions) {
			id, err := f.secret.EncryptServiceID(libsignalgo.NewPNIServiceID(f.self))
			joinCheck(t, err)
			a.SourceUserId = id[:]
		}, 7, false},
		{"missing source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = nil }, 7, false},
		{"short source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = []byte{1} }, 7, false},
		{"long source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = append(a.SourceUserId, 1) }, 7, false},
		{"corrupt source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = bytes.Repeat([]byte{255}, len(a.SourceUserId)) }, 7, false},
		{"wrong target", func(a *signalpb.GroupChange_Actions) {
			id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(acceptancePNI))
			joinCheck(t, err)
			a.DeleteMembersPendingAdminApproval[0].DeletedUserId = id[:]
		}, 7, false},
		{"PNI target same UUID", func(a *signalpb.GroupChange_Actions) {
			id, err := f.secret.EncryptServiceID(libsignalgo.NewPNIServiceID(f.self))
			joinCheck(t, err)
			a.DeleteMembersPendingAdminApproval[0].DeletedUserId = id[:]
		}, 7, false},
		{"missing target", func(a *signalpb.GroupChange_Actions) { a.DeleteMembersPendingAdminApproval[0].DeletedUserId = nil }, 7, false},
		{"short target", func(a *signalpb.GroupChange_Actions) {
			a.DeleteMembersPendingAdminApproval[0].DeletedUserId = []byte{1}
		}, 7, false},
		{"long target", func(a *signalpb.GroupChange_Actions) {
			a.DeleteMembersPendingAdminApproval[0].DeletedUserId = append(a.DeleteMembersPendingAdminApproval[0].DeletedUserId, 1)
		}, 7, false},
		{"corrupt target", func(a *signalpb.GroupChange_Actions) {
			a.DeleteMembersPendingAdminApproval[0].DeletedUserId = bytes.Repeat([]byte{255}, len(libsignalgo.UUIDCiphertext{}))
		}, 7, false},
		{"missing deletion", func(a *signalpb.GroupChange_Actions) { a.DeleteMembersPendingAdminApproval = nil }, 7, false},
		{"nil deletion", func(a *signalpb.GroupChange_Actions) { a.DeleteMembersPendingAdminApproval[0] = nil }, 7, false},
		{"multiple deletions", func(a *signalpb.GroupChange_Actions) {
			a.DeleteMembersPendingAdminApproval = append(a.DeleteMembersPendingAdminApproval, a.DeleteMembersPendingAdminApproval[0])
		}, 7, false},
		{"full member deletion", func(a *signalpb.GroupChange_Actions) {
			a.DeleteMembers = []*signalpb.GroupChange_Actions_DeleteMemberAction{{DeletedUserId: a.DeleteMembersPendingAdminApproval[0].DeletedUserId}}
			a.DeleteMembersPendingAdminApproval = nil
		}, 7, false},
		{"unrelated field", func(a *signalpb.GroupChange_Actions) {
			a.ModifyAvatar = &signalpb.GroupChange_Actions_ModifyAvatarAction{Avatar: "secret"}
		}, 7, false},
		{"unknown actions", func(a *signalpb.GroupChange_Actions) { a.ProtoReflect().SetUnknown([]byte{0xf8, 7, 1}) }, 7, false},
		{"unknown deletion", func(a *signalpb.GroupChange_Actions) {
			a.DeleteMembersPendingAdminApproval[0].ProtoReflect().SetUnknown([]byte{0xf8, 7, 1})
		}, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				a := cancellationResponseActions(t, f, acceptanceRequest(t, req))
				tc.modify(a)
				return joinResponse(200, io.NopCloser(bytes.NewReader(f.signed(t, a, tc.epoch)))), nil
			})
			out, err := cancellationRun(context.Background(), f, 7)
			if !out.Attempted || !out.Accepted || out.Revision != 8 {
				t.Fatal("lost accepted revision")
			}
			if tc.valid {
				joinCheck(t, err)
				if !out.Verified {
					t.Fatal("valid deletion rejected")
				}
			} else if !errors.Is(err, signalmeow.ErrGroupCancellationInvalid) || out.Verified || out.Change != nil || out.GroupContext != nil {
				t.Fatal("invalid signed deletion propagated")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupChangeResponse)
	}{
		{"bad signature", func(r *signalpb.GroupChangeResponse) { r.GroupChange.ServerSignature[0] ^= 1 }},
		{"short signature", func(r *signalpb.GroupChangeResponse) {
			r.GroupChange.ServerSignature = r.GroupChange.ServerSignature[:63]
		}},
		{"long signature", func(r *signalpb.GroupChangeResponse) {
			r.GroupChange.ServerSignature = append(r.GroupChange.ServerSignature, 1)
		}},
		{"missing signed actions", func(r *signalpb.GroupChangeResponse) { r.GroupChange.Actions = nil }},
		{"malformed signed actions", func(r *signalpb.GroupChangeResponse) {
			raw := []byte{255}
			sig, err := f.signer.Sign(raw, poksho.NewShoHmacSha256([]byte("cancellation malformed signed actions")))
			joinCheck(t, err)
			r.GroupChange.Actions = raw
			r.GroupChange.ServerSignature = sig
		}},
		{"unknown signed envelope", func(r *signalpb.GroupChangeResponse) { r.GroupChange.ProtoReflect().SetUnknown([]byte{0xf8, 7, 1}) }},
		{"missing signed change", func(r *signalpb.GroupChangeResponse) { r.GroupChange = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				response := &signalpb.GroupChangeResponse{}
				joinCheck(t, proto.Unmarshal(f.signed(t, cancellationResponseActions(t, f, acceptanceRequest(t, req)), 7), response))
				tc.modify(response)
				raw, err := proto.Marshal(response)
				joinCheck(t, err)
				return joinResponse(200, io.NopCloser(bytes.NewReader(raw))), nil
			})
			out, err := cancellationRun(context.Background(), f, 7)
			if !errors.Is(err, signalmeow.ErrGroupCancellationInvalid) || !out.Accepted || out.Verified || out.Change != nil || out.GroupContext != nil {
				t.Fatal("invalid signed envelope propagated")
			}
		})
	}
}

// An administrator approval race yields one conflict; cancellation must never
// switch to deleting full membership or resubmit against a fetched revision.
func TestGroupJoinRequestCancellationRace(t *testing.T) {
	f := loadJoinFixture(t)
	calls := 0
	joinHTTP(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPatch {
			t.Fatal("race triggered full state fetch")
		}
		a := acceptanceRequest(t, req)
		if a.Version != 8 || len(a.DeleteMembersPendingAdminApproval) != 1 || len(a.DeleteMembers) != 0 {
			t.Fatal("race broadened cancellation")
		}
		return joinResponse(409, io.NopCloser(strings.NewReader("secret administrator approval"))), nil
	})
	out, err := cancellationRun(context.Background(), f, 7)
	if !errors.Is(err, signalmeow.ConflictError) || calls != 1 || !out.Attempted || out.Accepted || out.Verified || out.Revision != 8 {
		t.Fatal("race retried or lost attempted revision")
	}
}

func TestGroupJoinRequestCancellationFailures(t *testing.T) {
	f := loadJoinFixture(t)
	cause := &url.Error{Op: "secret", URL: "https://secret.invalid/key", Err: context.Canceled}
	for _, tc := range []struct {
		name     string
		key      types.SerializedGroupMasterKey
		revision uint32
		aci      uuid.UUID
		server   *libsignalgo.ServerPublicParams
		authErr  error
		want     error
	}{
		{"overflow", joinKey(), ^uint32(0), f.self, f.server, nil, signalmeow.ErrGroupCancellationInvalid},
		{"zero ACI", joinKey(), 7, uuid.Nil, f.server, nil, signalmeow.ErrGroupCancellationInvalid},
		{"invalid key", "secret", 7, f.self, f.server, nil, signalmeow.ErrGroupCancellationInvalid},
		{"short key", "AQ==", 7, f.self, f.server, nil, signalmeow.ErrGroupCancellationInvalid},
		{"nil verification parameters", joinKey(), 7, f.self, nil, nil, signalmeow.ErrGroupCancellationInvalid},
		{"authorization failed", joinKey(), 7, f.self, f.server, cause, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return nil, cause })
			out, err := signalmeow.GroupJoinRequestCancellationOnceForTest(context.Background(), tc.key, tc.revision, tc.aci, tc.server, tc.authErr)
			if calls != 0 || out.Attempted || out.Accepted || out.Verified || !errors.Is(err, tc.want) || strings.Contains(err.Error(), "secret") {
				t.Fatal("preflight submitted or lost safe error identity")
			}
		})
	}
	for _, cli := range []*signalmeow.Client{nil, {}} {
		out, err := cli.CancelGroupJoinRequestOnce(context.Background(), joinKey(), 7)
		if !errors.Is(err, signalmeow.ErrGroupCancellationInvalid) || out.Attempted {
			t.Fatal("invalid account submitted")
		}
	}
	t.Run("canceled before submission", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, err := cancellationRun(ctx, f, 7)
		if out.Attempted || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled operation submitted")
		}
	})
	for _, tc := range []struct {
		status int
		want   error
	}{
		{400, signalmeow.GroupPatchNotAcceptedError}, {401, signalmeow.AuthorizationFailedError}, {403, signalmeow.AuthorizationFailedError}, {404, signalmeow.NotFoundError}, {409, signalmeow.ConflictError}, {423, signalmeow.ErrGroupCancellationTerminated}, {429, signalmeow.RateLimitError}, {499, signalmeow.DeprecatedVersionError}, {500, signalmeow.ErrGroupCancellationUncertain}, {204, signalmeow.ErrGroupCancellationUncertain}, {307, signalmeow.ErrGroupCancellationUncertain},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			calls := 0
			body := &joinBody{Reader: strings.NewReader("secret")}
			joinHTTP(t, func(*http.Request) (*http.Response, error) {
				calls++
				response := joinResponse(tc.status, body)
				response.Header.Set("Location", "https://secret.invalid")
				return response, nil
			})
			out, err := cancellationRun(context.Background(), f, 7)
			if calls != 1 || !body.closed || !out.Attempted || out.Accepted || out.Verified || out.Revision != 8 || !errors.Is(err, tc.want) || strings.Contains(err.Error(), "secret") {
				t.Fatal("wrong refusal/uncertainty outcome")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"unreadable", joinFailReader{errors.New("secret read failure")}}, {"empty", strings.NewReader("")}, {"oversized", strings.NewReader(strings.Repeat("x", (1<<20)+1))}, {"invalid protobuf", bytes.NewReader([]byte{255})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			body := &joinBody{Reader: tc.reader}
			joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return joinResponse(200, body), nil })
			out, err := cancellationRun(context.Background(), f, 7)
			if err == nil || calls != 1 || !body.closed || !out.Attempted || !out.Accepted || out.Verified || out.Revision != 8 || out.GroupContext != nil || out.Change != nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("lost accepted partial outcome")
			}
		})
	}
	t.Run("transport cancellation and log privacy", func(t *testing.T) {
		calls := 0
		var logs bytes.Buffer
		ctx := zerolog.New(&logs).Level(zerolog.TraceLevel).WithContext(context.Background())
		joinHTTP(t, func(req *http.Request) (*http.Response, error) {
			calls++
			zerolog.Ctx(req.Context()).Trace().Str("secret", "key").Msg("dependency")
			return nil, cause
		})
		out, err := cancellationRun(ctx, f, 7)
		var urlErr *url.Error
		if calls != 1 || !out.Attempted || out.Accepted || out.Verified || out.Revision != 8 || !errors.Is(err, signalmeow.ErrGroupCancellationUncertain) || !errors.Is(err, context.Canceled) || !errors.As(err, &urlErr) || strings.Contains(err.Error(), "secret") || logs.Len() != 0 {
			t.Fatal("lost transport identity or leaked/retried")
		}
	})
	t.Run("shared redirects retained", func(t *testing.T) {
		calls, redirects := 0, 0
		joinHTTP(t, func(*http.Request) (*http.Response, error) {
			calls++
			response := joinResponse(307, io.NopCloser(strings.NewReader("")))
			response.Header.Set("Location", "https://secret.invalid")
			return response, nil
		})
		web.SignalHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { redirects++; return nil }
		_, err := cancellationRun(context.Background(), f, 7)
		if err == nil || calls != 1 || redirects != 0 {
			t.Fatal("followed redirect")
		}
		_ = web.SignalHTTPClient.CheckRedirect(nil, nil)
		if redirects != 1 {
			t.Fatal("modified shared client")
		}
	})
}
