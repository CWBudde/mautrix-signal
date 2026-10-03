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

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

func acceptanceRun(ctx context.Context, f joinFixture, revision uint32, invited libsignalgo.ServiceID) (signalmeow.GroupInvitationAcceptOutcome, error) {
	return signalmeow.GroupAcceptanceOnceForTest(ctx, joinKey(), revision, invited, f.self, acceptancePNI, f.server, f.credential, nil, nil)
}
func acceptanceRequest(t *testing.T, req *http.Request) *signalpb.GroupChange_Actions {
	t.Helper()
	raw, err := io.ReadAll(req.Body)
	joinCheck(t, err)
	actions := &signalpb.GroupChange_Actions{}
	joinCheck(t, proto.Unmarshal(raw, actions))
	return actions
}
func acceptanceResponse(t *testing.T, f joinFixture, a *signalpb.GroupChange_Actions, invited libsignalgo.ServiceID, normalize bool) *signalpb.GroupChange_Actions {
	t.Helper()
	a = proto.Clone(a).(*signalpb.GroupChange_Actions)
	groupID, err := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32)).GroupIdentifier()
	joinCheck(t, err)
	a.GroupId = bytes.Clone(groupID[:])
	source, err := f.secret.EncryptServiceID(invited)
	joinCheck(t, err)
	a.SourceUserId = bytes.Clone(source[:])
	var presentation []byte
	if invited.Type == libsignalgo.ServiceIDTypePNI {
		m := a.PromoteMembersPendingPniAciProfileKey[0]
		presentation = m.Presentation
		pni, err := f.secret.EncryptServiceID(invited)
		joinCheck(t, err)
		m.Pni = bytes.Clone(pni[:])
	} else {
		presentation = a.PromoteMembersPendingProfileKey[0].Presentation
	}
	if normalize {
		p := libsignalgo.ProfileKeyCredentialPresentation(presentation)
		id, err := p.UUIDCiphertext()
		joinCheck(t, err)
		key, err := p.ProfileKeyCiphertext()
		joinCheck(t, err)
		if invited.Type == libsignalgo.ServiceIDTypePNI {
			m := a.PromoteMembersPendingPniAciProfileKey[0]
			m.UserId = id[:]
			m.ProfileKey = key[:]
			m.Presentation = nil
		} else {
			m := a.PromoteMembersPendingProfileKey[0]
			m.UserId = id[:]
			m.ProfileKey = key[:]
			m.Presentation = nil
		}
	}
	return a
}
func acceptanceOnlyFields(t *testing.T, m proto.Message, names ...protoreflect.Name) {
	t.Helper()
	m.ProtoReflect().Range(func(d protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		for _, name := range names {
			if d.Name() == name {
				return true
			}
		}
		t.Fatalf("unexpected action field %s", d.Name())
		return false
	})
	if len(m.ProtoReflect().GetUnknown()) != 0 {
		t.Fatal("unknown action field")
	}
}

// Wire form follows the official createAcceptInviteChange/createAcceptPniInviteChange
// at Signal-Android b377bd213ad370dea96c46f75491b598983ebf7f. Real server semantics
// remain separately opt-in; these signed offline responses bind both typed IDs.
func TestGroupAcceptanceActions(t *testing.T) {
	f := loadJoinFixture(t)
	for _, invited := range []libsignalgo.ServiceID{libsignalgo.NewACIServiceID(f.self), libsignalgo.NewPNIServiceID(acceptancePNI)} {
		t.Run(invited.Type.String(), func(t *testing.T) {
			calls := 0
			var signed []byte
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodPatch || req.URL.String() != "https://storage.signal.org/v2/groups/" || req.GetBody != nil {
					t.Fatal("wrong bounded PATCH")
				}
				a := acceptanceRequest(t, req)
				if a.Version != 8 || len(a.GroupId) != 0 || !bytes.Equal(a.SourceUserId, invited.Bytes()) {
					t.Fatal("wrong plaintext invited metadata")
				}
				var presentation []byte
				if invited.Type == libsignalgo.ServiceIDTypePNI {
					acceptanceOnlyFields(t, a, "sourceUserId", "version", "promote_members_pending_pni_aci_profile_key")
					if len(a.PromoteMembersPendingPniAciProfileKey) != 1 {
						t.Fatal("wrong PNI cardinality")
					}
					m := a.PromoteMembersPendingPniAciProfileKey[0]
					acceptanceOnlyFields(t, m, "presentation")
					presentation = m.Presentation
				} else {
					acceptanceOnlyFields(t, a, "sourceUserId", "version", "promoteMembersPendingProfileKey")
					if len(a.PromoteMembersPendingProfileKey) != 1 {
						t.Fatal("wrong ACI cardinality")
					}
					m := a.PromoteMembersPendingProfileKey[0]
					acceptanceOnlyFields(t, m, "presentation")
					presentation = m.Presentation
				}
				p := libsignalgo.ProfileKeyCredentialPresentation(presentation)
				joinCheck(t, p.CheckValidContents())
				cipher, err := p.UUIDCiphertext()
				joinCheck(t, err)
				sid, err := f.secret.DecryptServiceID(cipher)
				joinCheck(t, err)
				if sid != libsignalgo.NewACIServiceID(f.self) {
					t.Fatal("presentation is not own ACI")
				}
				signed = f.signed(t, acceptanceResponse(t, f, a, invited, true), 7)
				r := joinResponse(200, io.NopCloser(bytes.NewReader(signed)))
				r.Header.Del("X-Signal-Timestamp")
				return r, nil
			})
			out, err := acceptanceRun(context.Background(), f, 7, invited)
			joinCheck(t, err)
			if calls != 1 || !out.Attempted || !out.Accepted || !out.Verified || out.Revision != 8 || out.GroupContext == nil || out.Change == nil {
				t.Fatal("wrong verified outcome")
			}
			if out.GroupContext.GetRevision() != 8 || !bytes.Equal(out.GroupContext.MasterKey, bytes.Repeat([]byte{42}, 32)) || out.Change.SourceServiceID != invited {
				t.Fatal("context did not bind acceptance")
			}
			if invited.Type == libsignalgo.ServiceIDTypePNI {
				if len(out.Change.PromotePendingPniAciMembers) != 1 || out.Change.PromotePendingPniAciMembers[0].ACI != f.self || out.Change.PromotePendingPniAciMembers[0].PNI != acceptancePNI {
					t.Fatal("PNI semantic binding lost")
				}
			} else if len(out.Change.PromotePendingMembers) != 1 || out.Change.PromotePendingMembers[0].ACI != f.self {
				t.Fatal("ACI semantic binding lost")
			}
			retained := bytes.Clone(out.GroupContext.GroupChange)
			for i := range signed {
				signed[i] ^= 255
			}
			if !bytes.Equal(retained, out.GroupContext.GroupChange) {
				t.Fatal("signed context aliases transport response")
			}
		})
	}
}

func TestGroupAcceptanceResponseBinding(t *testing.T) {
	f := loadJoinFixture(t)
	for _, pni := range []bool{false, true} {
		invited := libsignalgo.NewACIServiceID(f.self)
		if pni {
			invited = libsignalgo.NewPNIServiceID(acceptancePNI)
		}
		for _, tc := range []struct {
			name              string
			change            func(*signalpb.GroupChange_Actions)
			epoch             uint32
			normalized, valid bool
		}{
			{"normalized", func(*signalpb.GroupChange_Actions) {}, 7, true, true},
			{"presentation", func(*signalpb.GroupChange_Actions) {}, 1, false, true},
			{"source ACI", func(a *signalpb.GroupChange_Actions) {
				id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(f.self))
				joinCheck(t, err)
				a.SourceUserId = id[:]
			}, 7, true, true},
			{"wrong group", func(a *signalpb.GroupChange_Actions) { a.GroupId[0] ^= 1 }, 7, true, false},
			{"missing group", func(a *signalpb.GroupChange_Actions) { a.GroupId = nil }, 7, true, false},
			{"wrong revision", func(a *signalpb.GroupChange_Actions) { a.Version++ }, 7, true, false},
			{"wrong source", func(a *signalpb.GroupChange_Actions) {
				id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(acceptancePNI))
				joinCheck(t, err)
				a.SourceUserId = id[:]
			}, 7, true, false},
			{"short source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = []byte{1} }, 7, true, false},
			{"unrelated", func(a *signalpb.GroupChange_Actions) {
				a.ModifyAvatar = &signalpb.GroupChange_Actions_ModifyAvatarAction{Avatar: "secret"}
			}, 7, true, false},
			{"unknown", func(a *signalpb.GroupChange_Actions) { a.ProtoReflect().SetUnknown([]byte{0xf8, 7, 1}) }, 7, true, false},
			{"empty", func(a *signalpb.GroupChange_Actions) {
				a.PromoteMembersPendingProfileKey = nil
				a.PromoteMembersPendingPniAciProfileKey = nil
			}, 7, true, false},
			{"multiple", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey = append(a.PromoteMembersPendingPniAciProfileKey, a.PromoteMembersPendingPniAciProfileKey[0])
				} else {
					a.PromoteMembersPendingProfileKey = append(a.PromoteMembersPendingProfileKey, a.PromoteMembersPendingProfileKey[0])
				}
			}, 7, true, false},
			{"wrong kind", func(a *signalpb.GroupChange_Actions) {
				a.PromoteMembersPendingProfileKey = nil
				a.PromoteMembersPendingPniAciProfileKey = nil
				a.AddMembers = []*signalpb.GroupChange_Actions_AddMemberAction{{Added: &signalpb.Member{}}}
			}, 7, true, false},
			{"short ID", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].UserId = []byte{1}
				} else {
					a.PromoteMembersPendingProfileKey[0].UserId = []byte{1}
				}
			}, 7, true, false},
			{"short profile", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].ProfileKey = []byte{1}
				} else {
					a.PromoteMembersPendingProfileKey[0].ProfileKey = []byte{1}
				}
			}, 7, true, false},
			{"incomplete profile", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].ProfileKey = nil
				} else {
					a.PromoteMembersPendingProfileKey[0].ProfileKey = nil
				}
			}, 7, true, false},
			{"contradictory presentation", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].Presentation = []byte{1}
				} else {
					a.PromoteMembersPendingProfileKey[0].Presentation = []byte{1}
				}
			}, 7, true, false},
			{"malformed presentation", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].Presentation = []byte{1}
				} else {
					a.PromoteMembersPendingProfileKey[0].Presentation = []byte{1}
				}
			}, 7, false, false},
			{"wrong ACI", func(a *signalpb.GroupChange_Actions) {
				id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(acceptancePNI))
				joinCheck(t, err)
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].UserId = id[:]
				} else {
					a.PromoteMembersPendingProfileKey[0].UserId = id[:]
				}
			}, 7, true, false},
			{"wrong profile", func(a *signalpb.GroupChange_Actions) {
				key, err := f.secret.EncryptProfileKey(libsignalgo.ProfileKey{1}, f.self)
				joinCheck(t, err)
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].ProfileKey = key[:]
				} else {
					a.PromoteMembersPendingProfileKey[0].ProfileKey = key[:]
				}
			}, 7, true, false},
			{"unknown promotion", func(a *signalpb.GroupChange_Actions) {
				if pni {
					a.PromoteMembersPendingPniAciProfileKey[0].ProtoReflect().SetUnknown([]byte{0xf8, 7, 1})
				} else {
					a.PromoteMembersPendingProfileKey[0].ProtoReflect().SetUnknown([]byte{0xf8, 7, 1})
				}
			}, 7, true, false},
			{"unsupported epoch", func(*signalpb.GroupChange_Actions) {}, 8, true, false},
		} {
			t.Run(invited.Type.String()+"/"+tc.name, func(t *testing.T) {
				joinHTTP(t, func(req *http.Request) (*http.Response, error) {
					a := acceptanceResponse(t, f, acceptanceRequest(t, req), invited, tc.normalized)
					tc.change(a)
					return joinResponse(200, io.NopCloser(bytes.NewReader(f.signed(t, a, tc.epoch)))), nil
				})
				out, err := acceptanceRun(context.Background(), f, 7, invited)
				if !out.Attempted || !out.Accepted {
					t.Fatal("lost acceptance")
				}
				if tc.valid {
					joinCheck(t, err)
					if !out.Verified {
						t.Fatal("valid response rejected")
					}
				} else if err == nil || out.Verified || out.Change != nil || out.GroupContext != nil {
					t.Fatal("unvalidated response propagated")
				}
			})
		}
	}
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupChange_Actions_PromoteMemberPendingPniAciProfileKeyAction)
	}{
		{"missing PNI", func(m *signalpb.GroupChange_Actions_PromoteMemberPendingPniAciProfileKeyAction) { m.Pni = nil }},
		{"short PNI", func(m *signalpb.GroupChange_Actions_PromoteMemberPendingPniAciProfileKeyAction) { m.Pni = []byte{1} }},
		{"wrong PNI", func(m *signalpb.GroupChange_Actions_PromoteMemberPendingPniAciProfileKeyAction) {
			id, err := f.secret.EncryptServiceID(libsignalgo.NewPNIServiceID(f.self))
			joinCheck(t, err)
			m.Pni = id[:]
		}},
		{"wrong type PNI", func(m *signalpb.GroupChange_Actions_PromoteMemberPendingPniAciProfileKeyAction) {
			id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(acceptancePNI))
			joinCheck(t, err)
			m.Pni = id[:]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invited := libsignalgo.NewPNIServiceID(acceptancePNI)
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				a := acceptanceResponse(t, f, acceptanceRequest(t, req), invited, true)
				tc.modify(a.PromoteMembersPendingPniAciProfileKey[0])
				return joinResponse(200, io.NopCloser(bytes.NewReader(f.signed(t, a, 7)))), nil
			})
			out, err := acceptanceRun(context.Background(), f, 7, invited)
			if err == nil || !out.Accepted || out.Verified || out.Change != nil || out.GroupContext != nil {
				t.Fatal("PNI not strictly bound")
			}
		})
	}
}

func TestGroupAcceptanceNoRetry(t *testing.T) {
	f := loadJoinFixture(t)
	cause := &url.Error{Op: "secret", URL: "https://secret.invalid/profile-secret", Err: context.Canceled}
	for _, tc := range []struct {
		name                   string
		aci, pni               uuid.UUID
		revision               uint32
		invited                libsignalgo.ServiceID
		credential             *libsignalgo.ExpiringProfileKeyCredential
		credentialErr, authErr error
	}{
		{"overflow", f.self, acceptancePNI, ^uint32(0), libsignalgo.NewACIServiceID(f.self), f.credential, nil, nil},
		{"missing ACI", uuid.Nil, acceptancePNI, 7, libsignalgo.NewPNIServiceID(acceptancePNI), f.credential, nil, nil},
		{"foreign invitation", f.self, acceptancePNI, 7, libsignalgo.NewACIServiceID(acceptancePNI), f.credential, nil, nil},
		{"zero PNI", f.self, uuid.Nil, 7, libsignalgo.NewPNIServiceID(uuid.Nil), f.credential, nil, nil},
		{"wrong type collision", f.self, acceptancePNI, 7, libsignalgo.NewPNIServiceID(f.self), f.credential, nil, nil},
		{"wrong own credential", acceptancePNI, f.self, 7, libsignalgo.NewACIServiceID(acceptancePNI), f.credential, nil, nil},
		{"credential error", f.self, acceptancePNI, 7, libsignalgo.NewACIServiceID(f.self), f.credential, cause, nil},
		{"nil credential", f.self, acceptancePNI, 7, libsignalgo.NewACIServiceID(f.self), nil, nil, nil},
		{"authorization error", f.self, acceptancePNI, 7, libsignalgo.NewACIServiceID(f.self), f.credential, nil, cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return nil, cause })
			out, err := signalmeow.GroupAcceptanceOnceForTest(context.Background(), joinKey(), tc.revision, tc.invited, tc.aci, tc.pni, f.server, tc.credential, tc.credentialErr, tc.authErr)
			if err == nil || calls != 0 || out.Attempted || out.Accepted || out.Verified || strings.Contains(err.Error(), "secret") {
				t.Fatal("preflight submitted or leaked")
			}
			if (tc.credentialErr != nil || tc.authErr != nil) && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cause")
			}
		})
	}
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, err := acceptanceRun(ctx, f, 7, libsignalgo.NewACIServiceID(f.self))
		if out.Attempted || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled submission")
		}
	})
	for _, cli := range []*signalmeow.Client{nil, {}} {
		out, err := cli.AcceptGroupInvitationOnce(context.Background(), joinKey(), 7, libsignalgo.NewACIServiceID(f.self))
		if err == nil || out.Attempted {
			t.Fatal("missing account submitted")
		}
	}
}

func TestGroupAcceptanceHTTP(t *testing.T) {
	f := loadJoinFixture(t)
	for _, tc := range []struct {
		status int
		want   error
	}{
		{400, signalmeow.GroupPatchNotAcceptedError}, {401, signalmeow.AuthorizationFailedError}, {403, signalmeow.AuthorizationFailedError}, {404, signalmeow.NotFoundError}, {409, signalmeow.ConflictError}, {423, signalmeow.ErrGroupAcceptanceTerminated}, {429, signalmeow.RateLimitError}, {499, signalmeow.DeprecatedVersionError}, {500, signalmeow.ErrGroupAcceptanceUncertain}, {204, signalmeow.ErrGroupAcceptanceUncertain}, {307, signalmeow.ErrGroupAcceptanceUncertain},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			calls := 0
			b := &joinBody{Reader: strings.NewReader("secret")}
			joinHTTP(t, func(*http.Request) (*http.Response, error) {
				calls++
				r := joinResponse(tc.status, b)
				r.Header.Set("Location", "https://secret.invalid/")
				return r, nil
			})
			out, err := acceptanceRun(context.Background(), f, 7, libsignalgo.NewACIServiceID(f.self))
			if calls != 1 || !b.closed || !out.Attempted || out.Accepted || out.Verified || out.Revision != 8 || !errors.Is(err, tc.want) || (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "link")) {
				t.Fatal("wrong refusal outcome")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"read failure", joinFailReader{errors.New("secret read failure")}}, {"oversized", strings.NewReader(strings.Repeat("x", (1<<20)+1))}, {"empty", strings.NewReader("")}, {"malformed", bytes.NewReader([]byte{255})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			patchCalls := 0
			b := &joinBody{Reader: tc.reader}
			joinHTTP(t, func(*http.Request) (*http.Response, error) { patchCalls++; return joinResponse(200, b), nil })
			outcome, err := acceptanceRun(context.Background(), f, 7, libsignalgo.NewACIServiceID(f.self))
			if !outcome.Attempted || !outcome.Accepted || outcome.Verified || outcome.GroupContext != nil || outcome.Change != nil || patchCalls != 1 {
				t.Fatalf("invalid accepted partial outcome: %+v; calls=%d", outcome, patchCalls)
			}
			if err == nil || !b.closed || strings.Contains(err.Error(), "secret") {
				t.Fatal("accepted response failure lost")
			}
		})
	}
	t.Run("transport privacy", func(t *testing.T) {
		calls := 0
		var logs bytes.Buffer
		ctx := zerolog.New(&logs).Level(zerolog.TraceLevel).WithContext(context.Background())
		cause := &url.Error{URL: "https://secret.invalid/profile-secret", Err: context.DeadlineExceeded}
		joinHTTP(t, func(req *http.Request) (*http.Response, error) {
			calls++
			zerolog.Ctx(req.Context()).Trace().Str("secret", "credential").Msg("logging")
			return nil, cause
		})
		out, err := acceptanceRun(ctx, f, 7, libsignalgo.NewACIServiceID(f.self))
		if calls != 1 || !out.Attempted || out.Accepted || !errors.Is(err, signalmeow.ErrGroupAcceptanceUncertain) || !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "secret") || logs.Len() != 0 {
			t.Fatal("transport retried or leaked")
		}
	})
	t.Run("shared redirects retained", func(t *testing.T) {
		calls := 0
		redirects := 0
		joinHTTP(t, func(*http.Request) (*http.Response, error) {
			calls++
			r := joinResponse(307, io.NopCloser(strings.NewReader("")))
			r.Header.Set("Location", "https://secret.invalid")
			return r, nil
		})
		web.SignalHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { redirects++; return nil }
		_, err := acceptanceRun(context.Background(), f, 7, libsignalgo.NewACIServiceID(f.self))
		if err == nil || calls != 1 || redirects != 0 {
			t.Fatal("redirect followed")
		}
		_ = web.SignalHTTPClient.CheckRedirect(nil, nil)
		if redirects != 1 {
			t.Fatal("modified shared client")
		}
	})
}

func TestGroupAcceptanceResponseBindingSignature(t *testing.T) {
	f := loadJoinFixture(t)
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupChange)
	}{
		{"tampered", func(c *signalpb.GroupChange) { c.ServerSignature[0] ^= 1 }},
		{"short", func(c *signalpb.GroupChange) { c.ServerSignature = c.ServerSignature[:63] }},
		{"long", func(c *signalpb.GroupChange) { c.ServerSignature = append(c.ServerSignature, 1) }},
		{"missing actions", func(c *signalpb.GroupChange) { c.Actions = nil }},
		{"unknown signed envelope", func(c *signalpb.GroupChange) { c.ProtoReflect().SetUnknown([]byte{0xf8, 7, 1}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invited := libsignalgo.NewACIServiceID(f.self)
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				a := acceptanceResponse(t, f, acceptanceRequest(t, req), invited, true)
				response := &signalpb.GroupChangeResponse{}
				joinCheck(t, proto.Unmarshal(f.signed(t, a, 7), response))
				tc.modify(response.GroupChange)
				raw, err := proto.Marshal(response)
				joinCheck(t, err)
				return joinResponse(200, io.NopCloser(bytes.NewReader(raw))), nil
			})
			out, err := acceptanceRun(context.Background(), f, 7, invited)
			if err == nil || !out.Accepted || out.Verified || out.Change != nil || out.GroupContext != nil {
				t.Fatal("invalid signed response propagated")
			}
		})
	}
}
