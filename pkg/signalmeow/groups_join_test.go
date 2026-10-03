// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

func joinKey() types.SerializedGroupMasterKey {
	return types.SerializedGroupMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)))
}
func joinPreviewProto(t *testing.T) *signalpb.GroupJoinInfo {
	t.Helper()
	secret, err := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32)).SecretParams()
	joinCheck(t, err)
	public, err := secret.GetPublicParams()
	joinCheck(t, err)
	blob, err := proto.Marshal(&signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_Title{Title: "Test group"}})
	joinCheck(t, err)
	title, err := secret.EncryptBlobWithPaddingDeterministic(libsignalgo.Randomness{1}, blob, 0)
	joinCheck(t, err)
	blob, err = proto.Marshal(&signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_DescriptionText{DescriptionText: "A group"}})
	joinCheck(t, err)
	description, err := secret.EncryptBlobWithPaddingDeterministic(libsignalgo.Randomness{1}, blob, 0)
	joinCheck(t, err)
	return &signalpb.GroupJoinInfo{PublicKey: public[:], Title: title, Description: description, Version: 7, AddFromInviteLink: signalpb.AccessControl_ANY}
}
func TestGroupJoinPreview(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupJoinInfo, *http.Response)
		bad    bool
	}{
		{"valid", func(*signalpb.GroupJoinInfo, *http.Response) {}, false},
		{"missing timestamp", func(_ *signalpb.GroupJoinInfo, r *http.Response) { r.Header.Del("X-Signal-Timestamp") }, true},
		{"timestamp overflow", func(_ *signalpb.GroupJoinInfo, r *http.Response) {
			r.Header.Set("X-Signal-Timestamp", "18446744073709551616")
		}, true},
		{"invalid UTF-8 title", func(g *signalpb.GroupJoinInfo, _ *http.Response) {
			secret, err := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32)).SecretParams()
			joinCheck(t, err)
			// Field 1 (title), one invalid UTF-8 byte. Marshal would reject it.
			g.Title, err = secret.EncryptBlobWithPaddingDeterministic(libsignalgo.Randomness{1}, []byte{10, 1, 255}, 0)
			joinCheck(t, err)
		}, true},
		{"corrupt title", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Title = []byte{1} }, true},
		{"malformed timestamp", func(_ *signalpb.GroupJoinInfo, r *http.Response) {
			r.Header.Set("X-Signal-Timestamp", "secret bad value")
		}, true},
		{"wrong public", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.PublicKey[2] ^= 1 }, true},
		{"missing title", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Title = nil }, true},
		{"wrong title oneof", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Title = g.Description }, true},
		{"wrong description oneof", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Description = g.Title }, true},
		{"optional description", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.Description = nil }, false},
		{"unknown access", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.AddFromInviteLink = 99 }, false},
		{"request pending", func(g *signalpb.GroupJoinInfo, _ *http.Response) { g.PendingAdminApproval = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := joinPreviewProto(t)
			res := joinResponse(200, nil)
			tc.modify(info, res)
			raw, err := proto.Marshal(info)
			joinCheck(t, err)
			body := &joinBody{Reader: bytes.NewReader(raw)}
			res.Body = body
			joinHTTP(t, func(*http.Request) (*http.Response, error) { return res, nil })
			preview, err := signalmeow.PreviewGroupJoinForTest(context.Background(), joinKey(), joinPassword())
			if tc.bad {
				if err == nil {
					t.Fatal("invalid preview accepted")
				}
			} else {
				joinCheck(t, err)
				if preview.Revision != 7 || preview.Title != "Test group" || preview.Access != signalmeow.AccessControl(info.AddFromInviteLink) || preview.PendingAdminApproval != info.PendingAdminApproval {
					t.Fatal("preview lost fields")
				}
			}
			if !body.closed {
				t.Fatal("body not closed")
			}
		})
	}
	for _, tc := range []struct {
		status int
		reason string
		want   error
	}{
		{403, "", signalmeow.AuthorizationFailedError}, {403, "unexpected secret", signalmeow.AuthorizationFailedError}, {423, "", signalmeow.ErrGroupJoinTerminated},
	} {
		t.Run(http.StatusText(tc.status)+tc.reason, func(t *testing.T) {
			joinHTTP(t, func(*http.Request) (*http.Response, error) {
				res := joinResponse(tc.status, io.NopCloser(bytes.NewReader(nil)))
				res.Header.Set("X-Signal-Forbidden-Reason", tc.reason)
				return res, nil
			})
			_, err := signalmeow.PreviewGroupJoinForTest(context.Background(), joinKey(), joinPassword())
			if !errors.Is(err, tc.want) {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
	t.Run("invalid input before authorization", func(t *testing.T) {
		var cli *signalmeow.Client
		for _, key := range []types.SerializedGroupMasterKey{"bad", types.SerializedGroupMasterKey(base64.StdEncoding.EncodeToString([]byte{1}))} {
			_, err := cli.PreviewGroupJoin(context.Background(), key, joinPassword())
			if err == nil {
				t.Fatal("bad key accepted")
			}
		}
		_, err := cli.PreviewGroupJoin(context.Background(), joinKey(), []byte{1})
		if err == nil {
			t.Fatal("bad password accepted")
		}
	})
}

// Protocol source: Signal-Android commit b377bd213ad370dea96c46f75491b598983ebf7f,
// retrieved 2026-10-03. See immutable HTTP and action sources:
// https://github.com/signalapp/Signal-Android/blob/b377bd213ad370dea96c46f75491b598983ebf7f/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java
// https://github.com/signalapp/Signal-Android/blob/b377bd213ad370dea96c46f75491b598983ebf7f/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/groupsv2/GroupsV2Operations.java
// Requests omit group_id and the direct invite marker, and use plaintext source.
// Responses encrypt source and bind the exact group via signed group_id.
// Pinned signal-cli commit 13d603d3b5898d7b3b527305afc23c9c7ba84c5b:
// GroupV2Helper.java joinGroup (lines 446-470).
type joinFixture struct {
	self       uuid.UUID
	server     *libsignalgo.ServerPublicParams
	credential *libsignalgo.ExpiringProfileKeyCredential
	secret     libsignalgo.GroupSecretParams
	signer     zkcrypto.SignatureKeyPair
}

func loadJoinFixture(t *testing.T) joinFixture {
	t.Helper()
	raw, err := os.ReadFile("../libsignalgo/testdata/zkgroup.json")
	joinCheck(t, err)
	var fixture struct {
		Params struct {
			ACI string `json:"aci"`
		}
		Result map[string]string
	}
	joinCheck(t, json.Unmarshal(raw, &fixture))
	decode := func(v string) []byte { b, err := hex.DecodeString(v); joinCheck(t, err); return b }
	f := joinFixture{self: uuid.UUID(decode(fixture.Params.ACI))}
	// Reuse the existing nonproduction profile parameters/credential fixture; a
	// fresh test-only notary key permits signed semantic adversarial cases.
	f.signer = zkcrypto.GenerateSignatureKeyPair(poksho.NewShoHmacSha256([]byte("go-signal group join offline test notary")))
	params := decode(fixture.Result["server"])
	copy(params[129:161], f.signer.Public().Bytes())
	f.server, err = libsignalgo.DeserializeServerPublicParams(params)
	joinCheck(t, err)
	credential := libsignalgo.ExpiringProfileKeyCredential(decode(fixture.Result["profile_credential"]))
	f.credential = &credential
	f.secret, err = libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32)).SecretParams()
	joinCheck(t, err)
	return f
}
func (f joinFixture) signed(t *testing.T, actions *signalpb.GroupChange_Actions, epoch uint32) []byte {
	t.Helper()
	raw, err := proto.Marshal(actions)
	joinCheck(t, err)
	signature, err := f.signer.Sign(raw, poksho.NewShoHmacSha256([]byte("go-signal group join test signing randomness")))
	joinCheck(t, err)
	response, err := proto.Marshal(&signalpb.GroupChangeResponse{GroupChange: &signalpb.GroupChange{Actions: raw, ServerSignature: signature, ChangeEpoch: epoch}})
	joinCheck(t, err)
	return response
}
func (f joinFixture) responseActions(t *testing.T, actions *signalpb.GroupChange_Actions, normalize bool) *signalpb.GroupChange_Actions {
	t.Helper()
	actions = proto.Clone(actions).(*signalpb.GroupChange_Actions)
	id, err := libsignalgo.GroupMasterKey(bytes.Repeat([]byte{42}, 32)).GroupIdentifier()
	joinCheck(t, err)
	actions.GroupId = id[:]
	source, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(f.self))
	joinCheck(t, err)
	actions.SourceUserId = source[:]
	if normalize {
		var presentation []byte
		if len(actions.AddMembers) > 0 {
			presentation = actions.AddMembers[0].Added.Presentation
		} else {
			presentation = actions.AddMembersPendingAdminApproval[0].Added.Presentation
		}
		p := libsignalgo.ProfileKeyCredentialPresentation(presentation)
		id, err := p.UUIDCiphertext()
		joinCheck(t, err)
		key, err := p.ProfileKeyCiphertext()
		joinCheck(t, err)
		if len(actions.AddMembers) > 0 {
			actions.AddMembers[0].Added = &signalpb.Member{UserId: id[:], ProfileKey: key[:], Role: signalpb.Member_DEFAULT, JoinedAtVersion: 8}
			actions.AddMembers[0].JoinFromInviteLink = true
		} else {
			actions.AddMembersPendingAdminApproval[0].Added = &signalpb.MemberPendingAdminApproval{UserId: id[:], ProfileKey: key[:], Timestamp: 123456}
		}
	}
	return actions
}
func joinRun(t *testing.T, f joinFixture, preview signalmeow.GroupJoinPreview, credentialErr error) (signalmeow.GroupJoinOutcome, error) {
	t.Helper()
	return signalmeow.GroupJoinOnceForTest(context.Background(), joinKey(), joinPassword(), preview, f.self, f.server, f.credential, credentialErr, nil)
}
func TestGroupJoinActions(t *testing.T) {
	f := loadJoinFixture(t)
	for _, access := range []signalmeow.AccessControl{signalmeow.AccessControl_ANY, signalmeow.AccessControl_ADMINISTRATOR} {
		t.Run(map[bool]string{false: "direct", true: "request"}[access == signalmeow.AccessControl_ADMINISTRATOR], func(t *testing.T) {
			calls := 0
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodPatch || req.URL.String() != "https://storage.signal.org/v2/groups/?inviteLinkPassword=_____________________w" {
					t.Fatal("wrong patch endpoint")
				}
				raw, err := io.ReadAll(req.Body)
				joinCheck(t, err)
				actions := &signalpb.GroupChange_Actions{}
				joinCheck(t, proto.Unmarshal(raw, actions))
				if actions.Version != 8 || len(actions.GroupId) != 0 || !bytes.Equal(actions.SourceUserId, f.self[:]) {
					t.Fatal("wrong request metadata")
				}
				var presentation []byte
				if access == signalmeow.AccessControl_ANY {
					if len(actions.AddMembers) != 1 || len(actions.AddMembersPendingAdminApproval) != 0 || actions.AddMembers[0].JoinFromInviteLink {
						t.Fatal("wrong direct action")
					}
					member := actions.AddMembers[0].Added
					presentation = member.Presentation
					if member.Role != signalpb.Member_DEFAULT || len(member.UserId) != 0 || len(member.ProfileKey) != 0 || member.JoinedAtVersion != 0 {
						t.Fatal("unexpected direct fields")
					}
				} else {
					if len(actions.AddMembers) != 0 || len(actions.AddMembersPendingAdminApproval) != 1 {
						t.Fatal("wrong request action")
					}
					member := actions.AddMembersPendingAdminApproval[0].Added
					presentation = member.Presentation
					if len(member.UserId) != 0 || len(member.ProfileKey) != 0 || member.Timestamp != 0 {
						t.Fatal("unexpected request fields")
					}
				}
				p := libsignalgo.ProfileKeyCredentialPresentation(presentation)
				joinCheck(t, p.CheckValidContents())
				cipher, err := p.UUIDCiphertext()
				joinCheck(t, err)
				self, err := f.secret.DecryptServiceID(cipher)
				joinCheck(t, err)
				if self != libsignalgo.NewACIServiceID(f.self) {
					t.Fatal("wrong presentation self")
				}
				res := joinResponse(200, io.NopCloser(bytes.NewReader(f.signed(t, f.responseActions(t, actions, true), 7))))
				res.Header.Del("X-Signal-Timestamp")
				return res, nil
			})
			result, err := joinRun(t, f, signalmeow.GroupJoinPreview{Revision: 7, Access: access}, nil)
			joinCheck(t, err)
			if calls != 1 || !result.Attempted || !result.Accepted || !result.Verified || result.Revision != 8 || result.Requesting != (access == signalmeow.AccessControl_ADMINISTRATOR) || result.GroupContext == nil || result.Change == nil {
				t.Fatal("bad verified outcome")
			}
			if !bytes.Equal(result.GroupContext.MasterKey, bytes.Repeat([]byte{42}, 32)) || result.GroupContext.GetRevision() != 8 || len(result.GroupContext.GroupChange) == 0 {
				t.Fatal("bad validated context")
			}
		})
	}
}
func TestGroupJoinResponseBinding(t *testing.T) {
	f := loadJoinFixture(t)
	for _, access := range []signalmeow.AccessControl{signalmeow.AccessControl_ANY, signalmeow.AccessControl_ADMINISTRATOR} {
		for _, tc := range []struct {
			name   string
			change func(*signalpb.GroupChange_Actions)
			epoch  uint32
			valid  bool
		}{
			{"presentation", func(*signalpb.GroupChange_Actions) {}, 1, true},
			{"wrong group", func(a *signalpb.GroupChange_Actions) { a.GroupId[0] ^= 1 }, 1, false},
			{"missing group", func(a *signalpb.GroupChange_Actions) { a.GroupId = nil }, 1, false},
			{"wrong revision", func(a *signalpb.GroupChange_Actions) { a.Version++ }, 1, false},
			{"plaintext source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = f.self[:] }, 1, false},
			{"wrong source", func(a *signalpb.GroupChange_Actions) {
				id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(uuid.New()))
				joinCheck(t, err)
				a.SourceUserId = id[:]
			}, 1, false},
			{"unrelated mutation", func(a *signalpb.GroupChange_Actions) {
				a.ModifyAvatar = &signalpb.GroupChange_Actions_ModifyAvatarAction{Avatar: "secret"}
			}, 1, false},
			{"unknown action", func(a *signalpb.GroupChange_Actions) { a.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 1}) }, 1, false},
			{"wrong self", func(a *signalpb.GroupChange_Actions) {
				self := uuid.MustParse("00000000-0000-0000-0000-000000000001")
				id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(self))
				joinCheck(t, err)
				key, err := f.secret.EncryptProfileKey(libsignalgo.ProfileKey{1}, self)
				joinCheck(t, err)
				if len(a.AddMembers) > 0 {
					m := a.AddMembers[0].Added
					m.UserId = id[:]
					m.ProfileKey = key[:]
					m.Presentation = nil
				} else {
					m := a.AddMembersPendingAdminApproval[0].Added
					m.UserId = id[:]
					m.ProfileKey = key[:]
					m.Presentation = nil
				}
			}, 1, false},
			{"wrong profile", func(a *signalpb.GroupChange_Actions) {
				id, err := f.secret.EncryptServiceID(libsignalgo.NewACIServiceID(f.self))
				joinCheck(t, err)
				key, err := f.secret.EncryptProfileKey(libsignalgo.ProfileKey{1}, f.self)
				joinCheck(t, err)
				if len(a.AddMembers) > 0 {
					m := a.AddMembers[0].Added
					m.UserId = id[:]
					m.ProfileKey = key[:]
					m.Presentation = nil
				} else {
					m := a.AddMembersPendingAdminApproval[0].Added
					m.UserId = id[:]
					m.ProfileKey = key[:]
					m.Presentation = nil
				}
			}, 1, false},
			{"wrong action kind", func(a *signalpb.GroupChange_Actions) {
				if len(a.AddMembers) > 0 {
					m := a.AddMembers[0].Added
					a.AddMembers = nil
					a.AddMembersPendingAdminApproval = []*signalpb.GroupChange_Actions_AddMemberPendingAdminApprovalAction{{Added: &signalpb.MemberPendingAdminApproval{Presentation: m.Presentation}}}
				} else {
					m := a.AddMembersPendingAdminApproval[0].Added
					a.AddMembersPendingAdminApproval = nil
					a.AddMembers = []*signalpb.GroupChange_Actions_AddMemberAction{{Added: &signalpb.Member{Role: signalpb.Member_DEFAULT, Presentation: m.Presentation}}}
				}
			}, 1, false},
			{"wrong role or duplicate", func(a *signalpb.GroupChange_Actions) {
				if len(a.AddMembers) > 0 {
					a.AddMembers[0].Added.Role = signalpb.Member_ADMINISTRATOR
				} else {
					a.AddMembersPendingAdminApproval = append(a.AddMembersPendingAdminApproval, a.AddMembersPendingAdminApproval[0])
				}
			}, 1, false},
			{"contradictory actions", func(a *signalpb.GroupChange_Actions) {
				a.DeleteMembers = []*signalpb.GroupChange_Actions_DeleteMemberAction{{DeletedUserId: []byte{1}}}
			}, 1, false},
			{"truncated source", func(a *signalpb.GroupChange_Actions) { a.SourceUserId = []byte{1} }, 1, false},
			{"nil added", func(a *signalpb.GroupChange_Actions) {
				if len(a.AddMembers) > 0 {
					a.AddMembers[0].Added = nil
				} else {
					a.AddMembersPendingAdminApproval[0].Added = nil
				}
			}, 1, false},
			{"truncated ciphertext", func(a *signalpb.GroupChange_Actions) {
				if len(a.AddMembers) > 0 {
					m := a.AddMembers[0].Added
					m.UserId = []byte{1}
					m.ProfileKey = []byte{1}
					m.Presentation = nil
				} else {
					m := a.AddMembersPendingAdminApproval[0].Added
					m.UserId = []byte{1}
					m.ProfileKey = []byte{1}
					m.Presentation = nil
				}
			}, 1, false},
			{"unsupported epoch", func(*signalpb.GroupChange_Actions) {}, 8, false},
		} {
			t.Run(string(rune('0'+access))+tc.name, func(t *testing.T) {
				joinHTTP(t, func(req *http.Request) (*http.Response, error) {
					raw, err := io.ReadAll(req.Body)
					joinCheck(t, err)
					a := &signalpb.GroupChange_Actions{}
					joinCheck(t, proto.Unmarshal(raw, a))
					a = f.responseActions(t, a, false)
					tc.change(a)
					return joinResponse(200, io.NopCloser(bytes.NewReader(f.signed(t, a, tc.epoch)))), nil
				})
				outcome, err := joinRun(t, f, signalmeow.GroupJoinPreview{Revision: 7, Access: access}, nil)
				if !outcome.Attempted || !outcome.Accepted {
					t.Fatal("acceptance lost")
				}
				if tc.valid {
					joinCheck(t, err)
					if !outcome.Verified {
						t.Fatal("valid signed presentation rejected")
					}
				} else {
					if err == nil || outcome.Verified || outcome.Change != nil || outcome.GroupContext != nil {
						t.Fatal("unvalidated response propagated")
					}
				}
			})
		}
	}
}
func TestGroupJoinOutcomes(t *testing.T) {
	f := loadJoinFixture(t)
	for _, tc := range []struct {
		name     string
		status   int
		body     []byte
		want     error
		accepted bool
	}{
		{"conflict", 409, nil, signalmeow.ConflictError, false},
		{"forbidden", 403, nil, signalmeow.AuthorizationFailedError, false},
		{"server failure", 500, nil, signalmeow.ErrGroupJoinUncertain, false},
		{"unexpected success", 204, nil, signalmeow.ErrGroupJoinUncertain, false},
		{"malformed accepted", 200, []byte{255}, nil, true},
		{"missing change", 200, nil, nil, true},
		{"invalid signature", 200, []byte{10, 1, 0}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			joinHTTP(t, func(*http.Request) (*http.Response, error) {
				calls++
				return joinResponse(tc.status, io.NopCloser(bytes.NewReader(tc.body))), nil
			})
			out, err := joinRun(t, f, signalmeow.GroupJoinPreview{Revision: 7, Access: signalmeow.AccessControl_ANY}, nil)
			if err == nil || calls != 1 || !out.Attempted || out.Accepted != tc.accepted || out.Verified || out.Change != nil || out.GroupContext != nil || out.Revision != 8 {
				t.Fatal("wrong partial outcome")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("lost identity: %v", err)
			}
		})
	}
	t.Run("accepted read failure", func(t *testing.T) {
		cause := errors.New("read failed")
		body := &joinBody{Reader: joinFailReader{cause}}
		joinHTTP(t, func(*http.Request) (*http.Response, error) { return joinResponse(200, body), nil })
		out, err := joinRun(t, f, signalmeow.GroupJoinPreview{Revision: 7, Access: signalmeow.AccessControl_ANY}, nil)
		if !body.closed || !out.Attempted || !out.Accepted || out.Verified || !errors.Is(err, cause) {
			t.Fatal("accepted read failure lost")
		}
	})
}

type joinFailReader struct{ err error }

func (r joinFailReader) Read([]byte) (int, error) { return 0, r.err }
func TestGroupJoinNoRetry(t *testing.T) {
	f := loadJoinFixture(t)
	for _, tc := range []struct {
		name          string
		preview       signalmeow.GroupJoinPreview
		credentialErr error
		transportErr  error
		wantCalls     int
	}{
		{"overflow", signalmeow.GroupJoinPreview{Revision: ^uint32(0), Access: signalmeow.AccessControl_ANY}, nil, nil, 0},
		{"disabled", signalmeow.GroupJoinPreview{Access: signalmeow.AccessControl_UNSATISFIABLE}, nil, nil, 0},
		{"unknown", signalmeow.GroupJoinPreview{Access: 99}, nil, nil, 0},
		{"pending", signalmeow.GroupJoinPreview{Access: signalmeow.AccessControl_ANY, PendingAdminApproval: true}, nil, nil, 0},
		{"credential", signalmeow.GroupJoinPreview{Access: signalmeow.AccessControl_ANY}, errors.New("credential unavailable"), nil, 0},
		{"transport", signalmeow.GroupJoinPreview{Access: signalmeow.AccessControl_ANY}, nil, context.DeadlineExceeded, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return nil, tc.transportErr })
			out, err := joinRun(t, f, tc.preview, tc.credentialErr)
			if err == nil || calls != tc.wantCalls || out.Attempted != (calls == 1) || out.Accepted {
				t.Fatal("wrong submission count")
			}
			if tc.transportErr != nil && (!errors.Is(err, tc.transportErr) || !errors.Is(err, signalmeow.ErrGroupJoinUncertain)) {
				t.Fatal("lost transport identity")
			}
			if tc.credentialErr != nil && !errors.Is(err, tc.credentialErr) {
				t.Fatal("lost credential identity")
			}
		})
	}
}

func TestGroupJoinResponseBindingSignature(t *testing.T) {
	f := loadJoinFixture(t)
	for _, tc := range []struct {
		name   string
		modify func(*signalpb.GroupChange)
	}{
		{"tampered signature", func(c *signalpb.GroupChange) { c.ServerSignature[0] ^= 1 }},
		{"short signature", func(c *signalpb.GroupChange) { c.ServerSignature = c.ServerSignature[:63] }},
		{"long signature", func(c *signalpb.GroupChange) { c.ServerSignature = append(c.ServerSignature, 1) }},
		{"missing actions", func(c *signalpb.GroupChange) { c.Actions = nil }},
		{"unknown envelope", func(c *signalpb.GroupChange) { c.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 1}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(req.Body)
				joinCheck(t, err)
				a := &signalpb.GroupChange_Actions{}
				joinCheck(t, proto.Unmarshal(raw, a))
				response := &signalpb.GroupChangeResponse{}
				joinCheck(t, proto.Unmarshal(f.signed(t, f.responseActions(t, a, true), 7), response))
				tc.modify(response.GroupChange)
				raw, err = proto.Marshal(response)
				joinCheck(t, err)
				return joinResponse(200, io.NopCloser(bytes.NewReader(raw))), nil
			})
			out, err := joinRun(t, f, signalmeow.GroupJoinPreview{Revision: 7, Access: signalmeow.AccessControl_ANY}, nil)
			if err == nil || !out.Accepted || out.Verified || out.Change != nil || out.GroupContext != nil {
				t.Fatal("unverified signed response propagated")
			}
		})
	}
}

func TestGroupJoinPreSubmissionSecrecy(t *testing.T) {
	f := loadJoinFixture(t)
	cause := &url.Error{Op: "get", URL: "https://signal.group/#actual-link-secret", Err: context.Canceled}
	for _, authFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "credential", true: "authorization"}[authFailure], func(t *testing.T) {
			calls := 0
			joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected request") })
			var credentialErr, authErr error
			if authFailure {
				authErr = cause
			} else {
				credentialErr = cause
			}
			out, err := signalmeow.GroupJoinOnceForTest(context.Background(), joinKey(), joinPassword(), signalmeow.GroupJoinPreview{Revision: 7, Access: signalmeow.AccessControl_ANY}, f.self, f.server, f.credential, credentialErr, authErr)
			if calls != 0 || out.Attempted || out.Accepted || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "actual-link-secret") {
				t.Fatal("credential or authorization error leaked or submitted")
			}
		})
	}
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, err := signalmeow.GroupJoinOnceForTest(ctx, joinKey(), joinPassword(), signalmeow.GroupJoinPreview{Access: signalmeow.AccessControl_ANY}, f.self, f.server, f.credential, nil, nil)
		if out.Attempted || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled context submitted")
		}
	})
	t.Run("wrong own credential", func(t *testing.T) {
		calls := 0
		joinHTTP(t, func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected request") })
		out, err := signalmeow.GroupJoinOnceForTest(context.Background(), joinKey(), joinPassword(), signalmeow.GroupJoinPreview{Access: signalmeow.AccessControl_ANY}, uuid.MustParse("00000000-0000-0000-0000-000000000001"), f.server, f.credential, nil, nil)
		if err == nil || calls != 0 || out.Attempted {
			t.Fatal("wrong own credential submitted")
		}
	})
}
