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

	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

type joinRoundTrip func(*http.Request) (*http.Response, error)

func (f joinRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type joinBody struct {
	io.Reader
	closed bool
}

func (b *joinBody) Close() error { b.closed = true; return nil }
func joinHTTP(t *testing.T, f joinRoundTrip) {
	t.Helper()
	old := web.SignalHTTPClient
	web.SignalHTTPClient = &http.Client{Transport: f}
	t.Cleanup(func() { web.SignalHTTPClient = old })
}
func joinResponse(status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"X-Signal-Timestamp": []string{"1791028800000"}}, Body: body}
}
func joinCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func joinPassword() []byte { return bytes.Repeat([]byte{255}, 16) }

func TestGroupJoinHTTPSecrecy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			var logs bytes.Buffer
			logger := zerolog.New(&logs).Level(zerolog.TraceLevel)
			cause := errors.New("transport failed")
			secretURL := ""
			joinHTTP(t, func(req *http.Request) (*http.Response, error) {
				secretURL = req.URL.String()
				want := "https://storage.signal.org/v2/groups/join/_____________________w"
				if method == http.MethodPatch {
					want = "https://storage.signal.org/v2/groups/?inviteLinkPassword=_____________________w"
				}
				if secretURL != want {
					t.Fatalf("unexpected endpoint %s", secretURL)
				}
				user, pass, ok := req.BasicAuth()
				if !ok || user != "test-user" || pass != "test-auth" {
					t.Fatal("missing basic auth")
				}
				if req.Header.Get("User-Agent") != web.UserAgent || req.Header.Get("X-Signal-Agent") != web.SignalAgent || req.Header.Get("Content-Type") != string(web.ContentTypeProtobuf) {
					t.Fatal("missing standard headers")
				}
				zerolog.Ctx(req.Context()).Trace().Stringer("url", req.URL).Msg("dependency logging")
				return nil, &url.Error{Op: "inner", URL: req.URL.String(), Err: cause}
			})
			_, attempted, accepted, err := signalmeow.GroupJoinHTTPForTest(logger.WithContext(context.Background()), method, joinPassword())
			if !attempted || accepted || !errors.Is(err, cause) {
				t.Fatalf("attempted=%v accepted=%v err=%v", attempted, accepted, err)
			}
			for _, secret := range []string{secretURL, "_____________________w", "test-auth"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(logs.String(), secret) {
					t.Fatal("secret leaked in error or logs")
				}
			}
		})
	}
}
func TestGroupJoinHTTPBounds(t *testing.T) {
	for _, size := range []int{1 << 20, (1 << 20) + 1} {
		t.Run(map[bool]string{false: "at limit", true: "over limit"}[size > (1<<20)], func(t *testing.T) {
			body := &joinBody{Reader: strings.NewReader(strings.Repeat("x", size))}
			joinHTTP(t, func(*http.Request) (*http.Response, error) { return joinResponse(200, body), nil })
			raw, attempted, accepted, err := signalmeow.GroupJoinHTTPForTest(context.Background(), http.MethodPatch, joinPassword())
			if !body.closed || !attempted || !accepted {
				t.Fatal("body not closed or acceptance lost")
			}
			if size == (1 << 20) {
				joinCheck(t, err)
				if len(raw) != size {
					t.Fatal("short read")
				}
			} else if err == nil {
				t.Fatal("oversized body accepted")
			}
		})
	}
	t.Run("redirect", func(t *testing.T) {
		calls := 0
		body := &joinBody{Reader: strings.NewReader("")}
		sharedRedirects := 0
		joinHTTP(t, func(*http.Request) (*http.Response, error) {
			calls++
			res := joinResponse(307, body)
			res.Header.Set("Location", "https://untrusted.invalid/secret")
			return res, nil
		})
		web.SignalHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { sharedRedirects++; return nil }
		_, _, accepted, err := signalmeow.GroupJoinHTTPForTest(context.Background(), http.MethodPatch, joinPassword())
		if err == nil || accepted || calls != 1 || sharedRedirects != 0 || !body.closed {
			t.Fatal("redirect followed or client modified")
		}
		_ = web.SignalHTTPClient.CheckRedirect(nil, nil)
		if sharedRedirects != 1 {
			t.Fatal("shared client modified")
		}
	})
}
