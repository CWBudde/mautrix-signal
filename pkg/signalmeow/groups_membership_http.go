// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

type groupMembershipHTTPPolicy struct {
	Operation                      string
	Invalid, Uncertain, Terminated error
	RejectEmpty                    bool
	RefusalHint, TransportHint     string
}

// Invitation acceptance uses a fixed endpoint without a link password/query.
func groupAcceptanceHTTPRequest(ctx context.Context, method string, body []byte, auth *GroupAuth) (groupJoinHTTPResult, error) {
	if method != http.MethodGet && method != http.MethodPatch {
		return groupJoinHTTPResult{}, ErrGroupAcceptanceInvalid
	}
	return groupMembershipHTTPRequest(ctx, method, "/v2/groups/", body, auth, groupMembershipHTTPPolicy{
		Operation: "group acceptance", Invalid: ErrGroupAcceptanceInvalid, Uncertain: ErrGroupAcceptanceUncertain, Terminated: ErrGroupAcceptanceTerminated,
		RejectEmpty: true, TransportHint: "; inspect membership before retrying",
	})
}

// One Do call, configured TLS/transport, no redirects/replay, bounded owned body.
// Policy errors are redacted while preserving their underlying identities.
func groupMembershipHTTPRequest(ctx context.Context, method, path string, body []byte, auth *GroupAuth, policy groupMembershipHTTPPolicy) (result groupJoinHTTPResult, err error) {
	if err = ctx.Err(); err != nil {
		return result, groupJoinSafeError(policy.Operation+" canceled before submission", err)
	}
	if auth == nil {
		return result, policy.Invalid
	}
	// Suppress contextual dependency logging on this sensitive path as well.
	ctx = web.WithSensitiveRequestLogging(zerolog.Nop().WithContext(ctx))
	req, err := http.NewRequestWithContext(ctx, method, "https://"+web.StorageHostname+path, bytes.NewReader(body))
	if err != nil {
		return result, groupJoinSafeError("could not prepare "+policy.Operation+" request", err)
	}
	req.Header.Set("Content-Type", string(web.ContentTypeProtobuf))
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("User-Agent", web.UserAgent)
	req.Header.Set("X-Signal-Agent", web.SignalAgent)
	req.SetBasicAuth(auth.Username, auth.Password)
	// Remove automatic body replay capability. PATCH is not idempotent and must
	// never gain a retry path through a replayable request body.
	req.GetBody = nil
	client := *web.SignalHTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	result.Attempted = true
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		cause := err
		if method == http.MethodPatch {
			cause = errors.Join(policy.Uncertain, err)
		}
		return result, groupJoinSafeError(policy.Operation+" transport failed"+policy.TransportHint, cause)
	}
	result.Accepted = method == http.MethodPatch && resp.StatusCode == http.StatusOK
	if resp.StatusCode != http.StatusOK {
		cause := groupJoinStatusError(resp.StatusCode)
		if resp.StatusCode == http.StatusLocked {
			cause = policy.Terminated
		}
		if cause != nil {
			return result, groupJoinSafeError(fmt.Sprintf("%s refused (HTTP %d)%s", policy.Operation, resp.StatusCode, policy.RefusalHint), cause)
		}
		if method == http.MethodPatch {
			cause = policy.Uncertain
		} else {
			cause = policy.Invalid
		}
		return result, groupJoinSafeError(fmt.Sprintf("unexpected %s response (HTTP %d); inspect before retrying", policy.Operation, resp.StatusCode), cause)
	}
	if method == http.MethodGet {
		timestamp := resp.Header.Get("X-Signal-Timestamp")
		if timestamp == "" {
			return result, groupJoinSafeError(policy.Operation+" response has no valid timestamp", policy.Invalid)
		}
		for _, c := range timestamp {
			if c < '0' || c > '9' {
				return result, groupJoinSafeError(policy.Operation+" response has no valid timestamp", policy.Invalid)
			}
		}
		if _, err = strconv.ParseUint(timestamp, 10, 64); err != nil {
			return result, groupJoinSafeError(policy.Operation+" response has no valid timestamp", policy.Invalid)
		}
	}
	if resp.Body == nil {
		return result, groupJoinSafeError(policy.Operation+" response has no body", policy.Invalid)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, groupJoinBodyLimit+1))
	if err != nil {
		return result, groupJoinSafeError("could not read "+policy.Operation+" response", err)
	}
	if len(raw) > groupJoinBodyLimit || (policy.RejectEmpty && len(raw) == 0) {
		return result, groupJoinSafeError(policy.Operation+" response exceeds local size limit", policy.Invalid)
	}
	result.Body = raw
	return result, nil
}
