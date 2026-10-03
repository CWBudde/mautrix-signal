// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

var (
	ErrGroupJoinTerminated = errors.New("group is terminated")
	ErrGroupJoinUncertain  = errors.New("group join outcome is uncertain; inspect membership or ask an administrator before retrying")
	ErrGroupJoinInvalid    = errors.New("invalid group join data")
	ErrGroupJoinInactive   = errors.New("group invite link is disabled or unsupported")
	ErrGroupJoinPending    = errors.New("group join request is already pending")
)

// Error text is deliberately independent of the cause: even nested URL errors
// and arbitrary server/header/body values may contain invite secrets. Unwrap
// preserves cancellation, transport and sentinel identity for callers.
type groupJoinError struct {
	message string
	cause   error
}

func (e *groupJoinError) Error() string { return e.message }
func (e *groupJoinError) Unwrap() error { return e.cause }
func groupJoinSafeError(message string, cause error) error {
	return &groupJoinError{message: message, cause: cause}
}

const groupJoinBodyLimit = 1 << 20

type groupJoinHTTPResult struct {
	Attempted bool
	Accepted  bool
	Body      []byte
}

func groupJoinStatusError(status int) error {
	switch status {
	case http.StatusBadRequest:
		return GroupPatchNotAcceptedError
	case http.StatusUnauthorized, http.StatusForbidden:
		return AuthorizationFailedError
	case http.StatusNotFound:
		return NotFoundError
	case http.StatusConflict:
		return ConflictError
	case http.StatusLocked:
		return ErrGroupJoinTerminated
	case http.StatusTooManyRequests:
		return RateLimitError
	case 499:
		return DeprecatedVersionError
	default:
		return nil
	}
}

// groupJoinHTTPRequest performs a single request with the configured transport
// and TLS settings. Its per-call client refuses redirects without changing the
// shared client. It never logs the password-bearing request or server contents.
func groupJoinHTTPRequest(ctx context.Context, method string, password, body []byte, auth *GroupAuth) (result groupJoinHTTPResult, err error) {
	if err = ctx.Err(); err != nil {
		return result, groupJoinSafeError("group join canceled before submission", err)
	}
	var path string
	switch method {
	case http.MethodGet:
		path = "/v2/groups/join/" + base64.RawURLEncoding.EncodeToString(password)
	case http.MethodPatch:
		path = "/v2/groups/?inviteLinkPassword=" + base64.RawURLEncoding.EncodeToString(password)
	default:
		return result, ErrGroupJoinInvalid
	}
	// Suppress contextual dependency logging on this sensitive path as well.
	ctx = zerolog.Nop().WithContext(ctx)
	req, err := http.NewRequestWithContext(ctx, method, "https://"+web.StorageHostname+path, bytes.NewReader(body))
	if err != nil {
		return result, groupJoinSafeError("could not prepare group join request", err)
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
			cause = errors.Join(ErrGroupJoinUncertain, err)
		}
		return result, groupJoinSafeError("group join transport failed; inspect membership or ask an administrator before retrying", cause)
	}
	result.Accepted = method == http.MethodPatch && resp.StatusCode == http.StatusOK
	if resp.StatusCode != http.StatusOK {
		cause := groupJoinStatusError(resp.StatusCode)
		if cause != nil {
			return result, groupJoinSafeError(fmt.Sprintf("group join refused (HTTP %d); the link may be unavailable, reset, disabled, or banned", resp.StatusCode), cause)
		}
		if method == http.MethodPatch {
			cause = ErrGroupJoinUncertain
		} else {
			cause = ErrGroupJoinInvalid
		}
		return result, groupJoinSafeError(fmt.Sprintf("unexpected group join response (HTTP %d); inspect before retrying", resp.StatusCode), cause)
	}
	if method == http.MethodGet {
		timestamp := resp.Header.Get("X-Signal-Timestamp")
		if timestamp == "" {
			return result, groupJoinSafeError("group join response has no valid timestamp", ErrGroupJoinInvalid)
		}
		for _, c := range timestamp {
			if c < '0' || c > '9' {
				return result, groupJoinSafeError("group join response has no valid timestamp", ErrGroupJoinInvalid)
			}
		}
		if _, err = strconv.ParseUint(timestamp, 10, 64); err != nil {
			return result, groupJoinSafeError("group join response has no valid timestamp", ErrGroupJoinInvalid)
		}
	}
	if resp.Body == nil {
		return result, groupJoinSafeError("group join response has no body", ErrGroupJoinInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, groupJoinBodyLimit+1))
	if err != nil {
		return result, groupJoinSafeError("could not read group join response", err)
	}
	if len(raw) > groupJoinBodyLimit {
		return result, groupJoinSafeError("group join response exceeds local size limit", ErrGroupJoinInvalid)
	}
	result.Body = raw
	return result, nil
}
