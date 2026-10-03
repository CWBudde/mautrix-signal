// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
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

// groupJoinHTTPRequest keeps the password-bearing join endpoints and policy.
func groupJoinHTTPRequest(ctx context.Context, method string, password, body []byte, auth *GroupAuth) (groupJoinHTTPResult, error) {
	var path string
	switch method {
	case http.MethodGet:
		path = "/v2/groups/join/" + base64.RawURLEncoding.EncodeToString(password)
	case http.MethodPatch:
		path = "/v2/groups/?inviteLinkPassword=" + base64.RawURLEncoding.EncodeToString(password)
	default:
		return groupJoinHTTPResult{}, ErrGroupJoinInvalid
	}
	return groupMembershipHTTPRequest(ctx, method, path, body, auth, groupMembershipHTTPPolicy{
		Operation: "group join", Invalid: ErrGroupJoinInvalid, Uncertain: ErrGroupJoinUncertain, Terminated: ErrGroupJoinTerminated,
		RefusalHint:   "; the link may be unavailable, reset, disabled, or banned",
		TransportHint: "; inspect membership or ask an administrator before retrying",
	})
}
