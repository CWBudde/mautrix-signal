// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build libsignal_go

package store_test

import (
	"fmt"
	"net/url"

	// Registers the "sqlite" database/sql driver.
	_ "modernc.org/sqlite"
)

const testSQLiteDriver = "sqlite"

// testSQLiteDSN matches go-signal's account database options (internal/store/sqlite_purego.go).
func testSQLiteDSN(path string, busyTimeoutMS int) string {
	return (&url.URL{
		Scheme: "file",
		Opaque: path,
		RawQuery: fmt.Sprintf("_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)", busyTimeoutMS) +
			"&_txlock=immediate",
	}).String()
}
