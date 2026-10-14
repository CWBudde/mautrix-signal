// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build cgo && !libsignal_go

package store_test

import (
	"fmt"
	"net/url"

	// Registers the "sqlite3" database/sql driver.
	_ "github.com/mattn/go-sqlite3"
)

const testSQLiteDriver = "sqlite3"

// testSQLiteDSN matches go-signal's account database options (internal/store/sqlite_cgo.go).
func testSQLiteDSN(path string, busyTimeoutMS int) string {
	return (&url.URL{
		Scheme:   "file",
		Opaque:   path,
		RawQuery: fmt.Sprintf("_foreign_keys=on&_journal_mode=WAL&_busy_timeout=%d&_txlock=immediate", busyTimeoutMS),
	}).String()
}
