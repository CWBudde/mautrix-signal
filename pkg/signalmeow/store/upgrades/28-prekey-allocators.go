// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package upgrades

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
)

// createPreKeyAllocatorsTable must match the table in 00-latest.sql.
const createPreKeyAllocatorsTable = `
CREATE TABLE signalmeow_prekey_allocators (
    account_id TEXT   NOT NULL,
    service_id TEXT   NOT NULL,
    kind       TEXT   NOT NULL CHECK ( kind IN ('ec', 'signed', 'kyber') ),
    next_id    BIGINT NOT NULL CHECK ( next_id >= 0 ),
    active_id  BIGINT CHECK ( active_id IS NULL OR (kind <> 'ec' AND active_id >= 0) ),

    PRIMARY KEY (account_id, service_id, kind),
    FOREIGN KEY (account_id) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
)`

const (
	legacyMaxIDsQuery = `
		SELECT
			(SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_signed=false),
			(SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_signed=true),
			(SELECT MAX(key_id) FROM signalmeow_kyber_pre_keys WHERE account_id=$1 AND service_id=$2)
	`
	legacySignedCandidatesQuery = `
		SELECT COUNT(*), MAX(key_id) FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_signed=true
	`
	legacyLastResortCandidatesQuery = `
		SELECT COUNT(*), MAX(key_id) FROM signalmeow_kyber_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_last_resort=true
	`
	insertLegacyAllocatorQuery = `
		INSERT INTO signalmeow_prekey_allocators (account_id, service_id, kind, next_id, active_id) VALUES ($1, $2, $3, $4, $5)
	`
)

// upgradeV28 adds durable prekey allocators. Existing scopes (each device's current ACI and
// PNI) are seeded once from their retained maxima, the legacy MAX+1 behaviour; consumption
// history that is already lost cannot be reconstructed. A unique retained signed or last-resort
// key becomes the active reference, otherwise it stays unknown. Compatibility v28 keeps older
// binaries, which would allocate from MAX+1 again, from opening the database.
var upgradeV28 = dbutil.WrapUpgrade(-1, 28, 28, "Add durable prekey allocators", dbutil.TxnModeOn, func(ctx context.Context, db *dbutil.Database) error {
	if _, err := db.Exec(ctx, createPreKeyAllocatorsTable); err != nil {
		return fmt.Errorf("failed to create prekey allocator table: %w", err)
	}
	type device struct{ aci, pni string }
	devices, err := dbutil.ConvertRowFn[device](func(row dbutil.Scannable) (device, error) {
		var d device
		return d, row.Scan(&d.aci, &d.pni)
	}).NewRowIter(db.Query(ctx, `SELECT aci_uuid, pni_uuid FROM signalmeow_device`)).AsList()
	if err != nil {
		return fmt.Errorf("failed to query devices: %w", err)
	}
	for _, d := range devices {
		scopes := []string{d.aci}
		if pni, err := uuid.Parse(d.pni); err == nil && pni != uuid.Nil {
			scopes = append(scopes, "PNI:"+pni.String())
		}
		for _, serviceID := range scopes {
			if err := seedLegacyAllocator(ctx, db, d.aci, serviceID); err != nil {
				return fmt.Errorf("failed to seed prekey allocator of %s/%s: %w", d.aci, serviceID, err)
			}
		}
	}
	return nil
})

func seedLegacyAllocator(ctx context.Context, db *dbutil.Database, accountID, serviceID string) error {
	var maxEC, maxSigned, maxKyber sql.NullInt64
	err := db.QueryRow(ctx, legacyMaxIDsQuery, accountID, serviceID).Scan(&maxEC, &maxSigned, &maxKyber)
	if err != nil {
		return err
	}
	activeSigned, err := uniqueCandidate(ctx, db, legacySignedCandidatesQuery, accountID, serviceID)
	if err != nil {
		return err
	}
	activeLastResort, err := uniqueCandidate(ctx, db, legacyLastResortCandidatesQuery, accountID, serviceID)
	if err != nil {
		return err
	}
	for _, row := range []struct {
		kind   string
		max    sql.NullInt64
		active sql.NullInt64
	}{
		{"ec", maxEC, sql.NullInt64{}},
		{"signed", maxSigned, activeSigned},
		{"kyber", maxKyber, activeLastResort},
	} {
		// Wide arithmetic: legacy IDs beyond the source range keep their real MAX+1.
		next := row.max.Int64 + 1
		_, err = db.Exec(ctx, insertLegacyAllocatorQuery, accountID, serviceID, row.kind, next, row.active)
		if err != nil {
			return err
		}
	}
	return nil
}

func uniqueCandidate(ctx context.Context, db *dbutil.Database, query, accountID, serviceID string) (sql.NullInt64, error) {
	var count int
	var id sql.NullInt64
	if err := db.QueryRow(ctx, query, accountID, serviceID).Scan(&count, &id); err != nil {
		return sql.NullInt64{}, err
	}
	if count != 1 {
		return sql.NullInt64{}, nil
	}
	return id, nil
}
