// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
)

// PreKeyKind names one of the three independent prekey ID counters of a local service ID.
// Ordinary and last-resort Kyber keys share the Kyber counter.
type PreKeyKind string

const (
	PreKeyEC     PreKeyKind = "ec"
	PreKeySigned PreKeyKind = "signed"
	PreKeyKyber  PreKeyKind = "kyber"
)

// PreKeyIDLimit is the exclusive bound of generated prekey IDs (0..0xfffffe), the modulo
// signal-cli uses. Allocation refuses to wrap at it.
const PreKeyIDLimit uint64 = 0xffffff

var (
	ErrPreKeyAllocatorUninitialized   = errors.New("prekey allocator is not initialized")
	ErrPreKeyAllocatorExists          = errors.New("prekey allocator is already initialized")
	ErrPreKeyAllocatorInvalid         = errors.New("invalid prekey allocator request")
	ErrPreKeyAllocatorExhausted       = errors.New("prekey ID space is exhausted")
	ErrPreKeyReservationInTransaction = errors.New("prekey IDs must not be reserved inside a transaction")
	ErrPreKeyTransactionRequired      = errors.New("operation requires an enclosing transaction")
)

// PreKeyAllocatorState is the durable allocator state of one account and local typed service ID.
// Active references are nil when unknown or absent.
type PreKeyAllocatorState struct {
	NextEC, NextSigned, NextKyber  uint64
	ActiveSigned, ActiveLastResort *uint32
}

const (
	getAllocatorQuery = `
		SELECT kind, next_id, active_id FROM signalmeow_prekey_allocators WHERE account_id=$1 AND service_id=$2
	`
	insertAllocatorQuery = `
		INSERT INTO signalmeow_prekey_allocators (account_id, service_id, kind, next_id, active_id) VALUES ($1, $2, $3, $4, $5)
	`
	reserveAllocatorQuery = `
		UPDATE signalmeow_prekey_allocators SET next_id=next_id+$4
		WHERE account_id=$1 AND service_id=$2 AND kind=$3 AND next_id<=$5
		RETURNING next_id
	`
	getAllocatorNextQuery = `
		SELECT next_id FROM signalmeow_prekey_allocators WHERE account_id=$1 AND service_id=$2 AND kind=$3
	`
	advanceAllocatorQuery = `
		UPDATE signalmeow_prekey_allocators SET next_id=$4 WHERE account_id=$1 AND service_id=$2 AND kind=$3 AND next_id<$4
	`
	countPreKeysQuery = `
		SELECT
			(SELECT COUNT(*) FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_signed=false),
			(SELECT COUNT(*) FROM signalmeow_kyber_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_last_resort=false)
	`
	maxPreKeyIDsQuery = `
		SELECT
			(SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_signed=false),
			(SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND is_signed=true),
			(SELECT MAX(key_id) FROM signalmeow_kyber_pre_keys WHERE account_id=$1 AND service_id=$2)
	`
	signedPreKeyExistsQuery = `
		SELECT EXISTS(SELECT 1 FROM signalmeow_pre_keys WHERE account_id=$1 AND service_id=$2 AND key_id=$3 AND is_signed=true)
	`
	lastResortKeyExistsQuery = `
		SELECT EXISTS(SELECT 1 FROM signalmeow_kyber_pre_keys WHERE account_id=$1 AND service_id=$2 AND key_id=$3 AND is_last_resort=true)
	`
	getDeviceServiceIDsQuery = `SELECT pni_uuid FROM signalmeow_device WHERE aci_uuid=$1`
)

// inTransaction reports whether ctx carries a transaction of db (or of a database sharing its
// root). Transactions of other database handles on the same file are not visible.
func inTransaction(ctx context.Context, db *dbutil.Database) bool {
	_, ok := db.Execable(ctx).(dbutil.Transaction)
	return ok
}

func (k PreKeyKind) valid() bool {
	return k == PreKeyEC || k == PreKeySigned || k == PreKeyKyber
}

// SeedPreKeyAllocator initializes the allocator of one local service ID of accountACI. It must
// run in the caller's transaction, together with the records it describes, and refuses to
// overwrite an existing allocator.
func (c *Container) SeedPreKeyAllocator(ctx context.Context, accountACI uuid.UUID, serviceID libsignalgo.ServiceID, state PreKeyAllocatorState) error {
	if !inTransaction(ctx, c.db) {
		return ErrPreKeyTransactionRequired
	}
	if err := c.checkLocalServiceID(ctx, accountACI, serviceID); err != nil {
		return err
	}
	var existing int
	err := c.db.QueryRow(ctx, `SELECT COUNT(*) FROM signalmeow_prekey_allocators WHERE account_id=$1 AND service_id=$2`,
		accountACI, serviceID).Scan(&existing)
	if err != nil {
		return fmt.Errorf("failed to query prekey allocator: %w", err)
	} else if existing > 0 {
		return fmt.Errorf("%w: %s", ErrPreKeyAllocatorExists, serviceID)
	}
	if err := c.validateSeed(ctx, accountACI, serviceID, state); err != nil {
		return err
	}
	return c.insertAllocator(ctx, accountACI, serviceID, state)
}

func (c *Container) insertAllocator(ctx context.Context, accountACI uuid.UUID, serviceID libsignalgo.ServiceID, state PreKeyAllocatorState) error {
	rows := []struct {
		kind   PreKeyKind
		next   uint64
		active *uint32
	}{
		{PreKeyEC, state.NextEC, nil},
		{PreKeySigned, state.NextSigned, state.ActiveSigned},
		{PreKeyKyber, state.NextKyber, state.ActiveLastResort},
	}
	for _, row := range rows {
		var active sql.NullInt64
		if row.active != nil {
			active = sql.NullInt64{Int64: int64(*row.active), Valid: true}
		}
		_, err := c.db.Exec(ctx, insertAllocatorQuery, accountACI, serviceID, string(row.kind), int64(row.next), active)
		if err != nil {
			return fmt.Errorf("failed to store %s prekey allocator: %w", row.kind, err)
		}
	}
	return nil
}

func (c *Container) checkLocalServiceID(ctx context.Context, accountACI uuid.UUID, serviceID libsignalgo.ServiceID) error {
	var pni uuid.UUID
	err := c.db.QueryRow(ctx, getDeviceServiceIDsQuery, accountACI).Scan(&pni)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: unknown account %s", ErrPreKeyAllocatorInvalid, accountACI)
	} else if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}
	switch {
	case serviceID.Type == libsignalgo.ServiceIDTypeACI && serviceID.UUID == accountACI:
	case serviceID.Type == libsignalgo.ServiceIDTypePNI && serviceID.UUID == pni && pni != uuid.Nil:
	default:
		return fmt.Errorf("%w: %s is not a local service ID of %s", ErrPreKeyAllocatorInvalid, serviceID, accountACI)
	}
	return nil
}

func (c *Container) validateSeed(ctx context.Context, accountACI uuid.UUID, serviceID libsignalgo.ServiceID, state PreKeyAllocatorState) error {
	var maxEC, maxSigned, maxKyber sql.NullInt64
	err := c.db.QueryRow(ctx, maxPreKeyIDsQuery, accountACI, serviceID).Scan(&maxEC, &maxSigned, &maxKyber)
	if err != nil {
		return fmt.Errorf("failed to query retained prekey IDs: %w", err)
	}
	for _, pos := range []struct {
		kind PreKeyKind
		next uint64
		max  sql.NullInt64
	}{
		{PreKeyEC, state.NextEC, maxEC},
		{PreKeySigned, state.NextSigned, maxSigned},
		{PreKeyKyber, state.NextKyber, maxKyber},
	} {
		if pos.next > PreKeyIDLimit {
			return fmt.Errorf("%w: %s next ID %d is beyond %d", ErrPreKeyAllocatorInvalid, pos.kind, pos.next, PreKeyIDLimit)
		} else if pos.max.Valid && pos.next <= uint64(pos.max.Int64) {
			return fmt.Errorf("%w: %s next ID %d is not above retained ID %d", ErrPreKeyAllocatorInvalid, pos.kind, pos.next, pos.max.Int64)
		}
	}
	for _, ref := range []struct {
		name  string
		id    *uint32
		query string
	}{
		{"active signed prekey", state.ActiveSigned, signedPreKeyExistsQuery},
		{"active last-resort Kyber prekey", state.ActiveLastResort, lastResortKeyExistsQuery},
	} {
		if ref.id == nil {
			continue
		}
		var exists bool
		if err := c.db.QueryRow(ctx, ref.query, accountACI, serviceID, *ref.id).Scan(&exists); err != nil {
			return fmt.Errorf("failed to query %s: %w", ref.name, err)
		} else if !exists {
			return fmt.Errorf("%w: %s %d is not stored", ErrPreKeyAllocatorInvalid, ref.name, *ref.id)
		}
	}
	return nil
}

// PreKeyAllocatorState returns a snapshot of the allocator without allocating.
func (s *scopedSQLStore) PreKeyAllocatorState(ctx context.Context) (PreKeyAllocatorState, error) {
	rows, err := s.db.Query(ctx, getAllocatorQuery, s.AccountID, s.ServiceID)
	if err != nil {
		return PreKeyAllocatorState{}, fmt.Errorf("failed to query prekey allocator: %w", err)
	}
	defer rows.Close()
	var state PreKeyAllocatorState
	seen := 0
	for rows.Next() {
		var kind string
		var next int64
		var active sql.NullInt64
		if err := rows.Scan(&kind, &next, &active); err != nil {
			return PreKeyAllocatorState{}, fmt.Errorf("failed to scan prekey allocator: %w", err)
		}
		var ref *uint32
		if active.Valid {
			id := uint32(active.Int64)
			ref = &id
		}
		switch PreKeyKind(kind) {
		case PreKeyEC:
			state.NextEC = uint64(next)
		case PreKeySigned:
			state.NextSigned, state.ActiveSigned = uint64(next), ref
		case PreKeyKyber:
			state.NextKyber, state.ActiveLastResort = uint64(next), ref
		default:
			continue
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return PreKeyAllocatorState{}, fmt.Errorf("failed to read prekey allocator: %w", err)
	}
	if seen != 3 {
		return PreKeyAllocatorState{}, fmt.Errorf("%w: %s", ErrPreKeyAllocatorUninitialized, s.ServiceID)
	}
	return state, nil
}

// PreKeyCounts returns the numbers of ordinary EC and ordinary (not last-resort) Kyber prekeys.
func (s *scopedSQLStore) PreKeyCounts(ctx context.Context) (ordinaryEC, ordinaryKyber uint32, err error) {
	err = s.db.QueryRow(ctx, countPreKeysQuery, s.AccountID, s.ServiceID).Scan(&ordinaryEC, &ordinaryKyber)
	if err != nil {
		err = fmt.Errorf("failed to count prekeys: %w", err)
	}
	return
}

// ReservePreKeyIDs durably reserves count consecutive IDs of kind and returns the first. The
// reservation commits in its own transaction before returning, so a later failure leaves a
// gap and never reusable IDs. It refuses to run inside a caller's transaction, whose rollback
// would otherwise hand the range out again. On error no IDs are consumed and start is 0.
func (s *scopedSQLStore) ReservePreKeyIDs(ctx context.Context, kind PreKeyKind, count uint32) (start uint32, err error) {
	if inTransaction(ctx, s.db) {
		return 0, ErrPreKeyReservationInTransaction
	} else if !kind.valid() {
		return 0, fmt.Errorf("%w: kind %q", ErrPreKeyAllocatorInvalid, kind)
	} else if count == 0 || uint64(count) > PreKeyIDLimit {
		return 0, fmt.Errorf("%w: count %d", ErrPreKeyAllocatorInvalid, count)
	} else if err = ctx.Err(); err != nil {
		return 0, fmt.Errorf("failed to reserve prekey IDs: %w", err)
	}
	var end int64
	err = s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		err := s.db.QueryRow(ctx, reserveAllocatorQuery, s.AccountID, s.ServiceID, string(kind),
			int64(count), int64(PreKeyIDLimit-uint64(count))).Scan(&end)
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var next int64
		err = s.db.QueryRow(ctx, getAllocatorNextQuery, s.AccountID, s.ServiceID, string(kind)).Scan(&next)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s %s", ErrPreKeyAllocatorUninitialized, s.ServiceID, kind)
		} else if err != nil {
			return err
		}
		return fmt.Errorf("%w: %s %s next ID %d, %d requested", ErrPreKeyAllocatorExhausted, s.ServiceID, kind, next, count)
	})
	if err != nil {
		return 0, fmt.Errorf("failed to reserve %d %s prekey IDs: %w", count, kind, err)
	}
	return uint32(end - int64(count)), nil
}

// nextPreKeyID returns the persisted next position of kind as a uint32 snapshot.
func (s *scopedSQLStore) nextPreKeyID(ctx context.Context, kind PreKeyKind) (uint32, error) {
	var next int64
	err := s.db.QueryRow(ctx, getAllocatorNextQuery, s.AccountID, s.ServiceID, string(kind)).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: %s %s", ErrPreKeyAllocatorUninitialized, s.ServiceID, kind)
	} else if err != nil {
		return 0, err
	} else if next > math.MaxUint32 {
		return 0, fmt.Errorf("%w: %s %s next ID %d", ErrPreKeyAllocatorExhausted, s.ServiceID, kind, next)
	}
	return uint32(next), nil
}

// advancePreKeyAllocator moves an existing allocator position monotonically past id. It runs
// in the transaction of the record write and never creates allocator state.
func (s *scopedSQLStore) advancePreKeyAllocator(ctx context.Context, kind PreKeyKind, id uint32) error {
	_, err := s.db.Exec(ctx, advanceAllocatorQuery, s.AccountID, s.ServiceID, string(kind), int64(id)+1)
	if err != nil {
		return fmt.Errorf("failed to advance %s prekey allocator: %w", kind, err)
	}
	return nil
}
