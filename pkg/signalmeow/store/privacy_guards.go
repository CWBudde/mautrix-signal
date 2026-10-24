// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/ptr"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

// Privacy guards protect privacy decisions that were imported from another client (blocking,
// profile sharing, account privacy settings and the own profile key) from being undone by
// storage service snapshots that predate them, and by other writers, until authenticated
// storage agrees. Every recipient write applies protected values, and storage application
// observes the raw remote values; see ObservePrivacyRemote for the release rule.

type PrivacyEntityKind string

const (
	PrivacyEntityAccount PrivacyEntityKind = "account"
	PrivacyEntityACI     PrivacyEntityKind = "aci"
	PrivacyEntityPNI     PrivacyEntityKind = "pni"
)

type PrivacyField string

const (
	PrivacyFieldBlocked                PrivacyField = "blocked"
	PrivacyFieldWhitelisted            PrivacyField = "whitelisted"
	PrivacyFieldReadReceipts           PrivacyField = "read_receipts"
	PrivacyFieldTypingIndicators       PrivacyField = "typing_indicators"
	PrivacyFieldSealedSenderIndicators PrivacyField = "sealed_sender_indicators"
	PrivacyFieldLinkPreviews           PrivacyField = "link_previews"
	PrivacyFieldUnlistedPhoneNumber    PrivacyField = "unlisted_phone_number"
	PrivacyFieldPhoneNumberSharingMode PrivacyField = "phone_number_sharing_mode"
	PrivacyFieldOwnProfileKey          PrivacyField = "own_profile_key"
)

// AccountPrivacyFields are the account fields a guard can protect, in a fixed order.
var AccountPrivacyFields = []PrivacyField{
	PrivacyFieldReadReceipts, PrivacyFieldTypingIndicators, PrivacyFieldSealedSenderIndicators,
	PrivacyFieldLinkPreviews, PrivacyFieldUnlistedPhoneNumber, PrivacyFieldPhoneNumberSharingMode,
	PrivacyFieldOwnProfileKey,
}

var (
	ErrPrivacyGuardInvalid = errors.New("invalid privacy guard")
	ErrPrivacyGuardsExist  = errors.New("privacy guards already seeded")
)

// PrivacyGuard is one protected field of an account or a typed recipient.
type PrivacyGuard struct {
	Kind  PrivacyEntityKind
	ID    uuid.UUID // uuid.Nil for PrivacyEntityAccount
	Field PrivacyField
	// LocalPresent records whether the source had an explicit local value. Value is the
	// effective local value either way (the source's default when it had none).
	LocalPresent bool
	Value        []byte
	Protected    bool
	// ArmedVersion is the storage manifest version the guard was armed at. Only a strictly
	// newer manifest can release it.
	ArmedVersion uint64
	// The last raw remote value observed, and the manifest version it was observed in (0: none).
	RemotePresent   bool
	RemoteValue     []byte
	ObservedVersion uint64
}

// PrivacyBool encodes a boolean guard value.
func PrivacyBool(value bool) []byte {
	if value {
		return []byte{1}
	}
	return []byte{0}
}

// PrivacySharingMode encodes a phone number sharing mode guard value.
func PrivacySharingMode(mode signalpb.AccountRecord_PhoneNumberSharingMode) []byte {
	return []byte{byte(mode)}
}

func validPrivacyValue(field PrivacyField, value []byte) bool {
	switch field {
	case PrivacyFieldOwnProfileKey:
		return len(value) == libsignalgo.ProfileKeyLength
	case PrivacyFieldPhoneNumberSharingMode:
		_, known := signalpb.AccountRecord_PhoneNumberSharingMode_name[int32(ptr.Val(firstByte(value)))]
		return len(value) == 1 && known
	default:
		return len(value) == 1 && value[0] <= 1
	}
}

func firstByte(value []byte) *byte {
	if len(value) == 0 {
		return nil
	}
	return &value[0]
}

func validPrivacyGuard(g PrivacyGuard) error {
	switch g.Kind {
	case PrivacyEntityAccount:
		if g.ID != uuid.Nil || g.Field == PrivacyFieldBlocked || g.Field == PrivacyFieldWhitelisted {
			return fmt.Errorf("%w: account guard %s/%s", ErrPrivacyGuardInvalid, g.ID, g.Field)
		}
	case PrivacyEntityACI, PrivacyEntityPNI:
		if g.ID == uuid.Nil || (g.Field != PrivacyFieldBlocked && g.Field != PrivacyFieldWhitelisted) {
			return fmt.Errorf("%w: %s guard %s/%s", ErrPrivacyGuardInvalid, g.Kind, g.ID, g.Field)
		}
	default:
		return fmt.Errorf("%w: entity kind %q", ErrPrivacyGuardInvalid, g.Kind)
	}
	if g.Kind == PrivacyEntityAccount && !isAccountPrivacyField(g.Field) {
		return fmt.Errorf("%w: field %q", ErrPrivacyGuardInvalid, g.Field)
	}
	if !validPrivacyValue(g.Field, g.Value) {
		return fmt.Errorf("%w: value of %s/%s/%s", ErrPrivacyGuardInvalid, g.Kind, g.ID, g.Field)
	}
	return nil
}

func isAccountPrivacyField(field PrivacyField) bool {
	for _, f := range AccountPrivacyFields {
		if f == field {
			return true
		}
	}
	return false
}

func privacyEntityID(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

type PrivacyGuardStore interface {
	// SeedPrivacyGuards stores the guards of an imported account. It refuses invalid guards
	// and an account that already has guards.
	SeedPrivacyGuards(ctx context.Context, guards []PrivacyGuard) error
	// PrivacyGuards returns all guards of the account, released ones included.
	PrivacyGuards(ctx context.Context) ([]PrivacyGuard, error)
	// ObservePrivacyRemote records a raw remote value from a complete storage snapshot with the
	// given manifest version and reports whether that released the guard.
	ObservePrivacyRemote(ctx context.Context, kind PrivacyEntityKind, id uuid.UUID, field PrivacyField, present bool, value []byte, version uint64) (released bool, err error)
	// RearmPrivacyGuard protects a new local value of an existing guard, armed at the stored
	// manifest highwater. Without a guard for the field it does nothing.
	RearmPrivacyGuard(ctx context.Context, kind PrivacyEntityKind, id uuid.UUID, field PrivacyField, value []byte) (rearmed bool, err error)
	// AdvanceStorageManifestVersion raises the stored storage manifest highwater to version.
	AdvanceStorageManifestVersion(ctx context.Context, version uint64) error
	// StorageManifestVersion returns the stored highwater (0: none).
	StorageManifestVersion(ctx context.Context) (uint64, error)
	// ProjectAccountRecord returns the effective copy of a raw account record.
	ProjectAccountRecord(ctx context.Context, raw *signalpb.AccountRecord) (*signalpb.AccountRecord, error)
}

var _ PrivacyGuardStore = (*sqlStore)(nil)

const (
	privacyGuardColumns = `entity_kind, entity_id, field, local_present, local_value, protected,
		armed_version, remote_present, remote_value, observed_version`
	countPrivacyGuardsQuery  = `SELECT COUNT(*) FROM signalmeow_privacy_guards WHERE account_id=$1`
	insertPrivacyGuardQuery  = `INSERT INTO signalmeow_privacy_guards (account_id, ` + privacyGuardColumns + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	getPrivacyGuardsQuery    = `SELECT ` + privacyGuardColumns + ` FROM signalmeow_privacy_guards WHERE account_id=$1 ORDER BY entity_kind, entity_id, field`
	getPrivacyGuardQuery     = `SELECT ` + privacyGuardColumns + ` FROM signalmeow_privacy_guards WHERE account_id=$1 AND entity_kind=$2 AND entity_id=$3 AND field=$4`
	observePrivacyGuardQuery = `
		UPDATE signalmeow_privacy_guards SET remote_present=$5, remote_value=$6, observed_version=$7, protected=$8
		WHERE account_id=$1 AND entity_kind=$2 AND entity_id=$3 AND field=$4
	`
	rearmPrivacyGuardQuery = `
		UPDATE signalmeow_privacy_guards SET local_present=true, local_value=$5, protected=true,
			armed_version=COALESCE((SELECT storage_manifest_version FROM signalmeow_device WHERE aci_uuid=$1), 0)
		WHERE account_id=$1 AND entity_kind=$2 AND entity_id=$3 AND field=$4
	`
	protectedRecipientGuardsQuery = `
		SELECT entity_kind, field, local_value FROM signalmeow_privacy_guards
		WHERE account_id=$1 AND protected AND (
			(entity_kind='aci' AND entity_id=$2) OR (entity_kind='pni' AND entity_id=$3) OR
			(entity_kind='account' AND field='own_profile_key' AND $2=$1)
		)
	`
	protectedAccountGuardsQuery = `SELECT field, local_value FROM signalmeow_privacy_guards WHERE account_id=$1 AND protected AND entity_kind='account'`
	advanceManifestVersionQuery = `
		UPDATE signalmeow_device SET storage_manifest_version=$2
		WHERE aci_uuid=$1 AND (storage_manifest_version IS NULL OR storage_manifest_version < $2)
	`
	getManifestVersionQuery = `SELECT COALESCE(storage_manifest_version, 0) FROM signalmeow_device WHERE aci_uuid=$1`
)

func scanPrivacyGuard(row dbutil.Scannable) (*PrivacyGuard, error) {
	var g PrivacyGuard
	var id string
	var armed int64
	var observed sql.NullInt64
	err := row.Scan(&g.Kind, &id, &g.Field, &g.LocalPresent, &g.Value, &g.Protected, &armed, &g.RemotePresent, &g.RemoteValue, &observed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if id != "" {
		if g.ID, err = uuid.Parse(id); err != nil {
			return nil, fmt.Errorf("%w: entity ID %q", ErrPrivacyGuardInvalid, id)
		}
	}
	g.ArmedVersion = uint64(armed)
	if observed.Valid {
		g.ObservedVersion = uint64(observed.Int64)
	}
	if len(g.RemoteValue) == 0 {
		g.RemoteValue = nil
	}
	return &g, nil
}

func (s *sqlStore) SeedPrivacyGuards(ctx context.Context, guards []PrivacyGuard) error {
	for _, g := range guards {
		if err := validPrivacyGuard(g); err != nil {
			return err
		}
	}
	return s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		var existing int
		if err := s.db.QueryRow(ctx, countPrivacyGuardsQuery, s.AccountID).Scan(&existing); err != nil {
			return fmt.Errorf("count privacy guards: %w", err)
		} else if existing > 0 {
			return ErrPrivacyGuardsExist
		}
		for _, g := range guards {
			_, err := s.db.Exec(ctx, insertPrivacyGuardQuery, s.AccountID, g.Kind, privacyEntityID(g.ID), g.Field,
				g.LocalPresent, g.Value, g.Protected, int64(g.ArmedVersion), g.RemotePresent, g.RemoteValue,
				sql.NullInt64{Int64: int64(g.ObservedVersion), Valid: g.ObservedVersion != 0})
			if err != nil {
				return fmt.Errorf("store privacy guard %s/%s/%s: %w", g.Kind, g.ID, g.Field, err)
			}
		}
		return nil
	})
}

func (s *sqlStore) PrivacyGuards(ctx context.Context) ([]PrivacyGuard, error) {
	rows, err := s.db.Query(ctx, getPrivacyGuardsQuery, s.AccountID)
	list, err := dbutil.NewRowIterWithError(rows, scanPrivacyGuard, err).AsList()
	if err != nil {
		return nil, err
	}
	guards := make([]PrivacyGuard, len(list))
	for i, g := range list {
		guards[i] = *g
	}
	return guards, nil
}

// ObservePrivacyRemote releases a protected guard only when the snapshot is strictly newer
// than the one the guard was armed at, carries the field (present: a present record, with
// proto3 defaults counting as values) with a valid value, and that value equals the local
// one. Missing records, unknown enums and absent keys never release a guard, and there is no
// timeout. Released guards stay as records of the last observation.
func (s *sqlStore) ObservePrivacyRemote(ctx context.Context, kind PrivacyEntityKind, id uuid.UUID, field PrivacyField, present bool, value []byte, version uint64) (released bool, err error) {
	err = s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		g, err := scanPrivacyGuard(s.db.QueryRow(ctx, getPrivacyGuardQuery, s.AccountID, kind, privacyEntityID(id), field))
		if err != nil || g == nil {
			return err
		}
		present = present && validPrivacyValue(field, value)
		if !present {
			value = nil
		}
		protected := g.Protected
		if protected && present && version > g.ArmedVersion && bytes.Equal(value, g.Value) {
			protected, released = false, true
		}
		observed := max(version, g.ObservedVersion)
		_, err = s.db.Exec(ctx, observePrivacyGuardQuery, s.AccountID, kind, privacyEntityID(id), field,
			present, value, int64(observed), protected)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("observe privacy guard %s/%s/%s: %w", kind, id, field, err)
	}
	return released, nil
}

func (s *sqlStore) RearmPrivacyGuard(ctx context.Context, kind PrivacyEntityKind, id uuid.UUID, field PrivacyField, value []byte) (bool, error) {
	if err := validPrivacyGuard(PrivacyGuard{Kind: kind, ID: id, Field: field, Value: value}); err != nil {
		return false, err
	}
	res, err := s.db.Exec(ctx, rearmPrivacyGuardQuery, s.AccountID, kind, privacyEntityID(id), field, value)
	if err != nil {
		return false, fmt.Errorf("rearm privacy guard %s/%s/%s: %w", kind, id, field, err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *sqlStore) AdvanceStorageManifestVersion(ctx context.Context, version uint64) error {
	_, err := s.db.Exec(ctx, advanceManifestVersionQuery, s.AccountID, int64(version))
	return err
}

func (s *sqlStore) StorageManifestVersion(ctx context.Context) (version uint64, err error) {
	var stored int64
	err = s.db.QueryRow(ctx, getManifestVersionQuery, s.AccountID).Scan(&stored)
	return uint64(stored), err
}

// applyRecipientGuards replaces protected fields of a recipient about to be written: blocked
// and whitelisted of its PNI and then its ACI (which wins), and our own profile key.
func (s *sqlStore) applyRecipientGuards(ctx context.Context, recipient *types.Recipient) error {
	rows, err := s.db.Query(ctx, protectedRecipientGuardsQuery, s.AccountID,
		recipient.ACI.String(), recipient.PNI.String())
	if err != nil {
		return fmt.Errorf("load protected recipient guards: %w", err)
	}
	var byACI, byPNI []struct {
		field PrivacyField
		value []byte
	}
	for rows.Next() {
		var kind PrivacyEntityKind
		var entry struct {
			field PrivacyField
			value []byte
		}
		if err = rows.Scan(&kind, &entry.field, &entry.value); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan protected recipient guard: %w", err)
		}
		if kind == PrivacyEntityPNI {
			byPNI = append(byPNI, entry)
		} else {
			byACI = append(byACI, entry)
		}
	}
	if err = rows.Close(); err != nil {
		return err
	} else if err = rows.Err(); err != nil {
		return err
	}
	for _, entry := range append(byPNI, byACI...) {
		if !validPrivacyValue(entry.field, entry.value) {
			return fmt.Errorf("%w: stored value of %s", ErrPrivacyGuardInvalid, entry.field)
		}
		switch entry.field {
		case PrivacyFieldBlocked:
			recipient.Blocked = entry.value[0] == 1
		case PrivacyFieldWhitelisted:
			recipient.Whitelisted = ptr.Ptr(entry.value[0] == 1)
		case PrivacyFieldOwnProfileKey:
			recipient.Profile.Key = libsignalgo.ProfileKey(entry.value)
		}
	}
	return nil
}

// protectedOwnProfileKey returns our protected profile key, or nil.
func (s *sqlStore) protectedOwnProfileKey(ctx context.Context) (*libsignalgo.ProfileKey, error) {
	g, err := scanPrivacyGuard(s.db.QueryRow(ctx, getPrivacyGuardQuery, s.AccountID, PrivacyEntityAccount, "", PrivacyFieldOwnProfileKey))
	if err != nil || g == nil || !g.Protected || !validPrivacyValue(g.Field, g.Value) {
		return nil, err
	}
	return ptr.Ptr(libsignalgo.ProfileKey(g.Value)), nil
}

// ProjectAccountRecord returns a copy of the raw authenticated account record with the
// account's protected values applied: the effective record to store and publish. The raw
// record is never modified.
func (s *sqlStore) ProjectAccountRecord(ctx context.Context, raw *signalpb.AccountRecord) (*signalpb.AccountRecord, error) {
	rows, err := s.db.Query(ctx, protectedAccountGuardsQuery, s.AccountID)
	if err != nil {
		return nil, fmt.Errorf("load protected account guards: %w", err)
	}
	defer rows.Close()
	projected := proto.Clone(raw).(*signalpb.AccountRecord)
	for rows.Next() {
		var field PrivacyField
		var value []byte
		if err = rows.Scan(&field, &value); err != nil {
			return nil, fmt.Errorf("scan protected account guard: %w", err)
		} else if !validPrivacyValue(field, value) {
			return nil, fmt.Errorf("%w: stored value of %s", ErrPrivacyGuardInvalid, field)
		}
		on := value[0] == 1
		switch field {
		case PrivacyFieldReadReceipts:
			projected.ReadReceipts = on
		case PrivacyFieldTypingIndicators:
			projected.TypingIndicators = on
		case PrivacyFieldSealedSenderIndicators:
			projected.SealedSenderIndicators = on
		case PrivacyFieldLinkPreviews:
			projected.LinkPreviews = on
		case PrivacyFieldUnlistedPhoneNumber:
			projected.UnlistedPhoneNumber = on
		case PrivacyFieldPhoneNumberSharingMode:
			projected.PhoneNumberSharingMode = signalpb.AccountRecord_PhoneNumberSharingMode(value[0])
		case PrivacyFieldOwnProfileKey:
			projected.ProfileKey = bytes.Clone(value)
		}
	}
	return projected, rows.Err()
}

// AccountPrivacyValues returns the raw remote values of the account record's guarded fields,
// as ObservePrivacyRemote takes them. An unknown sharing mode or an absent profile key is not
// present.
func AccountPrivacyValues(record *signalpb.AccountRecord) map[PrivacyField][]byte {
	values := map[PrivacyField][]byte{
		PrivacyFieldReadReceipts:           PrivacyBool(record.GetReadReceipts()),
		PrivacyFieldTypingIndicators:       PrivacyBool(record.GetTypingIndicators()),
		PrivacyFieldSealedSenderIndicators: PrivacyBool(record.GetSealedSenderIndicators()),
		PrivacyFieldLinkPreviews:           PrivacyBool(record.GetLinkPreviews()),
		PrivacyFieldUnlistedPhoneNumber:    PrivacyBool(record.GetUnlistedPhoneNumber()),
	}
	mode := record.GetPhoneNumberSharingMode()
	if _, known := signalpb.AccountRecord_PhoneNumberSharingMode_name[int32(mode)]; known && mode >= 0 && mode <= 255 {
		values[PrivacyFieldPhoneNumberSharingMode] = PrivacySharingMode(mode)
	}
	if len(record.GetProfileKey()) == libsignalgo.ProfileKeyLength {
		values[PrivacyFieldOwnProfileKey] = bytes.Clone(record.GetProfileKey())
	}
	return values
}

// SetRecipientBlocked records a local block decision for a typed user. An existing privacy
// guard for it is re-armed with the new value in the same transaction, so that storage
// snapshots predating the decision can't undo it.
func (d *Device) SetRecipientBlocked(ctx context.Context, serviceID libsignalgo.ServiceID, blocked bool) (*types.Recipient, error) {
	kind, aci, pni := PrivacyEntityACI, serviceID.UUID, uuid.Nil
	if serviceID.Type == libsignalgo.ServiceIDTypePNI {
		kind, aci, pni = PrivacyEntityPNI, uuid.Nil, serviceID.UUID
	}
	var recipient *types.Recipient
	err := d.DoContactTxn(ctx, func(ctx context.Context) error {
		if _, err := d.PrivacyGuardStore.RearmPrivacyGuard(ctx, kind, serviceID.UUID, PrivacyFieldBlocked, PrivacyBool(blocked)); err != nil {
			return err
		}
		var err error
		recipient, err = d.RecipientStore.LoadAndUpdateRecipient(ctx, aci, pni, func(r *types.Recipient) (bool, error) {
			if r.Blocked == blocked {
				return false, nil
			}
			r.Blocked = blocked
			return true, nil
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("set blocked state of %s: %w", serviceID, err)
	}
	return recipient, nil
}
