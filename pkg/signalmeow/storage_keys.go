// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
)

var errMalformedKeysSync = errors.New("malformed keys sync message")

// legacyStorageKeyField is SyncMessage.Keys.storageService, the derived storage service key
// older primaries send. Signal-Android's schema reserves it, so it is read from the unknown
// fields instead of a fork-only change to the generated protobufs.
const legacyStorageKeyField protowire.Number = 1

// legacyStorageServiceKey returns the legacy derived key of a keys sync message, or nil.
func legacyStorageServiceKey(keys *signalpb.SyncMessage_Keys) ([]byte, error) {
	var key []byte
	raw := keys.ProtoReflect().GetUnknown()
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, fmt.Errorf("%w: %w", errMalformedKeysSync, protowire.ParseError(n))
		}
		raw = raw[n:]
		if num == legacyStorageKeyField && typ == protowire.BytesType {
			value, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, fmt.Errorf("%w: %w", errMalformedKeysSync, protowire.ParseError(m))
			}
			// The last occurrence wins, as for any protobuf scalar.
			key, raw = append([]byte{}, value...), raw[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return nil, fmt.Errorf("%w: %w", errMalformedKeysSync, protowire.ParseError(m))
		}
		raw = raw[m:]
	}
	return key, nil
}

// HasStorageServiceKey reports whether the device's storage service key forms resolve.
func (cli *Client) HasStorageServiceKey() bool { return !cli.needsStorageKeys() }

// needsStorageKeys reports whether the storage service key is unknown, invalid or ambiguous,
// so that connecting should request the keys from the primary device.
func (cli *Client) needsStorageKeys() bool {
	_, err := cli.Store.ResolveStorageServiceKey()
	return err != nil
}

// handleKeysSync applies an authenticated SyncMessage.Keys update from our own ACI. It is
// persisted before the in-memory device changes; a failed write returns false so that the
// message is redelivered. Invalid key material is logged and dropped.
func (cli *Client) handleKeysSync(ctx context.Context, keys *signalpb.SyncMessage_Keys) bool {
	log := zerolog.Ctx(ctx)
	legacy, err := legacyStorageServiceKey(keys)
	if err != nil {
		log.Warn().Err(err).Msg("Ignoring malformed legacy storage service key")
		legacy = nil
	}
	aep := libsignalgo.AccountEntropyPool(keys.GetAccountEntropyPool())
	updated, changed, err := store.ApplyStorageKeySync(cli.Store.DeviceData, aep, legacy)
	if err != nil {
		log.Err(err).Msg("Ignoring invalid storage service keys")
		return true
	}
	if changed {
		if err := cli.Store.DeviceStore.PutDevice(ctx, &updated); err != nil {
			log.Err(err).Msg("Failed to save device after receiving storage service keys")
			return false
		}
		cli.Store.AccountEntropyPool, cli.Store.MasterKey, cli.Store.DerivedStorageKey =
			updated.AccountEntropyPool, updated.MasterKey, updated.DerivedStorageKey
		log.Info().Msg("Received storage service keys")
	} else {
		log.Debug().Msg("Storage service keys unchanged")
	}
	if _, err := cli.Store.ResolveStorageServiceKey(); err != nil {
		log.Warn().Err(err).Msg("Storage service key still unavailable after keys sync")
		return true
	}
	cli.startStorageSync(ctx)
	return true
}

func (cli *Client) startStorageSync(ctx context.Context) {
	if cli.storageSyncHook != nil {
		cli.storageSyncHook(ctx)
		return
	}
	go cli.SyncStorage(ctx)
}
