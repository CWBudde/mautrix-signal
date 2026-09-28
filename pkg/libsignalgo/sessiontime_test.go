// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2026 Christian Budde
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package libsignalgo_test

import (
	"context"
	"testing"
	"time"

	sigproto "github.com/cwbudde/libsignal-go/proto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
)

// maxUnacknowledgedSessionAge is libsignal's MAX_UNACKNOWLEDGED_SESSION_AGE.
const maxUnacknowledgedSessionAge = 30 * 24 * time.Hour

// TestUnacknowledgedSessionClock checks the clock both backends give libsignal for a new session:
// the pending pre-key's creation time is stored in epoch seconds (as libsignal and libsignal-go
// read it), and a session left unacknowledged for longer than MAX_UNACKNOWLEDGED_SESSION_AGE is
// stale for HasCurrentState and Encrypt. The cgo backend used to pass seconds where libsignal takes
// milliseconds, which stored 1970 timestamps that libsignal-go took as stale and made cgo's own
// staleness check never fire.
func TestUnacknowledgedSessionClock(t *testing.T) {
	ctx := context.Background()

	aliceAddress, err := libsignalgo.NewACIServiceID(uuid.New()).Address(1)
	require.NoError(t, err)
	bobAddress, err := libsignalgo.NewACIServiceID(uuid.New()).Address(1)
	require.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	bobStore := NewInMemorySignalProtocolStore()

	before := time.Now().Unix()
	initializeSessions(t, aliceStore, bobStore, bobAddress, aliceAddress)
	after := time.Now().Unix()

	record, err := aliceStore.LoadSession(ctx, bobAddress)
	require.NoError(t, err)
	serialized, err := record.Serialize()
	require.NoError(t, err)

	var structure sigproto.RecordStructure
	require.NoError(t, proto.Unmarshal(serialized, &structure))
	pending := structure.GetCurrentSession().GetPendingPreKey()
	require.NotNil(t, pending, "a new session has an unacknowledged pre-key")
	require.GreaterOrEqual(t, int64(pending.GetTimestamp()), before, "pending pre-key time (epoch seconds)")
	require.LessOrEqual(t, int64(pending.GetTimestamp()), after, "pending pre-key time (epoch seconds)")

	_, err = libsignalgo.Encrypt(ctx, []byte("fresh"), bobAddress, aliceAddress, aliceStore, aliceStore)
	require.NoError(t, err, "encrypting to a fresh unacknowledged session")

	// Backdate the session past MAX_UNACKNOWLEDGED_SESSION_AGE.
	record, err = aliceStore.LoadSession(ctx, bobAddress)
	require.NoError(t, err)
	serialized, err = record.Serialize()
	require.NoError(t, err)
	structure.Reset()
	require.NoError(t, proto.Unmarshal(serialized, &structure))
	stale := time.Now().Add(-maxUnacknowledgedSessionAge - time.Hour).Unix()
	structure.GetCurrentSession().GetPendingPreKey().Timestamp = uint64(stale)
	serialized, err = proto.Marshal(&structure)
	require.NoError(t, err)
	record, err = libsignalgo.DeserializeSessionRecord(serialized)
	require.NoError(t, err)

	usable, err := record.HasCurrentState()
	require.NoError(t, err)
	require.False(t, usable, "HasCurrentState of a stale unacknowledged session")

	require.NoError(t, aliceStore.StoreSession(ctx, bobAddress, record))
	_, err = libsignalgo.Encrypt(ctx, []byte("stale"), bobAddress, aliceAddress, aliceStore, aliceStore)
	require.Error(t, err, "encrypting to a stale unacknowledged session")
}
