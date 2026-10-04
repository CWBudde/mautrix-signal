// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

// incomingStoryMessage deliberately sends no delivery or read receipts.
func (cli *Client) incomingStoryMessage(ctx context.Context, msg *signalpb.StoryMessage, sender uuid.UUID, chat libsignalgo.ServiceID, timestamp, serverTimestamp uint64, blocked bool) bool {
	if msg.GetGroup() == nil && blocked {
		return true
	}
	if len(msg.GetProfileKey()) > 0 {
		if len(msg.GetProfileKey()) != libsignalgo.ProfileKeyLength {
			return false
		}
		if err := cli.Store.RecipientStore.StoreProfileKey(ctx, sender, libsignalgo.ProfileKey(msg.GetProfileKey())); err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to store story profile key")
			return false
		}
	}
	var groupID types.GroupIdentifier
	var revision uint32
	if group := msg.GetGroup(); group != nil {
		if len(group.GetMasterKey()) != libsignalgo.GroupMasterKeyLength {
			return false
		}
		var err error
		groupID, err = cli.StoreMasterKey(ctx, masterKeyFromBytes(libsignalgo.GroupMasterKey(group.GetMasterKey())))
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to store story group key")
			return false
		}
		revision = group.GetRevision()
	}
	return cli.handleEvent(&events.Story{Info: events.MessageInfo{Sender: sender, ChatID: groupOrUserID(groupID, chat), GroupRevision: revision, ServerTimestamp: serverTimestamp}, Timestamp: timestamp, Content: msg})
}
