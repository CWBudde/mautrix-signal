// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

// stampGroupMessage uses the same retrieved state for context and expiration.
func stampGroupMessage(content *signalpb.Content, group *Group) {
	msg := content.GetDataMessage()
	if msg == nil {
		msg = content.GetEditMessage().GetDataMessage()
	}
	if msg == nil {
		return
	}
	msg.GroupV2 = groupMetadataForDataMessage(*group)
	msg.ExpireTimer = ptr.Ptr(group.DisappearingMessagesDuration)
	msg.ExpireTimerVersion = nil
}

// storeContactSync exposes metadata only after the entire contact transaction
// succeeds. Timer pointers own their values and preserve absent versus zero.
func (cli *Client) storeContactSync(ctx context.Context, data []byte) (*events.ContactList, error) {
	contacts, avatars, err := unmarshalContactDetailsMessages(data)
	if err != nil {
		return nil, fmt.Errorf("decode contact sync: %w", err)
	}
	list := &events.ContactList{
		Contacts: make([]*types.Recipient, 0, len(contacts)),
		Timers:   make([]events.ContactTimer, 0, len(contacts)),
	}
	err = cli.Store.DoContactTxn(ctx, func(ctx context.Context) error {
		for i, details := range contacts {
			if (details.Aci == nil || *details.Aci == "") && len(details.AciBinary) != 16 {
				zerolog.Ctx(ctx).Info().Msg("Signal Contact UUID is nil, skipping")
				continue
			}
			contact, err := cli.StoreContactDetailsAsContact(ctx, details, &avatars[i])
			if err != nil {
				return err
			}
			timer := events.ContactTimer{ACI: contact.ACI}
			if details.ExpireTimer != nil {
				timer.ExpireTimer = ptr.Ptr(*details.ExpireTimer)
			}
			if details.ExpireTimerVersion != nil {
				timer.ExpireTimerVersion = ptr.Ptr(*details.ExpireTimerVersion)
			}
			list.Contacts = append(list.Contacts, contact)
			list.Timers = append(list.Timers, timer)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store contact sync: %w", err)
	}
	return list, nil
}
