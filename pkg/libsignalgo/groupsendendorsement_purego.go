//go:build purego

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2025 Tulir Asokan
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

package libsignalgo

import (
	"encoding/base64"
	"time"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/zkgroup"
)

type GroupSendFullToken []byte

func (t GroupSendFullToken) String() string { return base64.StdEncoding.EncodeToString(t) }
func (t GroupSendFullToken) CheckValidContents() error {
	_, e := zkgroup.ParseGroupSendFullToken(t)
	return zkError(e)
}
func (t GroupSendFullToken) GetExpiration() (time.Time, error) {
	parsed, e := zkgroup.ParseGroupSendFullToken(t)
	if e != nil {
		return time.Time{}, zkError(e)
	}
	return time.Unix(int64(parsed.Expiration()), 0), nil
}

type GroupSendToken []byte

func (t GroupSendToken) CheckValidContents() error {
	_, e := zkgroup.ParseGroupSendToken(t)
	return zkError(e)
}
func (t GroupSendToken) ToFullToken(expiration time.Time) (GroupSendFullToken, error) {
	parsed, e := zkgroup.ParseGroupSendToken(t)
	if e != nil {
		return nil, zkError(e)
	}
	return parsed.ToFullToken(uint64(expiration.Unix())).Bytes(), nil
}

type GroupSendEndorsement []byte

func (e GroupSendEndorsement) CheckValidContents() error {
	_, err := zkgroup.ParseGroupSendEndorsement(e)
	return zkError(err)
}
func (e GroupSendEndorsement) ToToken(params *GroupSecretParams) (GroupSendToken, error) {
	parsed, err := zkgroup.ParseGroupSendEndorsement(e)
	if err != nil {
		return nil, zkError(err)
	}
	g, err := zkgroup.ParseGroupSecretParams(params[:])
	if err != nil {
		return nil, zkError(err)
	}
	return parsed.ToToken(g).Bytes(), nil
}
func (e GroupSendEndorsement) ToFullToken(params *GroupSecretParams, expiration time.Time) (GroupSendFullToken, error) {
	token, err := e.ToToken(params)
	if err != nil {
		return nil, err
	}
	return token.ToFullToken(expiration)
}
func (e GroupSendEndorsement) Remove(other GroupSendEndorsement) (GroupSendEndorsement, error) {
	a, err := zkgroup.ParseGroupSendEndorsement(e)
	if err != nil {
		return nil, zkError(err)
	}
	b, err := zkgroup.ParseGroupSendEndorsement(other)
	if err != nil {
		return nil, zkError(err)
	}
	return a.Remove(b).Bytes(), nil
}
func GroupSendEndorsementCombine(endorsements ...GroupSendEndorsement) (GroupSendEndorsement, error) {
	parsed := make([]*zkgroup.GroupSendEndorsement, len(endorsements))
	for i, e := range endorsements {
		var err error
		parsed[i], err = zkgroup.ParseGroupSendEndorsement(e)
		if err != nil {
			return nil, zkError(err)
		}
	}
	return zkgroup.CombineGroupSendEndorsements(parsed...).Bytes(), nil
}

type GroupSendEndorsementsResponse []byte

func (r GroupSendEndorsementsResponse) CheckValidContents() error {
	_, e := zkgroup.ParseGroupSendEndorsementsResponse(r)
	return zkError(e)
}
func (r GroupSendEndorsementsResponse) GetExpiration() (time.Time, error) {
	parsed, e := zkgroup.ParseGroupSendEndorsementsResponse(r)
	if e != nil {
		return time.Time{}, zkError(e)
	}
	return time.Unix(int64(parsed.Expiration()), 0), nil
}
func (r GroupSendEndorsementsResponse) ReceiveWithServiceIDs(groupMembers []ServiceID, localUser ServiceID, params *GroupSecretParams, spp *ServerPublicParams) (GroupSendEndorsement, map[ServiceID]GroupSendEndorsement, error) {
	parsed, err := zkgroup.ParseGroupSendEndorsementsResponse(r)
	if err != nil {
		return nil, nil, zkError(err)
	}
	group, err := zkgroup.ParseGroupSecretParams(params[:])
	if err != nil {
		return nil, nil, zkError(err)
	}
	members := make([]address.ServiceID, len(groupMembers))
	localIndex := -1
	for i, member := range groupMembers {
		members[i], err = address.ParseServiceIDFixedWidthBinary(*member.FixedBytes())
		if err != nil {
			return nil, nil, zkError(zkgroup.ErrEncoding)
		}
		if member == localUser && localIndex < 0 {
			localIndex = i
		}
	}
	if localIndex < 0 {
		return nil, nil, zkError(zkgroup.ErrVerification)
	}
	received, err := parsed.ReceiveWithServiceIDs(members, uint64(time.Now().Unix()), group, spp.inner)
	if err != nil {
		return nil, nil, zkError(err)
	}
	result := make(map[ServiceID]GroupSendEndorsement, len(members))
	others := make([]*zkgroup.GroupSendEndorsement, 0, len(members)-1)
	for i, e := range received {
		result[groupMembers[i]] = e.Bytes()
		if i != localIndex {
			others = append(others, e)
		}
	}
	return zkgroup.CombineGroupSendEndorsements(others...).Bytes(), result, nil
}
