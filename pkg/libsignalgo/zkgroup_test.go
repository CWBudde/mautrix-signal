// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package libsignalgo_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// Both backends consume the same pinned Rust API fixture (zkgroup-api case 1).
func TestZKGroupAPI(t *testing.T) {
	b, e := os.ReadFile("testdata/zkgroup.json")
	require.NoError(t, e)
	var f struct {
		Params struct {
			Randomness string `json:"randomness"`
			MasterKey  string `json:"master_key"`
			ACI        string `json:"aci"`
			PNI        string `json:"pni"`
			ProfileKey string `json:"profile_key"`
			Message    string `json:"message"`
			Now        uint64 `json:"now"`
			Redemption uint64 `json:"redemption"`
			Padding    uint32 `json:"padding"`
		}
		Result map[string]string
	}
	require.NoError(t, json.Unmarshal(b, &f))
	raw := func(s string) []byte { b, e := hex.DecodeString(s); require.NoError(t, e); return b }
	get := func(s string) []byte { return raw(f.Result[s]) }
	r := libsignalgo.Randomness(raw(f.Params.Randomness))
	mk := libsignalgo.GroupMasterKey(raw(f.Params.MasterKey))
	aci, pni := uuid.UUID(raw(f.Params.ACI)), uuid.UUID(raw(f.Params.PNI))
	pk := libsignalgo.ProfileKey(raw(f.Params.ProfileKey))
	server, e := libsignalgo.DeserializeServerPublicParams(get("server"))
	require.NoError(t, e)
	signature := libsignalgo.NotarySignature(get("signature"))
	require.NoError(t, libsignalgo.ServerPublicParamsVerifySignature(server, raw(f.Params.Message), signature))
	signature[0] ^= 1
	require.Error(t, libsignalgo.ServerPublicParamsVerifySignature(server, raw(f.Params.Message), signature))
	group, e := mk.SecretParams()
	require.NoError(t, e)
	require.Equal(t, get("group"), group[:])
	generated, e := libsignalgo.GenerateGroupSecretParamsWithRandomness(r)
	require.NoError(t, e)
	require.Equal(t, get("generated_group"), generated[:])
	_, e = libsignalgo.GenerateGroupSecretParams()
	require.NoError(t, e)
	public, e := group.GetPublicParams()
	require.NoError(t, e)
	require.Equal(t, get("group_public"), public[:])
	id, e := libsignalgo.GetGroupIdentifier(*public)
	require.NoError(t, e)
	require.Equal(t, get("group_id"), id[:])
	require.Equal(t, base64.StdEncoding.EncodeToString(id[:]), id.String())
	id2, e := mk.GroupIdentifier()
	require.NoError(t, e)
	require.Equal(t, id, id2)
	master, e := group.GetMasterKey()
	require.NoError(t, e)
	require.Equal(t, mk, *master)
	for name, id := range map[string]libsignalgo.ServiceID{"aci_ciphertext": libsignalgo.NewACIServiceID(aci), "pni_ciphertext": libsignalgo.NewPNIServiceID(pni)} {
		c, e := group.EncryptServiceID(id)
		require.NoError(t, e)
		require.Equal(t, get(name), c[:])
		decoded, e := group.DecryptServiceID(*c)
		require.NoError(t, e)
		require.Equal(t, id, decoded)
	}
	ciphertext, e := group.EncryptProfileKey(pk, aci)
	require.NoError(t, e)
	require.Equal(t, get("profile_ciphertext"), ciphertext[:])
	key, e := group.DecryptProfileKey(*ciphertext, aci)
	require.NoError(t, e)
	require.Equal(t, pk, *key)
	blob, e := group.EncryptBlobWithPaddingDeterministic(r, raw(f.Params.Message), f.Params.Padding)
	require.NoError(t, e)
	require.Equal(t, get("blob"), blob)
	plain, e := group.DecryptBlobWithPadding(blob)
	require.NoError(t, e)
	require.Equal(t, raw(f.Params.Message), plain)
	commitment, e := pk.GetCommitment(aci)
	require.NoError(t, e)
	require.Equal(t, get("commitment"), commitment[:])
	version, e := pk.GetProfileKeyVersion(aci)
	require.NoError(t, e)
	require.Equal(t, get("version"), version[:])
	access, e := pk.DeriveAccessKey()
	require.NoError(t, e)
	require.Equal(t, get("access_key"), access[:])
	context := libsignalgo.ProfileKeyCredentialRequestContext(get("context"))
	request, e := context.ProfileKeyCredentialRequestContextGetRequest()
	require.NoError(t, e)
	require.Equal(t, get("request"), request[:])
	randomContext, e := libsignalgo.CreateProfileKeyCredentialRequestContext(server, aci, pk)
	require.NoError(t, e)
	_, e = randomContext.ProfileKeyCredentialRequestContextGetRequest()
	require.NoError(t, e)
	require.False(t, bytes.Equal(context[:], randomContext[:]))
	response, e := libsignalgo.NewExpiringProfileKeyCredentialResponse(get("profile_response"))
	require.NoError(t, e)
	credential, e := libsignalgo.ReceiveExpiringProfileKeyCredential(server, &context, response, f.Params.Now)
	require.NoError(t, e)
	require.Equal(t, get("profile_credential"), credential[:])
	presentation, e := group.CreateExpiringProfileKeyCredentialPresentation(server, *credential)
	require.NoError(t, e)
	require.NoError(t, presentation.CheckValidContents())
	for _, p := range []libsignalgo.ProfileKeyCredentialPresentation{*presentation, get("profile_presentation")} {
		u, e := p.UUIDCiphertext()
		require.NoError(t, e)
		require.Equal(t, get("aci_ciphertext"), u[:])
		k, e := p.ProfileKeyCiphertext()
		require.NoError(t, e)
		require.Equal(t, get("profile_ciphertext"), k[:])
	}
	authResponse, e := libsignalgo.NewAuthCredentialWithPniResponse(get("auth_response"))
	require.NoError(t, e)
	auth, e := libsignalgo.ReceiveAuthCredentialWithPni(server, aci, pni, f.Params.Redemption, *authResponse)
	require.NoError(t, e)
	require.Equal(t, get("auth_credential"), auth.Slice())
	authPresentation, e := libsignalgo.CreateAuthCredentialWithPniPresentation(server, r, group, *auth)
	require.NoError(t, e)
	require.Equal(t, get("auth_presentation"), []byte(*authPresentation))
	require.Error(t, libsignalgo.ProfileKeyCredentialPresentation{255}.CheckValidContents())
	_, e = libsignalgo.NewAuthCredentialWithPniResponse([]byte{3})
	require.Error(t, e)
	_, e = libsignalgo.NewExpiringProfileKeyCredentialResponse([]byte{0})
	require.Error(t, e)
}
