// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
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
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
)

// The device transfer fixture is a key the cgo build generated and the
// certificate the cgo build made from it:
//
//	LIBSIGNALGO_WRITE_FIXTURE=1 go test -run TestDeviceTransferFixture ./pkg/libsignalgo/   # cgo
//
// Both builds certify the same key and have to produce the same certificate,
// apart from the validity times and so the signature.
const (
	dtFixtureName = "go-signal fixture"
	dtFixtureDays = 365
)

func dtFixturePath(name string) string {
	return filepath.Join("testdata", "devicetransfer_"+name+".der")
}

// From PublicAPITests.swift:testDeviceTransferKey
func TestDeviceTransferKey(t *testing.T) {
	deviceKey, err := libsignalgo.GenerateDeviceTransferKey()
	require.NoError(t, err)

	/*
		Anything encoded in an ASN.1 SEQUENCE starts with 0x30 when encoded
		as DER. (This test could be better.)
	*/
	key := deviceKey.PrivateKeyMaterial()
	assert.Greater(t, len(key), 0)
	assert.EqualValues(t, 0x30, key[0])

	parsed, err := x509.ParsePKCS8PrivateKey(key)
	require.NoError(t, err)
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok, "key is %T, want RSA", parsed)
	assert.Equal(t, 4096, rsaKey.N.BitLen())
	assert.Equal(t, 65537, rsaKey.E)

	start := time.Now()
	cert, err := deviceKey.GenerateCertificate("name", 30)
	end := time.Now()
	require.NoError(t, err)
	assert.Greater(t, len(cert), 0)
	assert.EqualValues(t, 0x30, cert[0])
	checkDeviceTransferCert(t, key, cert, "name", 30, start, end)
}

// checkDeviceTransferCert checks that cert is upstream's self-signed
// certificate for key, issued to name and made between start and end.
func checkDeviceTransferCert(t *testing.T, key, cert []byte, name string, days int, start, end time.Time) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(cert)
	require.NoError(t, err)
	assert.Equal(t, 1, c.Version)
	assert.EqualValues(t, 0, c.SerialNumber.Int64())
	assert.Equal(t, x509.SHA256WithRSA, c.SignatureAlgorithm)
	assert.Equal(t, name, c.Subject.CommonName)
	assert.Equal(t, []string{"Signal Foundation"}, c.Subject.Organization)
	assert.Equal(t, []string{"Device Transfer"}, c.Subject.OrganizationalUnit)
	assert.Equal(t, c.RawSubject, c.RawIssuer)
	assert.Empty(t, c.Extensions)
	require.NoError(t, c.CheckSignatureFrom(c), "self-signature")

	parsed, err := x509.ParsePKCS8PrivateKey(key)
	require.NoError(t, err)
	signer, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, signer.PublicKey.Equal(c.PublicKey), "certificate is for another key")

	// Times are whole seconds: upstream truncates them.
	day := 24 * time.Hour
	start = start.Truncate(time.Second)
	assert.False(t, c.NotBefore.Before(start.Add(-day)), "NotBefore %v too early", c.NotBefore)
	assert.False(t, c.NotBefore.After(end.Add(-day)), "NotBefore %v too late", c.NotBefore)
	validity := time.Duration(days) * day
	assert.False(t, c.NotAfter.Before(start.Add(validity)), "NotAfter %v too early", c.NotAfter)
	assert.False(t, c.NotAfter.After(end.Add(validity)), "NotAfter %v too late", c.NotAfter)
	return c
}

// tbsFields splits a certificate's to-be-signed part into its fields.
func tbsFields(t *testing.T, c *x509.Certificate) []asn1.RawValue {
	t.Helper()
	var tbs asn1.RawValue
	rest, err := asn1.Unmarshal(c.RawTBSCertificate, &tbs)
	require.NoError(t, err)
	require.Empty(t, rest)
	var fields []asn1.RawValue
	for data := tbs.Bytes; len(data) > 0; {
		var field asn1.RawValue
		data, err = asn1.Unmarshal(data, &field)
		require.NoError(t, err)
		fields = append(fields, field)
	}
	return fields
}

func TestDeviceTransferFixture(t *testing.T) {
	if os.Getenv("LIBSIGNALGO_WRITE_FIXTURE") != "" {
		require.Equal(t, "cgo", testBackend, "the fixture comes from the cgo build")
		deviceKey, err := libsignalgo.GenerateDeviceTransferKey()
		require.NoError(t, err)
		cert, err := deviceKey.GenerateCertificate(dtFixtureName, dtFixtureDays)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dtFixturePath("key"), deviceKey.PrivateKeyMaterial(), 0o644))
		require.NoError(t, os.WriteFile(dtFixturePath("cert_cgo"), cert, 0o644))
	}

	key, err := os.ReadFile(dtFixturePath("key"))
	require.NoError(t, err)
	fixtureDER, err := os.ReadFile(dtFixturePath("cert_cgo"))
	require.NoError(t, err)
	fixture, err := x509.ParseCertificate(fixtureDER)
	require.NoError(t, err)
	require.NoError(t, fixture.CheckSignatureFrom(fixture))

	deviceKey := dtKey(t, key)
	start := time.Now()
	cert, err := deviceKey.GenerateCertificate(dtFixtureName, dtFixtureDays)
	end := time.Now()
	require.NoError(t, err)
	c := checkDeviceTransferCert(t, key, cert, dtFixtureName, dtFixtureDays, start, end)

	// v1: serial, signature algorithm, issuer, validity, subject, key.
	want, got := tbsFields(t, fixture), tbsFields(t, c)
	require.Len(t, got, 6)
	require.Len(t, want, 6)
	const validity = 3
	for i := range want {
		if i == validity {
			continue
		}
		assert.Equal(t, want[i].FullBytes, got[i].FullBytes, "TBS field %d", i)
	}
	// Same time encoding (UTCTime until 2049) and the same validity period.
	wantTimes, gotTimes := tbsFields2(t, want[validity]), tbsFields2(t, got[validity])
	require.Len(t, gotTimes, 2)
	for i := range wantTimes {
		assert.Equal(t, wantTimes[i].Tag, gotTimes[i].Tag, "validity time %d", i)
	}
	assert.Equal(t, fixture.NotAfter.Sub(fixture.NotBefore).Round(time.Minute),
		c.NotAfter.Sub(c.NotBefore).Round(time.Minute))
	assert.Equal(t, fixture.SignatureAlgorithm, c.SignatureAlgorithm)
	assert.Equal(t, len(fixture.Signature), len(c.Signature))
	assert.Equal(t, len(fixtureDER), len(cert))
}

// tbsFields2 splits a SEQUENCE into its elements.
func tbsFields2(t *testing.T, seq asn1.RawValue) []asn1.RawValue {
	t.Helper()
	var out []asn1.RawValue
	for data := seq.Bytes; len(data) > 0; {
		var v asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &v)
		require.NoError(t, err)
		out = append(out, v)
	}
	return out
}

// dtKey wraps existing key material in a DeviceTransferKey.
func dtKey(t *testing.T, key []byte) *libsignalgo.DeviceTransferKey {
	t.Helper()
	dtk := libsignalgo.NewDeviceTransferKeyForTest(key)
	require.Equal(t, key, dtk.PrivateKeyMaterial())
	return dtk
}

func dtErrorCode(t *testing.T, err error) libsignalgo.ErrorCode {
	t.Helper()
	var signalErr *libsignalgo.SignalError
	require.True(t, errors.As(err, &signalErr), "error %v (%T) is not a *SignalError", err, err)
	return signalErr.Code
}

func TestDeviceTransferCertificateErrors(t *testing.T) {
	key, err := os.ReadFile(dtFixturePath("key"))
	require.NoError(t, err)
	good := dtKey(t, key)
	for _, tc := range []struct {
		desc string
		key  *libsignalgo.DeviceTransferKey
		name string
		days int
		code libsignalgo.ErrorCode
	}{
		{"no key", &libsignalgo.DeviceTransferKey{}, "name", 30, libsignalgo.ErrorCodeInvalidKey},
		{"garbage key", dtKey(t, []byte("not a key")), "name", 30, libsignalgo.ErrorCodeInvalidKey},
		{"truncated key", dtKey(t, key[:len(key)/2]), "name", 30, libsignalgo.ErrorCodeInvalidKey},
		{"empty name", good, "", 30, libsignalgo.ErrorCodeInternalError},
		{"name too long", good, strings.Repeat("a", 65), 30, libsignalgo.ErrorCodeInternalError},
		{"name too many characters", good, strings.Repeat("ä", 65), 30, libsignalgo.ErrorCodeInternalError},
		// The name goes through a C string, which ends at the first NUL.
		{"name empty up to NUL", good, "\x00name", 30, libsignalgo.ErrorCodeInternalError},
		// The bridge checks the name before it decodes the key.
		{"invalid UTF-8", good, "\xff", 30, libsignalgo.ErrorCodeInvalidUtf8String},
		{"invalid UTF-8 and no key", &libsignalgo.DeviceTransferKey{}, "\xff", 30, libsignalgo.ErrorCodeInvalidUtf8String},
		// Upstream computes days·86400 in a u32 and panics when it overflows.
		{"days overflow", good, "name", 49711, libsignalgo.ErrorCodeInternalError},
		// days is passed as a u32, so -1 is 2^32-1.
		{"negative days", good, "name", -1, libsignalgo.ErrorCodeInternalError},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cert, err := tc.key.GenerateCertificate(tc.name, tc.days)
			require.Error(t, err)
			assert.Nil(t, cert)
			assert.Equal(t, tc.code, dtErrorCode(t, err))
			assert.True(t, errors.Is(err, tc.code), "errors.Is(%v, %v)", err, tc.code)
		})
	}
}

func TestDeviceTransferCertificateInputs(t *testing.T) {
	key, err := os.ReadFile(dtFixturePath("key"))
	require.NoError(t, err)
	deviceKey := dtKey(t, key)
	type input struct {
		desc string
		name string
		days int
		cn   string // the certificate's CN
		want int    // validity in days after now
	}
	inputs := []input{
		{"no days", "name", 0, "name", 0},
		{"longest validity", "name", 49710, "name", 49710},
		{"64 characters", strings.Repeat("a", 64), 1, strings.Repeat("a", 64), 1},
		{"64 two-byte characters", strings.Repeat("ä", 64), 1, strings.Repeat("ä", 64), 1},
		{"name up to NUL", "ab\x00cd", 1, "ab", 1},
	}
	if strconv.IntSize == 64 {
		// days is passed as a u32 and wraps.
		wrap := int64(1) << 32
		inputs = append(inputs,
			input{"days wrap to 0", "name", int(wrap), "name", 0},
			input{"days wrap to 5", "name", int(wrap + 5), "name", 5},
		)
	}
	for _, in := range inputs {
		t.Run(in.desc, func(t *testing.T) {
			start := time.Now()
			cert, err := deviceKey.GenerateCertificate(in.name, in.days)
			end := time.Now()
			require.NoError(t, err)
			c := checkDeviceTransferCert(t, key, cert, in.cn, in.want, start, end)
			if in.days == 49710 {
				// Past 2049 the time is a GeneralizedTime.
				times := tbsFields2(t, tbsFields(t, c)[3])
				assert.Equal(t, asn1.TagUTCTime, times[0].Tag)
				assert.Equal(t, asn1.TagGeneralizedTime, times[1].Tag)
			}
		})
	}
}
