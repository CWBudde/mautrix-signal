//go:build libsignal_go

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

package libsignalgo

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cwbudde/libsignal-go/devicetransfer"
)

type DeviceTransferKey struct {
	privateKey []byte
}

func GenerateDeviceTransferKey() (*DeviceTransferKey, error) {
	key, err := devicetransfer.GeneratePrivateKey()
	if err != nil {
		return nil, deviceTransferError(err)
	}
	return &DeviceTransferKey{privateKey: key}, nil
}

func (dtk *DeviceTransferKey) PrivateKeyMaterial() []byte {
	return dtk.privateKey
}

// GenerateCertificate reads its arguments as the cgo build passes them: the
// name as a C string, which ends at the first NUL and must be UTF-8, and days
// as a u32, so negative and larger values wrap. Upstream panics when the
// validity overflows a u32 of seconds (more than 49710 days), which the bridge
// reports as an internal error; libsignal-go returns ErrInternal there.
func (dtk *DeviceTransferKey) GenerateCertificate(name string, days int) ([]byte, error) {
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	if !utf8.ValidString(name) {
		return nil, &SignalError{Code: ErrorCodeInvalidUtf8String, Message: "invalid UTF8 string"}
	}
	cert, err := devicetransfer.GenerateCertificate(dtk.privateKey, name, uint32(days), time.Now())
	if err != nil {
		return nil, deviceTransferError(err)
	}
	return cert, nil
}

// deviceTransferError returns the error the cgo build reports for an error
// from libsignal-go's devicetransfer (IntoFfiError for DeviceTransferError in
// rust/bridge/shared/types/src/ffi/error.rs).
func deviceTransferError(err error) error {
	code := ErrorCodeInternalError
	if errors.Is(err, devicetransfer.ErrKeyDecoding) {
		code = ErrorCodeInvalidKey
	}
	return &SignalError{Code: code, Message: "Device transfer operation failed: " + err.Error()}
}
