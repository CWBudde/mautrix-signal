//go:build libsignal_go

// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
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
	"github.com/cwbudde/libsignal-go/address"
)

type Address struct {
	nc   noCopy
	addr address.ProtocolAddress
}

func NewUUIDAddressFromString(uuidStr string, deviceID uint) (*Address, error) {
	serviceID, err := ServiceIDFromString(uuidStr)
	if err != nil {
		return nil, err
	}
	return serviceID.Address(deviceID)
}

func newAddress(name string, deviceID uint) (*Address, error) {
	if deviceID > uint(^uint32(0)) {
		return nil, &SignalError{Code: ErrorCodeInvalidProtocolAddress, Message: "invalid device ID"}
	}
	id, err := address.NewDeviceID(uint32(deviceID))
	if err != nil {
		return nil, &SignalError{Code: ErrorCodeInvalidProtocolAddress, Message: err.Error()}
	}
	return &Address{addr: address.NewProtocolAddress(name, id)}, nil
}

// wrapAddress wraps a libsignal-go address.
func wrapAddress(addr address.ProtocolAddress) *Address {
	return &Address{addr: addr}
}

func (pa *Address) Clone() (*Address, error) {
	return &Address{addr: pa.addr}, nil
}

func (pa *Address) Destroy() error {
	return nil
}

func (pa *Address) CancelFinalizer() {}

func (pa *Address) Name() (string, error) {
	return pa.addr.Name(), nil
}

func (pa *Address) NameServiceID() (ServiceID, error) {
	name, err := pa.Name()
	if err != nil {
		return ServiceID{}, err
	}
	return ServiceIDFromString(name)
}

func (pa *Address) DeviceID() (uint, error) {
	return uint(pa.addr.DeviceID().Value()), nil
}
