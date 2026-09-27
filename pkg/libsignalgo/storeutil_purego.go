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
	"context"
	"errors"
	"unsafe"
)

// The purego build calls the stores directly, so these types only keep the API
// of the cgo build.

type WrappedStore[T any] struct {
	Store T
	Ctx   *CallbackContext
}

type CallbackContext struct {
	Error  error
	Ctx    context.Context
	Unrefs []unsafe.Pointer
}

func NewCallbackContext(ctx context.Context) *CallbackContext {
	if ctx == nil {
		panic(errors.New("nil context passed to NewCallbackContext"))
	}
	return &CallbackContext{Ctx: ctx}
}

func (ctx *CallbackContext) Unref() {}
