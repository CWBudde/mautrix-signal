//go:build !libsignal_go

package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl -lm -lz -lstdc++
*/
import "C"

import (
	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo/signalversion"
)

const Version = signalversion.Version
