//go:build purego

package libsignalgo

import (
	"errors"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

func zkError(err error) error {
	if err == nil {
		return nil
	}
	code := ErrorCodeVerificationFailure
	if errors.Is(err, zkgroup.ErrEncoding) || errors.Is(err, zkcrypto.ErrEncoding) || errors.Is(err, zkcredential.ErrEncoding) {
		code = ErrorCodeInvalidType
	}
	return &SignalError{Code: code, Message: err.Error()}
}
