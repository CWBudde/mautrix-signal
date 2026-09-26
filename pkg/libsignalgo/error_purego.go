//go:build purego

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
	"fmt"

	"github.com/cwbudde/libsignal-go/accountkeys"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/fingerprint"
	"github.com/cwbudde/libsignal-go/groups"
	"github.com/cwbudde/libsignal-go/identity"
	"github.com/cwbudde/libsignal-go/kem"
	"github.com/cwbudde/libsignal-go/protocol"
	"github.com/cwbudde/libsignal-go/sealedsender"
	"github.com/cwbudde/libsignal-go/session"
)

type ErrorCode int

func (e ErrorCode) Error() string {
	return fmt.Sprintf("libsignalgo.ErrorCode(%d)", int(e))
}

const (
	ErrorCodeUnknownError                                ErrorCode = 1
	ErrorCodeInvalidState                                ErrorCode = 2
	ErrorCodeInternalError                               ErrorCode = 3
	ErrorCodeNullParameter                               ErrorCode = 4
	ErrorCodeInvalidArgument                             ErrorCode = 5
	ErrorCodeInvalidType                                 ErrorCode = 6
	ErrorCodeInvalidUtf8String                           ErrorCode = 7
	ErrorCodeCancelled                                   ErrorCode = 8
	ErrorCodeProtobufError                               ErrorCode = 10
	ErrorCodeLegacyCiphertextVersion                     ErrorCode = 21
	ErrorCodeUnknownCiphertextVersion                    ErrorCode = 22
	ErrorCodeUnrecognizedMessageVersion                  ErrorCode = 23
	ErrorCodeInvalidMessage                              ErrorCode = 30
	ErrorCodeSealedSenderSelfSend                        ErrorCode = 31
	ErrorCodeInvalidKey                                  ErrorCode = 40
	ErrorCodeInvalidSignature                            ErrorCode = 41
	ErrorCodeInvalidAttestationData                      ErrorCode = 42
	ErrorCodeFingerprintVersionMismatch                  ErrorCode = 51
	ErrorCodeFingerprintParsingError                     ErrorCode = 52
	ErrorCodeUntrustedIdentity                           ErrorCode = 60
	ErrorCodeInvalidKeyIdentifier                        ErrorCode = 70
	ErrorCodeSessionNotFound                             ErrorCode = 80
	ErrorCodeInvalidRegistrationId                       ErrorCode = 81
	ErrorCodeInvalidSession                              ErrorCode = 82
	ErrorCodeInvalidSenderKeySession                     ErrorCode = 83
	ErrorCodeInvalidProtocolAddress                      ErrorCode = 84
	ErrorCodeDuplicatedMessage                           ErrorCode = 90
	ErrorCodeCallbackError                               ErrorCode = 100
	ErrorCodeVerificationFailure                         ErrorCode = 110
	ErrorCodeUsernameCannotBeEmpty                       ErrorCode = 120
	ErrorCodeUsernameCannotStartWithDigit                ErrorCode = 121
	ErrorCodeUsernameMissingSeparator                    ErrorCode = 122
	ErrorCodeUsernameBadDiscriminatorCharacter           ErrorCode = 123
	ErrorCodeUsernameBadNicknameCharacter                ErrorCode = 124
	ErrorCodeUsernameTooShort                            ErrorCode = 125
	ErrorCodeUsernameTooLong                             ErrorCode = 126
	ErrorCodeUsernameLinkInvalidEntropyDataLength        ErrorCode = 127
	ErrorCodeUsernameLinkInvalid                         ErrorCode = 128
	ErrorCodeUsernameDiscriminatorCannotBeEmpty          ErrorCode = 130
	ErrorCodeUsernameDiscriminatorCannotBeZero           ErrorCode = 131
	ErrorCodeUsernameDiscriminatorCannotBeSingleDigit    ErrorCode = 132
	ErrorCodeUsernameDiscriminatorCannotHaveLeadingZeros ErrorCode = 133
	ErrorCodeUsernameDiscriminatorTooLarge               ErrorCode = 134
	ErrorCodeIoError                                     ErrorCode = 140
	ErrorCodeInvalidMediaInput                           ErrorCode = 141
	ErrorCodeUnsupportedMediaInput                       ErrorCode = 142
	ErrorCodeConnectionTimedOut                          ErrorCode = 143
	ErrorCodeNetworkProtocol                             ErrorCode = 144
	ErrorCodeRateLimited                                 ErrorCode = 145
	ErrorCodeWebSocket                                   ErrorCode = 146
	ErrorCodeCdsiInvalidToken                            ErrorCode = 147
	ErrorCodeConnectionFailed                            ErrorCode = 148
	ErrorCodeChatServiceInactive                         ErrorCode = 149
	ErrorCodeRequestTimedOut                             ErrorCode = 150
	ErrorCodeRateLimitChallenge                          ErrorCode = 151
	ErrorCodePossibleCaptiveNetwork                      ErrorCode = 152
	ErrorCodeSvrDataMissing                              ErrorCode = 160
	ErrorCodeSvrRestoreFailed                            ErrorCode = 161
	ErrorCodeSvrRotationMachineTooManySteps              ErrorCode = 162
	ErrorCodeSvrRequestFailed                            ErrorCode = 163
	ErrorCodeAppExpired                                  ErrorCode = 170
	ErrorCodeDeviceDeregistered                          ErrorCode = 171
	ErrorCodeConnectionInvalidated                       ErrorCode = 172
	ErrorCodeConnectedElsewhere                          ErrorCode = 173
	ErrorCodeBackupValidation                            ErrorCode = 180
	ErrorCodeRegistrationInvalidSessionId                ErrorCode = 190
	ErrorCodeRegistrationUnknown                         ErrorCode = 192
	ErrorCodeRegistrationSessionNotFound                 ErrorCode = 193
	ErrorCodeRegistrationNotReadyForVerification         ErrorCode = 194
	ErrorCodeRegistrationSendVerificationCodeFailed      ErrorCode = 195
	ErrorCodeRegistrationCodeNotDeliverable              ErrorCode = 196
	ErrorCodeRegistrationSessionUpdateRejected           ErrorCode = 197
	ErrorCodeRegistrationCredentialsCouldNotBeParsed     ErrorCode = 198
	ErrorCodeRegistrationDeviceTransferPossible          ErrorCode = 199
	ErrorCodeRegistrationRecoveryVerificationFailed      ErrorCode = 200
	ErrorCodeRegistrationLock                            ErrorCode = 201
	ErrorCodeKeyTransparencyError                        ErrorCode = 210
	ErrorCodeKeyTransparencyVerificationFailed           ErrorCode = 211
	ErrorCodeRequestUnauthorized                         ErrorCode = 220
	ErrorCodeMismatchedDevices                           ErrorCode = 221
)

type SignalError struct {
	Code    ErrorCode
	Message string
}

func (e *SignalError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func (e *SignalError) Unwrap() error {
	return e.Code
}

// callbackError marks an error returned by one of the caller's stores. Like the
// cgo build, which hands back the store's own error (ErrorCodeCallbackError),
// wrapError returns it unchanged.
type callbackError struct {
	err error
}

func (e callbackError) Error() string { return e.err.Error() }

func (e callbackError) Unwrap() error { return e.err }

// errorCodes maps libsignal-go's errors to the codes libsignal's FFI reports for
// the same condition (rust/bridge/shared/types/src/ffi/error.rs). The first
// match wins, so more specific errors come first.
var errorCodes = []struct {
	err  error
	code ErrorCode
}{
	{session.ErrUntrustedIdentity, ErrorCodeUntrustedIdentity},
	{session.ErrDuplicateMessage, ErrorCodeDuplicatedMessage},
	{groups.ErrDuplicateMessage, ErrorCodeDuplicatedMessage},
	{session.ErrSessionNotFound, ErrorCodeSessionNotFound},
	{groups.ErrNoSenderKeyState, ErrorCodeSessionNotFound},
	{groups.ErrInvalidSenderKeySession, ErrorCodeInvalidSenderKeySession},
	{groups.ErrUnrecognizedMessageVersion, ErrorCodeUnrecognizedMessageVersion},
	{groups.ErrSignatureInvalid, ErrorCodeInvalidMessage},
	{session.ErrInvalidSignature, ErrorCodeInvalidSignature},
	{session.ErrInvalidKey, ErrorCodeInvalidKey},
	{session.ErrNoKyberPreKey, ErrorCodeInvalidArgument},
	{session.ErrInvalidPreKeyBundle, ErrorCodeInvalidArgument},
	{session.ErrInvalidRecord, ErrorCodeProtobufError},
	{session.ErrInvalidMessage, ErrorCodeInvalidMessage},
	{identity.ErrInvalidKeyPair, ErrorCodeInvalidKey},
	{protocol.ErrInvalidArgument, ErrorCodeInvalidArgument},
	{protocol.ErrNoDecryptionErrorMessage, ErrorCodeInvalidArgument},
	{protocol.ErrLegacyVersion, ErrorCodeLegacyCiphertextVersion},
	{protocol.ErrUnrecognizedVersion, ErrorCodeUnknownCiphertextVersion},
	{protocol.ErrInvalidProtobuf, ErrorCodeProtobufError},
	{protocol.ErrInvalidMACKeyLength, ErrorCodeInvalidKey},
	{protocol.ErrCiphertextTooShort, ErrorCodeInvalidMessage},
	{protocol.ErrInvalidMessage, ErrorCodeInvalidMessage},
	{sealedsender.ErrUnknownServerCertificateID, ErrorCodeVerificationFailure},
	{sealedsender.ErrUnknownVersion, ErrorCodeUnrecognizedMessageVersion},
	{sealedsender.ErrInvalidSealedSenderMessage, ErrorCodeInvalidMessage},
	{sealedsender.ErrBadCiphertext, ErrorCodeInvalidMessage},
	{sealedsender.ErrInvalidUSMC, ErrorCodeInvalidMessage},
	{sealedsender.ErrExpiredCertificate, ErrorCodeInvalidMessage},
	{sealedsender.ErrInvalidCertificate, ErrorCodeInvalidMessage},
	{fingerprint.ErrVersionMismatch, ErrorCodeFingerprintVersionMismatch},
	{fingerprint.ErrParsing, ErrorCodeFingerprintParsingError},
	{fingerprint.ErrInvalidIterationCount, ErrorCodeInvalidArgument},
	{accountkeys.ErrInvalidAccountEntropyPool, ErrorCodeInvalidArgument},
	{address.ErrInvalidDeviceID, ErrorCodeInvalidArgument},
	{address.ErrInvalidServiceID, ErrorCodeInvalidArgument},
}

// wrapError converts an error from libsignal-go into the *SignalError the cgo
// build returns for the same condition. Errors from the caller's stores are
// returned as they are.
func wrapError(err error) error {
	if err == nil {
		return nil
	}
	var cbErr callbackError
	if errors.As(err, &cbErr) {
		return cbErr.err
	}
	var signalErr *SignalError
	if errors.As(err, &signalErr) {
		return signalErr
	}
	return &SignalError{Code: errorCodeOf(err), Message: err.Error()}
}

func errorCodeOf(err error) ErrorCode {
	for _, e := range errorCodes {
		if errors.Is(err, e.err) {
			return e.code
		}
	}
	var (
		badKeyLength   curve.BadKeyLengthError
		badKeyType     curve.BadKeyTypeError
		noKeyType      curve.ErrNoKeyTypeIdentifier
		badAgreement   curve.ErrInvalidKeyAgreement
		badKEMLength   kem.BadKEMKeyLengthError
		badKEMType     kem.BadKEMKeyTypeError
		noKEMKeyType   kem.ErrNoKeyTypeIdentifier
		wrongKEMType   kem.WrongKEMKeyTypeError
		unsupportedKEM kem.UnsupportedKEMKeyTypeError
		badKEMCipher   kem.BadKEMCiphertextLengthError
	)
	switch {
	case errors.As(err, &badKeyLength), errors.As(err, &badKeyType), errors.As(err, &noKeyType),
		errors.As(err, &badAgreement), errors.As(err, &badKEMLength), errors.As(err, &badKEMType),
		errors.As(err, &noKEMKeyType), errors.As(err, &wrongKEMType), errors.As(err, &unsupportedKEM):
		return ErrorCodeInvalidKey
	case errors.As(err, &badKEMCipher):
		return ErrorCodeInvalidMessage
	}
	return ErrorCodeUnknownError
}

// errInvalidArgument returns the error libsignal reports for a bad argument.
func errInvalidArgument(format string, args ...any) error {
	return &SignalError{Code: ErrorCodeInvalidArgument, Message: fmt.Sprintf(format, args...)}
}
