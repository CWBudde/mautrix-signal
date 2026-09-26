package libsignalgo

import "errors"

// ErrNotImplemented is returned by the parts of the purego build (pure-Go implementation on top
// of github.com/cwbudde/libsignal-go) that aren't ported yet. It's declared in both builds so
// that callers can match it with errors.Is.
var ErrNotImplemented = errors.New("libsignalgo: not implemented in the purego build")
