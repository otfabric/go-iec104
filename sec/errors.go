// SPDX-License-Identifier: MIT

package sec

import "errors"

// Errors of the package. They are usually wrapped with detail; test with
// errors.Is.
var (
	// ErrMessage reports a security message that cannot be encoded or
	// decoded: a field out of range, a wrong length, a type or cause that
	// is not permitted in the direction it travels.
	ErrMessage = errors.New("sec: malformed security message")

	// ErrNotReady reports application data that cannot be protected yet:
	// no session keys are established, or the controlling station holds
	// its data back while it changes them. The caller waits for
	// [Endpoint.Changed] and tries again.
	ErrNotReady = errors.New("sec: no secure session")

	// ErrUnsecured reports an ordinary ASDU received on a connection the
	// A-Profile applies to. It is discarded.
	ErrUnsecured = errors.New("sec: unprotected ASDU refused")

	// ErrAuthentication reports a message whose MAC or AEAD tag does not
	// verify, or whose wrapped keys do not unwrap. It is discarded.
	ErrAuthentication = errors.New("sec: authentication failed")

	// ErrReplay reports Secure Data whose sequence number is not above the
	// last one accepted. It is discarded.
	ErrReplay = errors.New("sec: replayed secure data")

	// ErrUnexpected reports a security message that the state machine does
	// not expect now, or whose association IDs do not match. It is
	// discarded.
	ErrUnexpected = errors.New("sec: unexpected security message")

	// ErrCertificate reports a remote certificate that is not valid (wrong
	// curve, outside its validity period, bad signature) or not authorized
	// by [Trust], or a local one that cannot be used.
	ErrCertificate = errors.New("sec: certificate refused")

	// ErrAlgorithm reports an algorithm the remote station selected that
	// this station does not support or does not accept.
	ErrAlgorithm = errors.New("sec: algorithm not supported")

	// ErrProcedure reports that a Station Association or Session Key Change
	// failed: the remote station did not answer within the expected reply
	// time, repeatedly.
	ErrProcedure = errors.New("sec: key management procedure failed")

	// ErrConfig reports a [Config] an Endpoint cannot run with.
	ErrConfig = errors.New("sec: invalid configuration")
)
