// SPDX-License-Identifier: MIT

package iec104

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-iec104/asdu"
)

// Sentinel errors shared by the client and the server. They are usually
// wrapped with detail; test with errors.Is.
var (
	// ErrClosed reports an operation on a client, server or session that
	// was closed by the application.
	ErrClosed = errors.New("iec104: closed")

	// ErrNotConnected reports an operation on a client that has no
	// established connection.
	ErrNotConnected = errors.New("iec104: not connected")

	// ErrConnectFailed reports that a client could not establish its
	// connection: the TCP dial or TLS handshake failed, or the controlled
	// station did not confirm STARTDT. The underlying error is wrapped
	// alongside it.
	ErrConnectFailed = errors.New("iec104: connect failed")

	// ErrNotStarted reports an attempt to send an ASDU while data transfer
	// is stopped: before STARTDT or after STOPDT.
	ErrNotStarted = errors.New("iec104: data transfer not started")

	// ErrConnectionLost reports that the peer closed the connection or the
	// transport failed.
	ErrConnectionLost = errors.New("iec104: connection lost")

	// ErrTimeout reports that the peer did not acknowledge an I frame or
	// confirm a U frame within t1. The connection is closed.
	ErrTimeout = errors.New("iec104: acknowledgement timeout (t1)")

	// ErrProtocol reports a peer that violated the protocol: a malformed
	// APDU, a sequence number error or a frame that is not allowed in the
	// current state. The connection is closed.
	ErrProtocol = errors.New("iec104: protocol violation")

	// ErrBusy reports a request that cannot be issued because an identical
	// one is still awaiting its confirmation.
	ErrBusy = errors.New("iec104: request already pending")

	// ErrInHandler reports a client request method (one that waits for the
	// station's answer) called from inside the client's Handler or state
	// handler. The answer could not be delivered while that call has not
	// returned; issue the request from another goroutine.
	ErrInHandler = errors.New("iec104: request from inside a handler")

	// ErrInvalidOption reports an option value a client or server cannot be
	// constructed with. Invalid protocol parameters are reported by the
	// apci and asdu packages (apci.ErrInvalidParams, asdu.ErrInvalidParams).
	ErrInvalidOption = errors.New("iec104: invalid option")
)

// NegativeError reports that the controlled station answered a request with
// a negative confirmation or with one of the "unknown ..." causes of
// transmission.
type NegativeError struct {
	// ASDU is the answer of the controlled station.
	ASDU *asdu.ASDU
}

// Error describes the rejection.
func (e *NegativeError) Error() string {
	if e.ASDU == nil {
		return "iec104: negative confirmation"
	}
	return fmt.Sprintf("iec104: %s rejected by station %d: %s", e.ASDU.Type, e.ASDU.CommonAddr, e.ASDU.Cause)
}

// Cause returns the cause of transmission of the rejection, for example
// [asdu.CauseUnknownIOA], or [asdu.CauseActivationCon] for a plain negative
// confirmation.
func (e *NegativeError) Cause() asdu.Cause {
	if e.ASDU == nil {
		return 0
	}
	return e.ASDU.Cause
}
