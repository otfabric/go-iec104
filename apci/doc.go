// SPDX-License-Identifier: MIT

// Package apci implements the IEC 60870-5-104 Application Protocol Control
// Information: APDU framing, the I/S/U control field formats, 15-bit sequence
// number arithmetic and the protocol parameters (k, w, t0..t3).
//
// The package is pure encode/decode: it owns no sockets, timers or state
// machines. The connection state machine built on top of it is shared by
// [github.com/otfabric/go-iec104/client] and
// [github.com/otfabric/go-iec104/server].
package apci
