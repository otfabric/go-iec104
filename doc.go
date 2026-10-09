// SPDX-License-Identifier: MIT

// Package iec104 is the module root of a pure Go implementation of
// IEC 60870-5-104, the TCP/IP telecontrol protocol used between control
// centres and substations, RTUs and generation assets.
//
// Applications import the subpackages:
//
//   - [github.com/otfabric/go-iec104/client]: the controlling station
//     (master): connect, STARTDT, interrogation, commands, clock
//     synchronization, automatic reconnect
//   - [github.com/otfabric/go-iec104/server]: the controlled station
//     (outstation): listener, sessions, request routing, spontaneous data
//   - [github.com/otfabric/go-iec104/asdu]: the ASDU model and codec,
//     shared with IEC 60870-5-101
//   - [github.com/otfabric/go-iec104/apci]: APDU framing, I/S/U control
//     fields, sequence numbers and the protocol parameters
//
// This package holds what client and server share: the sentinel errors, the
// [Logger] and [Metrics] interfaces and the data transfer [State].
//
// Docs: README.md, API.md (public API), ERRORS.md (error semantics),
// OBSERVABILITY.md (logging and metrics), RELEASE.md (changelog).
package iec104
