// SPDX-License-Identifier: MIT

// Package sec is the application-layer security of IEC 60870-5-104: the
// A-Profile of IEC 62351-5:2023 as IEC TS 60870-5-7:2025 maps it onto
// IEC 60870-5-101 and -104.
//
// Two stations first agree on update keys (the Station Association: their
// certificates are exchanged, checked against what each side trusts, and an
// ECDH key agreement followed by HKDF gives both the same keys), then on
// session keys (the Session Key Change: the controlling station wraps fresh
// keys with the update keys). From then on every application ASDU travels
// inside a Secure Data message (S_SD_NA_1) that is authenticated with a
// truncated HMAC, or encrypted and authenticated with AES-256-GCM, and
// numbered so that a replayed message is refused. Messages longer than an
// ASDU are cut into segments.
//
// An [Endpoint] is one station's end of such an association. It does no I/O:
// the caller hands it what was received and sends what it returns, which is
// what the client and server packages do when they are given one
// (client.WithSecurity, server.WithSecurity). On its own it is useful to test
// and to analyse.
//
// # Provenance
//
// The normative documents are not public. The message formats, MAC inputs,
// key derivation and state machines of this package were derived from the
// open-source implementation github.com/cB-Sigma/iec60870 (Apache-2.0),
// which states that it follows licensed copies of both standards; the code
// is this module's own. Interoperability with that implementation is tested
// (the module interop/cbsigma of this repository); conformance to the
// standards is not established independently. See SECURITY.md.
package sec
