// SPDX-License-Identifier: MIT

// Package cbsigma tests the application-layer security of go-iec104
// (package sec, IEC 62351-5:2023 with IEC TS 60870-5-7:2025) against
// github.com/cB-Sigma/iec60870, the open-source implementation its formats
// were derived from.
//
// It is a module of its own so that go-iec104 keeps no dependencies. The
// tests run both implementations in one process and hand the ASDUs from one
// to the other: the encodings of every message, complete associations in
// both roles with every data protection algorithm, segmentation, renewal,
// restarts and reconnects, and certificates issued by an authority.
//
//	cd interop/cbsigma && go test ./...
//
// or make test-cbsigma in the repository root.
package cbsigma
