//go:build interop

// SPDX-License-Identifier: MIT

// Package interop runs black-box tests of go-iec104 against independent
// IEC 60870-5-104 implementations: MZ Automation lib60870-C, OpenMUC j60870
// and wendy512/iec104, packaged as container images by
// otfabric/iec104-interop.
//
// Both directions are covered:
//
//   - the go-iec104 client against the reference servers (client_test.go)
//   - the reference clients against a go-iec104 server (server_test.go)
//
// The images are the only thing shared with iec104-interop: their container
// contract (commands, JSON documents, exit codes) and the fixture baked into
// them, which the tests read with "print-fixture". The scenarios, expected
// values and assertions are owned here. The fixture-driven go-iec104 station
// the reference clients talk to lives in internal/station, shared with the
// end-to-end tests of package e2e.
//
// Build with -tags=interop. Running needs Docker; see README.md § Interop
// tests. Editor/gopls: add -tags=interop to buildFlags.
package interop
