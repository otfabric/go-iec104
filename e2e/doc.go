// SPDX-License-Identifier: MIT

// Package e2e holds end-to-end tests of go-iec104 against itself: the
// client of this module as controlling station and the server of this
// module as controlled station, over real TCP (and TLS) connections on
// loopback.
//
// The station is the one the interop suite uses against third-party
// clients (internal/station, serving the baseline fixture of
// otfabric/iec104-interop), and the scenarios are the ones that suite runs
// against third-party servers. Where package interop shows that each side
// agrees with other implementations, this package shows that the two sides
// agree with each other, on every "go test" and without Docker.
package e2e
