module github.com/otfabric/go-iec104/interop/cbsigma

go 1.26.0

require (
	github.com/cB-Sigma/iec60870 v0.3.0
	github.com/otfabric/go-iec104 v0.0.5
)

require (
	github.com/cB-Sigma/iotcrypto v0.1.0 // indirect
	github.com/cB-Sigma/iotsec v0.1.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// The tests run against the go-iec104 of this checkout.
replace github.com/otfabric/go-iec104 => ../..
