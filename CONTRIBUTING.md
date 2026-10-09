# Contributing to go-iec104

Thank you for your interest in contributing to `go-iec104`! This document covers the guidelines for contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```sh
   git clone git@github.com:<your-username>/go-iec104.git
   cd go-iec104
   ```
3. Create a feature branch:
   ```sh
   git checkout -b feature/my-change
   ```

## Development Setup

### Prerequisites

- Go 1.23+ (see [go.mod](go.mod)); the code must build and pass on Go 1.23, so do not use newer language or standard-library features
- [staticcheck](https://staticcheck.dev/), [golangci-lint](https://golangci-lint.run/) and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for the checks
- No hardware and no external simulator: tests run client and server against each other and against scripted peers over loopback TCP

### Build & Test

```sh
# Run all checks (format, lint, vet, vulnerability scan, tests, coverage)
make check

# Run the library tests with the race detector
make test

# Run the codec fuzz targets (FUZZTIME=30s by default)
make fuzz

# Build the examples into ./bin
make build
```

Run `make` (or `make help`) for the full list of targets.

## Making Changes

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Start every Go file with `// SPDX-License-Identifier: MIT`
- No dependencies outside the standard library
- Type identifications keep the mnemonics of the standard (`M_SP_NA_1`); everything else follows Go naming
- Respect the package boundaries and import rules in [ARCHITECTURE.md](ARCHITECTURE.md): `apci` and `asdu` are pure codecs, protocol state lives in `internal/link`, and `client` and `server` do not import each other

### Formatting

`make fmt` formats with the `gofmt` of the Go version in `go.mod`, which is the version CI uses, not necessarily the one you have installed. `make fmt-check` (part of `make check`) fails if either that `gofmt` or your local one would change a file. If they disagree, restructure the code (for example, move trailing comments onto their own lines) rather than picking a side.

### Tests

- Every change to the wire format needs a byte-level vector in `apci` or `asdu`, taken from the standard or from a capture, not from the encoder's own output
- A new type identification must appear in the round-trip test (`TestRoundTripAllTypes` fails for a registered type without coverage) and in [INTEROPERABILITY.md](INTEROPERABILITY.md)
- Protocol machine behaviour is tested in `internal/link` with the scripted peer, where the exact frames are visible
- Tests must pass with `-race` and must not depend on timing beyond generous upper bounds

### Documentation

Update the document that owns the topic: [API.md](API.md) for signatures, [ERRORS.md](ERRORS.md) for error behaviour, [OBSERVABILITY.md](OBSERVABILITY.md) for logs and metrics, [INTEROPERABILITY.md](INTEROPERABILITY.md) for protocol coverage, and add an entry to [RELEASE.md](RELEASE.md).

## Submitting

1. Run `make check`
2. Commit with a message that says what changed and why
3. Open a pull request against `main` describing the change and how it was tested

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
