# AGENTS.md — go-iec104

## What this is

Pure Go IEC 60870-5-104 client and server with no dependencies outside the standard library: APCI protocol machine, ASDU codec, file transfer, redundancy groups, TLS and IEC 62351-5 application-layer security. Profile: **protocol-library**. Nothing is certified; see LIMITATIONS.md.

## Organisation standards

This repository follows **otfabric/engineering policy 1.0**, profile **protocol-library** (`.otfabric/policy.yaml`, mode `baseline`). Organisation skills: `otfabric` Claude Code plugin. Where this file and the organisation standards disagree, this file wins here — say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| What is implemented, clause by clause; verification status | INTEROPERABILITY.md |
| Packages, goroutines, protocol machine | ARCHITECTURE.md |
| Scope not implemented, known deviations | LIMITATIONS.md |
| Application-layer security | SECURITY.md |
| Errors | ERRORS.md |
| Release history | RELEASE.md (`## vX.Y.Z` … `---`) |

## Hard rules

1. Never lower the go-ci `coverage-min` (90), add lint suppressions, or skip/delete tests to make CI pass.
2. Never invent protocol semantics; cite the clause.
3. Interop claims only from passing runs against the pinned images: the digests in the Makefile and `interop/harness.go` stay in step.
4. The module stays free of dependencies outside the standard library; `interop/cbsigma` is a module of its own. This library stays on v0 or v1.
5. The code must build and pass on the Go version in go.mod.

## Commands

| When you change… | Run |
|---|---|
| anything | `make check` |
| a codec | `make fuzz` |
| interop-relevant behaviour | `make interop` (Docker) |
| application-layer security | `make test-cbsigma` (Go 1.26) |

## Definition of Done

`make check` green; tests for new behaviour including error paths; fuzz target for any new decoder; INTEROPERABILITY.md and API.md updated in the same change; RELEASE.md section for user-visible changes.

## Git and releases

Branches and PRs. Do not push to `main`, tag or run the Release workflow unless the maintainer asks in the session.
