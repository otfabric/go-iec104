# go-iec104 Releases

## Unreleased

**Date:** 2026-10-09

## Summary

First version of the library: an IEC 60870-5-104 controlling station
(`client`) and controlled station (`server`) on a shared protocol machine,
with an ASDU codec that is independent of the transport.

## Changes

### Added

- **`apci`** — APDU framing (`Frame`, `Parse`, `ReadFrame`, `AppendBinary`), I/S/U control fields, the six U functions, 15-bit sequence arithmetic and `Params` (`k`, `w`, `t0`..`t3`) with validation.
- **`asdu`** — ASDU model and codec for 59 type identifications: process information in monitor direction (1..21, 30..40), process commands (45..51, 58..64), system information (70, 100..107) and parameters (110..113). CP24Time2a and CP56Time2a time tags, SQ = 0 and SQ = 1, configurable field sizes (`Params`) for IEC 60870-5-101. File transfer and private types travel as `ASDU.Raw`.
- **`client`** — `Dial`/`Connect`, `StartDT`/`StopDT`/`TestLink`, `Interrogate`, `CounterInterrogate`, `Read`, `ClockSync`, `Command`, `Deactivate`, `TestCommand`, `ResetProcess`, raw `Send`; ordered delivery of every received ASDU to a `Handler`; automatic reconnect with exponential backoff; TLS; custom `Dialer`.
- **`server`** — `Server` with any number of `Session`s, `Mux` routing by type identification with standard-conformant rejection (unknown type, cause, common address), `Confirm`/`Negative`/`Terminate`/`Reject`, `Broadcast` to started sessions, session limit, accept filter, TLS.
- **Protocol machine** (`internal/link`) — send/receive sequence numbers, `k`/`w` windows, `t1`/`t2`/`t3` supervision, STARTDT/STOPDT/TESTFR in both roles, bounded receive queue with TCP backpressure.
- **Root package** — sentinel errors, `NegativeError`, `State`, `Logger` (with `log/slog` and `log` adapters) and `Metrics`.
- **Examples** — `examples/server` and `examples/client`.
- **Docs** — README, API.md, ARCHITECTURE.md, INTEROPERABILITY.md, ERRORS.md, OBSERVABILITY.md, SECURITY.md, CONTRIBUTING.md.

### Known limitations

- No file transfer state machine and no object model for types 120..127.
- No redundancy group management; no buffering of events for stopped connections.
- No IEC 62351-5 application-layer authentication.
- Not yet verified against third-party implementations.
