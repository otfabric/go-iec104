# go-iec104 Releases

## v0.0.1

**Date:** 2026-10-09
**Previous release:** none

## Summary

First release: an IEC 60870-5-104 controlling station (`client`) and
controlled station (`server`) in pure Go on a shared protocol machine, with
an ASDU codec that is independent of the transport. No dependencies outside
the standard library; Go 1.23 or later.

The library is qualified against two independent implementations, MZ
Automation lib60870-C v2.4.1 and OpenMUC j60870 1.7.2, as client and as
server.

The API is not frozen: until v1.0.0 a minor release may change it.

## Changes

### Added

- **`client`** — `Dial`/`Connect`, `StartDT`/`StopDT`/`TestLink`, `Interrogate`, `CounterInterrogate`, `Read`, `ClockSync`, `Command`, `Deactivate`, `TestCommand`, `ResetProcess` and raw `Send`. Every received ASDU is delivered in order to a `Handler`. TLS (IEC 62351-3), custom `Dialer`, connection state handler.
- **Resilience** — `context.Context` on every call; automatic reconnect with exponential backoff (`WithReconnect`); a start handler that runs on every fresh connection (`WithStartHandler`); automatic retries of the requests that only read (`WithRetry`), never of commands.
- **Redundancy groups** (`client.Group`) — several connections to one station with exactly one started, automatic failover and manual `Switchover`. This is the protocol's counterpart of a connection pool.
- **Observability** — silent by default. Structured logging through `FieldLogger`/`ContextLogger` (`NewSlogLogger` returns both), with a formatted fallback for printf-style loggers. Metrics hooks for connections and frames (`Metrics`), request outcomes with duration and retries (`RequestMetrics`) and handler duration (`HandlerMetrics`).
- **`server`** — `Server` with any number of `Session`s; `Mux` routing by type identification with the refusals of the standard (unknown type, cause, common address); `Confirm`/`Negative`/`Terminate`/`Reject`; `Broadcast` to started sessions; session limit, accept filter, TLS with a bounded handshake.
- **`asdu`** — model and codec for 59 type identifications: process information in monitor direction (1..21, 30..40), process commands (45..51, 58..64), system information (70, 100..107) and parameters (110..113). CP24Time2a and CP56Time2a, SQ = 0 and SQ = 1, configurable field sizes (`Params`) so that the package serves IEC 60870-5-101 as well. File transfer and private types travel as `ASDU.Raw`.
- **`apci`** — APDU framing (`Frame`, `Parse`, `ReadFrame`, `AppendBinary`), I/S/U control fields, 15-bit sequence arithmetic and `Params` (`k`, `w`, `t0`..`t3`) with validation.
- **Protocol machine** (`internal/link`) — send and receive sequence numbers, the `k`/`w` windows, `t1`/`t2`/`t3` supervision, STARTDT/STOPDT/TESTFR in both roles including the "unconfirmed stopped" state, receive flow control that withholds acknowledgements before it stops reading.
- **Root package `iec104`** — sentinel errors (`ErrClosed`, `ErrNotConnected`, `ErrConnectFailed`, `ErrNotStarted`, `ErrConnectionLost`, `ErrTimeout`, `ErrProtocol`, `ErrBusy`, `ErrInvalidOption`), `NegativeError`, `State`, the `Logger` and `Metrics` interfaces with their extensions, `log/slog` and `log` adapters.
- **Examples** — `examples/server` and `examples/client`, and runnable examples in the package documentation.
- **Docs** — README, API.md, ARCHITECTURE.md, INTEROPERABILITY.md, ERRORS.md, OBSERVABILITY.md, SECURITY.md, CONTRIBUTING.md.

### Verification

- **Unit and integration tests** with the race detector: codec vectors from the standard, round trips over every type identification, a scripted peer for every window, timer and protocol violation, client and server against each other including TLS and reconnect. Statement coverage is above 90% in every package.
- **Fuzzing** of `apci.Parse`/`ReadFrame` and `asdu.Decode` (parse, re-encode, fixed point).
- **Interop suite** (`interop`, `make interop`, the Interop workflow on every push) against the images of [otfabric/iec104-interop v0.1.0](https://github.com/otfabric/iec104-interop/releases/tag/v0.1.0), pinned by digest:

  | Reference | go-iec104 client → reference server | reference client → go-iec104 server |
  |-----------|:-----------------------------------:|:-----------------------------------:|
  | lib60870-C v2.4.1 | pass | pass |
  | j60870 1.7.2 | pass | pass |

  In the server direction each of 30 scenarios must have the outcome the standard prescribes, and the reference client's complete result must equal what it gets from the server of its own stack.

### Known limitations

- No file transfer state machine and no object model for types 120..127.
- Redundancy groups are managed on the client side only; a server does not group its sessions. No buffering of events for stopped connections.
- No connection pool, deliberately: connections of this protocol are sessions, not interchangeable request channels. Use a redundancy group.
- No IEC 62351-5 application-layer authentication.
- A client `Handler` cannot call the request methods (`Command`, `Interrogate`, ...) from inside `HandleASDU`; use another goroutine.
- Verified against lib60870-C and j60870 only; not against certified test equipment or field devices. The interop suite covers the types of the reference fixture; the other type identifications are covered by this repository's codec tests.
