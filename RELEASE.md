# go-iec104 Releases

## v0.0.2

**Date:** 2026-10-10
**Previous release:** v0.0.1

## Summary

Fixes a client bug that could hide a refused command, and closes the gaps
with lib60870-C and j60870: file transfer (typed ASDUs and the download
procedure in both roles), server-side redundancy groups and a server-side
event queue with acknowledged delivery. Qualified against three reference
stacks instead of two. No breaking API change.

**Upgrade if you use v0.0.1**: see "Fixed".

## Changes

### Added

- **File transfer types** (`asdu`) — `F_FR_NA_1`..`F_SC_NB_1` (120..127) now decode into `FileReady`, `SectionReady`, `FileCall`, `FileLastSegment`, `FileAck`, `FileSegment`, `FileDirectoryEntry` and `FileQueryLog`, with the qualifier constants and `TypeID.IsFileTransfer`. 67 type identifications are modelled.
- **File download** — `Client.GetFile` (and `Group.GetFile`) runs the file transfer procedure in monitor direction: select, call, sections, segments, with the length and checksum of every section and of the file checked and acknowledged. `server.FileServer`, registered on a `Mux` for `server.FileTypes`, serves the files of a `FileSource`; `server.NewFile` splits content into sections and `FileServer.OnDone` reports the end of each transfer.
- **Server-side redundancy groups** — `server.WithRedundancyGroups` assigns connections to groups by client address; `Session.Group`. The connection of a group that started data transfer last is its active one.
- **Event queue** — `Server.Enqueue` queues an event per redundancy group, delivers in order to the group's active connection, keeps events while no controlling station is connected and repeats what was not acknowledged when a connection stops or is lost. `server.WithEventQueue` sets the size (default 1024, oldest dropped when full); `Server.Pending` and `Server.Dropped` expose it.

### Changed

- **File transfer ASDUs are no longer raw.** Code that read `ASDU.Raw` for types 120..127 now finds typed `ASDU.Objects` instead. `ASDU.Raw` remains for the private range.
- A server now turns away a client that no redundancy group allows. With the default configuration (one group for everyone) nothing changes.

### Fixed

- **A command or interrogation could take the activation termination of an earlier request for its own answer.** `Command`, `Deactivate`, `ClockSync`, `TestCommand` and `ResetProcess` returned success, without waiting for the confirmation, when the termination of a previous command to the same object arrived after the new one was sent: a refusal by the station went unnoticed. `Interrogate` and `CounterInterrogate` could likewise return early, with no data, on the termination of the previous run. A termination now only ends the request whose confirmation preceded it. Present in v0.0.1; found by the new end-to-end tests, where both sides answer within microseconds.

### Verification

- **End-to-end tests of the library against itself** (package `e2e`, part of `go test ./...`), 33 tests that execute about 85% of the library:
  - the client against a go-iec104 station serving the interop fixture, over TCP, TLS and with `k = w = 1`: interrogation, counters and read value by value; all command types, select-before-operate and refusals; file download; STARTDT/STOPDT; the idle test in both directions; reconnect; concurrent sessions; the event queue; redundancy groups on the client and on the server;
  - a wire matrix of all 67 type identifications in every variant, through both codecs and both protocol machines, also with the IEC 101 field sizes and a non-UTC time zone, and a 40,000-frame run across the sequence number wrap;
  - state callbacks, logs and metrics of both sides checked against each other; retries; admission (session limit, accept filter, redundancy groups by address); event queue overflow; broadcast; timeouts, cancellation, `ErrBusy` and shutdown under a pending request; handler panics; mutual TLS; unsolicited data amid requests; STOPDT during an event stream; a silent link detected by t1 on both sides.

- Byte-level vectors and fuzzing for the file transfer types.
- **Qualified against [otfabric/iec104-interop v0.2.0](https://github.com/otfabric/iec104-interop/releases/tag/v0.2.0)**, pinned by digest: lib60870-C v2.4.1, j60870 1.7.2 and, new, wendy512/iec104 v1.0.4 on go-iecp5 v1.2.6 as a third independent implementation. All three pass in both directions.
- File download against the reference stacks: `GetFile` fetches the files of a lib60870-C station with the content its fixture defines, and the lib60870-C and j60870 clients download from a go-iec104 station and see, ASDU by ASDU, what they see from the lib60870-C file server.
- The interop suite reads the capabilities of each reference image and skips what an image does not declare: commands with time tag and file transfer for wendy512/iec104, the file server role for j60870.
- The event queue is tested against all three reference clients: events queued before a connection arrive in order and their acknowledgements empty the queue.

### Still open against lib60870-C

- File transfer in control direction (upload), the file directory and deletion: typed in the codec, no procedure.
- IEC 60870-5-101 serial link layer: out of scope for this module (see README).

---

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
