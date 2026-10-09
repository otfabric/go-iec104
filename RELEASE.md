# go-iec104 Releases

## v0.0.3

**Date:** 2026-10-10
**Previous release:** v0.0.2

## Summary

File transfer in control direction and the file directory, a comparison
with wendy512/iec104, and a folder of examples to start from. A thorough
overhaul of the order in which the two protocol machines, the redundancy
group and the event queue change state and tell their applications: 25
fixes, found by a new suite of state machine tests, a randomized chaos test
and two independent reviews of the code. No breaking API change.

**Upgrade notes**

- `Close` (client, group, session and server) now waits for a handler call in progress to return. A handler that never returns blocks it; see "Changed".
- A request that is waiting when data transfer stops now fails with `iec104.ErrNotStarted` instead of its timeout error; see "Fixed".
- A request method called from inside the client's `Handler` or state handler now fails at once with the new `iec104.ErrInHandler`. It could never be answered there and used to run into its timeout; see "Changed".

## Changes

### Added

- **File upload** — `Client.PutFile` (and `Group.PutFile`) delivers a file to a station: file ready, then the sections and segments the station calls for, each with its checksum, until the station acknowledges the file. On the station, `server.FileServer.Sink` (a `FileSink`) decides whether a file is accepted and stores what arrived intact; a length or checksum that does not match, or a failed store, is acknowledged negatively.
- **File directory** — `Client.ListFiles` (and `Group.ListFiles`) calls the directory and returns its entries; `server.FileServer.Directory` answers the call, as `F_DR_TA_1` sequences.
- **Names for the secure authentication types** — `asdu.S_CH_NA_1` .. `asdu.S_UC_NA_1` and `asdu.S_IT_TC_1` (IEC TS 60870-5-7), `TypeID.IsSecurity`, and the causes `asdu.CauseAuthentication`, `CauseSessionKey` and `CauseUserRoleUpdateKey`. These types print by name and are still carried as `ASDU.Raw`: the procedures of IEC 62351-5 are not implemented (see SECURITY.md).
- **Examples** — nine programs under `examples/`: `quickstart`, `commands`, `files`, `events`, `redundancy`, `tls` and `observability` are self-contained and run with `go run`; `server` and `client` are the two separate programs that were there. `make examples` runs the self-contained ones, and so does CI.

### Changed

- `server.FileTypes` now also lists `F_FR_NA_1`, `F_SR_NA_1`, `F_SG_NA_1` and `F_LS_NA_1`, which a station receives when a file is delivered to it. A `FileServer` without a `Sink` refuses them with "unknown information object address"; before, a `Mux` answered them with "unknown type identification".
- **`Close` waits for the callbacks**, on `Client`, `Group`, `Session` and `Server`. It returns when the `Handler`, the state handler and the switch handler have been called for the last time (see "Fixed"); several callers at once all wait for that. A handler that blocks forever therefore blocks `Close` called from another goroutine. From inside a handler `Close` returns at once, as before, the handler is not called again, and the close completes when that call has returned.
- **`Client.Close` hands over what was received.** Called from outside a callback it first gives the `Handler` everything the connection had already received and acknowledged to the station.
- **Callbacks may call back.** A client state handler may call `StartDT`, `StopDT`, `Send`, `Connect` and `Close`; a group's state and switch handlers may call `Switchover` and `Close`; a server handler may call `Session.Close` and `Server.Close`, also from the first "stopped" notification. Before, several of these deadlocked.
- **New error `iec104.ErrInHandler`** for a client request method (`Command`, `Interrogate`, `Read`, `GetFile`, ...) called from the client's `Handler` or state handler. The answer is delivered by the goroutine the callback occupies: from the `Handler` such a call always ran into its timeout, from the state handler it did so depending on timing. It now fails at once, every time. It is not retried.
- **`Group.Switchover` reports when nothing was switched.** It returns `ErrNotConnected` when the standby could not be started and data transfer is back on the connection it was on; before, it returned nil.
- **A `Group` follows its connections, not the `Handler`.** It notices a lost or stopped connection when the connection changes, also while the application's `Handler` is busy on it. It no longer holds its lock while the application is called: a slow state handler delays the notifications of its own connection and nothing else.
- A `Group` waits `Reconnect.MinDelay`, doubling up to `MaxDelay`, before it dials an address again that could not be reached.
- `server.NewFileServer` accepts a nil source, for a station that only takes files or only has a directory.
- The comparison matrix in the README has a column for wendy512/iec104.

### Fixed

Link and state order:

- **A station confirmed STOPDT and STARTDT before it had changed its own state.** For a moment after the confirmation was on the wire, `Session.Started` still reported the old state and `Session.Send` followed it: a controlling station that had its STOPDT confirmed could find the station still "started". The state now changes before the confirmation is sent. Found by the end-to-end tests on a CI runner.
- **A request that was waiting when data transfer stopped kept waiting until its timeout.** After STOPDT (the client's own, or a group's switchover) the station cannot answer any more. Such requests now fail at once with `iec104.ErrNotStarted`, after everything the station sent before it confirmed the stop has been delivered, so an answer that did arrive is not lost. A request sent after the restart is not affected by the stop before it.
- **Sending on a connection that was just ending could report the wrong error.** For a moment during shutdown a `Send`, and with it any request, was told `ErrNotStarted`, or `ErrConnectionLost` for a connection the application itself was closing. It now gets the reason the connection ended: `ErrClosed` for a local `Close`.
- **A deactivation confirmation could pass for an activation confirmation.** The late answer to a `Deactivate` the caller had given up on was taken as the positive confirmation of a following command on the same object. Confirmations are now matched by cause.

- **A directory listing could break a file transfer on the same connection.** `ListFiles` running while `GetFile` or `PutFile` was under way failed that transfer with a protocol violation when the directory listed the file being transferred first: the directory was taken for a part of the transfer. Found by the end-to-end tests in the release pipeline.
- **A directory listing could be returned as the value of a read.** `Read` of an address took a directory that `ListFiles` had called for at the same time, when the directory listed a file at that address: both carry the cause "request". Interrogations and reads no longer take anything that belongs to file transfer. Found by the cross-talk tests below.

Close:

- **Callbacks could still arrive after `Close` had returned.** `Client.Close`, `Session.Close` and `Server.Close` returned as soon as the connection was down, while a `Handler` or state handler call could still be in progress or about to start. They now return when the last callback has returned and none follows.
- **After `Close` from inside a handler, the handler was called again** for what was still queued, on client and server.
- **`Close` from a state handler could deadlock**: `Client.Close` from the client's state handler, and `Session.Close` or `Server.Close` from the first "stopped" notification of a session.
- **A second `Close` returned early.** Called while another `Close` was still waiting for a handler, `Client.Close` and `Server.Close` returned at once.
- **`Server.Close` did not wait for sessions that were already ending**: one whose connection the peer had dropped and whose state handler was still running, or one whose `Handler` had closed its own session.
- **A client lost monitoring data it had acknowledged.** `Client.Close` discarded what the connection had received but the `Handler` had not yet seen; the station had been told it arrived and did not send it again. Found by the chaos test.
- **A client could be told about a connection after it had closed it, and "disconnected" twice**, when the station dropped the connection at the moment the application called `Close`.
- **A client could report "stopped" for a connection that was already lost**, before "disconnected". A connection that has ended is now only reported by its loss.
- **`Connect` racing `Close` could leave a closed client reporting a state other than "disconnected"**, and read the client's state without its lock (a data race, found by the chaos test).

Event queue (`Server.Enqueue`):

- **Events could be sent twice on the same connection** after a STOPDT and STARTDT, when the session's `Handler` was slow: the queue learned of the stop only when the `Handler` had returned and took the events of the next started period for unacknowledged ones. The queue now follows the connection itself.
- **Events could wait in the queue of a started connection** when the controlling station sent STARTDT while its STOPDT was still waiting for an acknowledgement; they moved again with the next event.
- **A switchover could be held up to t1** by the old connection, when its window was full and it no longer acknowledged.
- The application's logger is no longer called with the queue's lock held.

Redundancy group (`client.Group`):

- **Two connections could end up started.** A STARTDT the group had given up on could still be confirmed later, and nothing stopped that connection. The group now stops such a stray, or drops the connection when it cannot.
- **`Group.Close` and `Group.Switchover` from a state handler deadlocked**, and a state handler that was slow held up the whole group, `Close` included.
- **`Group.Close` returned while the switch handler was running**, and the handler could be called again afterwards.
- **Failover waited for the `Handler`.** A lost active connection was noticed only when the `Handler` that was busy on it had returned.
- **`Group.Switchover` could return before the switch handler had been told**, when the group's own goroutine was telling it at that moment. The group now calls the application from a goroutine of its own, which a slow callback cannot keep from supervising the connections.
- **An address that refused connections was dialed without pause**, thousands of times per second.

### Verification

- Upload and directory: round trips of files of every shape, refusals, corrupted deliveries (wrong checksum, too much or too little data, deliveries out of order, abandoned transfers) against the station, and a station that misbehaves against the client; end to end over TCP, TLS and with `k = w = 1`, including delivering, fetching and listing at once on one connection.
- **State machine tests**, written after the first of the fixes above to look for its relatives:
  - in `internal/link`, every frame a link writes is checked against the link's own state at that moment (no confirmation before the state has changed, no I frame outside a started period), in 500 strict start/stop cycles and in randomized runs where both applications start, stop and send at once; every frame a `Send` accepted must arrive once and in order, both sides must report the same sequence of states, and neither may see a protocol error;
  - in `e2e`, 200 STARTDT/STOPDT cycles with both sides checked at the return of every call; connections that come and go at random while the station drops sessions, with the story each session and each client is told checked against a grammar; every control call at once from eight goroutines, with a `Close` in the middle; nothing after `Close` on either side, also when the station drops the connection at that very moment; requests pending across a stop; 60 redundancy switchovers with both stations checked at each return.
- **A chaos test** (`e2e`, `TestChaos`): clients that connect, start, stop, send, request and close at random, a station that drops sessions, broadcasts and queues events, and a network that delays, fragments and cuts connections, for several seeds. Afterwards every call has returned, every queued event has reached a `Handler`, each side was told a story that fits the grammar and ends in the state it is in, and no goroutine is left. `E2E_CHAOS_SECONDS` and `E2E_CHAOS_SEEDS` lengthen it; it ran for minutes under the race detector, also on one and two CPUs.
- **Two independent reviews** of the state machines, each asked to break them and to prove every finding with a failing test. Their reproductions are part of the suite (`TestOrdering...`, `TestReview2...`), next to tests that call back into the library from every callback, close from several goroutines at once, and place a `Close` at a chosen point of a connection loss (a failpoint).
- **Cross-talk tests**: every request method against a station that, around each ASDU of its answer, sends what every other procedure would send for the same station and the same object, and all of it again for another object and as another station, with refusals where a confirmation would be and with other values. Then every pair of request methods at once on one connection, all of them at once, and end to end several clients issuing every kind of request at once over TCP, TLS and `k = w = 1`. Taking out any one of the eleven conditions by which a request recognizes its answers fails these tests.
- **Mutation checks**: each fix was taken out again in turn, to see a test fail for it.
- **Under load**: the whole suite repeatedly without and with the race detector, on two CPUs with every core kept busy, as on a shared CI runner. Two tests assumed more about timing than the library promises and were corrected (`TestSilentLink`, which failed in the release pipeline, and `TestReceiveBackpressure`).
- The end-to-end suite (`e2e`) covers what is new: upload, directory and fetching a delivered file over TCP, TLS and `k = w = 1`, through a redundancy group on both of its paths and with IEC 101 field sizes; the station's state at the moment STARTDT and STOPDT are confirmed; the secure authentication types in the wire matrix.
- Not yet against a reference stack: the interop images have no upload or directory operation. lib60870-C can receive a file; none of the three has a directory.

---

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
