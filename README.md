# go-iec104 - IEC 60870-5-104 Client and Server Library for Go

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-iec104.svg)](https://pkg.go.dev/github.com/otfabric/go-iec104)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Status](https://github.com/otfabric/go-iec104/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-iec104/actions/workflows/ci.yml)
[![Interop](https://github.com/otfabric/go-iec104/actions/workflows/interop.yml/badge.svg)](https://github.com/otfabric/go-iec104/actions/workflows/interop.yml)
[![Code Coverage](https://codecov.io/gh/otfabric/go-iec104/graph/badge.svg)](https://codecov.io/gh/otfabric/go-iec104)
[![Latest Release](https://img.shields.io/github/v/release/otfabric/go-iec104?label=release)](https://github.com/otfabric/go-iec104/releases)

A pure Go implementation of IEC 60870-5-104, the TCP/IP telecontrol protocol
between control centres and substations, RTUs and generation assets. No cgo,
no dependencies outside the standard library.

The library provides:

- A **client** (controlling station): STARTDT/STOPDT, general and counter
  interrogation, read, clock synchronization, process commands with
  select-before-operate, test command, automatic reconnect
- A **server** (controlled station): any number of sessions, routing by type
  identification, standard-conformant rejection of what the application does
  not serve, redundancy groups with an event queue that keeps events until a
  control centre has acknowledged them
- The complete **APCI** protocol machine on both sides: I/S/U frames, 15-bit
  sequence numbers, the `k`/`w` flow-control windows and the `t0`..`t3` timers
- An **ASDU** model and codec for 67 type identifications, file transfer
  included, independent of the transport and reusable for IEC 60870-5-101
- **File transfer** in both directions and the directory: `GetFile`,
  `PutFile` and `ListFiles` on the client, `server.FileServer` on the
  station, with sections, segments, checksums and acknowledgements handled
  by the library
- What production use needs: `context.Context` on every call, automatic
  reconnect, retries for the requests that are safe to repeat, redundancy
  groups with failover, structured logging, metrics hooks and TLS
  (IEC 62351-3)
- **Verified against third-party stacks**: every push runs the library, as
  client and as server, against MZ Automation lib60870-C, OpenMUC j60870 and
  wendy512/iec104

**Docs:** [API.md](API.md) (public API) · [ARCHITECTURE.md](ARCHITECTURE.md) (packages, goroutines, protocol machine) · [INTEROPERABILITY.md](INTEROPERABILITY.md) (what is implemented, clause by clause) · [ERRORS.md](ERRORS.md) (error semantics) · [OBSERVABILITY.md](OBSERVABILITY.md) (logging and metrics) · [SECURITY.md](SECURITY.md) · [RELEASE.md](RELEASE.md) (changelog)

## Table of contents

- [go-iec104 - IEC 60870-5-104 Client and Server Library for Go](#go-iec104---iec-60870-5-104-client-and-server-library-for-go)
	- [Table of contents](#table-of-contents)
	- [go-iec104 vs lib60870, j60870 and wendy512/iec104](#go-iec104-vs-lib60870-j60870-and-wendy512iec104)
	- [Install](#install)
	- [Project structure](#project-structure)
	- [Client quickstart](#client-quickstart)
	- [Server quickstart](#server-quickstart)
	- [Production features](#production-features)
	- [The ASDU model](#the-asdu-model)
	- [Protocol parameters](#protocol-parameters)
	- [Error semantics](#error-semantics)
	- [Examples](#examples)
	- [Development](#development)
	- [Interop tests](#interop-tests)
	- [Limitations](#limitations)
	- [License](#license)

## go-iec104 vs lib60870, j60870 and wendy512/iec104

go-iec104 is tested against three other implementations (see
[Interop tests](#interop-tests)):
[MZ Automation lib60870-C](https://github.com/mz-automation/lib60870),
[OpenMUC j60870](https://www.openmuc.org/iec-60870-5-104/) and
[wendy512/iec104](https://github.com/wendy512/iec104) on its engine
go-iecp5. All are good libraries; this table shows where the four differ so
you can pick the right one for your project.

| Capability | otfabric/go-iec104 | lib60870-C | j60870 | wendy512/iec104 |
|---|:---:|:---:|:---:|:---:|
| Language | Go | C | Java | Go |
| License | MIT | GPL-3.0 or commercial | GPL-3.0 | Apache-2.0, on an LGPL-3.0 engine |
| IEC 60870-5-104 client (controlling station) | ✅ | ✅ | ✅ | ✅ |
| IEC 60870-5-104 server (controlled station) | ✅ | ✅ | ✅ | ✅ |
| IEC 60870-5-101 serial link layer | — by design ¹ | ✅ | — | — frame format only |
| Process information, commands, system types (1..40, 45..64, 70, 100..107) | ✅ | ✅ | ✅ | partly ³ |
| Parameter types (110..113) | ✅ | ✅ | ✅ | ✅ |
| File transfer types (120..127) | ✅ | ✅ | ✅ | — identifiers only |
| File transfer procedure, monitor direction (download) | ✅ client and server | ✅ server side | — | — |
| File transfer procedure, control direction (upload) | ✅ client and server | ✅ server side | — | — |
| File directory | ✅ client and server | — | — | — |
| Private types (128..255) | raw payload | raw payload | custom decoder | — dropped |
| Configurable `k`, `w`, `t0`..`t3` | ✅ | ✅ | ✅ | ✅ |
| TLS (IEC 62351-3) | ✅ `crypto/tls` | ✅ mbedTLS | via socket factory | ✅ `crypto/tls` |
| Application-layer security (IEC 62351-5) | — types carried, no procedure | — commercial add-on (2013 edition) | — | — |
| Blocking request methods (interrogate and collect, command and confirm) | ✅ | — callbacks | — callbacks | — callbacks |
| Server-side routing with standard refusals (unknown type, cause, address) | ✅ `Mux` | partly built in | unknown type only | partly, without the P/N bit |
| Redundancy group, client side (failover, switchover) | ✅ `Group` | — | — | — |
| Redundancy groups, server side | ✅ | ✅ | — | — |
| Server-side event queue for stopped or absent clients | ✅ acknowledged delivery | ✅ | — | — |
| Automatic reconnect with back-off | ✅ | — | — | fixed interval |
| Automatic retries (read-only requests) | ✅ | — | — | — |
| Cancellation and deadlines per call | ✅ `context.Context` | — | — timeouts only | — |
| Structured logging | ✅ `log/slog` | — compile-time debug output | — (pluggable logger from 1.8.0) | — pluggable printf-style logger |
| Metrics hooks | ✅ | — raw message callback | — | — |
| Threadless / single-loop operation | — by design ² | ✅ | — | — |
| Dependencies | none | none (mbedTLS optional) | none | one (`spf13/cast`) besides its engine |
| Cross-tested against other stacks in CI | ✅ against all three | — not documented | — not documented | — not documented |

¹ IEC 60870-5-101 is a different companion standard with its own serial link
layer (FT 1.2 framing, balanced and unbalanced procedures). It belongs in a
module of its own, built on the `asdu` package of this one, which already
takes the 101 field sizes.

² A mode for C programs without threads. In Go the protocol machine runs on
goroutines, and a single-threaded variant would add nothing.

³ go-iecp5 encodes the commands with time tag (58..63) but has no length
for them and drops them on reception, as it does the file segment
(F_SG_NA_1) and every type it does not know.

✅ = available · — = not available or not documented. For lib60870-C
v2.4.1, j60870 1.7.2 and wendy512/iec104 v1.0.4 on go-iecp5 v1.2.6, the
versions go-iec104 is tested against, from their public sources and
documentation as of October 2026. If you spot an
inaccuracy, please [open an issue](https://github.com/otfabric/go-iec104/issues)
and we will correct it.

**Choose go-iec104 if** you write Go and want client and server in one
library with no cgo and a permissive license, blocking calls with `context`
control, reconnect, retries, client-side redundancy and observability built
in.

**Choose lib60870-C if** you need IEC 60870-5-101 over serial lines or a C 
library for embedded targets.

**Choose j60870 if** you are on the JVM and want a compact
IEC 60870-5-104 library.

## Install

```sh
go get github.com/otfabric/go-iec104
```

Requires Go 1.23 or later.

## Project structure

```text
go-iec104/
├── doc.go, errors.go, state.go     package iec104: shared errors, State,
├── logger.go, metrics.go           Logger and Metrics
├── apci/                           APDU framing, I/S/U control fields,
│                                   sequence numbers, k/w/t0..t3 parameters
├── asdu/                           ASDU model and codec (IEC 101/104)
├── client/                         controlling station
├── server/                         controlled station, sessions, Mux
├── internal/link/                  the protocol machine client and server share
├── internal/station/               a fixture-driven station for the tests below
├── e2e/                            go-iec104 client against go-iec104 server
├── interop/                        tests against lib60870, OpenMUC j60870, wendy512
│                                   (build tag "interop", needs Docker)
└── examples/                       nine programs to start from
```

APCI is specific to IEC 60870-5-104 and lives with it. The ASDU package has no
dependency on the transport: the field widths that differ between companion
standards are a parameter (`asdu.Params`), so the same codec serves an
IEC 60870-5-101 link layer. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Client quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
)

func main() {
	ctx := context.Background()

	// Dial connects and sends STARTDT. Every ASDU the station sends reaches
	// the handler, in order.
	c, err := client.Dial(ctx, "10.0.0.5:2404",
		client.WithReconnect(client.Reconnect{}),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			for _, obj := range a.Objects {
				if m, ok := obj.(asdu.MeasuredFloat); ok {
					fmt.Printf("%s ioa=%d value=%g quality=%s\n", a.Cause, m.IOA, m.Value, m.Quality)
				}
			}
		})))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// General interrogation of station 1: returns when the station sends
	// the activation termination.
	data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("interrogation returned %d ASDUs\n", len(data))

	if err := c.ClockSync(ctx, 1, time.Now()); err != nil {
		log.Fatal(err)
	}

	// Select before operate.
	cmd := asdu.SingleCommand{IOA: 6001, Value: true, Select: true}
	if err := c.Command(ctx, 1, cmd); err != nil {
		log.Fatal(err)
	}
	cmd.Select = false
	if err := c.Command(ctx, 1, cmd); err != nil {
		log.Fatal(err)
	}
}
```

Request methods block until the station answers and return a
`*iec104.NegativeError` when it refuses. A context without a deadline is
bounded by `WithRequestTimeout` (default 10s).

## Server quickstart

```go
package main

import (
	"log"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

func main() {
	mux := server.NewMux()

	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		qoi := req.First().(asdu.Interrogation).Qualifier
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(qoi.Cause(), req.CommonAddr,
			asdu.SinglePoint{IOA: 1001, Value: true},
			asdu.SinglePoint{IOA: 1002, Value: false}))
		_ = s.Terminate(req)
	})

	mux.HandleFunc(asdu.C_SC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		cmd := req.First().(asdu.SingleCommand)
		if cmd.IOA != 6001 {
			_ = s.Reject(req, asdu.CauseUnknownIOA)
			return
		}
		_ = s.Confirm(req)
		// operate the process ...
	})

	srv, err := server.New(mux, server.WithCommonAddrs(1))
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.ListenAndServe(":2404"))
}
```

`Mux` answers a type without a handler with "unknown type identification" and
an invalid cause of transmission with "unknown cause of transmission";
`WithCommonAddrs` answers a foreign station address with "unknown common
address".

Events go out with `Server.Enqueue`: each redundancy group delivers them, in
order, to its one started connection, keeps them while no control centre is
connected and sends again what was not acknowledged when a connection is
lost. `Session.Send` and `Server.Broadcast` send immediately and buffer
nothing.

```go
srv, err := server.New(mux,
	server.WithRedundancyGroups(
		server.RedundancyGroup{Name: "main", Allow: []string{"10.0.0.0/24"}},
		server.RedundancyGroup{Name: "backup"}), // everyone else
	server.WithEventQueue(10000))

_ = srv.Enqueue(asdu.New(asdu.CauseSpontaneous, 1,
	asdu.SinglePoint{IOA: 1001, Value: true, Time: asdu.Now()}))
```

## Production features

| Feature | How | Notes |
|---------|-----|-------|
| Cancellation | `context.Context` on `Connect`, every request, `Send`, `StartDT`/`StopDT` and on a server's `Session.Send` | A cancelled request releases its slot and leaves the connection up |
| Automatic reconnect | `client.WithReconnect` | Exponential backoff; `WithStartHandler` runs on every fresh connection, the place for a general interrogation |
| Automatic retries | `client.WithRetry` | Only for requests that read: `Interrogate`, `CounterInterrogate` (read), `Read`, `TestCommand`. Commands are never repeated |
| Redundancy | `client.NewGroup` | Several connections to one station, exactly one started, automatic failover and manual `Switchover` |
| Structured logging | `iec104.NewSlogLogger`, or any `iec104.FieldLogger` | Constant messages with fields (`component`, `remote`, `state`, `type`, `error`, …); silent by default |
| Metrics hooks | `iec104.Metrics`, `RequestMetrics`, `HandlerMetrics` | Connections, frames, request outcomes with duration and retries, handler duration |

```go
c, err := client.Dial(ctx, "10.0.0.5:2404",
	client.WithLogger(iec104.NewSlogLogger(slog.NewJSONHandler(os.Stderr, nil))),
	client.WithMetrics(myMetrics),
	client.WithReconnect(client.Reconnect{}),
	client.WithRetry(client.Retry{Attempts: 3}),
	client.WithStartHandler(func(ctx context.Context, c *client.Client) {
		_, _ = c.Interrogate(ctx, 1, asdu.QOIStation) // refresh after every (re)connect
	}))
```

**Why there is no connection pool.** A pool suits request/response protocols
whose connections are interchangeable. An IEC 60870-5-104 connection is a
session: the station pushes its spontaneous data on the one connection that
has data transfer started, and sequence numbers, acknowledgements and command
procedures belong to it. More connections add availability, not throughput,
and the standard defines exactly that as a redundancy group:

```go
g, err := client.NewGroup([]string{"10.0.0.5:2404", "10.1.0.5:2404"},
	client.WithHandler(h),
	client.WithSwitchHandler(func(active *client.Client) { /* failover happened */ }))
if err := g.Connect(ctx); err != nil { ... }
defer g.Close()

data, err := g.Interrogate(ctx, 1, asdu.QOIStation) // on the active connection
```

**Why commands are not retried.** When the confirmation of a command is lost,
the command may still have operated the process, and the protocol has no way
to ask. Repeating it is a decision for the application, with the process
state in hand. See [ERRORS.md](ERRORS.md#retries).

## The ASDU model

Information objects are plain structs named for what they mean. The type
identification selects the variant on the wire:

| Struct | Without time tag | CP24Time2a | CP56Time2a |
|--------|------------------|------------|------------|
| `SinglePoint` | `M_SP_NA_1` | `M_SP_TA_1` | `M_SP_TB_1` |
| `DoublePoint` | `M_DP_NA_1` | `M_DP_TA_1` | `M_DP_TB_1` |
| `MeasuredFloat` | `M_ME_NC_1` | `M_ME_TC_1` | `M_ME_TF_1` |
| `SingleCommand` | `C_SC_NA_1` | | `C_SC_TA_1` |
| … | | | |

`asdu.New` picks the type from the first object: no time tag when its `Time`
is zero, CP56Time2a otherwise. Set `ASDU.Type` for the other variants and
`ASDU.Sequence` for the compact SQ=1 encoding. The full table is in
[INTEROPERABILITY.md](INTEROPERABILITY.md).

```go
a := asdu.New(asdu.CauseSpontaneous, 1,
	asdu.MeasuredFloat{IOA: 4001, Value: 49.98, Time: asdu.Now()})
wire, err := a.Encode(asdu.IEC104)   // M_ME_TF_1
back, err := asdu.Decode(wire, asdu.IEC104)
```

Types without an object model (the private range 128..255) are not an error:
they travel as `ASDU.Raw` in both directions.

## Protocol parameters

Both sides take `apci.Params`; the defaults are those of the standard.

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `K` | 12 | Maximum I frames sent and not yet acknowledged; `Send` blocks beyond it |
| `W` | 8 | Acknowledge at the latest after this many received I frames |
| `T0` | 30s | Connection establishment timeout (client) |
| `T1` | 15s | Timeout for an acknowledgement or U-frame confirmation; closes the connection |
| `T2` | 10s | Longest wait before acknowledging when there is nothing to send (`T2 < T1`) |
| `T3` | 20s | Idle time before a TESTFR is sent; 0 disables |

```go
p := apci.DefaultParams()
p.T3 = 10 * time.Second
c, err := client.Dial(ctx, addr, client.WithParams(p))
```

## Error semantics

| Situation | How it is reported |
|-----------|--------------------|
| Station refuses a request (P/N bit, or cause 44..47) | `*iec104.NegativeError`; `Cause()` tells why |
| No answer in time | `context.DeadlineExceeded`, wrapped |
| Connection could not be established | `iec104.ErrConnectFailed`, wrapping the cause |
| Not connected / data transfer stopped | `iec104.ErrNotConnected` / `iec104.ErrNotStarted` |
| Identical request still pending | `iec104.ErrBusy` |
| Request method called from a client handler | `iec104.ErrInHandler` |
| Peer closed or transport failed | `iec104.ErrConnectionLost` |
| No acknowledgement within `T1` | `iec104.ErrTimeout`; connection closed |
| Peer broke the protocol | `iec104.ErrProtocol`; connection closed |
| Value cannot be encoded | `asdu.ErrInvalidValue`, `asdu.ErrTypeMismatch`, … |

Full guide: **[ERRORS.md](ERRORS.md)**.

## Examples

The [examples](examples/README.md) folder has nine programs to start from.
Seven are self-contained (station and controlling station in one process,
over TCP on loopback), so they run as they are:

```sh
go run ./examples/quickstart      # the smallest station and client
go run ./examples/commands        # select-before-operate, set points, refusals
go run ./examples/files           # download, upload and directory
go run ./examples/events          # event queue, broadcast, end of initialization
go run ./examples/redundancy      # redundancy group, switchover, failover
go run ./examples/tls             # TLS with certificates on both sides
go run ./examples/observability   # logs, states, metrics, retries, reconnect
```

Two are separate programs, for trying the library against another
implementation or a device:

```sh
make build
./bin/example-server -addr :2404
./bin/example-client -addr 127.0.0.1:2404 -operate 6001
```

Both take `-debug` to log every APDU.

## Development

```sh
make check      # format, lint, vet, vulnerability scan, tests, coverage
make test       # tests with the race detector
make fuzz       # codec fuzz targets (FUZZTIME=30s each)
make bench      # codec benchmarks
```

Tests need no hardware and no external process: client and server are tested
against each other and against scripted peers over loopback TCP.

The `e2e` package runs the library against itself, end to end, as part of
`go test ./...`:

- **Station scenarios** over TCP, TLS and with `k = w = 1`, against a station
  that serves the fixture of the interop suite (the one the reference
  clients are run against below): interrogation, counter interrogation and
  read value by value, every command type with and without time tag,
  select-before-operate, the refusals, file download, STARTDT/STOPDT, the
  idle test, reconnect, concurrent sessions, the event queue and redundancy
  on both sides.
- **Wire matrix**: every one of the 67 type identifications, in the variants
  the wire format distinguishes (time tags and their flags, SQ = 0 and
  SQ = 1, full APDUs, the P/N and test bits, raw private types), sent
  through both codecs and both protocol machines and compared field by
  field; again with the IEC 101 field sizes and a time zone other than UTC;
  and 40,000 frames each way to wrap the 15-bit sequence numbers.
- **Everything around a connection**: state callbacks, logs and metrics of
  both sides against each other; retries; session limit, accept filter and
  redundancy groups by address; event queue overflow; broadcast; requests
  that time out, are cancelled, collide or are pending when the station
  shuts down; a handler that panics; mutual TLS; unsolicited data amid
  requests; STOPDT in the middle of an event stream; a link that goes
  silent without closing, so that both sides find out by their timers.

Together they execute about 85% of the library's statements. The rest is
what two correct peers never do to each other (malformed frames, sequence
errors, protocol violations) and is covered by the scripted-peer tests of
`internal/link` and the codec tests.

## Interop tests

The `interop` package tests go-iec104 against three independent
implementations, [MZ Automation lib60870-C](https://github.com/mz-automation/lib60870),
[OpenMUC j60870](https://www.openmuc.org/iec-60870-5-104/) and
[wendy512/iec104](https://github.com/wendy512/iec104) on its engine go-iecp5,
packaged as container images by [otfabric/iec104-interop](https://github.com/otfabric/iec104-interop).

```sh
make interop    # needs Docker; about four minutes
```

| Direction | What is checked |
|-----------|-----------------|
| go-iec104 client → reference servers | File download with the content the fixture defines. Interrogation, counter interrogation and read return the fixture value by value; every command type with and without time tag, select-before-operate and deactivation; refusals (unknown type, cause, common address, object); STARTDT/STOPDT cycles; `k = w = 1`; the idle test in both directions; reconnect after a station restart; concurrent sessions; a redundancy group across two stacks with failover and switchover |
| reference clients → go-iec104 server | 34 scenarios per client, file download among them. Each must have the outcome the standard prescribes, and the client's complete result (every ASDU, in order, field by field) must equal what it gets from the reference server of its own stack; an event queue delivered and acknowledged |

The images are the only thing shared with iec104-interop; nothing of it is
cloned or built here. Scenarios, expected values and assertions live in this
repository.

This version is qualified against
[iec104-interop v0.2.0](https://github.com/otfabric/iec104-interop/releases/tag/v0.2.0)
(lib60870-C v2.4.1, j60870 1.7.2, wendy512/iec104 v1.0.4 on go-iecp5
v1.2.6). The three images are pinned by digest in `interop/harness.go`, the
Makefile and the Interop workflow, which runs on every push and pull
request. To test against another build, set `IEC104_INTEROP_LIB60870_IMAGE`,
`IEC104_INTEROP_OPENMUC_IMAGE` or `IEC104_INTEROP_WENDY512_IMAGE`; to run
one stack only, `IEC104_INTEROP_ADAPTERS=lib60870`.

The references do not all support the same. The suite asks each image what
it declares (`print-capabilities`) and skips, rather than fails, what an
image lacks:

| | lib60870-C | j60870 | wendy512/iec104 |
|---|:---:|:---:|:---:|
| Everything in the table above except the rows below | ✅ | ✅ | ✅ |
| Commands with time tag | ✅ | ✅ | — the stack drops them |
| File download, reference as server (`GetFile`) | ✅ | — no file server | — |
| File download, reference as client (`FileServer`) | ✅ | ✅ | — |

## Limitations

- **No IEC 62351-5 application-layer security.** Its type identifications
  are named and carried as raw payload, the procedures are not implemented;
  see [SECURITY.md](SECURITY.md#application-layer-security-iec-62351-5).
  Use TLS with client certificates.
- **File transfer** covers download, upload and the directory. Upload and
  the directory are verified by this repository's own tests only: no
  reference stack offers them through the interop images yet. File deletion
  and the query log have their types in the codec but no procedure.
- **The event queue is in memory.** It survives a control centre that is
  away, not a restart of the station.
- **Verified against three third-party stacks**, lib60870-C, j60870 and
  wendy512/iec104 (see [Interop tests](#interop-tests)); not against certified test equipment or
  field devices.

Details in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## License

MIT, see [LICENSE](LICENSE).
