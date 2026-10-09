# otfabric/go-iec104 - IEC 60870-5-104 Client and Server Library for Go

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
  not serve, spontaneous data to one or all control centres
- The complete **APCI** protocol machine on both sides: I/S/U frames, 15-bit
  sequence numbers, the `k`/`w` flow-control windows and the `t0`..`t3` timers
- An **ASDU** model and codec for 59 type identifications, independent of the
  transport and reusable for IEC 60870-5-101
- What production use needs: `context.Context` on every call, automatic
  reconnect, retries for the requests that are safe to repeat, redundancy
  groups with failover, structured logging, metrics hooks and TLS
  (IEC 62351-3)
- **Verified against third-party stacks**: every push runs the library, as
  client and as server, against MZ Automation lib60870-C and OpenMUC j60870

**Docs:** [API.md](API.md) (public API) · [ARCHITECTURE.md](ARCHITECTURE.md) (packages, goroutines, protocol machine) · [INTEROPERABILITY.md](INTEROPERABILITY.md) (what is implemented, clause by clause) · [ERRORS.md](ERRORS.md) (error semantics) · [OBSERVABILITY.md](OBSERVABILITY.md) (logging and metrics) · [SECURITY.md](SECURITY.md) · [RELEASE.md](RELEASE.md) (changelog)

## Table of contents

- [go-iec104 vs lib60870 and j60870](#go-iec104-vs-lib60870-and-j60870)
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

## go-iec104 vs lib60870 and j60870

go-iec104 is tested against two established implementations,
[MZ Automation lib60870-C](https://github.com/mz-automation/lib60870) and
[OpenMUC j60870](https://www.openmuc.org/iec-60870-5-104/) (see
[Interop tests](#interop-tests)). Both are good libraries; this table shows
where the three differ so you can pick the right one for your project.

| Capability | otfabric/go-iec104 | lib60870-C | j60870 |
|---|:---:|:---:|:---:|
| Language | Go | C | Java |
| License | MIT | GPL-3.0 or commercial | GPL-3.0 |
| IEC 60870-5-104 client (controlling station) | ✅ | ✅ | ✅ |
| IEC 60870-5-104 server (controlled station) | ✅ | ✅ | ✅ |
| IEC 60870-5-101 serial link layer | — (ASDU codec is 101-ready) | ✅ | — |
| Process information, commands, system types (1..40, 45..64, 70, 100..107) | ✅ | ✅ | ✅ |
| Parameter types (110..113) | ✅ | ✅ | ✅ |
| File transfer types (120..127) | raw payload | ✅ typed, with file server | ✅ typed |
| Private types (128..255) | raw payload | raw payload | custom decoder |
| Configurable `k`, `w`, `t0`..`t3` | ✅ | ✅ | ✅ |
| TLS (IEC 62351-3) | ✅ `crypto/tls` | ✅ mbedTLS | via socket factory |
| Blocking request methods (interrogate and collect, command and confirm) | ✅ | — callbacks | — callbacks |
| Server-side routing with standard refusals (unknown type, cause, address) | ✅ `Mux` | partly built in | unknown type only |
| Redundancy group, client side (failover, switchover) | ✅ `Group` | — | — |
| Redundancy groups, server side | — | ✅ | — |
| Server-side event queue for stopped or absent clients | — | ✅ | — |
| Automatic reconnect with back-off | ✅ | — | — |
| Automatic retries (read-only requests) | ✅ | — | — |
| Cancellation and deadlines per call | ✅ `context.Context` | — | — timeouts only |
| Structured logging | ✅ `log/slog` | — compile-time debug output | — (pluggable logger from 1.8.0) |
| Metrics hooks | ✅ | — raw message callback | — |
| Threadless / single-loop operation | — | ✅ | — |
| Dependencies | none | none (mbedTLS optional) | none |
| Cross-tested against other stacks in CI | ✅ against both | — not documented | — not documented |

✅ = available · — = not available or not documented. For lib60870-C v2.4.1
and j60870 1.7.2, the versions go-iec104 is tested against, from their
public sources and documentation as of October 2026. If you spot an
inaccuracy, please [open an issue](https://github.com/otfabric/go-iec104/issues)
and we will correct it.

**Choose go-iec104 if** you write Go and want client and server in one
library with no cgo and a permissive license, blocking calls with `context`
control, reconnect, retries, client-side redundancy and observability built
in.

**Choose lib60870-C if** you need IEC 60870-5-101 over serial lines, file
transfer, server-side redundancy groups and event queueing, or a C library
for embedded targets; it is the most complete of the three.

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
├── interop/                        tests against lib60870 and OpenMUC j60870
│                                   (build tag "interop", needs Docker)
└── examples/client, examples/server
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
address". Spontaneous data goes out with `Session.Send` or, to every control
centre whose data transfer is started, with `Server.Broadcast`.

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

Types without an object model (file transfer, the private range 128..255)
are not an error: they travel as `ASDU.Raw` in both directions.

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
| Peer closed or transport failed | `iec104.ErrConnectionLost` |
| No acknowledgement within `T1` | `iec104.ErrTimeout`; connection closed |
| Peer broke the protocol | `iec104.ErrProtocol`; connection closed |
| Value cannot be encoded | `asdu.ErrInvalidValue`, `asdu.ErrTypeMismatch`, … |

Full guide: **[ERRORS.md](ERRORS.md)**.

## Examples

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

## Interop tests

The `interop` package tests go-iec104 against two independent
implementations, [MZ Automation lib60870-C](https://github.com/mz-automation/lib60870)
and [OpenMUC j60870](https://www.openmuc.org/iec-60870-5-104/), packaged as
container images by [otfabric/iec104-interop](https://github.com/otfabric/iec104-interop).

```sh
make interop    # needs Docker; about two minutes
```

| Direction | What is checked |
|-----------|-----------------|
| go-iec104 client → reference servers | Interrogation, counter interrogation and read return the fixture value by value; every command type with and without time tag, select-before-operate and deactivation; refusals (unknown type, cause, common address, object); STARTDT/STOPDT cycles; `k = w = 1`; the idle test in both directions; reconnect after a station restart; concurrent sessions; a redundancy group across the two stacks with failover and switchover |
| reference clients → go-iec104 server | 30 scenarios per client. Each must have the outcome the standard prescribes, and the client's complete result (every ASDU, in order, field by field) must equal what it gets from the reference server of its own stack |

The images are the only thing shared with iec104-interop; nothing of it is
cloned or built here. Scenarios, expected values and assertions live in this
repository.

This version is qualified against
[iec104-interop v0.1.0](https://github.com/otfabric/iec104-interop/releases/tag/v0.1.0)
(lib60870-C v2.4.1, j60870 1.7.2). The two images are pinned by digest in
`interop/harness.go`, the Makefile and the Interop workflow, which runs on
every push and pull request. To test against another build, set
`IEC104_INTEROP_LIB60870_IMAGE` and `IEC104_INTEROP_OPENMUC_IMAGE`; to run
one stack only, `IEC104_INTEROP_ADAPTERS=lib60870`.

## Limitations

- **File transfer** (`F_*`, types 120..127) has no object model and no
  transfer state machine; the ASDUs pass through as raw payload.
- **Redundancy groups** are managed on the client side (`client.Group`). A
  server accepts several connections and each controls its own
  STARTDT/STOPDT, but it does not group them or enforce one started
  connection per group.
- **No event buffering**: `Server.Broadcast` skips sessions in STOPDT.
  Queueing events for a control centre that is away is left to the application.
- **Verified against two third-party stacks**, lib60870-C and j60870 (see
  [Interop tests](#interop-tests)); not against certified test equipment or
  field devices.

Details in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## License

MIT, see [LICENSE](LICENSE).
