# Examples

Runnable programs to start from. Each is one `main.go` that uses only the
public API.

The first seven are self-contained: they start a station and a controlling
station in one process, connected over TCP on loopback, so `go run` shows
the whole exchange and there is nothing to set up.

| Example | Shows | Run |
|---------|-------|-----|
| [quickstart](quickstart/main.go) | The smallest complete station and client: a `Mux`, an interrogation handler, `Dial`, `Interrogate` | `go run ./examples/quickstart` |
| [commands](commands/main.go) | Direct execution, select-before-operate, cancelling a selection, a set point with time tag, refusals and how they surface as `NegativeError` | `go run ./examples/commands` |
| [files](files/main.go) | File transfer in both directions and the directory: `FileServer` with a source, a sink and a directory; `GetFile`, `PutFile`, `ListFiles` | `go run ./examples/files` |
| [events](events/main.go) | Reporting on the station's own initiative: the event queue (`Enqueue`, `Pending`), `Broadcast` for cyclic data, end of initialization from a state handler | `go run ./examples/events` |
| [redundancy](redundancy/main.go) | A redundancy group over two paths: one connection started, `Switchover`, automatic failover, the switch handler | `go run ./examples/redundancy` |
| [tls](tls/main.go) | TLS with certificates on both sides (IEC 62351-3): a station that only accepts its authority's control centres and reads who is calling | `go run ./examples/tls` |
| [observability](observability/main.go) | `slog` logging, state handlers and metrics on both sides; request timeout, retries, reconnect and the start handler | `go run ./examples/observability` |

The last two are a station and a controlling station as separate programs,
for trying the library against something else: another implementation, a
simulator, a device.

| Example | Shows | Run |
|---------|-------|-----|
| [server](server/main.go) | A station with single and double points, measurements, counters, a commandable switch and spontaneous updates | `go run ./examples/server -addr :2404` |
| [client](client/main.go) | Connect, interrogate, synchronize the clock, optionally operate a switch, then print what the station reports | `go run ./examples/client -addr 127.0.0.1:2404 -operate 6001` |

Both take `-debug` to log every APDU.

`make build` compiles all of them to `bin/example-<name>`; `make examples`
runs the self-contained ones, which is also how CI keeps them working.

## Where to go from each

- A station of your own: start from **quickstart**, add handlers per type
  identification as in **commands**, report changes as in **events**.
- A control centre of your own: **client** for the shape of the program,
  **observability** for the options a long-running one needs,
  **redundancy** when the station has two links.
- The API in full: [API.md](../API.md). What the library does and does not
  implement of the standard: [INTEROPERABILITY.md](../INTEROPERABILITY.md).
