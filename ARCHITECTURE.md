# Architecture: otfabric/go-iec104

How the module is divided, why, and how a connection works inside.

## Layers

IEC 60870-5-104 is two things in one standard: a control protocol for
running a TCP connection (APCI) and the application data it carries (ASDU).

```text
                 IEC 60870-5-104
┌──────────────────────────────────────────────┐
│  ASDU   type identification, cause of        │  package asdu
│         transmission, common address,        │  (shared with IEC 60870-5-101)
│         information objects                  │
├──────────────────────────────────────────────┤
│  APCI   APDU framing, I/S/U frames,          │  package apci (codec)
│         sequence numbers, acknowledgements,  │  internal/link (state machine)
│         STARTDT / STOPDT / TESTFR            │
└──────────────────────────────────────────────┘
                      TCP (optionally TLS)
```

The packages follow the reuse boundaries rather than the picture:

- **APCI stays inside this module.** It has no life outside
  IEC 60870-5-104, so it is not a separate library. It is split into a pure
  codec (`apci`, exported, useful to analysers and test tools) and the state
  machine (`internal/link`, private, because its API is shaped by the client
  and the server and nothing else).
- **ASDU is the reusable part.** IEC 60870-5-101 carries the same ASDUs over
  a serial link layer with different field widths. `asdu` therefore knows
  nothing about TCP or APCI and takes the widths as `asdu.Params`.
- **TCP is the standard library.** The client accepts any `Dialer`, the
  server any `net.Listener`.

## Packages and import rules

```text
iec104 (root)      errors, State, Logger, Metrics
  ├── apci         frames, sequence arithmetic, Params          imports: nothing
  ├── asdu         ASDU model and codec                         imports: nothing
  ├── internal/link  connection state machine                   imports: root, apci
  ├── client       controlling station                          imports: root, apci, asdu, link
  └── server       controlled station                           imports: root, apci, asdu, link
```

- `apci` and `asdu` import nothing from the module and nothing outside the
  standard library. They do no I/O beyond `apci.ReadFrame(io.Reader)`.
- `internal/link` deals in raw ASDU bytes. It never imports `asdu`: the
  protocol machine is independent of what the I frames carry.
- `client` and `server` never import each other (their tests do, to use the
  other side as a peer).
- The root package imports `apci` and `asdu` only for the types in its
  `Metrics` and `NegativeError` signatures.

## One connection

Both stations run the same machine, `link.Link`, with a role flag. A link
owns an established `net.Conn` and three goroutines:

```text
           ┌────────┐  frames   ┌──────────────────────────┐  events  ┌────────────┐
 net.Conn ─► reader ├──────────►│ loop                     ├─────────►│ dispatcher ├─► callbacks
           └────────┘           │  owns V(S) V(R) ack      │  (queue) └────────────┘   OnASDU
                                │  unacked[], timers,      │                           OnState
 Send/StartDT/StopDT ──────────►│  STARTDT/STOPDT state    │                           OnClose
   (channels)                   │  performs every write    ├─► net.Conn
                                └──────────────────────────┘
```

- **The loop owns all protocol state** and is the only writer. There are no
  locks around sequence numbers or timers because nothing else touches them.
  `Send` and the U-frame procedures are requests on channels; the loop stops
  receiving from the send channel while `k` I frames are unacknowledged,
  which is what makes `Send` block.
- **One timer** is armed for the earliest deadline among `t1` (oldest
  unacknowledged I frame, each pending U activation), `t2` (first
  unacknowledged received I frame) and `t3` (idle).
- **The dispatcher decouples callbacks from the protocol.** A handler may
  take as long as it likes, and may call `Send`, without stalling
  acknowledgements or test frames. Events are delivered in order: an ASDU,
  a start/stop notification and the final close arrive exactly as they
  happened on the wire.
- **Receive flow control uses the protocol's own window.** When 256 events
  wait for the dispatcher the loop stops acknowledging received I frames,
  so the peer stops after `k` more. Frames are still read: the peer's
  acknowledgements keep arriving, which matters when the slow handler is
  itself blocked in `Send`. Only a peer that ignores its window (or has an
  enormous `k`) reaches the second limit, where the loop stops reading and
  TCP pushes back. Memory per connection is bounded either way.

### Conformance decisions

| Situation | Behaviour |
|-----------|-----------|
| I frame with unexpected N(S) | Close (`ErrProtocol`) |
| N(R) acknowledging frames never sent | Close (`ErrProtocol`) |
| I frame received while stopped | Close (`ErrProtocol`) |
| I frame received between STOPDT act and con | Accepted, acknowledged with the con |
| `t1` expires on an I frame or a U activation | Close (`ErrTimeout`) |
| `w` I frames received, or `t2` since the first | S frame |
| Own I frame sent | Counts as the acknowledgement; no S frame |
| `t3` without any received frame | TESTFR act, supervised by `t1` |
| STOPDT act received (server) | Pending acknowledgement, then STOPDT con |
| STARTDT/STOPDT act received by a client | Ignored with a warning |
| U confirmation nobody asked for | Ignored with a warning |

## Client

`client.Client` wraps at most one link and adds:

- **Connection lifecycle**: `Connect` dials (bounded by `t0`), starts the
  link and sends STARTDT. With `WithReconnect` a loop re-dials with
  exponential backoff after a loss.
- **Request matching**: IEC 60870-5-104 has no transaction identifier. An
  answer is recognised by type identification, common address, information
  object address and cause of transmission. Each request method registers an
  *exchange* (a matcher plus a queue), sends, and consumes what the matcher
  selects. Two identical requests would be indistinguishable, so the second
  fails with `ErrBusy`.
- **Delivery**: every ASDU goes to the `Handler`, whether an exchange took
  it or not. Request methods are a convenience on top of the stream, never a
  filter in front of it.

## Server

`server.Server` accepts connections and wraps each in a `Session`. A session
decodes received ASDUs, applies the common address filter and calls the
`Handler` on the session's dispatcher goroutine: one session is served
serially, sessions are served concurrently. `Mux` is a `Handler` that routes
by type identification and produces the negative answers of the standard for
what is not registered.

## Testing

| Layer | How it is tested |
|-------|------------------|
| `apci`, `asdu` | Byte vectors from the standard, round trips over every type identification, error tables, fuzzing (parse, re-encode, fixed point) |
| `internal/link` | A scripted peer writing raw APDUs over loopback TCP: windows, each timer, each violation |
| `client`, `server` | Against each other over loopback TCP, including TLS, reconnect and server restart |

Everything runs with the race detector.
