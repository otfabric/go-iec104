# Errors: otfabric/go-iec104

How go-iec104 reports failures. For signatures see [API.md](API.md).

## Table of contents

- [Quick reference](#quick-reference)
- [Sentinels](#sentinels)
- [Negative answers (`NegativeError`)](#negative-answers-negativeerror)
- [Connection-fatal errors](#connection-fatal-errors)
- [Codec errors](#codec-errors)
- [Context and timeouts](#context-and-timeouts)
- [What is not an error](#what-is-not-an-error)
- [Detection patterns](#detection-patterns)

## Quick reference

| Situation | Error | Connection |
|-----------|-------|------------|
| Station answers with P/N = 1 or cause 44..47 | `*iec104.NegativeError` | stays up |
| Answer does not arrive before the deadline | wraps `context.DeadlineExceeded` | stays up |
| Request while the same one is pending | `iec104.ErrBusy` | stays up |
| Client has no connection | `iec104.ErrNotConnected` | - |
| Data transfer stopped (before STARTDT, after STOPDT) | `iec104.ErrNotStarted` | stays up |
| Operation after `Close` | `iec104.ErrClosed` | - |
| Peer closed, write or read failed | `iec104.ErrConnectionLost` | closed |
| I frame not acknowledged or U frame not confirmed within `t1` | `iec104.ErrTimeout` | closed |
| Malformed APDU, sequence error, I frame in STOPDT | `iec104.ErrProtocol` | closed |
| ASDU cannot be encoded | `asdu.Err…` | stays up |
| Invalid `apci.Params` / `asdu.Params` at construction | `apci.ErrInvalidParams` / `asdu.ErrInvalidParams` | - |

All sentinels are wrapped with detail. Always test with `errors.Is` and
`errors.As`, never with `==`.

## Sentinels

Defined in the root package and shared by client and server:

| Sentinel | Meaning |
|----------|---------|
| `ErrClosed` | The client, server or session was closed by the application |
| `ErrNotConnected` | The client has no established connection (never connected, or reconnecting) |
| `ErrNotStarted` | An ASDU was to be sent while data transfer is stopped |
| `ErrConnectionLost` | The peer closed the connection or the transport failed |
| `ErrTimeout` | `t1` expired; the connection was closed |
| `ErrProtocol` | The peer violated the protocol; the connection was closed |
| `ErrBusy` | An identical request, or a conflicting STARTDT/STOPDT, is in progress |

`server.ErrServerClosed` is what `Serve` and `ListenAndServe` return after
`Server.Close`. It is the normal way for them to end.

## Negative answers (`NegativeError`)

A controlled station refuses a request by mirroring it. The client request
methods turn both forms of refusal into `*iec104.NegativeError`:

| The station sends | `Cause()` | Typical reason |
|-------------------|-----------|----------------|
| Activation confirmation with P/N = 1 | `asdu.CauseActivationCon` | Interlocked, execute without select, value out of range |
| Deactivation confirmation with P/N = 1 | `asdu.CauseDeactivationCon` | Nothing to deactivate |
| Cause 44 | `asdu.CauseUnknownType` | Type identification not supported |
| Cause 45 | `asdu.CauseUnknownCause` | Cause of transmission not valid for the type |
| Cause 46 | `asdu.CauseUnknownCommonAddr` | No such station |
| Cause 47 | `asdu.CauseUnknownIOA` | No such information object |

`NegativeError.ASDU` is the station's answer in full. `Interrogate` and
`CounterInterrogate` return the ASDUs collected so far together with the
error.

## Connection-fatal errors

`ErrConnectionLost`, `ErrTimeout` and `ErrProtocol` end the connection. They
surface in three places:

- as the return value of a call that was in flight (`Send`, `StartDT`, a
  pending request)
- in the state handler: `client.WithStateHandler` receives
  `StateDisconnected` (or `StateConnecting` with `WithReconnect`) and the
  error; `server.WithStateHandler` receives `StateDisconnected` and the error
- from `Session.Err` on the server

With `client.WithReconnect` the client re-dials by itself; requests made in
the meantime fail with `ErrNotConnected`. A failed attempt is reported to the
state handler as `StateConnecting` with the dial error.

On the server, a session closed by `Session.Close` or `Server.Close` ends
with a nil error.

## Codec errors

Returned by `asdu.Encode`/`Decode` and by every method that encodes an ASDU
(`Client.Send`, `Client.Command`, `Session.Send`, `Server.Broadcast`):

| Sentinel | Meaning |
|----------|---------|
| `asdu.ErrInvalidValue` | A field does not fit: qualifier out of range, address wider than the field, more than 127 objects |
| `asdu.ErrTypeMismatch` | An object does not belong to the ASDU's type, or is not a command where one is required |
| `asdu.ErrUnsupportedType` | Typed objects under a type identification without an object model |
| `asdu.ErrNotSequential` | `Sequence` is set and the addresses are not consecutive |
| `asdu.ErrTooLong` | The encoded ASDU exceeds 249 octets (`Params.MaxSize`) |
| `asdu.ErrMalformed` | Decode: truncated header or payload size not matching the object count |
| `asdu.ErrInvalidParams` | The `Params` field sizes are not allowed |

`apci` has the framing counterparts: `ErrInvalidStart`, `ErrInvalidLength`,
`ErrInvalidControl`, `ErrASDUTooLong`. Received over a connection they are
wrapped in `iec104.ErrProtocol`.

An encode error never touches the connection: nothing was sent.

## Context and timeouts

- **Connect** is bounded by the context and by `t0`, whichever ends first.
- **Request methods** (`Command`, `Interrogate`, `Read`, …) wait for the
  station's answer. A context without deadline is bounded by
  `WithRequestTimeout` (default 10s); a context with a deadline is used as
  is. On expiry the error wraps `context.DeadlineExceeded`, the request slot
  is released and the connection stays up: IEC 60870-5-104 has no way to
  cancel a request, so a late answer still reaches the `Handler`.
- **Send** blocks only while the send window is full (`k` unacknowledged I
  frames). If the peer never acknowledges, `t1` closes the connection and
  `Send` returns that error.
- **StartDT/StopDT/TestLink** wait for the confirmation. If the context ends
  first the call returns, but the U frame stays outstanding and `t1` still
  applies to it.

## What is not an error

- **An unknown type identification** on receive decodes into `ASDU.Raw`.
- **A received ASDU that does not decode** is dropped and reported through
  `Metrics.OnDecodeError` and a warning; the connection stays up. The peer is
  not answered, because a mirror cannot be built from bytes that do not parse.
- **An invalid time tag** (a field out of range or a date that does not
  exist) decodes to the zero time with `Timestamp.Invalid` set.
- **Reserved bits** in quality descriptors and qualifiers are ignored on
  receive and sent as zero.
- **Unsolicited U-frame confirmations** are ignored.

## Detection patterns

```go
err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 6001, Value: true})

var neg *iec104.NegativeError
switch {
case err == nil:
	// confirmed
case errors.As(err, &neg):
	if neg.Cause() == asdu.CauseUnknownIOA {
		// no such object
	}
case errors.Is(err, context.DeadlineExceeded):
	// the station did not answer; the connection is still up
case errors.Is(err, iec104.ErrNotConnected), errors.Is(err, iec104.ErrConnectionLost):
	// no connection: retry after the state handler reports StateStarted
case errors.Is(err, asdu.ErrInvalidValue):
	// programming error: the command cannot be encoded
}
```
