# Observability: otfabric/go-iec104

Logging and metrics for the client and the server. Both are off by default
and cost nothing when off.

## Logging (silent by default)

`client.WithLogger` and `server.WithLogger` accept an `iec104.Logger`:

```go
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}
```

| Level | What is logged |
|-------|----------------|
| Debug | Every APDU sent (`->`) and received (`<-`), connections closed by either side |
| Info | Client state changes, server listening, sessions connected and ended |
| Warn | Connections ended by `t1` or a protocol violation, undecodable ASDUs, refused connections, failed reconnect attempts |
| Error | A panic in a server handler, with stack |

Adapters: `iec104.NewSlogLogger(handler)` for `log/slog` (messages are only
formatted when the handler is enabled for the level),
`iec104.NewStdLogger(logger)` for the standard `log` package and
`iec104.NopLogger()`.

```go
logger := iec104.NewSlogLogger(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelDebug,
}))
c, err := client.Dial(ctx, addr, client.WithLogger(logger))
```

```text
level=DEBUG msg="iec104 client 10.0.0.5:2404: -> U STARTDT act"
level=DEBUG msg="iec104 client 10.0.0.5:2404: <- U STARTDT con"
level=INFO  msg="iec104 client 10.0.0.5:2404: started"
level=DEBUG msg="iec104 client 10.0.0.5:2404: -> I N(S)=0 N(R)=0 len=10"
```

Log calls are made synchronously on the protocol path. Keep implementations
non-blocking.

## Metrics

`client.WithMetrics` and `server.WithMetrics` accept an `iec104.Metrics`:

```go
type Metrics interface {
	OnConnect(remote net.Addr)
	OnDisconnect(remote net.Addr, err error)
	OnFrameSent(remote net.Addr, f apci.Frame, size int)
	OnFrameReceived(remote net.Addr, f apci.Frame, size int)
	OnDecodeError(remote net.Addr, err error)
}
```

| Callback | When | Useful for |
|----------|------|------------|
| `OnConnect` | A transport connection is established (client: each successful dial; server: each accepted session) | Connection counts, reconnect rate |
| `OnDisconnect` | A connection ends; `err` is nil when the local application closed it | Classifying losses with `errors.Is` (`ErrTimeout`, `ErrProtocol`, `ErrConnectionLost`) |
| `OnFrameSent` / `OnFrameReceived` | Every APDU; `f.Format` distinguishes I, S and U, `f.Function` the U function | Throughput, TESTFR activity, bytes on the wire |
| `OnDecodeError` | A received ASDU did not decode and was dropped | Detecting a peer with a different ASDU layout |

Embed `iec104.NopMetrics` to implement only what you need:

```go
type counters struct {
	iec104.NopMetrics
	iFrames atomic.Int64
}

func (c *counters) OnFrameReceived(_ net.Addr, f apci.Frame, _ int) {
	if f.Format == apci.FormatI {
		c.iFrames.Add(1)
	}
}
```

The callbacks run synchronously on the protocol path, from several goroutines
on a server. They must be safe for concurrent use and must not block.

`f.ASDU` in the frame callbacks is memory the library still uses: do not
modify it.

## Connection state

State is observable without logs or metrics:

- `Client.State()` and `client.WithStateHandler` on the client
- `Server.Sessions()`, `Session.Started()`, `Session.Err()` and
  `server.WithStateHandler` on the server

See [ERRORS.md](ERRORS.md#connection-fatal-errors) for the errors the state
handlers receive.
