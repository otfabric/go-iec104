# API Reference: otfabric/go-iec104

The public API by package. The godoc on [pkg.go.dev](https://pkg.go.dev/github.com/otfabric/go-iec104)
is the authoritative text for each symbol; this document is the map.

## Table of contents

- [Package `iec104`](#package-iec104)
- [Package `client`](#package-client)
- [Package `server`](#package-server)
- [Package `asdu`](#package-asdu)
- [Package `apci`](#package-apci)
- [Concurrency](#concurrency)

## Package `iec104`

`import iec104 "github.com/otfabric/go-iec104"`

What client and server share.

### Errors

```go
var (
	ErrClosed         // closed by the application
	ErrNotConnected   // client has no connection
	ErrConnectFailed  // Connect/Dial failed; wraps the cause
	ErrNotStarted     // data transfer stopped
	ErrConnectionLost // peer closed or transport failed
	ErrTimeout        // t1 expired; connection closed
	ErrProtocol       // peer violated the protocol; connection closed
	ErrBusy           // identical request or conflicting procedure pending
	ErrInHandler      // client request method called from inside a handler
	ErrInvalidOption  // option value a client or server cannot be built with
)

type NegativeError struct{ ASDU *asdu.ASDU }
func (e *NegativeError) Error() string
func (e *NegativeError) Cause() asdu.Cause
```

See [ERRORS.md](ERRORS.md).

### State

```go
type State uint8
const (
	StateDisconnected State = iota // no transport connection
	StateConnecting                // client is (re)establishing the connection
	StateStopped                   // connected, data transfer stopped (STOPDT)
	StateStarted                   // connected, data transfer started (STARTDT)
)
func (s State) String() string
```

### Logger and Metrics

```go
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}
func NewSlogLogger(h slog.Handler) Logger
func NewStdLogger(l *log.Logger) Logger
func NopLogger() Logger

type Metrics interface {
	OnConnect(remote net.Addr)
	OnDisconnect(remote net.Addr, err error)
	OnFrameSent(remote net.Addr, f apci.Frame, size int)
	OnFrameReceived(remote net.Addr, f apci.Frame, size int)
	OnDecodeError(remote net.Addr, err error)
}
type NopMetrics struct{} // embed to implement a subset

// Optional extensions, detected on the value given to WithMetrics.
type RequestMetrics interface { // client
	OnRequest(remote net.Addr, t asdu.TypeID, ca asdu.CommonAddr)
	OnRequestDone(remote net.Addr, t asdu.TypeID, ca asdu.CommonAddr, duration time.Duration, err error)
	OnRetry(remote net.Addr, t asdu.TypeID, ca asdu.CommonAddr, attempt int, err error)
}
type HandlerMetrics interface { // server
	OnHandled(remote net.Addr, t asdu.TypeID, cause asdu.Cause, duration time.Duration)
}

// Optional extensions of Logger; NewSlogLogger returns both.
type FieldLogger interface {
	Logger
	With(keysAndValues ...any) FieldLogger
	DebugKV(msg string, keysAndValues ...any)
	InfoKV(msg string, keysAndValues ...any)
	WarnKV(msg string, keysAndValues ...any)
	ErrorKV(msg string, keysAndValues ...any)
}
type ContextLogger interface {
	Logger
	DebugContext(ctx context.Context, msg string, keysAndValues ...any)
	InfoContext(ctx context.Context, msg string, keysAndValues ...any)
	WarnContext(ctx context.Context, msg string, keysAndValues ...any)
	ErrorContext(ctx context.Context, msg string, keysAndValues ...any)
}
func NewSlogFieldLogger(h slog.Handler) FieldLogger
```

See [OBSERVABILITY.md](OBSERVABILITY.md).

## Package `client`

`import "github.com/otfabric/go-iec104/client"`

The controlling station.

### Construction and lifecycle

```go
func New(addr string, opts ...Option) (*Client, error)
func Dial(ctx context.Context, addr string, opts ...Option) (*Client, error)

func (c *Client) Connect(ctx context.Context) error
func (c *Client) Close() error
func (c *Client) State() iec104.State
func (c *Client) Addr() string
```

- `addr` is `host:port`; a missing port becomes 2404, or 19998 with `WithTLS`.
- `Connect` dials (bounded by `ctx` and `t0`) and, unless `WithAutoStart(false)`,
  sends STARTDT. It returns `ErrBusy` when already connected or connecting and
  `ErrConnectFailed`, wrapping the cause, when the connection cannot be made.
- `Dial` is `New` + `Connect`.
- `Close` is idempotent, stops reconnecting and fails pending requests with
  `ErrClosed`. A closed client cannot be reused.

### Options

| Option | Default | Effect |
|--------|---------|--------|
| `WithParams(apci.Params)` | `apci.DefaultParams()` | `k`, `w`, `t0`..`t3`; zero fields take defaults, `T3: 0` disables the idle test |
| `WithASDUParams(asdu.Params)` | `asdu.IEC104` | ASDU layout and time zone of time tags |
| `WithOriginator(uint8)` | 0 | Originator address in requests built by the client |
| `WithHandler(Handler)` | none | Receiver of every ASDU from the station |
| `WithStateHandler(func(iec104.State, error))` | none | Connection state changes, with the reason |
| `WithAutoStart(bool)` | true | Send STARTDT on connect and reconnect |
| `WithReconnect(Reconnect)` | off | Re-dial after a loss; `MinDelay` 1s, `MaxDelay` 30s, exponential |
| `WithRetry(Retry)` | off | Repeat idempotent requests on transient failure; `Attempts` 3, `Backoff` 500ms doubling up to `MaxBackoff` 10s |
| `WithStartHandler(func(context.Context, *Client))` | none | Runs on its own goroutine after every connect and reconnect that started data transfer |
| `WithSwitchHandler(func(*Client))` | none | `Group` only: the active connection changed |
| `WithRequestTimeout(time.Duration)` | 10s | Bound for request methods when the context has no deadline, and for every attempt with `WithRetry`; ≤ 0 disables |
| `WithTLS(*tls.Config)` | none | TLS on top of the dialled connection |
| `WithDialer(Dialer)` | `net.Dialer` | Custom transport |
| `WithLogger(iec104.Logger)` | silent | Logging |
| `WithMetrics(iec104.Metrics)` | none | Metrics callbacks |

```go
type Handler interface{ HandleASDU(a *asdu.ASDU) }
type HandlerFunc func(a *asdu.ASDU)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Reconnect struct{ MinDelay, MaxDelay time.Duration }

type Retry struct {
	Attempts   int           // total attempts, default 3
	Backoff    time.Duration // before the second attempt, doubling; default 500ms
	MaxBackoff time.Duration // default 10s
}
```

### Link control

```go
func (c *Client) StartDT(ctx context.Context) error  // STARTDT act → con
func (c *Client) StopDT(ctx context.Context) error   // STOPDT act → con
func (c *Client) TestLink(ctx context.Context) error // TESTFR act → con
```

### Application functions

Each sends a request and blocks until the station answers. A refusal is a
`*iec104.NegativeError`.

```go
func (c *Client) Interrogate(ctx context.Context, ca asdu.CommonAddr, qoi asdu.QOI) ([]*asdu.ASDU, error)
func (c *Client) CounterInterrogate(ctx context.Context, ca asdu.CommonAddr, request, freeze uint8) ([]*asdu.ASDU, error)
func (c *Client) Read(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) (*asdu.ASDU, error)
func (c *Client) ClockSync(ctx context.Context, ca asdu.CommonAddr, t time.Time) error
func (c *Client) Command(ctx context.Context, ca asdu.CommonAddr, obj asdu.InformationObject) error
func (c *Client) Deactivate(ctx context.Context, ca asdu.CommonAddr, obj asdu.InformationObject) error
func (c *Client) TestCommand(ctx context.Context, ca asdu.CommonAddr) error
func (c *Client) ResetProcess(ctx context.Context, ca asdu.CommonAddr, qualifier uint8) error
func (c *Client) GetFile(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) ([]byte, error)
func (c *Client) PutFile(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, sections ...[]byte) error
func (c *Client) ListFiles(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) ([]asdu.FileDirectoryEntry, error)
```

| Method | Sends | Returns when |
|--------|-------|--------------|
| `Interrogate` | `C_IC_NA_1` activation | activation termination; result is the data with the matching "interrogated by …" cause |
| `CounterInterrogate` | `C_CI_NA_1` activation | activation termination; result is the counters with the matching "requested by … counter request" cause |
| `Read` | `C_RD_NA_1` request | the ASDU with cause "request" containing the address |
| `ClockSync` | `C_CS_NA_1` activation | activation confirmation |
| `Command` | process command, activation | activation confirmation |
| `Deactivate` | process command, deactivation | deactivation confirmation |
| `TestCommand` | `C_TS_TA_1` activation | activation confirmation |
| `ResetProcess` | `C_RP_NA_1` activation | activation confirmation |
| `GetFile` | `F_SC_NA_1` select, then the calls and acknowledgements of the procedure | the file is acknowledged; result is its content |
| `PutFile` | `F_FR_NA_1` file ready, then the sections, segments and checksums the station calls for | the station acknowledged the file |
| `ListFiles` | `F_SC_NA_1` with cause "request" | the entry marked as the last of the directory; result is the entries |

- `Command` accepts `SingleCommand`, `DoubleCommand`, `StepCommand`,
  `SetpointNormalized`, `SetpointScaled`, `SetpointFloat` and
  `BitstringCommand`. A non-zero `Time` selects the CP56Time2a type.
- Collected ASDUs are also delivered to the `Handler`.
- Two requests with the same type, common address and object address cannot
  be pending at once (`ErrBusy`): their answers would be indistinguishable.
- A request that is waiting when data transfer stops (`StopDT`, or a
  switchover of a group) fails with `ErrNotStarted`: the station cannot
  answer it any more. What the station sent before it confirmed the stop is
  delivered first.
- `GetFile` downloads a file (file transfer in monitor direction): select,
  call, then section by section, checking the length and checksum of every
  section and of the file and acknowledging them. A file the station refuses
  is a `*iec104.NegativeError`; a length or checksum that does not match is
  acknowledged negatively and returned as `ErrProtocol`. The request timeout
  bounds each wait for the station, the context the whole transfer. It is
  never retried.
- `PutFile` delivers a file (file transfer in control direction): each
  argument after the name is one section, sent in segments of up to 236
  octets. A station that refuses the file, or answers a section or the file
  with a negative acknowledgement, is a `*iec104.NegativeError`. Timeouts as
  for `GetFile`; never retried.
- `ListFiles` calls the directory at `ioa` (0: the station's default one)
  and collects `F_DR_TA_1` entries until the one with
  `asdu.FileLastOfDirectory`. It only reads and is retried under `WithRetry`.

### Retries

With `WithRetry` a request that only reads is repeated when it failed for a
transient reason:

| | |
|---|---|
| Retried | `Interrogate`, `CounterInterrogate` with `asdu.FreezeRead`, `Read`, `TestCommand` |
| Never retried | `Command`, `Deactivate`, `ClockSync`, `ResetProcess`, `CounterInterrogate` with a freeze or reset, `Send` |
| Repeated on | `ErrNotConnected`, `ErrNotStarted`, `ErrConnectionLost`, `ErrTimeout`, `ErrProtocol`, an attempt that ran into the request timeout |
| Not repeated on | `*NegativeError`, `ErrBusy`, `ErrInHandler`, `ErrClosed`, encode errors, the caller's context ending |

Each attempt is bounded by the request timeout, the whole call by the
caller's context. See [ERRORS.md](ERRORS.md#retries).

### Raw send

```go
func (c *Client) Send(ctx context.Context, a *asdu.ASDU) error
```

Transmits one ASDU and does not wait for an answer. Blocks while the send
window is full. For parameters, private types, file deletion and anything
else the request methods leave out.

### Redundancy group

```go
func NewGroup(addrs []string, opts ...Option) (*Group, error)

func (g *Group) Connect(ctx context.Context) error
func (g *Group) Close() error
func (g *Group) Active() *Client   // nil when no connection is started
func (g *Group) Clients() []*Client
func (g *Group) Switchover(ctx context.Context) error

// On the active connection; ErrNotConnected when there is none:
func (g *Group) Interrogate(...)        func (g *Group) CounterInterrogate(...)
func (g *Group) Read(...)               func (g *Group) ClockSync(...)
func (g *Group) Command(...)            func (g *Group) Deactivate(...)
func (g *Group) TestCommand(...)        func (g *Group) ResetProcess(...)
func (g *Group) Send(...)
```

A `Group` is IEC 60870-5-104's alternative to a connection pool: several
connections to one station, exactly one with data transfer started, the
others established in STOPDT and supervised by test frames.

- `Connect` returns when one connection is started; the others, and any
  connection lost later, are (re-)established in the background.
- Data transfer starts on the first connection that becomes established.
  When the active one is lost, another established one is started and
  `WithSwitchHandler` is called.
- A path that returns becomes a standby. `Switchover` moves data transfer to
  the next standby (STOPDT on one, STARTDT on the other) and fails with
  `ErrNotConnected`, leaving the active connection alone, when there is none.
- Options apply to every connection. The group controls `WithAutoStart` and
  always reconnects. `WithStartHandler` is not used by a group; use
  `WithSwitchHandler`.
- A select and its execute must use the same connection: select again after
  a switchover.

## Package `server`

`import "github.com/otfabric/go-iec104/server"`

The controlled station.

### Server

```go
func New(h Handler, opts ...Option) (*Server, error)

func (s *Server) ListenAndServe(addr string) error
func (s *Server) Serve(ln net.Listener) error
func (s *Server) Close() error
func (s *Server) Addr() net.Addr
func (s *Server) Sessions() []*Session
func (s *Server) Broadcast(ctx context.Context, a *asdu.ASDU) (int, error)
func (s *Server) Enqueue(a *asdu.ASDU) error
func (s *Server) Pending(group string) int
func (s *Server) Dropped(group string) uint64

var ErrServerClosed error
```

- `ListenAndServe("")` listens on `:2404`, or `:19998` with `WithTLS`.
- `Serve` and `ListenAndServe` block and return `ErrServerClosed` after `Close`.
- `Broadcast` sends to every session whose data transfer is started and
  returns how many it reached; per-session errors are joined.
- A nil handler rejects everything with "unknown type identification".
- `Enqueue` queues an event for every redundancy group and never blocks; see
  [Redundancy groups and the event queue](#redundancy-groups-and-the-event-queue).

### Options

| Option | Default | Effect |
|--------|---------|--------|
| `WithParams(apci.Params)` | `apci.DefaultParams()` | `k`, `w`, `t1`..`t3` |
| `WithASDUParams(asdu.Params)` | `asdu.IEC104` | ASDU layout and time zone of time tags |
| `WithCommonAddrs(...asdu.CommonAddr)` | all | Stations served; others get "unknown common address" (broadcast always passes) |
| `WithRedundancyGroups(...RedundancyGroup)` | one group `default` for every client | Which clients form a redundancy group; a client no group allows is turned away |
| `WithEventQueue(int)` | 1024 | Events buffered per redundancy group; the oldest is dropped when full |
| `WithMaxSessions(int)` | unlimited | Close connections beyond the limit on accept |
| `WithAccept(func(net.Addr) bool)` | all | Filter connections before any exchange |
| `WithStateHandler(func(*Session, iec104.State, error))` | none | Session accepted / started / stopped / ended |
| `WithTLS(*tls.Config)` | none | TLS in `ListenAndServe` |
| `WithLogger(iec104.Logger)` | silent | Logging |
| `WithMetrics(iec104.Metrics)` | none | Metrics callbacks |

### Handler and Mux

```go
type Handler interface{ HandleASDU(s *Session, a *asdu.ASDU) }
type HandlerFunc func(s *Session, a *asdu.ASDU)

type Mux struct{ /* zero value is ready */ }
func NewMux() *Mux
func (m *Mux) Handle(h Handler, types ...asdu.TypeID)
func (m *Mux) HandleFunc(t asdu.TypeID, f func(s *Session, req *asdu.ASDU))
func (m *Mux) HandleASDU(s *Session, a *asdu.ASDU)

var ProcessCommands []asdu.TypeID // types 45..51 and 58..64
```

`Mux` rejects a type without a handler ("unknown type identification") and,
for system commands, process commands and parameters, a cause other than
activation or deactivation ("unknown cause of transmission"; `C_RD_NA_1`
requires "request"). File transfer and private types reach their handler
with any cause. `Handle(nil, t)` removes a registration.

### File server

```go
type File struct{ Sections [][]byte }
func NewFile(data []byte, sectionSize int) File
func (f File) Len() int

type FileSource interface {
    OpenFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (File, bool)
}
type FileSourceFunc func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (File, bool)

type FileSink interface {
    AcceptFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, length int) bool
    StoreFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, file File) error
}

type FileServer struct {
    Sink      FileSink
    Directory func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA) []asdu.FileDirectoryEntry
    OnDone    func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, err error)
}
func NewFileServer(source FileSource) *FileServer
func (f *FileServer) HandleASDU(s *Session, a *asdu.ASDU)

var FileTypes []asdu.TypeID // F_SC, F_AF, F_FR, F_SR, F_SG, F_LS
var ErrFileNotAcknowledged error
```

`FileServer` is a `Handler` for the file transfer services, the counterpart
of `Client.GetFile`, `PutFile` and `ListFiles`: it serves the files of its
`FileSource`, takes files into its `Sink` and answers directory calls with
`Directory`. Each of the three is optional (`NewFileServer(nil)` for a
station that only takes files); what is not set is refused.

```go
mux.Handle(server.NewFileServer(source), server.FileTypes...)
```

| Controlling station | `FileServer` answers |
|---------------------|----------------------|
| `F_SC_NA_1` select file | `F_FR_NA_1` with the length, or the mirrored call with "unknown information object address" when the source has no such file |
| `F_SC_NA_1` request file | `F_SR_NA_1` for section 1 |
| `F_SC_NA_1` request section | the section in `F_SG_NA_1` segments of up to 236 octets, then `F_LS_NA_1` (last segment) with its checksum |
| `F_AF_NA_1` section acknowledged | `F_SR_NA_1` for the next section, or `F_LS_NA_1` (last section) with the checksum of the file |
| `F_AF_NA_1` file acknowledged | nothing: the transfer is complete |

- `NewFile` splits content into sections; a `FileSource` may also return
  sections of its own. A file has at most 254 sections and 16 MiB − 1.
- A session can transfer several files at once, one per address. Selecting
  an address again starts over. Transfers end with their session.
- `OnDone` reports the end of a transfer: `nil` once the file was
  acknowledged, `ErrFileNotAcknowledged` after a negative acknowledgement, a
  deactivation or a new selection.
- **Taking a file**: the station is sent `F_FR_NA_1` and asks `Sink.AcceptFile`.
  It then calls the file and each section (`F_SC_NA_1`), checks the length
  and checksum of every section and of the file, and calls `Sink.StoreFile`
  before it acknowledges the file. A mismatch, or an error from `StoreFile`,
  makes the acknowledgement negative.
- **Directory**: `F_SC_NA_1` with cause "request" is answered with the
  entries `Directory` returns, as `F_DR_TA_1` sequences with cause
  "request"; the last entry is marked `asdu.FileLastOfDirectory`. No entries
  refuse the call.
- A call or delivery out of order is refused with "unknown information
  object address". Deletion is not served: such a call is mirrored with the
  P/N bit set.

### Redundancy groups and the event queue

```go
type RedundancyGroup struct {
	Name  string
	Allow []string // IP addresses or prefixes; empty: any client not claimed by an earlier group
}
```

A redundancy group is the set of connections of one controlling station (or
of several that back each other up). At most one of them receives events at
a time: the one that started data transfer last.

`Server.Enqueue(a)` appends the event to the queue of every group. Per group:

- events are sent in order on the active connection, subject to its `k`
  window;
- an event stays in the queue until the controlling station acknowledges its
  I frame;
- with no started connection, events wait;
- when the active connection stops or is lost, what it had not acknowledged
  becomes pending again and is sent on the next active connection. A
  controlling station can therefore see an event twice across a switchover,
  and does not miss one;
- when a connection starts data transfer while another one of the group is
  active, it takes over;
- a full queue drops its oldest event; `Dropped` counts them.

`Pending(group)` is the number of events queued or awaiting acknowledgement.
`Broadcast` and `Session.Send` bypass the queue.

### Session

```go
func (s *Session) Group() string            // redundancy group
func (s *Session) ID() uint64
func (s *Session) RemoteAddr() net.Addr
func (s *Session) LocalAddr() net.Addr
func (s *Session) Conn() net.Conn           // e.g. to read the TLS peer certificate
func (s *Session) Context() context.Context // cancelled when the session ends
func (s *Session) Started() bool
func (s *Session) Err() error
func (s *Session) Close() error

func (s *Session) Send(ctx context.Context, a *asdu.ASDU) error
func (s *Session) Reply(req *asdu.ASDU, cause asdu.Cause, negative bool) error
func (s *Session) Confirm(req *asdu.ASDU) error   // activation/deactivation confirmation
func (s *Session) Negative(req *asdu.ASDU) error  // the same with P/N = 1
func (s *Session) Terminate(req *asdu.ASDU) error // activation termination
func (s *Session) Reject(req *asdu.ASDU, cause asdu.Cause) error // causes 44..47 with P/N = 1
```

`Send` fails with `ErrNotStarted` in STOPDT and blocks while the send window
is full. The reply helpers mirror `req` and send it under the session context.

## Package `asdu`

`import "github.com/otfabric/go-iec104/asdu"`

### ASDU

```go
type ASDU struct {
	Type       TypeID
	Sequence   bool   // SQ: one address, consecutive elements
	Cause      Cause
	Negative   bool   // P/N
	Test       bool   // T
	Originator uint8
	CommonAddr CommonAddr
	Objects    []InformationObject
	Raw        []byte // payload of a type without object model
	RawCount   int    // object count announced for Raw
}

func New(cause Cause, ca CommonAddr, objs ...InformationObject) *ASDU
func Decode(b []byte, p Params) (*ASDU, error)
func (a *ASDU) Encode(p Params) ([]byte, error)
func (a *ASDU) AppendEncode(b []byte, p Params) ([]byte, error)
func (a *ASDU) Reply(cause Cause, negative bool) *ASDU
func (a *ASDU) First() InformationObject
func (a *ASDU) Len() int
func (a *ASDU) String() string

func TypeOf(obj InformationObject) TypeID
```

- `New` takes the type from the first object via `TypeOf`: the variant
  without time tag when `Time` is zero, the CP56Time2a variant otherwise.
- `Decode` copies; the result does not alias the input.
- A failed `AppendEncode` returns the buffer unchanged. Encoding a nil
  `*ASDU` is an error (`ErrInvalidValue`), not a panic.

### Params

```go
type Params struct {
	CauseSize      int            // 1 or 2
	CommonAddrSize int            // 1 or 2
	IOASize        int            // 1, 2 or 3
	MaxSize        int            // 0 means 249
	Location       *time.Location // zone of time tags; nil means UTC
}
var IEC104 = Params{CauseSize: 2, CommonAddrSize: 2, IOASize: 3, MaxSize: 249}

func (p Params) Validate() error
func (p Params) In(loc *time.Location) Params
func (p Params) IsBroadcast(ca CommonAddr) bool
```

### Identifiers

```go
type TypeID uint8      // M_SP_NA_1 … F_SC_NB_1
func (t TypeID) String() string        // "M_ME_NC_1"
func (t TypeID) Description() string   // "Measured value, short floating point"
func (t TypeID) Supported() bool       // has an object model
func (t TypeID) HasTimeTag() bool
func (t TypeID) InControlDirection() bool
func (t TypeID) IsProcessCommand() bool
func (t TypeID) IsFileTransfer() bool
func (t TypeID) IsPrivate() bool

type Cause uint8       // CausePeriodic … CauseUnknownIOA
func (c Cause) String() string
func (c Cause) IsUnknown() bool        // 44..47

type IOA uint32
type CommonAddr uint16
const Broadcast CommonAddr = 0xFFFF
```

### Information objects

Every object is a struct with an `IOA` field, used by value, implementing
`InformationObject` (`Address() IOA`). Objects that can carry a time tag have
a `Time Timestamp` field.

| Struct | Fields besides `IOA` | Types |
|--------|----------------------|-------|
| `SinglePoint` | `Value bool`, `Quality`, `Time` | 1, 2, 30 |
| `DoublePoint` | `Value DoubleState`, `Quality`, `Time` | 3, 4, 31 |
| `StepPosition` | `Value int8` (-64..63), `Transient bool`, `Quality`, `Time` | 5, 6, 32 |
| `Bitstring32` | `Value uint32`, `Quality`, `Time` | 7, 8, 33 |
| `MeasuredNormalized` | `Value Normalized`, `Quality`, `Time` | 9, 10, 21, 34 |
| `MeasuredScaled` | `Value int16`, `Quality`, `Time` | 11, 12, 35 |
| `MeasuredFloat` | `Value float32`, `Quality`, `Time` | 13, 14, 36 |
| `IntegratedTotal` | `Value int32`, `Sequence uint8`, `Carry`, `Adjusted`, `Invalid bool`, `Time` | 15, 16, 37 |
| `ProtectionEvent` | `State DoubleState`, `Quality`, `Elapsed uint16`, `Time` | 17, 38 |
| `ProtectionStart` | `Events uint8`, `Quality`, `Duration uint16`, `Time` | 18, 39 |
| `ProtectionOutput` | `Circuits uint8`, `Quality`, `Operating uint16`, `Time` | 19, 40 |
| `PackedSinglePoints` | `Status`, `Changed uint16`, `Quality` | 20 |
| `SingleCommand` | `Value bool`, `Qualifier CommandQualifier`, `Select bool`, `Time` | 45, 58 |
| `DoubleCommand` | `Value DoubleState`, `Qualifier`, `Select`, `Time` | 46, 59 |
| `StepCommand` | `Value StepDirection`, `Qualifier`, `Select`, `Time` | 47, 60 |
| `SetpointNormalized` | `Value Normalized`, `Qualifier uint8`, `Select`, `Time` | 48, 61 |
| `SetpointScaled` | `Value int16`, `Qualifier uint8`, `Select`, `Time` | 49, 62 |
| `SetpointFloat` | `Value float32`, `Qualifier uint8`, `Select`, `Time` | 50, 63 |
| `BitstringCommand` | `Value uint32`, `Time` | 51, 64 |
| `EndOfInitialization` | `Cause uint8`, `LocalChange bool` | 70 |
| `Interrogation` | `Qualifier QOI` | 100 |
| `CounterInterrogation` | `Request`, `Freeze uint8` | 101 |
| `Read` | | 102 |
| `ClockSync` | `Time` | 103 |
| `TestCommand` | `Counter uint16`, `Time` | 104, 107 |
| `ResetProcess` | `Qualifier uint8` | 105 |
| `DelayAcquisition` | `Delay uint16` | 106 |
| `ParameterNormalized` | `Value Normalized`, `Qualifier uint8` | 110 |
| `ParameterScaled` | `Value int16`, `Qualifier uint8` | 111 |
| `ParameterFloat` | `Value float32`, `Qualifier uint8` | 112 |
| `ParameterActivation` | `Qualifier uint8` | 113 |
| `FileReady` | `Name uint16`, `Length uint32`, `Qualifier uint8` | 120 |
| `SectionReady` | `Name uint16`, `Section uint8`, `Length uint32`, `Qualifier uint8` | 121 |
| `FileCall` | `Name uint16`, `Section uint8`, `Qualifier uint8` | 122 |
| `FileLastSegment` | `Name uint16`, `Section uint8`, `Qualifier uint8`, `Checksum uint8` | 123 |
| `FileAck` | `Name uint16`, `Section uint8`, `Qualifier uint8` | 124 |
| `FileSegment` | `Name uint16`, `Section uint8`, `Data []byte` | 125 |
| `FileDirectoryEntry` | `Name uint16`, `Length uint32`, `Status uint8`, `Time` | 126 |
| `FileQueryLog` | `Name uint16`, `Start`, `Stop Timestamp` | 127 |

The set is closed: the interface has unexported methods. Consume objects
with a type switch.

File transfer notes: an `F_SG_NA_1` ASDU carries exactly one `FileSegment`
of up to `MaxSegmentLength` (236) octets; a directory (`F_DR_TA_1`) is sent
with `ASDU.Sequence` set; lengths are 24 bit (`MaxFileLength`). The
qualifier constants are `FileSelect`…`SectionDeactivate` (SCQ),
`LastFile…`/`LastSection…` (LSQ), `AckFile…`/`AckSection…` (AFQ),
`FileNegative` (FRQ/SRQ) and `FileLastOfDirectory`, `FileIsDirectory`,
`FileActive` (SOF).

### Information elements

```go
type Quality uint8
const (
	QualityGood           Quality = 0
	QualityOverflow       Quality = 0x01 // OV
	QualityElapsedInvalid Quality = 0x08 // EI (protection events)
	QualityBlocked        Quality = 0x10 // BL
	QualitySubstituted    Quality = 0x20 // SB
	QualityNotTopical     Quality = 0x40 // NT
	QualityInvalid        Quality = 0x80 // IV
)
func (q Quality) Good() bool
func (q Quality) Has(f Quality) bool
func (q Quality) String() string // "NT|IV", "good"

type DoubleState uint8   // DoubleIntermediate, DoubleOff, DoubleOn, DoubleIndeterminate
type StepDirection uint8 // StepLower, StepHigher
type CommandQualifier uint8 // QualifierNone, QualifierShortPulse, QualifierLongPulse, QualifierPersistent

type Normalized int16
func (n Normalized) Float64() float64        // [-1, 1)
func NormalizedFromFloat(f float64) Normalized // clamps

type QOI uint8           // QOIStation, QOIGroup1 … QOIGroup16
func QOIGroup(n int) QOI
func (q QOI) Cause() Cause

type Timestamp struct {
	time.Time
	Invalid     bool // IV
	Substituted bool // GEN
	SummerTime  bool // SU (CP56Time2a)
}
func At(t time.Time) Timestamp
func Now() Timestamp
```

Constant groups: `CounterGroup1`…`CounterGeneral` and `FreezeRead`…
`FreezeResetOnly` (QCC), `InitLocalPowerOn`… (COI), `ResetProcessGeneral`,
`ResetPendingEvents` (QRP), `ParameterThreshold`… (QPM),
`ActivateLoadedParameters`… (QPA), `StartGeneral`… (SPE), `OutputGeneral`…
(OCI), `TestPattern` (FBP).

Time tag rules:

- Times are converted to and from `Params.Location` (UTC by default).
- CP56Time2a years are two digits: 70..99 → 1970..1999, 0..69 → 2000..2069.
- CP24Time2a carries minute, second and millisecond only; it decodes onto
  0001-01-01 00:mm:ss and the receiver supplies hour and date.
- A zero `Time` under a CP56Time2a type is sent flagged invalid; a received
  time that is not a real date decodes to the zero time flagged invalid.

## Package `apci`

`import "github.com/otfabric/go-iec104/apci"`

Framing and parameters. Applications normally need only `Params`.

```go
type Params struct {
	K, W           int
	T0, T1, T2, T3 time.Duration
}
func DefaultParams() Params            // 12, 8, 30s, 15s, 10s, 20s
func (p Params) WithDefaults() Params  // fills zero K, W, T0, T1, T2
func (p Params) Validate() error       // 1 ≤ W ≤ K ≤ 32767, T2 < T1, T3 ≥ 0

const DefaultPort, DefaultTLSPort = 2404, 19998
```

```go
type Format uint8 // FormatI, FormatS, FormatU
type UFunction uint8 // StartDTAct, StartDTCon, StopDTAct, StopDTCon, TestFRAct, TestFRCon
func (fn UFunction) Valid() bool
func (fn UFunction) IsAct() bool
func (fn UFunction) Confirmation() UFunction

type Frame struct {
	Format   Format
	SendSeq  uint16    // I
	RecvSeq  uint16    // I, S
	Function UFunction // U
	ASDU     []byte    // I
}
func NewI(sendSeq, recvSeq uint16, asdu []byte) Frame
func NewS(recvSeq uint16) Frame
func NewU(fn UFunction) Frame
func Parse(b []byte) (Frame, error)       // one whole APDU; ASDU aliases b
func ReadFrame(r io.Reader) (Frame, error) // reads exactly one APDU
func (f Frame) MarshalBinary() ([]byte, error)
func (f Frame) AppendBinary(b []byte) ([]byte, error)
func (f Frame) Len() int
func (f Frame) String() string // "I N(S)=2 N(R)=300 len=10"

const StartByte, MaxAPDULength, MaxASDULength, MaxFrameLength = 0x68, 253, 249, 255
const SeqModulus = 1 << 15
func SeqNext(n uint16) uint16
func SeqDiff(a, b uint16) int
func SeqAcks(nr, ack, next uint16) (n int, ok bool)
```

Errors: `ErrInvalidStart`, `ErrInvalidLength`, `ErrInvalidControl`,
`ErrASDUTooLong`, `ErrInvalidParams`.

## Concurrency

- Every method of `Client`, `Server`, `Session` and `Mux` is safe for
  concurrent use.
- A client `Handler` runs on one goroutine per connection; a server
  `Handler` on one goroutine per session. ASDUs arrive in wire order.
- A server handler may call any method of the library, `Session.Close` and
  `Server.Close` included. For one session the `Handler` and the state
  handler run on the same goroutine, in protocol order.
- A client `Handler` and state handler may call `Send`, `State`, `StartDT`,
  `StopDT`, `Connect` and `Close`. The request methods (`Command`,
  `Interrogate`, `Read`, `GetFile`, …) fail there at once with
  `iec104.ErrInHandler`: their answers are delivered by the goroutine the
  callback is holding. Use another goroutine.
- State notifications are delivered one at a time and in order, on either
  side. A closed client reports "disconnected" once, as the last thing.
- A handler that blocks delays what follows on the same connection, including
  the answers other goroutines are waiting for in request methods. It does
  not delay acknowledgements or test frames: the protocol machine keeps
  running.
- `Close` (`Client`, `Group`, `Session`, `Server`) returns when the last
  callback has returned and none follows; concurrent callers all wait for
  that. `Client.Close` first gives the `Handler` what the connection had
  already received and acknowledged. Called from inside a callback, `Close`
  cannot wait for it: it returns at once, the `Handler` is not called again,
  and the close completes when the callback returns.
- A start handler (`WithStartHandler`) runs on its own goroutine and may call
  any method. A switch handler (`WithSwitchHandler`) is called one call at a
  time, in order, and may call the group, `Switchover` and `Close` included.
- `asdu.ASDU` values passed to handlers are owned by the receiver; values
  passed to `Send` are not retained.
