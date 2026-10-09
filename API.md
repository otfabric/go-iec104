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
	ErrNotStarted     // data transfer stopped
	ErrConnectionLost // peer closed or transport failed
	ErrTimeout        // t1 expired; connection closed
	ErrProtocol       // peer violated the protocol; connection closed
	ErrBusy           // identical request or conflicting procedure pending
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
  sends STARTDT. It returns `ErrBusy` when already connected or connecting.
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
| `WithRequestTimeout(time.Duration)` | 10s | Bound for request methods when the context has no deadline; ≤ 0 disables |
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

- `Command` accepts `SingleCommand`, `DoubleCommand`, `StepCommand`,
  `SetpointNormalized`, `SetpointScaled`, `SetpointFloat` and
  `BitstringCommand`. A non-zero `Time` selects the CP56Time2a type.
- Collected ASDUs are also delivered to the `Handler`.
- Two requests with the same type, common address and object address cannot
  be pending at once (`ErrBusy`): their answers would be indistinguishable.

### Raw send

```go
func (c *Client) Send(ctx context.Context, a *asdu.ASDU) error
```

Transmits one ASDU and does not wait for an answer. Blocks while the send
window is full. For parameters, file transfer, private types and anything
the request methods do not cover.

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

var ErrServerClosed error
```

- `ListenAndServe("")` listens on `:2404`, or `:19998` with `WithTLS`.
- `Serve` and `ListenAndServe` block and return `ErrServerClosed` after `Close`.
- `Broadcast` sends to every session whose data transfer is started and
  returns how many it reached; per-session errors are joined.
- A nil handler rejects everything with "unknown type identification".

### Options

| Option | Default | Effect |
|--------|---------|--------|
| `WithParams(apci.Params)` | `apci.DefaultParams()` | `k`, `w`, `t1`..`t3` |
| `WithASDUParams(asdu.Params)` | `asdu.IEC104` | ASDU layout and time zone of time tags |
| `WithCommonAddrs(...asdu.CommonAddr)` | all | Stations served; others get "unknown common address" (broadcast always passes) |
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

### Session

```go
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
- A failed `AppendEncode` returns the buffer unchanged.

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

The set is closed: the interface has unexported methods. Consume objects
with a type switch.

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
- A server handler may call any method of the library. A client handler may
  call `Send`, `State` and `Close`, but not the request methods (`Command`,
  `Interrogate`, `Read`, …): their answers are delivered by the goroutine
  the handler runs on, so they would only time out. Use another goroutine.
- A handler that blocks delays what follows on the same connection, including
  the answers other goroutines are waiting for in request methods. It does
  not delay acknowledgements or test frames: the protocol machine keeps
  running.
- State handlers run on the protocol path and must not block. The client's
  may call `State` and nothing else on the client.
- `asdu.ASDU` values passed to handlers are owned by the receiver; values
  passed to `Send` are not retained.
