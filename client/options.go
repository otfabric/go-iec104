// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

// Handler receives the ASDUs the controlled station sends.
//
// HandleASDU is called from a single goroutine per connection, in the order
// the ASDUs arrived. A handler that blocks delays the delivery of everything
// that follows, including the answers other goroutines are waiting for.
//
// It may call [Client.Send], [Client.State] and [Client.Close]. It must not
// call the request methods ([Client.Command], [Client.Interrogate],
// [Client.Read] and the like): their answers are delivered by the very
// goroutine the handler is running on, so they would only time out. Start a
// goroutine for work that needs them.
type Handler interface {
	HandleASDU(a *asdu.ASDU)
}

// HandlerFunc adapts a function to a [Handler].
type HandlerFunc func(a *asdu.ASDU)

// HandleASDU calls f.
func (f HandlerFunc) HandleASDU(a *asdu.ASDU) { f(a) }

// Dialer establishes the transport connection. *net.Dialer and *tls.Dialer
// satisfy it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Reconnect configures automatic reconnection.
type Reconnect struct {
	// MinDelay is the delay before the first attempt after a connection
	// was lost. Default 1s.
	MinDelay time.Duration
	// MaxDelay caps the exponential backoff between attempts. Default 30s.
	MaxDelay time.Duration
}

// Option configures a [Client].
type Option func(*options)

type options struct {
	params     apci.Params
	asduParams asdu.Params
	originator uint8
	handler    Handler
	onState    func(iec104.State, error)
	logger     iec104.Logger
	metrics    iec104.Metrics
	dialer     Dialer
	tls        *tls.Config
	autoStart  bool
	reconnect  *Reconnect
	retry      *Retry
	onStart    func(ctx context.Context, c *Client)
	onSwitch   func(active *Client)
	stateTap   func() // Group: called after every state change
	// failpoint, when not nil, is called at named points inside the client
	// where a test wants to hold it: the windows between two steps that
	// belong together. Tests only.
	failpoint      func(name string)
	requestTimeout time.Duration
}

func defaultOptions() options {
	return options{
		params:         apci.DefaultParams(),
		asduParams:     asdu.IEC104,
		autoStart:      true,
		requestTimeout: 10 * time.Second,
	}
}

// WithParams sets the protocol parameters k, w and t0..t3. Zero K, W, T0,
// T1 and T2 take their defaults; a zero T3 disables the idle test. The
// values must match the configuration of the controlled station.
func WithParams(p apci.Params) Option {
	return func(o *options) { o.params = p.WithDefaults() }
}

// WithASDUParams overrides the ASDU layout. IEC 60870-5-104 fixes it to
// [asdu.IEC104], so this is only needed for non-conformant devices or to
// set the time zone of time tags with [asdu.Params.In].
func WithASDUParams(p asdu.Params) Option {
	return func(o *options) { o.asduParams = p }
}

// WithOriginator sets the originator address placed in ASDUs built by the
// client's request methods. Default 0.
func WithOriginator(oa uint8) Option {
	return func(o *options) { o.originator = oa }
}

// WithHandler sets the receiver of ASDUs. Without one, received ASDUs are
// only visible through the request methods that collect them.
func WithHandler(h Handler) Option {
	return func(o *options) { o.handler = h }
}

// WithStateHandler registers a callback for connection state changes. err
// is the reason when the state is [iec104.StateDisconnected] or a
// reconnect attempt failed, nil otherwise. Notifications are delivered one
// at a time, in order, and each state once: "disconnected" is the last
// thing a closed client reports.
//
// The callback may call the client, [Client.Close] included. It should
// return soon: the next notification waits for it, and so does a
// [Client.Close] called from another goroutine.
func WithStateHandler(f func(state iec104.State, err error)) Option {
	return func(o *options) { o.onState = f }
}

// WithLogger sets the logger. Nil, the default, disables logging.
func WithLogger(l iec104.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithMetrics sets the metrics callbacks. Nil, the default, disables them.
func WithMetrics(m iec104.Metrics) Option {
	return func(o *options) { o.metrics = m }
}

// WithDialer replaces the transport dialer, for example to bind a local
// address, go through a proxy or connect over an in-memory pipe in tests.
// When combined with [WithTLS] the TLS handshake runs on top of the
// connection the dialer returns.
func WithDialer(d Dialer) Option {
	return func(o *options) { o.dialer = d }
}

// WithTLS secures the connection with TLS as profiled by IEC 62351-3. The
// conventional port is [apci.DefaultTLSPort]. If cfg.ServerName is empty it
// is taken from the address.
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) { o.tls = cfg }
}

// WithAutoStart controls whether STARTDT is sent as part of connecting and
// reconnecting. Default true. Disable it for a redundant standby
// connection, which stays in STOPDT until [Client.StartDT] is called.
func WithAutoStart(enabled bool) Option {
	return func(o *options) { o.autoStart = enabled }
}

// WithReconnect enables automatic reconnection: when an established
// connection is lost, the client re-dials with exponential backoff until it
// succeeds or is closed. Requests issued while disconnected fail with
// [iec104.ErrNotConnected]. Zero fields of r take their defaults.
func WithReconnect(r Reconnect) Option {
	return func(o *options) {
		if r.MinDelay <= 0 {
			r.MinDelay = time.Second
		}
		if r.MaxDelay < r.MinDelay {
			r.MaxDelay = max(30*time.Second, r.MinDelay)
		}
		o.reconnect = &r
	}
}

// Retry configures automatic retries of idempotent requests.
type Retry struct {
	// Attempts is the total number of attempts, the first one included.
	// Default 3.
	Attempts int
	// Backoff is the delay before the second attempt; it doubles with
	// every further attempt. Default 500ms.
	Backoff time.Duration
	// MaxBackoff caps the delay. Default 10s.
	MaxBackoff time.Duration
}

// WithRetry makes the client repeat requests that are safe to repeat when
// they fail for a transient reason. Zero fields of r take their defaults.
//
// Retried: [Client.Interrogate], [Client.CounterInterrogate] with
// [asdu.FreezeRead], [Client.Read] and [Client.TestCommand]. They only read
// from the station.
//
// Never retried: [Client.Command], [Client.Deactivate], [Client.ClockSync],
// [Client.ResetProcess] and [Client.Send]. A command whose confirmation was
// lost may already have operated the process, and IEC 60870-5-104 has no way
// to ask; repeating it is the application's decision.
//
// A request is repeated when the connection was lost or is not established,
// or when the station did not answer within the request timeout. It is not
// repeated when the station refused it ([*iec104.NegativeError]), when an
// identical request is pending or when the caller's context ended. Combine
// with [WithReconnect]: the backoff gives the client time to come back.
//
// With retries enabled the request timeout bounds each attempt, also when
// the caller's context has a deadline; that deadline bounds the whole call.
func WithRetry(r Retry) Option {
	return func(o *options) {
		if r.Attempts <= 0 {
			r.Attempts = 3
		}
		if r.Backoff <= 0 {
			r.Backoff = 500 * time.Millisecond
		}
		if r.MaxBackoff < r.Backoff {
			r.MaxBackoff = max(10*time.Second, r.Backoff)
		}
		o.retry = &r
	}
}

// WithStartHandler registers a function that runs each time the client has
// established a connection and started data transfer on it: after
// [Client.Connect] and after every automatic reconnect. It is the place for
// what a controlling station does on a fresh connection, typically a general
// interrogation and a clock synchronization.
//
// f runs on its own goroutine and may call any method of the client. ctx is
// cancelled when that connection ends or the client is closed.
func WithStartHandler(f func(ctx context.Context, c *Client)) Option {
	return func(o *options) { o.onStart = f }
}

// WithSwitchHandler registers a callback of a [Group]: it is called when
// another connection of the group becomes the active one, with that
// connection's client, or with nil when no connection is available any more.
// Calls are made one at a time and in order. The callback may call the
// group, [Group.Switchover] and [Group.Close] included, and should return
// soon: the next call waits for it. A plain [Client] ignores the option.
func WithSwitchHandler(f func(active *Client)) Option {
	return func(o *options) { o.onSwitch = f }
}

// WithRequestTimeout bounds how long a request method waits for the
// confirmation or the data it asked for when its context has no deadline.
// Default 10s. Zero or negative disables the bound. With [WithRetry] it
// bounds every attempt, whatever the context.
func WithRequestTimeout(d time.Duration) Option {
	return func(o *options) { o.requestTimeout = d }
}
