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
	params        apci.Params
	asduParams    asdu.Params
	originator    uint8
	handler       Handler
	onState       func(iec104.State, error)
	logger        iec104.Logger
	metrics       iec104.Metrics
	dialer        Dialer
	tls           *tls.Config
	autoStart     bool
	reconnect     *Reconnect
	requestTimout time.Duration
}

func defaultOptions() options {
	return options{
		params:        apci.DefaultParams(),
		asduParams:    asdu.IEC104,
		autoStart:     true,
		requestTimout: 10 * time.Second,
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
// at a time, in order. The callback runs on the protocol path: it may call
// [Client.State] but must not block and must not call any other method of
// the client. Hand anything else to another goroutine.
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

// WithRequestTimeout bounds how long a request method waits for the
// confirmation or the data it asked for when its context has no deadline.
// Default 10s. Zero or negative disables the bound.
func WithRequestTimeout(d time.Duration) Option {
	return func(o *options) { o.requestTimout = d }
}
