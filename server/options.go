// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"net"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/sec"
)

// Option configures a [Server].
type Option func(*options)

type options struct {
	params      apci.Params
	asduParams  asdu.Params
	tls         *tls.Config
	logger      iec104.Logger
	metrics     iec104.Metrics
	maxSessions int
	groups      []RedundancyGroup
	queueSize   int
	commonAddrs map[asdu.CommonAddr]struct{}
	accept      func(remote net.Addr) bool
	onState     func(s *Session, state iec104.State, err error)
	security    func(group string, aim uint16) (*sec.Endpoint, error)
}

func defaultOptions() options {
	return options{params: apci.DefaultParams(), asduParams: asdu.IEC104}
}

// WithParams sets the protocol parameters k, w and t1..t3; t0 bounds the TLS
// handshake of an accepted connection. Zero K, W, T1 and T2 take their defaults; a zero T3
// disables the idle test. The values must match the configuration of the
// controlling stations.
func WithParams(p apci.Params) Option {
	return func(o *options) { o.params = p.WithDefaults() }
}

// WithASDUParams overrides the ASDU layout. IEC 60870-5-104 fixes it to
// [asdu.IEC104], so this is only needed for non-conformant peers or to set
// the time zone of time tags with [asdu.Params.In].
func WithASDUParams(p asdu.Params) Option {
	return func(o *options) { o.asduParams = p }
}

// WithTLS makes [Server.ListenAndServe] accept TLS connections, as profiled
// by IEC 62351-3. Set cfg.ClientAuth to tls.RequireAndVerifyClientCert to
// authenticate controlling stations. It has no effect on [Server.Serve],
// which uses the listener it is given.
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) { o.tls = cfg }
}

// WithLogger sets the logger. Nil, the default, disables logging.
func WithLogger(l iec104.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithMetrics sets the metrics callbacks. Nil, the default, disables them.
func WithMetrics(m iec104.Metrics) Option {
	return func(o *options) { o.metrics = m }
}

// WithMaxSessions limits the number of simultaneous connections. Further
// connections are closed immediately after accept. Zero, the default,
// means no limit.
func WithMaxSessions(n int) Option {
	return func(o *options) { o.maxSessions = n }
}

// WithCommonAddrs declares the common addresses this station answers to.
// An ASDU for any other address, except the broadcast address, is rejected
// with cause "unknown common address" before it reaches the [Handler].
// Without this option every common address is passed to the handler.
func WithCommonAddrs(addrs ...asdu.CommonAddr) Option {
	return func(o *options) {
		o.commonAddrs = make(map[asdu.CommonAddr]struct{}, len(addrs))
		for _, ca := range addrs {
			o.commonAddrs[ca] = struct{}{}
		}
	}
}

// WithAccept installs a filter for incoming connections, for example an
// allow-list of controlling station addresses. A connection for which f
// returns false is closed before any protocol exchange.
func WithAccept(f func(remote net.Addr) bool) Option {
	return func(o *options) { o.accept = f }
}

// WithStateHandler registers a callback for session state changes:
// [iec104.StateStopped] when a connection is accepted and after STOPDT,
// [iec104.StateStarted] after STARTDT and [iec104.StateDisconnected] when
// the session ends, with err holding the reason (nil when the server
// closed it).
//
// For one session the callback and the [Handler] run on the same
// goroutine, in protocol order.
func WithStateHandler(f func(s *Session, state iec104.State, err error)) Option {
	return func(o *options) { o.onState = f }
}

// WithSecurity applies the application-layer security of IEC 62351-5
// (IEC TS 60870-5-7) to every connection.
//
// The station keeps one association per controlling station, which names
// itself by the AIM in every security message. newEndpoint makes the
// association when a controlling station is first heard in a redundancy
// group ("default" without [WithRedundancyGroups]); it must return an
// endpoint with the role sec.Controlled, or an error to refuse that AIM.
// Give each AIM a sec.Trust that accepts only that station's certificate
// (sec.Trust.Subjects or a pinned certificate), and the sec.Config.Roles
// it may exercise. The connections of one controlling station in a group
// (a client redundancy group) share its association, carried by the one
// with data transfer started; other controlling stations have their own.
// A connection is bound to an association by the first security message
// it carries; until then the station sends nothing on it.
//
// With security, an ASDU that is not protected is discarded, the
// [Handler] sees only the verified application data, and what the station
// sends waits until the controlling station has established a session. A
// request that the roles of the association do not permit is answered with
// a negative confirmation with cause [asdu.CauseNotAuthorized] before it
// reaches the Handler. Security can be combined with [WithTLS].
func WithSecurity(newEndpoint func(group string, aim uint16) (*sec.Endpoint, error)) Option {
	return func(o *options) { o.security = newEndpoint }
}
