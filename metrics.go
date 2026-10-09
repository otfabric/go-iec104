// SPDX-License-Identifier: MIT

package iec104

import (
	"net"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

// Metrics is an optional callback interface for observing connections and
// traffic of a client or a server. A nil Metrics disables collection.
//
// The methods are called synchronously on the protocol path, possibly from
// several goroutines at once; implementations must be safe for concurrent
// use and must not block (increment a counter, send on a buffered channel).
//
// Embed [NopMetrics] to implement only the callbacks you need and to stay
// compatible when methods are added.
type Metrics interface {
	// OnConnect is called when a transport connection is established.
	OnConnect(remote net.Addr)

	// OnDisconnect is called when a connection ends. err is nil when the
	// application closed it.
	OnDisconnect(remote net.Addr, err error)

	// OnFrameSent is called after an APDU was written. size is its length
	// on the wire in octets.
	OnFrameSent(remote net.Addr, f apci.Frame, size int)

	// OnFrameReceived is called for every APDU read from the peer.
	OnFrameReceived(remote net.Addr, f apci.Frame, size int)

	// OnDecodeError is called when a received ASDU could not be decoded
	// and was dropped.
	OnDecodeError(remote net.Addr, err error)
}

// NopMetrics is a [Metrics] that does nothing. Embed it in your own type.
type NopMetrics struct{}

// OnConnect does nothing.
func (NopMetrics) OnConnect(net.Addr) {}

// OnDisconnect does nothing.
func (NopMetrics) OnDisconnect(net.Addr, error) {}

// OnFrameSent does nothing.
func (NopMetrics) OnFrameSent(net.Addr, apci.Frame, int) {}

// OnFrameReceived does nothing.
func (NopMetrics) OnFrameReceived(net.Addr, apci.Frame, int) {}

// OnDecodeError does nothing.
func (NopMetrics) OnDecodeError(net.Addr, error) {}

// RequestMetrics is an optional extension of [Metrics] for a client. When
// the value given to client.WithMetrics also implements it, the client
// reports every request method call (Interrogate, Command, Read, ...).
//
// The callbacks are request-level: OnRequest fires once before the first
// attempt and OnRequestDone once with the final outcome, whose duration
// includes retries and their delays. OnRetry fires for each attempt that
// failed and will be repeated.
//
// remote is the address of the station, or nil while the client has never
// been connected. Implementations must be safe for concurrent use and must
// not block.
type RequestMetrics interface {
	// OnRequest is called before a request is sent.
	OnRequest(remote net.Addr, t asdu.TypeID, ca asdu.CommonAddr)

	// OnRequestDone is called with the final outcome. err is nil on
	// success; classify failures with errors.Is and errors.As
	// (*NegativeError, context.DeadlineExceeded, ErrConnectionLost, ...).
	OnRequestDone(remote net.Addr, t asdu.TypeID, ca asdu.CommonAddr, duration time.Duration, err error)

	// OnRetry is called when attempt (1 for the first) failed with err and
	// the request is about to be tried again.
	OnRetry(remote net.Addr, t asdu.TypeID, ca asdu.CommonAddr, attempt int, err error)
}

// HandlerMetrics is an optional extension of [Metrics] for a server. When
// the value given to server.WithMetrics also implements it, the server
// reports every ASDU it passed to the Handler and how long the handler took.
// Implementations must be safe for concurrent use and must not block.
type HandlerMetrics interface {
	// OnHandled is called after the handler returned, or panicked.
	OnHandled(remote net.Addr, t asdu.TypeID, cause asdu.Cause, duration time.Duration)
}
