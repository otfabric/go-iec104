// SPDX-License-Identifier: MIT

package iec104

import (
	"net"

	"github.com/otfabric/go-iec104/apci"
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
