// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"time"

	iec104 "github.com/otfabric/go-iec104"
)

// reconnectLoop re-establishes a lost connection with exponential backoff.
// It runs until a connection is established or the client is closed. The
// caller has set c.dialing and added to c.wg.
func (c *Client) reconnectLoop() {
	defer c.wg.Done()

	delay := c.opts.reconnect.MinDelay
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-c.closeCh:
		case <-timer.C:
		}

		var err error
		if !c.isClosed() {
			if err = c.connect(context.Background()); err == nil {
				return
			}
		}
		if c.isClosed() {
			c.mu.Lock()
			c.dialing = false
			c.mu.Unlock()
			c.setState(iec104.StateDisconnected, nil)
			return
		}
		// Still connecting: report the failed attempt.
		c.setState(iec104.StateConnecting, err)
		if c.opts.logger != nil {
			c.opts.logger.Warnf("iec104 client %s: reconnect failed, retrying in %s: %v", c.addr, delay, err)
		}
		delay = min(delay*2, c.opts.reconnect.MaxDelay)
		timer.Reset(delay)
	}
}
