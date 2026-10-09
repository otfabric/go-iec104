// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
)

// Group is a redundancy group in the sense of IEC 60870-5-104: several
// connections to one controlled station, of which exactly one has data
// transfer started. The others are established, stay in STOPDT and are
// supervised with test frames, ready to take over.
//
// This is what the protocol offers in place of a connection pool. An
// IEC 60870-5-104 connection is not an interchangeable request channel: the
// station sends its spontaneous data on the one started connection, and
// sequence numbers, acknowledgements and command procedures belong to it.
// Opening more connections does not add throughput; it adds availability.
//
// The group starts data transfer on the first connection that becomes
// established; when several are, on the one whose address comes first. When
// the active connection is lost it starts another one and re-establishes the
// lost one in the background as a standby. A path that returns does not take
// data transfer back by itself: see [Group.Switchover]. Every connection
// delivers to the same [Handler].
//
// The request methods act on the active connection and fail with
// [iec104.ErrNotConnected] when there is none. A Group is safe for
// concurrent use.
type Group struct {
	clients        []*Client
	dialing        []atomic.Bool
	onSwitch       func(active *Client)
	interval       time.Duration
	connectTimeout time.Duration

	active atomic.Pointer[Client]

	mu      sync.Mutex // serializes reconcile and Switchover
	started bool
	closed  bool

	kick    chan struct{}
	closeCh chan struct{}
	wg      sync.WaitGroup
}

// NewGroup returns a redundancy group over the given station addresses,
// which are typically two network paths to the same station or two redundant
// front ends. opts apply to every connection; [WithAutoStart] is controlled
// by the group and reconnection is always on ([WithReconnect] sets its
// delays). The group is not connected until [Group.Connect] is called.
func NewGroup(addrs []string, opts ...Option) (*Group, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a group needs at least one address", iec104.ErrInvalidOption)
	}
	g := &Group{
		dialing: make([]atomic.Bool, len(addrs)),
		kick:    make(chan struct{}, 1),
		closeCh: make(chan struct{}),
	}
	wake := func() {
		select {
		case g.kick <- struct{}{}:
		default:
		}
	}
	for _, addr := range addrs {
		all := append([]Option{WithReconnect(Reconnect{})}, opts...)
		all = append(all, WithAutoStart(false), func(o *options) { o.stateTap = wake })
		c, err := New(addr, all...)
		if err != nil {
			return nil, err
		}
		g.clients = append(g.clients, c)
	}
	first := g.clients[0].opts
	g.onSwitch = first.onSwitch
	g.interval = first.reconnect.MinDelay
	g.connectTimeout = first.params.T0
	return g, nil
}

// Clients returns the connections of the group, in the order of the
// addresses. Use them to observe the state of each path; requests belong on
// the group.
func (g *Group) Clients() []*Client {
	return append([]*Client(nil), g.clients...)
}

// Active returns the connection that currently has data transfer started,
// or nil when there is none.
func (g *Group) Active() *Client { return g.active.Load() }

// Connect establishes the connections and returns as soon as one of them
// has data transfer started. The others keep being established in the
// background, as does every connection that is lost later.
//
// If no connection can be started before ctx ends, Connect returns an error
// that matches [iec104.ErrConnectFailed]; the group keeps trying in the
// background until it is closed.
func (g *Group) Connect(ctx context.Context) error {
	g.mu.Lock()
	switch {
	case g.closed:
		g.mu.Unlock()
		return iec104.ErrClosed
	case !g.started:
		g.started = true
		g.wg.Add(1)
		go g.supervise()
	}
	g.mu.Unlock()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for g.Active() == nil {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: no connection of the group could be started: %w",
				iec104.ErrConnectFailed, ctx.Err())
		case <-g.closeCh:
			return iec104.ErrClosed
		case <-tick.C:
		}
	}
	return nil
}

// Close closes every connection of the group. It is idempotent.
func (g *Group) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	close(g.closeCh)
	g.mu.Unlock()

	g.wg.Wait()
	for _, c := range g.clients {
		_ = c.Close()
	}
	g.active.Store(nil)
	return nil
}

func (g *Group) supervise() {
	defer g.wg.Done()
	tick := time.NewTicker(g.interval)
	defer tick.Stop()
	for {
		g.reconcile()
		select {
		case <-g.closeCh:
			return
		case <-g.kick:
		case <-tick.C:
		}
	}
}

// reconcile brings the group towards its invariant: every connection
// established, exactly one of them started.
func (g *Group) reconcile() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	// A connection that was never established, or whose first attempt
	// failed, does not reconnect by itself: dial it here.
	for i, c := range g.clients {
		if c.State() == iec104.StateDisconnected && g.dialing[i].CompareAndSwap(false, true) {
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				defer g.dialing[i].Store(false)
				ctx, cancel := context.WithTimeout(context.Background(), g.connectTimeout)
				defer cancel()
				go func() {
					select {
					case <-g.closeCh:
						cancel()
					case <-ctx.Done():
					}
				}()
				_ = c.Connect(ctx) // the state change wakes the supervisor
			}()
		}
	}

	old := g.active.Load()
	if old != nil && old.State() == iec104.StateStarted {
		return
	}
	g.active.Store(nil)
	next := g.start(nil)
	if next != old && g.onSwitch != nil {
		g.onSwitch(next)
	}
}

// start starts data transfer on the first established connection other than
// skip and makes it the active one. The caller holds g.mu.
func (g *Group) start(skip *Client) *Client {
	for _, c := range g.clients {
		if c == skip || c.State() != iec104.StateStopped {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.opts.params.T1)
		err := c.StartDT(ctx)
		cancel()
		if err == nil {
			g.active.Store(c)
			return c
		}
	}
	return nil
}

// Switchover moves data transfer from the active connection to the next
// established standby: STOPDT on the one, STARTDT on the other. It fails
// with [iec104.ErrNotConnected] when no standby is established, in which
// case the active connection is left as it is.
func (g *Group) Switchover(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return iec104.ErrClosed
	}
	old := g.active.Load()
	standby := false
	for _, c := range g.clients {
		standby = standby || (c != old && c.State() == iec104.StateStopped)
	}
	if !standby {
		return fmt.Errorf("%w: no standby connection is established", iec104.ErrNotConnected)
	}
	if old != nil {
		if err := old.StopDT(ctx); err != nil && !errors.Is(err, iec104.ErrNotConnected) {
			return err
		}
	}
	g.active.Store(nil)
	next := g.start(old)
	if next == nil {
		// The standby went away in the meantime: fall back to any connection.
		next = g.start(nil)
	}
	if next != old && g.onSwitch != nil {
		g.onSwitch(next)
	}
	if next == nil {
		return fmt.Errorf("%w: no connection of the group could be started", iec104.ErrNotConnected)
	}
	return nil
}

func (g *Group) use() (*Client, error) {
	if c := g.active.Load(); c != nil {
		return c, nil
	}
	select {
	case <-g.closeCh:
		return nil, iec104.ErrClosed
	default:
		return nil, iec104.ErrNotConnected
	}
}

// Send transmits one ASDU on the active connection. See [Client.Send].
func (g *Group) Send(ctx context.Context, a *asdu.ASDU) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.Send(ctx, a)
}

// Interrogate runs an interrogation on the active connection. See
// [Client.Interrogate].
func (g *Group) Interrogate(ctx context.Context, ca asdu.CommonAddr, qoi asdu.QOI) ([]*asdu.ASDU, error) {
	c, err := g.use()
	if err != nil {
		return nil, err
	}
	return c.Interrogate(ctx, ca, qoi)
}

// CounterInterrogate runs a counter interrogation on the active connection.
// See [Client.CounterInterrogate].
func (g *Group) CounterInterrogate(ctx context.Context, ca asdu.CommonAddr, request, freeze uint8) ([]*asdu.ASDU, error) {
	c, err := g.use()
	if err != nil {
		return nil, err
	}
	return c.CounterInterrogate(ctx, ca, request, freeze)
}

// Read reads one information object over the active connection. See
// [Client.Read].
func (g *Group) Read(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) (*asdu.ASDU, error) {
	c, err := g.use()
	if err != nil {
		return nil, err
	}
	return c.Read(ctx, ca, ioa)
}

// ClockSync synchronizes the station clock over the active connection. See
// [Client.ClockSync].
func (g *Group) ClockSync(ctx context.Context, ca asdu.CommonAddr, t time.Time) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.ClockSync(ctx, ca, t)
}

// Command sends a process command over the active connection. See
// [Client.Command]. A select and its execute must go over the same
// connection: after a switchover, select again.
func (g *Group) Command(ctx context.Context, ca asdu.CommonAddr, obj asdu.InformationObject) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.Command(ctx, ca, obj)
}

// Deactivate cancels a selected command over the active connection. See
// [Client.Deactivate].
func (g *Group) Deactivate(ctx context.Context, ca asdu.CommonAddr, obj asdu.InformationObject) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.Deactivate(ctx, ca, obj)
}

// TestCommand sends a test command over the active connection. See
// [Client.TestCommand].
func (g *Group) TestCommand(ctx context.Context, ca asdu.CommonAddr) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.TestCommand(ctx, ca)
}

// ResetProcess sends a reset process command over the active connection.
// See [Client.ResetProcess].
func (g *Group) ResetProcess(ctx context.Context, ca asdu.CommonAddr, qualifier uint8) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.ResetProcess(ctx, ca, qualifier)
}
