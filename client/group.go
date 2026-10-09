// SPDX-License-Identifier: MIT

package client

import (
	"context"
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
	onSwitch       func(active *Client)
	interval       time.Duration
	maxDelay       time.Duration
	connectTimeout time.Duration

	active atomic.Pointer[Client]

	// mu serializes reconcile and Switchover. It is held across STARTDT and
	// STOPDT, which wait for the station, and never across a callback of
	// the application: those may call the group.
	mu sync.Mutex

	// stateMu guards started and closed and is never held across a call
	// that blocks, so that Close can be called from anywhere.
	stateMu sync.Mutex
	started bool
	closed  bool
	ctx     context.Context // ends when the group is closed
	cancel  context.CancelFunc

	// A connection that was never established, or whose first attempt
	// failed, is dialed by the group, with the delays of [WithReconnect].
	dialMu  sync.Mutex
	dialing []bool
	delay   []time.Duration
	notYet  []time.Time

	// The switch handler is called outside mu, one call at a time and in
	// order, so that it may call back into the group.
	switchMu   sync.Mutex
	switchIdle *sync.Cond
	switches   []*Client
	switching  bool
	switcher   atomic.Uint64 // goroutine calling the switch handler, 0 when idle

	kick      chan struct{}
	pending   chan struct{} // callbacks are due: see tell
	closeCh   chan struct{}
	closeDone chan struct{}
	wg        sync.WaitGroup
}

// switched reports a change of the active connection to the switch handler.
// The caller holds g.mu; the call itself happens later, see tellSwitches.
func (g *Group) switched(next *Client) {
	if g.onSwitch == nil {
		return
	}
	g.switchMu.Lock()
	g.switches = append(g.switches, next)
	g.switchMu.Unlock()
}

// settle delivers what Switchover left for the application: the state
// changes of the connections and the change of the active one. The caller
// does not hold g.mu.
//
// The switch handler has been told when settle returns, also when another
// goroutine was telling it. The state handlers are not waited for: one that
// does not return holds up the notifications of its connection, and must
// not hold up the group.
func (g *Group) settle() {
	// Not from inside a callback: the application would be called from
	// within its own call. The group's own goroutine delivers instead.
	if g.inCallback() {
		g.later()
		return
	}
	for _, c := range g.clients {
		c.deliverNotices()
	}
	g.tellSwitches(true)
}

// later leaves what is queued for the application to the group's own
// goroutine for that, see tell.
func (g *Group) later() {
	select {
	case g.pending <- struct{}{}:
	default:
	}
}

// tell delivers what the supervisor left for the application. It has a
// goroutine of its own: a callback that is slow, or that calls the group,
// must not keep the supervisor from its work.
func (g *Group) tell() {
	defer g.wg.Done()
	for {
		select {
		case <-g.closeCh:
			return
		case <-g.pending:
		}
		for _, c := range g.clients {
			c.deliverNotices()
		}
		g.tellSwitches(false)
	}
}

// tellSwitches calls the switch handler for what switched queued, one call
// at a time and in order. When another goroutine is doing so it leaves the
// calls to it, and with wait returns only when they have been made.
func (g *Group) tellSwitches(wait bool) {
	g.switchMu.Lock()
	defer g.switchMu.Unlock()
	for g.switching {
		if !wait {
			return
		}
		g.switchIdle.Wait()
	}
	g.switching = true
	g.switcher.Store(goroutineID())
	for len(g.switches) > 0 {
		next := g.switches[0]
		g.switches = g.switches[1:]
		g.switchMu.Unlock()
		g.onSwitch(next)
		g.switchMu.Lock()
	}
	g.switching = false
	g.switcher.Store(0)
	g.switchIdle.Broadcast()
}

// wake makes the supervisor look at the group again.
func (g *Group) wake() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// inCallback reports whether the caller is inside the switch handler or a
// callback of one of the group's connections.
func (g *Group) inCallback() bool {
	if g.switcher.Load() == goroutineID() {
		return true
	}
	for _, c := range g.clients {
		if c.inCallback() {
			return true
		}
	}
	return false
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
		dialing:   make([]bool, len(addrs)),
		delay:     make([]time.Duration, len(addrs)),
		notYet:    make([]time.Time, len(addrs)),
		kick:      make(chan struct{}, 1),
		pending:   make(chan struct{}, 1),
		closeCh:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	g.switchIdle = sync.NewCond(&g.switchMu)
	g.ctx, g.cancel = context.WithCancel(context.Background())
	for _, addr := range addrs {
		all := append([]Option{WithReconnect(Reconnect{})}, opts...)
		all = append(all, WithAutoStart(false), func(o *options) { o.stateTap = g.wake })
		c, err := New(addr, all...)
		if err != nil {
			g.cancel()
			return nil, err
		}
		g.clients = append(g.clients, c)
	}
	first := g.clients[0].opts
	g.onSwitch = first.onSwitch
	g.interval = first.reconnect.MinDelay
	g.maxDelay = max(first.reconnect.MaxDelay, g.interval)
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

func (g *Group) isClosed() bool {
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	return g.closed
}

// Connect establishes the connections and returns as soon as one of them
// has data transfer started. The others keep being established in the
// background, as does every connection that is lost later.
//
// If no connection can be started before ctx ends, Connect returns an error
// that matches [iec104.ErrConnectFailed]; the group keeps trying in the
// background until it is closed.
func (g *Group) Connect(ctx context.Context) error {
	g.stateMu.Lock()
	switch {
	case g.closed:
		g.stateMu.Unlock()
		return iec104.ErrClosed
	case !g.started:
		g.started = true
		g.wg.Add(2)
		go g.supervise()
		go g.tell()
	}
	g.stateMu.Unlock()

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

// Close closes every connection of the group. When it returns the handlers,
// the switch handler included, have been called for the last time, as for
// [Client.Close]. Called from one of them it cannot wait for that call: it
// returns at once and the close completes when the call has returned. Close
// is idempotent; every caller outside a callback returns when the group is
// closed.
func (g *Group) Close() error {
	g.stateMu.Lock()
	first := !g.closed
	if first {
		g.closed = true
		close(g.closeCh)
		// Gives up a STARTDT or STOPDT the group is waiting for.
		g.cancel()
	}
	g.stateMu.Unlock()

	inside := g.inCallback()
	if inside {
		for _, c := range g.clients {
			c.quiet.Store(true)
		}
	}
	if first {
		go func() {
			g.wg.Wait()
			var wg sync.WaitGroup
			for _, c := range g.clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = c.Close()
				}()
			}
			wg.Wait()
			// Under mu: a Switchover that was under way has finished, and
			// another one finds the group closed.
			g.mu.Lock()
			g.active.Store(nil)
			g.mu.Unlock()
			// The switch handler: not called again, and a call in progress
			// has returned.
			g.switchMu.Lock()
			g.switches = nil
			for g.switching {
				g.switchIdle.Wait()
			}
			g.switchMu.Unlock()
			close(g.closeDone)
		}()
	}
	if inside {
		return nil
	}
	<-g.closeDone
	return nil
}

func (g *Group) supervise() {
	defer g.wg.Done()
	tick := time.NewTicker(g.interval)
	defer tick.Stop()
	for {
		g.reconcile()
		g.later()
		select {
		case <-g.closeCh:
			return
		case <-g.kick:
		case <-tick.C:
		}
	}
}

// dial establishes connection i when it is disconnected and not being
// dialed, and its delay after a failed attempt has passed.
func (g *Group) dial(i int) {
	c := g.clients[i]
	if c.State() != iec104.StateDisconnected {
		return
	}
	g.dialMu.Lock()
	if g.dialing[i] || time.Now().Before(g.notYet[i]) {
		g.dialMu.Unlock()
		return
	}
	g.stateMu.Lock()
	if g.closed {
		g.stateMu.Unlock()
		g.dialMu.Unlock()
		return
	}
	g.wg.Add(1)
	g.stateMu.Unlock()
	g.dialing[i] = true
	g.dialMu.Unlock()

	go func() {
		defer g.wg.Done()
		ctx, cancel := context.WithTimeout(g.ctx, g.connectTimeout)
		err := c.Connect(ctx) // the state change wakes the supervisor
		cancel()
		g.dialMu.Lock()
		g.dialing[i] = false
		if err != nil {
			// As a client does for a connection it lost: wait, longer
			// after every failure.
			g.delay[i] = min(max(2*g.delay[i], g.interval), g.maxDelay)
			g.notYet[i] = time.Now().Add(g.delay[i])
		} else {
			g.delay[i] = 0
			g.notYet[i] = time.Time{}
		}
		g.dialMu.Unlock()
	}()
}

// reconcile brings the group towards its invariant: every connection
// established, exactly one of them started.
//
// It goes by what the links say of themselves and not by [Client.State],
// which follows only when the application has been told: a Handler that is
// slow on the active connection must not delay the switch to another when
// that connection is lost.
func (g *Group) reconcile() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.isClosed() {
		return
	}
	for i := range g.clients {
		g.dial(i)
	}

	old := g.active.Load()
	if old != nil {
		if _, started := old.transfer(); started {
			g.stopStrays(old)
			return
		}
	}
	g.active.Store(nil)
	next := g.start(nil)
	g.stopStrays(next)
	if next != old {
		g.switched(next)
	}
}

// stopStrays stops data transfer on every connection other than active that
// has it started: exactly one connection of a group is started. A STARTDT
// the group gave up on may still be confirmed later; this is where that is
// put right. The caller holds g.mu.
func (g *Group) stopStrays(active *Client) {
	for _, c := range g.clients {
		if _, started := c.transfer(); c == active || !started {
			continue
		}
		ctx, cancel := context.WithTimeout(g.ctx, c.opts.params.T1)
		err := c.stopQuietly(ctx)
		cancel()
		if err != nil {
			c.drop()
		}
	}
}

// start makes a connection other than skip the active one: one that has
// data transfer started already, or else the first established one, on
// which it starts data transfer. The caller holds g.mu.
func (g *Group) start(skip *Client) *Client {
	for _, c := range g.clients {
		if _, started := c.transfer(); c != skip && started {
			g.active.Store(c)
			return c
		}
	}
	for _, c := range g.clients {
		if established, started := c.transfer(); c == skip || !established || started {
			continue
		}
		// Bounded by t1, the time the station has to confirm, and not by
		// the request timeout.
		ctx, cancel := context.WithTimeout(g.ctx, c.opts.params.T1)
		err := c.startQuietly(ctx)
		cancel()
		if err == nil {
			g.active.Store(c)
			return c
		}
		if g.isClosed() {
			return nil
		}
		// A STARTDT that was not confirmed may still be: a connection in
		// that state is not a standby. Drop it; it is established anew.
		c.drop()
	}
	return nil
}

// Switchover moves data transfer from the active connection to the next
// established standby: STOPDT on the one, STARTDT on the other. It fails
// with [iec104.ErrNotConnected] when no standby is established, in which
// case the active connection is left as it is.
//
// The switch handler has been told of the change when Switchover returns,
// and so have the state handlers, unless one of them is still busy with an
// earlier call. Switchover may be called from a handler; the handlers are
// then told after that handler has returned.
func (g *Group) Switchover(ctx context.Context) error {
	defer g.settle()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.isClosed() {
		return iec104.ErrClosed
	}
	old := g.active.Load()
	standby := false
	for _, c := range g.clients {
		established, started := c.transfer()
		standby = standby || (c != old && established && !started)
	}
	if !standby {
		return fmt.Errorf("%w: no standby connection is established", iec104.ErrNotConnected)
	}
	if old != nil {
		if err := old.stopQuietly(ctx); err != nil {
			// A connection that is lost needs no STOPDT.
			if established, _ := old.transfer(); established {
				return err
			}
		}
	}
	g.active.Store(nil)
	next := g.start(old)
	if next == nil {
		// The standby went away in the meantime: fall back to any connection.
		next = g.start(nil)
	}
	g.stopStrays(next)
	if next != old {
		g.switched(next)
	}
	switch next {
	case nil:
		return fmt.Errorf("%w: no connection of the group could be started", iec104.ErrNotConnected)
	case old:
		// Data transfer is back where it was: nothing was switched over.
		return fmt.Errorf("%w: the standby connection could not be started", iec104.ErrNotConnected)
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

// GetFile downloads a file over the active connection. See [Client.GetFile].
func (g *Group) GetFile(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) ([]byte, error) {
	c, err := g.use()
	if err != nil {
		return nil, err
	}
	return c.GetFile(ctx, ca, ioa, name)
}

// PutFile sends a file over the active connection. See [Client.PutFile].
func (g *Group) PutFile(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, sections ...[]byte) error {
	c, err := g.use()
	if err != nil {
		return err
	}
	return c.PutFile(ctx, ca, ioa, name, sections...)
}

// ListFiles calls the directory over the active connection. See
// [Client.ListFiles].
func (g *Group) ListFiles(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) ([]asdu.FileDirectoryEntry, error) {
	c, err := g.use()
	if err != nil {
		return nil, err
	}
	return c.ListFiles(ctx, ca, ioa)
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
