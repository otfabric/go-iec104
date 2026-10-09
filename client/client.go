// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/link"
	"github.com/otfabric/go-iec104/internal/logx"
)

// Client is the controlling station end of one IEC 60870-5-104 connection.
// Create it with [New] or [Dial]. It is safe for concurrent use.
type Client struct {
	addr string
	opts options
	log  *logx.Logger

	mu        sync.Mutex
	link      *link.Link
	last      *link.Link // the most recent link, current or ended
	remote    net.Addr   // of the current or the last connection
	state     iec104.State
	closed    bool
	dialing   bool // a connect attempt owns the connection state
	exchanges []*exchange
	testSeq   uint16

	// State notifications are queued and delivered one at a time, in
	// order, by whichever goroutine finds the queue idle (see notify).
	notifyMu  sync.Mutex
	notices   []notice
	queued    uint64 // notices ever queued
	delivered uint64 // notices whose callback has returned
	notifying bool
	notifier  atomic.Uint64 // goroutine delivering notices, 0 when idle
	idle      *sync.Cond    // on notifyMu: signalled after every delivery

	// dispatching is the most recent link, readable without c.mu.
	dispatching atomic.Pointer[link.Link]

	closeCh   chan struct{}
	closeDone chan struct{} // closed when Close has finished everything
	// quiet is set when the client is closed from inside one of its
	// callbacks: the Handler is not called again. A Close from elsewhere
	// waits instead, until the Handler has seen what was received.
	quiet atomic.Bool
	wg    sync.WaitGroup
}

type notice struct {
	state iec104.State
	err   error
}

// New returns a client for the controlled station at addr ("host:port").
// A missing port defaults to 2404, or 19998 with [WithTLS]. The client is
// not connected until [Client.Connect] is called.
func New(addr string, opts ...Option) (*Client, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	if err := o.params.Validate(); err != nil {
		return nil, err
	}
	if err := o.asduParams.Validate(); err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := apci.DefaultPort
		if o.tls != nil {
			port = apci.DefaultTLSPort
		}
		addr = net.JoinHostPort(addr, strconv.Itoa(port))
	}
	c := &Client{
		addr:      addr,
		opts:      o,
		log:       logx.New(o.logger, "client", "remote", addr),
		closeCh:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	c.idle = sync.NewCond(&c.notifyMu)
	return c, nil
}

// Dial creates a client and connects it. It is shorthand for [New] followed
// by [Client.Connect].
func Dial(ctx context.Context, addr string, opts ...Option) (*Client, error) {
	c, err := New(addr, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Addr returns the address of the controlled station.
func (c *Client) Addr() string { return c.addr }

// State returns the current connection state.
func (c *Client) State() iec104.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Connect establishes the transport connection and, unless disabled with
// [WithAutoStart], starts data transfer. The connection attempt is bounded
// by ctx and by t0, whichever is shorter.
//
// Connect fails with [iec104.ErrBusy] when the client is already connected
// or connecting. With [WithReconnect] it only needs to succeed once: the
// client re-establishes a lost connection by itself.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return iec104.ErrClosed
	case c.dialing || c.state != iec104.StateDisconnected:
		state := c.state
		c.mu.Unlock()
		return fmt.Errorf("%w: client is %s", iec104.ErrBusy, state)
	}
	c.dialing = true
	// Counted under the lock that guards closed: Close waits for a Connect
	// that got past the check above, and for what it reports.
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	c.setState(iec104.StateConnecting, nil)

	err := c.connect(ctx)
	if err != nil {
		c.mu.Lock()
		c.dialing = false
		c.mu.Unlock()
		c.setState(iec104.StateDisconnected, err)
	}
	return err
}

// connect dials, starts a link and, on success, clears c.dialing. The
// caller has set c.dialing, which keeps onLinkClose from reacting to a link
// that dies before connect returns: connect reports that failure itself.
func (c *Client) connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.opts.params.T0)
	defer cancel()
	go func() {
		select {
		case <-c.closeCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	conn, err := c.dial(ctx)
	if err != nil {
		if c.isClosed() {
			return iec104.ErrClosed
		}
		return fmt.Errorf("%w: %s: %w", iec104.ErrConnectFailed, c.addr, err)
	}
	remote := conn.RemoteAddr()
	if m := c.opts.metrics; m != nil {
		m.OnConnect(remote)
	}

	var l *link.Link
	ready := make(chan struct{})
	l = link.New(conn, link.Config{
		Role:    link.Controlling,
		Params:  c.opts.params,
		Log:     c.log,
		Metrics: c.opts.metrics,
		Drain:   true,
		// A group follows the link itself: the dispatcher may be busy in
		// the Handler long after the connection has changed or is lost.
		OnTransfer: func(*link.Link, bool, uint64) {
			if f := c.opts.stateTap; f != nil {
				f()
			}
		},
		OnASDU: func(raw []byte) { c.onASDU(remote, raw) },
		OnState: func(bool) {
			<-ready
			c.syncState(l)
		},
		OnStopped: func(epoch uint64) {
			<-ready
			// Nothing more arrives for a started period that has ended, and
			// this runs after everything that arrived in it: a request of
			// that period that is still waiting will not be answered.
			c.failPending(l, epoch, iec104.ErrNotStarted)
		},
		OnClose: func(err error) {
			<-ready
			c.onLinkClose(l, remote, err)
		},
	})

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		close(ready)
		_ = l.Close()
		return iec104.ErrClosed
	}
	c.link = l
	c.last = l
	c.dispatching.Store(l)
	c.remote = remote
	c.mu.Unlock()
	close(ready)
	c.syncState(l)

	if c.opts.autoStart {
		if err := l.StartDT(ctx); err != nil {
			c.detach(l)
			_ = l.Close()
			return fmt.Errorf("%w: STARTDT %s: %w", iec104.ErrConnectFailed, c.addr, err)
		}
	}

	c.mu.Lock()
	alive := c.link == l
	if alive {
		c.dialing = false
	}
	c.mu.Unlock()
	if !alive {
		return fmt.Errorf("%w: %s: %w", iec104.ErrConnectFailed, c.addr, l.Err())
	}
	c.syncState(l)
	if f := c.opts.onStart; f != nil && l.Started() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer cancel()
			f(ctx, c)
		}()
		go func() {
			select {
			case <-l.Done():
			case <-c.closeCh:
			case <-ctx.Done():
			}
			cancel()
		}()
	}
	return nil
}

// at marks a named point for tests; see options.failpoint.
func (c *Client) at(name string) {
	if f := c.opts.failpoint; f != nil {
		f(name)
	}
}

// failPending ends the requests sent on l in a started period up to epoch
// that still wait for an answer.
func (c *Client) failPending(l *link.Link, epoch uint64, err error) {
	c.mu.Lock()
	var pending, keep []*exchange
	if c.link == l {
		for _, x := range c.exchanges {
			if x.epoch.Load() <= epoch {
				pending = append(pending, x)
			} else {
				keep = append(keep, x)
			}
		}
		c.exchanges = keep
	}
	c.mu.Unlock()
	for _, x := range pending {
		x.fail(err)
	}
}

// detach forgets l so that its OnClose callback is ignored.
func (c *Client) detach(l *link.Link) {
	c.mu.Lock()
	if c.link == l {
		c.link = nil
	}
	c.mu.Unlock()
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := c.opts.dialer
	if d == nil {
		d = &net.Dialer{}
	}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	if c.opts.tls == nil {
		return conn, nil
	}
	cfg := c.opts.tls
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		cfg = cfg.Clone()
		cfg.ServerName, _, _ = net.SplitHostPort(c.addr)
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

// Close closes the connection and stops reconnecting. Pending requests fail
// with [iec104.ErrClosed]. When Close returns the [Handler] and the state
// handler have been called for the last time: a call in progress has
// returned and none follows. Before that the Handler is given what the
// connection had received, and acknowledged to the station, up to the
// moment of the call.
//
// Called from the Handler or the state handler, Close cannot wait for that
// call: it returns at once, the Handler is not called again, and
// "disconnected" is reported after the call has returned. Close is
// idempotent; every caller outside a callback returns when the client is
// closed.
func (c *Client) Close() error {
	c.mu.Lock()
	first := !c.closed
	if first {
		c.closed = true
		close(c.closeCh)
	}
	// The last link, not the current one: a link that has just ended is no
	// longer current while its dispatcher may still be telling the
	// application so.
	l := c.last
	c.mu.Unlock()

	// From inside a callback Close cannot wait for that callback to return:
	// the close completes behind it, and what was received and not yet
	// handled is discarded. Every other caller, also a second one while the
	// first is still waiting, returns when the Handler has been given
	// everything the station was told has arrived.
	inside := c.inCallback()
	if inside {
		c.quiet.Store(true)
	}
	if first {
		if l != nil {
			l.Shutdown()
		}
		go c.finishClose(l)
	}
	if inside {
		return nil
	}
	<-c.closeDone
	return nil
}

// finishClose completes Close: the link has delivered its last callback,
// every connect attempt has ended, and "disconnected" has been reported.
func (c *Client) finishClose(l *link.Link) {
	if l != nil {
		<-l.Dispatched()
		// The link's close notification has settled the client, unless the
		// link was already detached from it.
		c.mu.Lock()
		var pending []*exchange
		if c.link == l {
			c.link = nil
			pending, c.exchanges = c.exchanges, nil
		}
		c.mu.Unlock()
		for _, x := range pending {
			x.fail(iec104.ErrClosed)
		}
	}
	c.wg.Wait()
	c.setState(iec104.StateDisconnected, nil)
	c.flushNotices()
	close(c.closeDone)
}

// inCallback reports whether the caller is inside a callback of this
// client: on the goroutine that is delivering a state notification, or on
// the dispatcher of its link, which calls the Handler.
func (c *Client) inCallback() bool {
	if c.notifier.Load() == goroutineID() {
		return true
	}
	c.mu.Lock()
	cur, last := c.link, c.last
	c.mu.Unlock()
	return (cur != nil && cur.OnDispatcher()) || (last != nil && last.OnDispatcher())
}

// StartDT starts data transfer (STARTDT act) and waits for the
// confirmation. It is a no-op when data transfer is already started.
func (c *Client) StartDT(ctx context.Context) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	return c.startDT(ctx)
}

// startDT is StartDT bounded by ctx alone.
func (c *Client) startDT(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	err = l.StartDT(ctx)
	c.syncState(l)
	return err
}

// stopDT is StopDT bounded by ctx alone.
func (c *Client) stopDT(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	err = l.StopDT(ctx)
	c.syncState(l)
	return err
}

// startQuietly and stopQuietly are startDT and stopDT for a caller that
// holds a lock the state handler may want, a redundancy group: the state
// change is queued for the state handler, not delivered, and the caller
// calls deliverNotices once it has let go of its lock.
func (c *Client) startQuietly(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	err = l.StartDT(ctx)
	c.sync(l, false)
	return err
}

func (c *Client) stopQuietly(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	err = l.StopDT(ctx)
	c.sync(l, false)
	return err
}

// transfer reports what the client's link says of itself, which is ahead
// of [Client.State] while the dispatcher is busy: whether the connection is
// established, and whether data transfer is started on it.
func (c *Client) transfer() (established, started bool) {
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	if l == nil || l.Err() != nil {
		return false, false
	}
	return true, l.Settled()
}

// drop closes the current connection without closing the client: with
// [WithReconnect] it is established anew. A redundancy group uses it for a
// connection whose data transfer state it can no longer be sure of.
func (c *Client) drop() {
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	if l != nil {
		l.Drop()
	}
}

// StopDT stops data transfer (STOPDT act) and waits for the confirmation.
// The connection stays open and is supervised with test frames.
func (c *Client) StopDT(ctx context.Context) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	return c.stopDT(ctx)
}

// TestLink sends a test frame (TESTFR act) and waits for the confirmation,
// which proves the peer's protocol machine is alive. The client does this
// by itself after t3 of inactivity.
func (c *Client) TestLink(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	return l.TestFR(ctx)
}

// Send transmits one ASDU without waiting for any answer. It blocks while
// the send window is full (k unacknowledged I frames). Use the request
// methods for the standard application functions; Send is for everything
// else, such as deactivations, parameters, file transfer and private types.
func (c *Client) Send(ctx context.Context, a *asdu.ASDU) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	raw, err := a.Encode(c.opts.asduParams)
	if err != nil {
		return err
	}
	return l.Send(ctx, raw)
}

func (c *Client) current() (*link.Link, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closed:
		return nil, iec104.ErrClosed
	case c.link == nil:
		return nil, iec104.ErrNotConnected
	}
	return c.link, nil
}

// bound applies the request timeout: to a context without deadline, or to
// every attempt when retries are enabled.
func (c *Client) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.opts.requestTimeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok && c.opts.retry == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.opts.requestTimeout)
}

func (c *Client) remoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

// setState records a state change and notifies the state handler.
// notifyMu serializes the notifications without holding c.mu, so the
// handler may query the client.
func (c *Client) setState(s iec104.State, err error) {
	c.notifyMu.Lock()
	c.mu.Lock()
	// A reconnect attempt that fails is reported each time, with its
	// reason; a client that is disconnected is told so once.
	same := c.state == s && (err == nil || s == iec104.StateDisconnected)
	c.state = s
	c.mu.Unlock()
	c.notify(!same, notice{s, err})
}

// syncState sets the state from the data transfer state of l, unless l is
// no longer the current link. It reads the link rather than taking the
// state as an argument because it is called both from the goroutine that
// ran STARTDT or STOPDT and, later, from the link's own notification.
func (c *Client) syncState(l *link.Link) { c.sync(l, true) }

// sync is syncState; without deliver the notice is only queued, see
// startQuietly.
func (c *Client) sync(l *link.Link, deliver bool) {
	c.notifyMu.Lock()
	c.mu.Lock()
	// The confirmed state: "stopped" is reported when STOPDT is confirmed,
	// not when it is sent, in step with the link's own notifications.
	//
	// A link that has ended is neither started nor stopped: its close
	// notification says what became of the connection.
	started := l.Settled()
	if c.link != l || l.Err() != nil {
		c.mu.Unlock()
		c.notifyMu.Unlock()
		return
	}
	s := iec104.StateStopped
	if started {
		s = iec104.StateStarted
	}
	same := c.state == s
	c.state = s
	c.mu.Unlock()
	if !deliver {
		if !same {
			c.notices = append(c.notices, notice{s, nil})
			c.queued++
		}
		c.notifyMu.Unlock()
		return
	}
	c.notify(!same, notice{s, nil})
}

// deliverNotices delivers what is queued for the state handler, unless
// another goroutine is doing so. It never waits for one.
func (c *Client) deliverNotices() {
	c.notifyMu.Lock()
	if c.notifying {
		c.notifyMu.Unlock()
		return
	}
	c.notify(false, notice{})
}

// notify queues n, when add is set, and makes sure the queue is delivered.
// The caller holds notifyMu; notify releases it.
//
// Notices are delivered one at a time and in the order they were queued, by
// the first goroutine that finds nobody delivering. A caller that finds
// another goroutine delivering waits until its own notice has been
// delivered, so that for example StartDT returns after "started" has been
// reported. Two callers cannot wait: the goroutine that is delivering (the
// state handler called back into the client) and the dispatcher of the
// link (which must stay free to deliver what the handler may be waiting
// for). Their notices are delivered behind them.
func (c *Client) notify(add bool, n notice) {
	if add {
		c.notices = append(c.notices, n)
		c.queued++
	}
	mine := c.queued
	if c.notifying {
		if c.notifier.Load() != goroutineID() && !c.onDispatcher() {
			for c.delivered < mine {
				c.idle.Wait()
			}
		}
		c.notifyMu.Unlock()
		return
	}
	c.notifying = true
	c.notifier.Store(goroutineID())
	for len(c.notices) > 0 {
		next := c.notices[0]
		c.notices = c.notices[1:]
		c.notifyMu.Unlock()
		c.emit(next.state, next.err)
		c.notifyMu.Lock()
		c.delivered++
		c.idle.Broadcast()
	}
	c.notifying = false
	c.notifier.Store(0)
	c.idle.Broadcast()
	c.notifyMu.Unlock()
}

// onDispatcher reports whether the caller is the dispatcher of the client's
// link. It must not take c.mu: notify holds notifyMu, and c.mu is taken
// inside it elsewhere.
func (c *Client) onDispatcher() bool {
	l := c.dispatching.Load()
	return l != nil && l.OnDispatcher()
}

// flushNotices returns when every queued notice has been delivered.
func (c *Client) flushNotices() {
	c.notifyMu.Lock()
	// Delivers what is queued, or waits for the goroutine that does.
	c.notify(false, notice{})
}

// emit logs and reports a state change. One call at a time: see notify.
func (c *Client) emit(s iec104.State, err error) {
	if err != nil {
		c.log.Info("connection state", "state", s.String(), "error", err)
	} else {
		c.log.Info("connection state", "state", s.String())
	}
	if f := c.opts.onState; f != nil {
		f(s, err)
	}
	if f := c.opts.stateTap; f != nil {
		f()
	}
}

// goroutineID returns the id of the calling goroutine, from the header of
// its stack trace: the runtime has no other way to ask. It is only used to
// recognise a call made from inside one of the client's own callbacks.
func goroutineID() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	if i := bytes.IndexByte(b, ' '); i > 0 {
		if id, err := strconv.ParseUint(string(b[:i]), 10, 64); err == nil {
			return id
		}
	}
	return 0
}

func (c *Client) onLinkClose(l *link.Link, remote net.Addr, err error) {
	local := errors.Is(err, iec104.ErrClosed)
	if m := c.opts.metrics; m != nil {
		if local {
			m.OnDisconnect(remote, nil)
		} else {
			m.OnDisconnect(remote, err)
		}
	}

	c.mu.Lock()
	if c.link != l {
		// Detached by connect, which reports the failure itself.
		c.mu.Unlock()
		return
	}
	c.link = nil
	pending := c.exchanges
	c.exchanges = nil
	dialing := c.dialing
	reconnect := c.opts.reconnect != nil && !c.closed && !local && !dialing
	if reconnect {
		c.dialing = true
		c.wg.Add(1)
	}
	c.mu.Unlock()

	for _, x := range pending {
		x.fail(err)
	}
	// The link is no longer the current one and its loss is not reported
	// yet: Close must not take this for "nothing left to wait for".
	c.at("link-detached")
	switch {
	case dialing:
		// connect notices the missing link and reports the failure.
	case reconnect:
		c.setState(iec104.StateConnecting, err)
		go c.reconnectLoop()
	case local:
		c.setState(iec104.StateDisconnected, nil)
	default:
		c.setState(iec104.StateDisconnected, err)
	}
}

func (c *Client) onASDU(remote net.Addr, raw []byte) {
	a, err := asdu.Decode(raw, c.opts.asduParams)
	if err != nil {
		if m := c.opts.metrics; m != nil {
			m.OnDecodeError(remote, err)
		}
		c.log.Warn("dropping undecodable ASDU", "error", err)
		return
	}
	c.mu.Lock()
	for _, x := range c.exchanges {
		if x.match(a) {
			x.deliver(a)
		}
	}
	c.mu.Unlock()
	if h := c.opts.handler; h != nil && !c.quiet.Load() {
		h.HandleASDU(a)
	}
}
