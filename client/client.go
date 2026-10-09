// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/link"
)

// Client is the controlling station end of one IEC 60870-5-104 connection.
// Create it with [New] or [Dial]. It is safe for concurrent use.
type Client struct {
	addr string
	opts options

	mu        sync.Mutex
	link      *link.Link
	state     iec104.State
	closed    bool
	dialing   bool // a connect attempt owns the connection state
	exchanges []*exchange
	testSeq   uint16

	notifyMu sync.Mutex
	closeCh  chan struct{}
	wg       sync.WaitGroup
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
	return &Client{addr: addr, opts: o, closeCh: make(chan struct{})}, nil
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
		c.mu.Unlock()
		return fmt.Errorf("%w: client is %s", iec104.ErrBusy, c.state)
	}
	c.dialing = true
	c.mu.Unlock()
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
		return fmt.Errorf("iec104: connect %s: %w", c.addr, err)
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
		Name:    "iec104 client " + c.addr,
		Logger:  c.opts.logger,
		Metrics: c.opts.metrics,
		OnASDU:  func(raw []byte) { c.onASDU(remote, raw) },
		OnState: func(bool) {
			<-ready
			c.syncState(l)
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
	c.mu.Unlock()
	close(ready)
	c.syncState(l)

	if c.opts.autoStart {
		if err := l.StartDT(ctx); err != nil {
			c.detach(l)
			_ = l.Close()
			return fmt.Errorf("iec104: STARTDT %s: %w", c.addr, err)
		}
	}

	c.mu.Lock()
	alive := c.link == l
	if alive {
		c.dialing = false
	}
	c.mu.Unlock()
	if !alive {
		return fmt.Errorf("iec104: connect %s: %w", c.addr, l.Err())
	}
	c.syncState(l)
	return nil
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
// with [iec104.ErrClosed]. Close is idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeCh)
	l := c.link
	c.mu.Unlock()

	if l != nil {
		_ = l.Close()
		// The link's close notification follows asynchronously; settle the
		// client now so that Close returns with everything released.
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
	return nil
}

// StartDT starts data transfer (STARTDT act) and waits for the
// confirmation. It is a no-op when data transfer is already started.
func (c *Client) StartDT(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	err = l.StartDT(ctx)
	c.syncState(l)
	return err
}

// StopDT stops data transfer (STOPDT act) and waits for the confirmation.
// The connection stays open and is supervised with test frames.
func (c *Client) StopDT(ctx context.Context) error {
	l, err := c.current()
	if err != nil {
		return err
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	err = l.StopDT(ctx)
	c.syncState(l)
	return err
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

// bound applies the request timeout to a context without deadline.
func (c *Client) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok || c.opts.requestTimout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.opts.requestTimout)
}

// setState records a state change and notifies the state handler.
// notifyMu serializes the notifications without holding c.mu, so the
// handler may query the client.
func (c *Client) setState(s iec104.State, err error) {
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	c.mu.Lock()
	same := c.state == s && err == nil
	c.state = s
	c.mu.Unlock()
	if !same {
		c.emit(s, err)
	}
}

// syncState sets the state from the data transfer state of l, unless l is
// no longer the current link. It reads the link rather than taking the
// state as an argument because it is called both from the goroutine that
// ran STARTDT or STOPDT and, later, from the link's own notification.
func (c *Client) syncState(l *link.Link) {
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	c.mu.Lock()
	if c.link != l {
		c.mu.Unlock()
		return
	}
	s := iec104.StateStopped
	if l.Started() {
		s = iec104.StateStarted
	}
	same := c.state == s
	c.state = s
	c.mu.Unlock()
	if !same {
		c.emit(s, nil)
	}
}

// emit logs and reports a state change. The caller holds notifyMu.
func (c *Client) emit(s iec104.State, err error) {
	if c.opts.logger != nil {
		if err != nil {
			c.opts.logger.Infof("iec104 client %s: %s: %v", c.addr, s, err)
		} else {
			c.opts.logger.Infof("iec104 client %s: %s", c.addr, s)
		}
	}
	if f := c.opts.onState; f != nil {
		f(s, err)
	}
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
		if c.opts.logger != nil {
			c.opts.logger.Warnf("iec104 client %s: dropping undecodable ASDU: %v", c.addr, err)
		}
		return
	}
	c.mu.Lock()
	for _, x := range c.exchanges {
		if x.match(a) {
			x.deliver(a)
		}
	}
	c.mu.Unlock()
	if h := c.opts.handler; h != nil {
		h.HandleASDU(a)
	}
}
