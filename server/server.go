// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

// ErrServerClosed is returned by [Server.Serve] and
// [Server.ListenAndServe] after [Server.Close].
var ErrServerClosed = errors.New("iec104: server closed")

// Handler processes the ASDUs a controlling station sends.
//
// HandleASDU is called from a single goroutine per session, in the order
// the ASDUs arrived; different sessions are served concurrently. It may
// call any Session or Server method. While it runs, later ASDUs of the same
// session wait, so long-running work belongs in its own goroutine.
//
// A handler that panics has its session closed; the server keeps running.
type Handler interface {
	HandleASDU(s *Session, a *asdu.ASDU)
}

// HandlerFunc adapts a function to a [Handler].
type HandlerFunc func(s *Session, a *asdu.ASDU)

// HandleASDU calls f.
func (f HandlerFunc) HandleASDU(s *Session, a *asdu.ASDU) { f(s, a) }

// Server is a controlled station serving any number of connections. Create
// it with [New]. It is safe for concurrent use.
type Server struct {
	handler Handler
	opts    options
	nextID  atomic.Uint64

	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	sessions  map[*Session]struct{}
	pending   map[net.Conn]struct{} // accepted, TLS handshake in progress
}

// New returns a server that passes received ASDUs to h. A nil h rejects
// every ASDU with cause "unknown type identification".
func New(h Handler, opts ...Option) (*Server, error) {
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
	if o.maxSessions < 0 {
		return nil, fmt.Errorf("iec104: max sessions %d, want >= 0", o.maxSessions)
	}
	if h == nil {
		h = NewMux()
	}
	return &Server{
		handler:   h,
		opts:      o,
		listeners: make(map[net.Listener]struct{}),
		sessions:  make(map[*Session]struct{}),
		pending:   make(map[net.Conn]struct{}),
	}, nil
}

// ListenAndServe listens on the TCP address addr and serves connections
// until the server is closed. An empty addr means ":2404", or ":19998"
// with [WithTLS]. It always returns a non-nil error: [ErrServerClosed]
// after [Server.Close].
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		port := apci.DefaultPort
		if s.opts.tls != nil {
			port = apci.DefaultTLSPort
		}
		addr = ":" + strconv.Itoa(port)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if s.opts.tls != nil {
		ln = tls.NewListener(ln, s.opts.tls)
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln and serves them until the server is
// closed. It takes ownership of ln and always returns a non-nil error:
// [ErrServerClosed] after [Server.Close]. Serve may be called on several
// listeners.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, ln)
		s.mu.Unlock()
		_ = ln.Close()
	}()

	s.infof("listening on %s", ln.Addr())
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// A transient accept failure: back off and retry.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				s.warnf("accept: %v; retrying in %s", err, delay)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		go s.accept(conn)
	}
}

func (s *Server) accept(conn net.Conn) {
	remote := conn.RemoteAddr()
	if f := s.opts.accept; f != nil && !f(remote) {
		s.warnf("rejected connection from %s: not accepted", remote)
		_ = conn.Close()
		return
	}
	if err := s.handshake(conn); err != nil {
		s.warnf("rejected connection from %s: %v", remote, err)
		_ = conn.Close()
		return
	}
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		_ = conn.Close()
		return
	case s.opts.maxSessions > 0 && len(s.sessions) >= s.opts.maxSessions:
		s.mu.Unlock()
		s.warnf("rejected connection from %s: session limit %d reached", remote, s.opts.maxSessions)
		_ = conn.Close()
		return
	}
	sess := newSession(s, conn)
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
	sess.start()
}

// handshake completes the TLS handshake of an accepted connection, bounded
// by t0, so that a peer that never speaks cannot hold a session. It is a
// no-op for other connections.
func (s *Server) handshake(conn net.Conn) error {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.pending[conn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, conn)
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.params.T0)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}
	return nil
}

func (s *Server) remove(sess *Session) {
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Addr returns the address of a listener the server is serving on, or nil
// when there is none. It is mainly useful after listening on port 0.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ln := range s.listeners {
		return ln.Addr()
	}
	return nil
}

// Sessions returns the sessions that are currently connected.
func (s *Server) Sessions() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

// Broadcast sends a to every session whose data transfer is started and
// returns how many sessions it was sent to. Sessions in STOPDT are skipped:
// buffering events for them is the application's decision.
//
// The sessions are served one after the other. A session whose send window
// is full blocks until its controlling station acknowledges, ctx ends or
// the session times out (t1). Errors of individual sessions are joined.
func (s *Server) Broadcast(ctx context.Context, a *asdu.ASDU) (int, error) {
	raw, err := a.Encode(s.opts.asduParams)
	if err != nil {
		return 0, err
	}
	var (
		sent int
		errs []error
	)
	for _, sess := range s.Sessions() {
		if !sess.Started() {
			continue
		}
		switch err := sess.link.Send(ctx, raw); {
		case err == nil:
			sent++
		case errors.Is(err, iec104.ErrNotStarted):
			// Stopped in the meantime.
		default:
			errs = append(errs, fmt.Errorf("session %s: %w", sess.RemoteAddr(), err))
		}
	}
	return sent, errors.Join(errs...)
}

// Close stops listening and closes every session. Serve returns
// [ErrServerClosed]. Close is idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listeners := make([]net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		listeners = append(listeners, ln)
	}
	sessions := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	for conn := range s.pending {
		_ = conn.Close()
	}
	s.mu.Unlock()

	var err error
	for _, ln := range listeners {
		if cerr := ln.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	for _, sess := range sessions {
		_ = sess.Close()
	}
	return err
}

func (s *Server) infof(format string, args ...any) {
	if s.opts.logger != nil {
		s.opts.logger.Infof("iec104 server: "+format, args...)
	}
}

func (s *Server) warnf(format string, args ...any) {
	if s.opts.logger != nil {
		s.opts.logger.Warnf("iec104 server: "+format, args...)
	}
}
