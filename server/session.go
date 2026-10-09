// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/link"
	"github.com/otfabric/go-iec104/internal/logx"
)

// Session is one connection from a controlling station. It is safe for
// concurrent use.
type Session struct {
	srv    *Server
	group  *group
	log    *logx.Logger
	id     uint64
	conn   net.Conn
	link   *link.Link
	ready  chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

// newSession starts the protocol machine on conn. The callbacks wait for
// ready, which start closes after the initial state notification.
func newSession(srv *Server, conn net.Conn, grp *group) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		srv:    srv,
		group:  grp,
		id:     srv.nextID.Add(1),
		conn:   conn,
		ready:  make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
	o := &srv.opts
	s.log = srv.log.With("session", s.id, "remote", conn.RemoteAddr().String(), "group", grp.name)
	s.link = link.New(conn, link.Config{
		Role:    link.Controlled,
		Params:  o.params,
		Log:     s.log,
		Metrics: o.metrics,
		OnASDU: func(raw []byte) {
			<-s.ready
			s.onASDU(raw)
		},
		OnState: func(started bool) {
			<-s.ready
			if started {
				s.group.started(s)
				s.notify(iec104.StateStarted, nil)
			} else {
				s.group.stopped(s)
				s.notify(iec104.StateStopped, nil)
			}
		},
		OnClose: func(err error) {
			<-s.ready
			s.onClose(err)
		},
	})
	return s
}

// start announces the session and releases its callbacks.
func (s *Session) start() {
	if m := s.srv.opts.metrics; m != nil {
		m.OnConnect(s.conn.RemoteAddr())
	}
	s.log.Info("session connected")
	s.notify(iec104.StateStopped, nil)
	close(s.ready)
}

func (s *Session) notify(state iec104.State, err error) {
	if f := s.srv.opts.onState; f != nil {
		f(s, state, err)
	}
}

func (s *Session) onClose(err error) {
	if errors.Is(err, iec104.ErrClosed) {
		err = nil
	}
	s.cancel()
	s.srv.remove(s)
	s.group.stopped(s)
	if m := s.srv.opts.metrics; m != nil {
		m.OnDisconnect(s.conn.RemoteAddr(), err)
	}
	if err != nil {
		s.log.Info("session disconnected", "error", err)
	} else {
		s.log.Info("session closed")
	}
	s.notify(iec104.StateDisconnected, err)
}

func (s *Session) onASDU(raw []byte) {
	o := &s.srv.opts
	a, err := asdu.Decode(raw, o.asduParams)
	if err != nil {
		if m := o.metrics; m != nil {
			m.OnDecodeError(s.conn.RemoteAddr(), err)
		}
		s.log.Warn("dropping undecodable ASDU", "error", err)
		return
	}
	if o.commonAddrs != nil && !o.asduParams.IsBroadcast(a.CommonAddr) {
		if _, ok := o.commonAddrs[a.CommonAddr]; !ok {
			_ = s.Reject(a, asdu.CauseUnknownCommonAddr)
			return
		}
	}
	if hm, ok := o.metrics.(iec104.HandlerMetrics); ok {
		begin := time.Now()
		defer func() { hm.OnHandled(s.conn.RemoteAddr(), a.Type, a.Cause, time.Since(begin)) }()
	}
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("handler panic", "asdu", a.String(), "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			go func() { _ = s.Close() }()
		}
	}()
	s.srv.handler.HandleASDU(s, a)
}

// ID returns a number that identifies the session within its server.
func (s *Session) ID() uint64 { return s.id }

// RemoteAddr returns the address of the controlling station.
func (s *Session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// LocalAddr returns the local address of the connection.
func (s *Session) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// Conn returns the underlying connection, for example to inspect the peer
// certificate of a *tls.Conn. It must not be read from, written to or
// closed.
func (s *Session) Conn() net.Conn { return s.conn }

// Context returns a context that is cancelled when the session ends. Use it
// to bound the work a handler does on behalf of the session.
func (s *Session) Context() context.Context { return s.ctx }

// Started reports whether the controlling station has started data
// transfer on this session.
func (s *Session) Started() bool { return s.link.Started() }

// Err returns why the session ended: nil while it is running or when it
// was closed by the server.
func (s *Session) Err() error {
	if err := s.link.Err(); !errors.Is(err, iec104.ErrClosed) {
		return err
	}
	return nil
}

// Close closes the connection. It is idempotent and may be called from a
// handler.
func (s *Session) Close() error {
	err := s.link.Close()
	// The close notification follows asynchronously; the session is gone
	// from the server as soon as Close returns.
	s.srv.remove(s)
	return err
}

// Send transmits one ASDU to the controlling station. It fails with
// [iec104.ErrNotStarted] while data transfer is stopped, and blocks while
// the send window is full (k unacknowledged I frames) until the peer
// acknowledges, ctx ends or the session ends.
func (s *Session) Send(ctx context.Context, a *asdu.ASDU) error {
	raw, err := a.Encode(s.srv.opts.asduParams)
	if err != nil {
		return err
	}
	return s.link.Send(ctx, raw)
}

// Reply mirrors req back with the given cause of transmission and P/N bit.
// [Session.Confirm], [Session.Negative], [Session.Terminate] and
// [Session.Reject] cover the usual cases.
func (s *Session) Reply(req *asdu.ASDU, cause asdu.Cause, negative bool) error {
	return s.Send(s.ctx, req.Reply(cause, negative))
}

// Confirm sends the positive confirmation of req: "activation
// confirmation", or "deactivation confirmation" when req is a deactivation.
func (s *Session) Confirm(req *asdu.ASDU) error {
	return s.Reply(req, confirmation(req), false)
}

// Negative sends the negative confirmation of req: the station knows the
// request but will not execute it, for example a command that is
// interlocked or an execute without a prior select.
func (s *Session) Negative(req *asdu.ASDU) error {
	return s.Reply(req, confirmation(req), true)
}

// Terminate sends the "activation termination" of req, which concludes an
// interrogation or a command execution.
func (s *Session) Terminate(req *asdu.ASDU) error {
	return s.Reply(req, asdu.CauseActivationTerm, false)
}

// Reject mirrors req with the P/N bit set and one of the "unknown ..."
// causes: [asdu.CauseUnknownType], [asdu.CauseUnknownCause],
// [asdu.CauseUnknownCommonAddr] or [asdu.CauseUnknownIOA].
func (s *Session) Reject(req *asdu.ASDU, cause asdu.Cause) error {
	return s.Reply(req, cause, true)
}

func confirmation(req *asdu.ASDU) asdu.Cause {
	if req.Cause == asdu.CauseDeactivation {
		return asdu.CauseDeactivationCon
	}
	return asdu.CauseActivationCon
}
