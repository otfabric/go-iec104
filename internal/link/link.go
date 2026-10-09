// SPDX-License-Identifier: MIT

// Package link implements the IEC 60870-5-104 connection state machine that
// the client and the server share: send and receive sequence numbers, the
// k/w flow control windows, the t1/t2/t3 timers and the STARTDT/STOPDT/
// TESTFR procedures.
//
// A Link owns an established net.Conn. One goroutine reads frames, one
// goroutine (the loop) owns all protocol state and performs every write, and
// one goroutine (the dispatcher) delivers received ASDUs and state changes
// to the callbacks in order. Callbacks may therefore call Send, StartDT and
// Close without deadlocking the protocol.
package link

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
)

// Role is the station role of the local end of a connection.
type Role uint8

const (
	// Controlling is the station that issues STARTDT and STOPDT: the client.
	Controlling Role = iota
	// Controlled is the station that confirms them: the server.
	Controlled
)

// Receive flow control. The callbacks may be slower than the peer, so the
// events waiting for the dispatcher are bounded in two steps.
const (
	// softQueue is the number of undelivered events above which received I
	// frames are no longer acknowledged. A conformant peer then stops after
	// k further frames. Frames are still read, so the acknowledgements and
	// U frames of the peer keep being processed: a callback blocked in Send
	// on a full window is released as soon as the peer acknowledges.
	softQueue = 256

	// hardQueue is the number of undelivered events above which the loop
	// stops taking frames from the reader altogether, which pushes back
	// through TCP. It is only reached by a peer with a very large k or one
	// that ignores flow control.
	hardQueue = softQueue + 8192
)

// Config configures a Link. Params must be valid.
type Config struct {
	Role    Role
	Params  apci.Params
	Name    string         // log prefix
	Logger  iec104.Logger  // nil disables logging
	Metrics iec104.Metrics // nil disables metrics

	// OnASDU receives the payload of every I frame, in order.
	OnASDU func(raw []byte)
	// OnState is called when data transfer starts or stops.
	OnState func(started bool)
	// OnClose is called exactly once, after every other callback returned.
	// err is iec104.ErrClosed when the local application closed the link.
	OnClose func(err error)
}

type dtState uint8

const (
	stopped dtState = iota
	starting
	started
	stopping
)

type sendReq struct {
	asdu []byte
	done chan error
}

type ctlReq struct {
	fn   apci.UFunction
	done chan error
}

type readResult struct {
	frame apci.Frame
	err   error
}

type pendingU struct {
	deadline time.Time
	waiters  []chan error
}

type eventKind uint8

const (
	evASDU eventKind = iota
	evState
	evClose
)

type event struct {
	kind    eventKind
	data    []byte
	started bool
	err     error
}

// Link is one IEC 60870-5-104 connection.
type Link struct {
	conn net.Conn
	cfg  Config

	sendCh  chan sendReq
	ctlCh   chan ctlReq
	frameCh chan readResult
	closeCh chan struct{}
	done    chan struct{}
	wake    chan struct{}

	closeOnce sync.Once
	isStarted atomic.Bool

	errMu sync.Mutex
	err   error

	qmu   sync.Mutex
	queue []event
	qsig  chan struct{}

	// Owned by the loop goroutine.
	state       dtState
	reported    bool // last data transfer state passed to OnState
	vs, vr, ack uint16
	unacked     []time.Time // send times of the outstanding I frames
	recvUnacked int
	sentNR      uint16 // last N(R) sent to the peer
	throttled   bool   // softQueue reached: acknowledgements are withheld
	t2At        time.Time
	idleAt      time.Time
	pending     map[apci.UFunction]*pendingU
	wbuf        []byte
}

// New starts the protocol machine on an established connection. The Link
// takes ownership of conn.
func New(conn net.Conn, cfg Config) *Link {
	l := &Link{
		conn:    conn,
		cfg:     cfg,
		sendCh:  make(chan sendReq),
		ctlCh:   make(chan ctlReq),
		frameCh: make(chan readResult, 64),
		closeCh: make(chan struct{}),
		done:    make(chan struct{}),
		wake:    make(chan struct{}, 1),
		qsig:    make(chan struct{}, 1),
		pending: make(map[apci.UFunction]*pendingU),
		wbuf:    make([]byte, 0, apci.MaxFrameLength),
	}
	l.idleAt = time.Now().Add(cfg.Params.T3)
	go l.read()
	go l.run()
	go l.dispatch()
	return l
}

// RemoteAddr returns the address of the peer.
func (l *Link) RemoteAddr() net.Addr { return l.conn.RemoteAddr() }

// LocalAddr returns the local address.
func (l *Link) LocalAddr() net.Addr { return l.conn.LocalAddr() }

// Started reports whether data transfer is started.
func (l *Link) Started() bool { return l.isStarted.Load() }

// Done is closed when the link has terminated.
func (l *Link) Done() <-chan struct{} { return l.done }

// Err returns why the link terminated, or nil while it is running.
func (l *Link) Err() error {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	return l.err
}

// Close terminates the link and closes the connection. It is idempotent and
// safe to call from a callback.
func (l *Link) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		// Unblocks a write the loop may be stuck in.
		_ = l.conn.Close()
	})
	<-l.done
	return nil
}

// Send transmits one ASDU in an I frame. It blocks while the send window is
// full (k unacknowledged frames) and returns once the frame was written, not
// when it was acknowledged.
func (l *Link) Send(ctx context.Context, asdu []byte) error {
	if len(asdu) > apci.MaxASDULength {
		return fmt.Errorf("%w: %d octets", apci.ErrASDUTooLong, len(asdu))
	}
	select {
	case <-l.done:
		return l.Err()
	default:
	}
	if !l.isStarted.Load() {
		return iec104.ErrNotStarted
	}
	r := sendReq{asdu: asdu, done: make(chan error, 1)}
	select {
	case l.sendCh <- r:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return l.Err()
	}
	return <-r.done
}

// StartDT sends STARTDT act and waits for its confirmation.
func (l *Link) StartDT(ctx context.Context) error { return l.control(ctx, apci.StartDTAct) }

// StopDT sends STOPDT act and waits for its confirmation.
func (l *Link) StopDT(ctx context.Context) error { return l.control(ctx, apci.StopDTAct) }

// TestFR sends TESTFR act and waits for its confirmation.
func (l *Link) TestFR(ctx context.Context) error { return l.control(ctx, apci.TestFRAct) }

func (l *Link) control(ctx context.Context, fn apci.UFunction) error {
	r := ctlReq{fn: fn, done: make(chan error, 1)}
	select {
	case l.ctlCh <- r:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return l.Err()
	}
	// The loop always answers an accepted request: with the confirmation,
	// or with the link error when it terminates first.
	select {
	case err := <-r.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- reader ---

func (l *Link) read() {
	br := bufio.NewReaderSize(l.conn, 4*apci.MaxFrameLength)
	for {
		f, err := apci.ReadFrame(br)
		select {
		case l.frameCh <- readResult{frame: f, err: err}:
		case <-l.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func readError(err error) error {
	switch {
	case errors.Is(err, apci.ErrInvalidStart), errors.Is(err, apci.ErrInvalidLength),
		errors.Is(err, apci.ErrInvalidControl):
		return fmt.Errorf("%w: %w", iec104.ErrProtocol, err)
	case errors.Is(err, io.EOF):
		return fmt.Errorf("%w: closed by peer", iec104.ErrConnectionLost)
	default:
		return fmt.Errorf("%w: %w", iec104.ErrConnectionLost, err)
	}
}

// --- loop ---

func (l *Link) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	var err error
	for err == nil {
		frameCh := l.frameCh
		queued := l.queueLen()
		if queued >= hardQueue {
			frameCh = nil
		}
		if l.throttled = queued >= softQueue; !l.throttled && l.recvUnacked >= l.cfg.Params.W {
			// Acknowledgements that were withheld while throttled.
			if err = l.sendS(); err != nil {
				break
			}
		}
		sendCh := l.sendCh
		if len(l.unacked) >= l.cfg.Params.K {
			sendCh = nil
		}
		timer.Reset(l.untilDeadline())

		select {
		case <-l.closeCh:
			err = iec104.ErrClosed
		case r := <-frameCh:
			if r.err != nil {
				err = readError(r.err)
			} else {
				err = l.onFrame(r.frame)
			}
		case r := <-sendCh:
			err = l.onSend(r)
		case r := <-l.ctlCh:
			err = l.onControl(r)
		case <-l.wake:
		case <-timer.C:
			err = l.onTimer(time.Now())
		}
	}
	select {
	case <-l.closeCh:
		// Close also closes the connection, which may surface first as a
		// read or write error.
		err = iec104.ErrClosed
	default:
	}
	l.shutdown(err)
}

func (l *Link) shutdown(err error) {
	l.errMu.Lock()
	l.err = err
	l.errMu.Unlock()
	l.isStarted.Store(false)
	_ = l.conn.Close()
	for _, p := range l.pending {
		for _, w := range p.waiters {
			w <- err
		}
	}
	close(l.done)
	switch {
	case errors.Is(err, iec104.ErrClosed):
		l.debugf("closed")
	case errors.Is(err, iec104.ErrConnectionLost):
		l.debugf("connection terminated: %v", err)
	default:
		l.warnf("connection terminated: %v", err)
	}
	l.push(event{kind: evClose, err: err})
}

func (l *Link) untilDeadline() time.Duration {
	p := l.cfg.Params
	var next time.Time
	consider := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	if len(l.unacked) > 0 {
		consider(l.unacked[0].Add(p.T1))
	}
	for _, u := range l.pending {
		consider(u.deadline)
	}
	if l.recvUnacked > 0 && !l.throttled {
		consider(l.t2At)
	}
	if p.T3 > 0 {
		consider(l.idleAt)
	}
	if next.IsZero() {
		return time.Hour
	}
	if d := time.Until(next); d > 0 {
		return d
	}
	return 0
}

func (l *Link) onTimer(now time.Time) error {
	p := l.cfg.Params
	if len(l.unacked) > 0 && !now.Before(l.unacked[0].Add(p.T1)) {
		return fmt.Errorf("%w: I frame N(S)=%d not acknowledged", iec104.ErrTimeout, l.ack)
	}
	for fn, u := range l.pending {
		if !now.Before(u.deadline) {
			return fmt.Errorf("%w: %s not confirmed", iec104.ErrTimeout, fn)
		}
	}
	if l.recvUnacked > 0 && !l.throttled && !now.Before(l.t2At) {
		if err := l.sendS(); err != nil {
			return err
		}
	}
	if p.T3 > 0 && !now.Before(l.idleAt) {
		l.idleAt = now.Add(p.T3)
		if _, busy := l.pending[apci.TestFRAct]; !busy {
			return l.sendAct(apci.TestFRAct, nil)
		}
	}
	return nil
}

func (l *Link) setState(s dtState) {
	l.state = s
	is := s == started
	l.isStarted.Store(is)
	// starting and stopping are transient: report only the settled states.
	if (s == started || s == stopped) && l.reported != is {
		l.reported = is
		l.push(event{kind: evState, started: is})
	}
}

func (l *Link) onSend(r sendReq) error {
	if l.state != started {
		r.done <- iec104.ErrNotStarted
		return nil
	}
	if !l.throttled {
		// The I frame carries N(R) and so acknowledges what was received.
		l.sentNR = l.vr
		l.recvUnacked = 0
	}
	if err := l.write(apci.NewI(l.vs, l.sentNR, r.asdu)); err != nil {
		r.done <- err
		return err
	}
	l.vs = apci.SeqNext(l.vs)
	l.unacked = append(l.unacked, time.Now())
	r.done <- nil
	return nil
}

func (l *Link) sendS() error {
	l.recvUnacked = 0
	l.sentNR = l.vr
	return l.write(apci.NewS(l.vr))
}

// sendAct writes a U activation and registers the wait for its confirmation.
func (l *Link) sendAct(fn apci.UFunction, waiter chan error) error {
	if u, ok := l.pending[fn]; ok {
		if waiter != nil {
			u.waiters = append(u.waiters, waiter)
		}
		return nil
	}
	if err := l.write(apci.NewU(fn)); err != nil {
		if waiter != nil {
			waiter <- err
		}
		return err
	}
	u := &pendingU{deadline: time.Now().Add(l.cfg.Params.T1)}
	if waiter != nil {
		u.waiters = append(u.waiters, waiter)
	}
	l.pending[fn] = u
	return nil
}

func (l *Link) confirm(act apci.UFunction) bool {
	u, ok := l.pending[act]
	if !ok {
		return false
	}
	delete(l.pending, act)
	for _, w := range u.waiters {
		w <- nil
	}
	return true
}

func (l *Link) onControl(r ctlReq) error {
	switch r.fn {
	case apci.StartDTAct, apci.StopDTAct:
		if l.cfg.Role != Controlling {
			r.done <- fmt.Errorf("%w: only the controlling station sends %s", iec104.ErrProtocol, r.fn)
			return nil
		}
		if r.fn == apci.StartDTAct {
			switch l.state {
			case started:
				r.done <- nil
				return nil
			case stopping:
				r.done <- fmt.Errorf("%w: STOPDT in progress", iec104.ErrBusy)
				return nil
			case stopped, starting:
			}
			l.state = starting
		} else {
			switch l.state {
			case stopped:
				r.done <- nil
				return nil
			case starting:
				r.done <- fmt.Errorf("%w: STARTDT in progress", iec104.ErrBusy)
				return nil
			case started, stopping:
			}
			// No further I frames once STOPDT act is on its way.
			l.state = stopping
			l.isStarted.Store(false)
		}
	case apci.TestFRAct:
	default:
		r.done <- fmt.Errorf("%w: %s", apci.ErrInvalidControl, r.fn)
		return nil
	}
	return l.sendAct(r.fn, r.done)
}

func (l *Link) onFrame(f apci.Frame) error {
	now := time.Now()
	l.idleAt = now.Add(l.cfg.Params.T3)
	if m := l.cfg.Metrics; m != nil {
		m.OnFrameReceived(l.conn.RemoteAddr(), f, f.Len())
	}
	if l.cfg.Logger != nil {
		l.debugf("<- %s", f)
	}

	switch f.Format {
	case apci.FormatS:
		return l.acknowledge(f.RecvSeq)
	case apci.FormatU:
		return l.onU(f.Function)
	case apci.FormatI:
	}

	if l.state == stopped || l.state == starting {
		return fmt.Errorf("%w: I frame received while data transfer is stopped", iec104.ErrProtocol)
	}
	if f.SendSeq != l.vr {
		return fmt.Errorf("%w: received N(S)=%d, expected %d", iec104.ErrProtocol, f.SendSeq, l.vr)
	}
	if err := l.acknowledge(f.RecvSeq); err != nil {
		return err
	}
	l.vr = apci.SeqNext(l.vr)
	l.recvUnacked++
	if l.recvUnacked == 1 {
		l.t2At = now.Add(l.cfg.Params.T2)
	}
	l.push(event{kind: evASDU, data: f.ASDU})
	if l.recvUnacked >= l.cfg.Params.W && !l.throttled {
		return l.sendS()
	}
	return nil
}

func (l *Link) acknowledge(nr uint16) error {
	n, ok := apci.SeqAcks(nr, l.ack, l.vs)
	if !ok {
		return fmt.Errorf("%w: received N(R)=%d, outstanding %d..%d", iec104.ErrProtocol, nr, l.ack, l.vs)
	}
	l.unacked = append(l.unacked[:0], l.unacked[n:]...)
	l.ack = nr
	return nil
}

func (l *Link) onU(fn apci.UFunction) error {
	switch fn {
	case apci.TestFRAct:
		return l.write(apci.NewU(apci.TestFRCon))
	case apci.TestFRCon:
		l.confirm(apci.TestFRAct)
		return nil

	case apci.StartDTAct, apci.StopDTAct:
		if l.cfg.Role != Controlled {
			l.warnf("ignoring %s from controlled station", fn)
			return nil
		}
		if fn == apci.StopDTAct && l.recvUnacked > 0 {
			if err := l.sendS(); err != nil {
				return err
			}
		}
		if err := l.write(apci.NewU(fn.Confirmation())); err != nil {
			return err
		}
		if fn == apci.StartDTAct {
			l.setState(started)
		} else {
			l.setState(stopped)
		}
		return nil

	case apci.StartDTCon:
		if _, ok := l.pending[apci.StartDTAct]; !ok {
			l.warnf("ignoring unsolicited %s", fn)
			return nil
		}
		l.setState(started)
		l.confirm(apci.StartDTAct)
		return nil

	case apci.StopDTCon:
		if _, ok := l.pending[apci.StopDTAct]; !ok {
			l.warnf("ignoring unsolicited %s", fn)
			return nil
		}
		if l.recvUnacked > 0 {
			if err := l.sendS(); err != nil {
				return err
			}
		}
		l.setState(stopped)
		l.confirm(apci.StopDTAct)
		return nil
	}
	return nil
}

func (l *Link) write(f apci.Frame) error {
	b, err := f.AppendBinary(l.wbuf[:0])
	if err != nil {
		return err
	}
	_ = l.conn.SetWriteDeadline(time.Now().Add(l.cfg.Params.T1))
	if _, err := l.conn.Write(b); err != nil {
		return fmt.Errorf("%w: %w", iec104.ErrConnectionLost, err)
	}
	if m := l.cfg.Metrics; m != nil {
		m.OnFrameSent(l.conn.RemoteAddr(), f, len(b))
	}
	if l.cfg.Logger != nil {
		l.debugf("-> %s", f)
	}
	return nil
}

// --- dispatcher ---

func (l *Link) queueLen() int {
	l.qmu.Lock()
	defer l.qmu.Unlock()
	return len(l.queue)
}

func (l *Link) push(ev event) {
	l.qmu.Lock()
	l.queue = append(l.queue, ev)
	l.qmu.Unlock()
	select {
	case l.qsig <- struct{}{}:
	default:
	}
}

func (l *Link) pop() event {
	for {
		l.qmu.Lock()
		if n := len(l.queue); n > 0 {
			ev := l.queue[0]
			l.queue[0] = event{}
			l.queue = l.queue[1:]
			if n == 1 {
				l.queue = nil
			}
			l.qmu.Unlock()
			if n == softQueue || n == hardQueue {
				// The loop changes its behaviour at these levels: let it
				// look again.
				select {
				case l.wake <- struct{}{}:
				default:
				}
			}
			return ev
		}
		l.qmu.Unlock()
		<-l.qsig
	}
}

func (l *Link) dispatch() {
	for {
		switch ev := l.pop(); ev.kind {
		case evASDU:
			if l.cfg.OnASDU != nil {
				l.cfg.OnASDU(ev.data)
			}
		case evState:
			if l.cfg.OnState != nil {
				l.cfg.OnState(ev.started)
			}
		case evClose:
			if l.cfg.OnClose != nil {
				l.cfg.OnClose(ev.err)
			}
			return
		}
	}
}

func (l *Link) debugf(format string, args ...any) {
	if l.cfg.Logger != nil {
		l.cfg.Logger.Debugf(l.cfg.Name+": "+format, args...)
	}
}

func (l *Link) warnf(format string, args ...any) {
	if l.cfg.Logger != nil {
		l.cfg.Logger.Warnf(l.cfg.Name+": "+format, args...)
	}
}
