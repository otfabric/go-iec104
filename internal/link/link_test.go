// SPDX-License-Identifier: MIT

package link

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/internal/logx"
)

// peer is a scripted remote station speaking raw APDUs.
type peer struct {
	t    *testing.T
	conn net.Conn
}

func (p *peer) send(f apci.Frame) {
	p.t.Helper()
	b, err := f.MarshalBinary()
	if err != nil {
		p.t.Fatalf("peer marshal: %v", err)
	}
	if _, err := p.conn.Write(b); err != nil {
		p.t.Fatalf("peer write: %v", err)
	}
}

func (p *peer) read() apci.Frame {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := apci.ReadFrame(p.conn)
	if err != nil {
		p.t.Fatalf("peer read: %v", err)
	}
	return f
}

func (p *peer) expectU(fn apci.UFunction) {
	p.t.Helper()
	if f := p.read(); f.Format != apci.FormatU || f.Function != fn {
		p.t.Fatalf("peer got %s, want U %s", f, fn)
	}
}

func (p *peer) expectS(nr uint16) {
	p.t.Helper()
	if f := p.read(); f.Format != apci.FormatS || f.RecvSeq != nr {
		p.t.Fatalf("peer got %s, want S N(R)=%d", f, nr)
	}
}

func (p *peer) expectI(ns, nr uint16) apci.Frame {
	p.t.Helper()
	f := p.read()
	if f.Format != apci.FormatI || f.SendSeq != ns || f.RecvSeq != nr {
		p.t.Fatalf("peer got %s, want I N(S)=%d N(R)=%d", f, ns, nr)
	}
	return f
}

// recorder collects the callbacks of a link.
type recorder struct {
	mu     sync.Mutex
	asdus  [][]byte
	states []bool
	closed chan error
	gate   chan struct{} // when not nil, OnASDU blocks on it
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.asdus)
}

func fastParams() apci.Params {
	return apci.Params{K: 12, W: 8, T0: time.Second, T1: 2 * time.Second, T2: time.Second, T3: 0}
}

func setup(t *testing.T, role Role, params apci.Params, mutate ...func(*recorder)) (*Link, *peer, *recorder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	local, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}

	rec := &recorder{closed: make(chan error, 1)}
	for _, m := range mutate {
		m(rec)
	}
	l := New(local, Config{
		Role:   role,
		Params: params,
		Log:    logx.New(iec104.NopLogger(), "test"),
		OnASDU: func(raw []byte) {
			if rec.gate != nil {
				<-rec.gate
			}
			rec.mu.Lock()
			rec.asdus = append(rec.asdus, raw)
			rec.mu.Unlock()
		},
		OnState: func(started bool) {
			rec.mu.Lock()
			rec.states = append(rec.states, started)
			rec.mu.Unlock()
		},
		OnClose: func(err error) { rec.closed <- err },
	})
	t.Cleanup(func() {
		_ = l.Close()
		_ = r.c.Close()
	})
	return l, &peer{t: t, conn: r.c}, rec
}

func waitClosed(t *testing.T, l *Link, rec *recorder, want error) {
	t.Helper()
	select {
	case err := <-rec.closed:
		if !errors.Is(err, want) {
			t.Fatalf("OnClose error = %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("link did not terminate")
	}
	<-l.Done()
	if err := l.Err(); !errors.Is(err, want) {
		t.Fatalf("Err = %v, want %v", err, want)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// start brings a controlling link into the started state.
func start(t *testing.T, l *Link, p *peer) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- l.StartDT(context.Background()) }()
	p.expectU(apci.StartDTAct)
	p.send(apci.NewU(apci.StartDTCon))
	if err := <-errc; err != nil {
		t.Fatalf("StartDT: %v", err)
	}
	if !l.Started() {
		t.Fatal("not started after STARTDT con")
	}
}

func TestStartSendStop(t *testing.T) {
	l, p, rec := setup(t, Controlling, fastParams())
	ctx := context.Background()

	if err := l.Send(ctx, []byte{1}); !errors.Is(err, iec104.ErrNotStarted) {
		t.Fatalf("Send before STARTDT: %v", err)
	}
	start(t, l, p)
	if err := l.StartDT(ctx); err != nil {
		t.Fatalf("second StartDT: %v", err)
	}

	if err := l.Send(ctx, []byte{0xAA}); err != nil {
		t.Fatal(err)
	}
	if f := p.expectI(0, 0); len(f.ASDU) != 1 || f.ASDU[0] != 0xAA {
		t.Fatalf("payload % X", f.ASDU)
	}
	p.send(apci.NewI(0, 1, []byte{0xBB}))
	p.send(apci.NewI(1, 1, []byte{0xCC}))
	eventually(t, "two ASDUs", func() bool { return rec.count() == 2 })

	// The next I frame acknowledges both and so needs no S frame.
	if err := l.Send(ctx, []byte{0xDD}); err != nil {
		t.Fatal(err)
	}
	p.expectI(1, 2)
	p.send(apci.NewI(2, 2, []byte{0xEE}))
	eventually(t, "third ASDU", func() bool { return rec.count() == 3 })

	errc := make(chan error, 1)
	go func() { errc <- l.StopDT(ctx) }()
	p.expectS(3) // what was received is acknowledged before STOPDT act
	p.expectU(apci.StopDTAct)
	p.send(apci.NewU(apci.StopDTCon))
	if err := <-errc; err != nil {
		t.Fatalf("StopDT: %v", err)
	}
	if l.Started() {
		t.Fatal("still started after STOPDT con")
	}
	if err := l.StopDT(ctx); err != nil {
		t.Fatalf("second StopDT: %v", err)
	}
	if err := l.Send(ctx, []byte{1}); !errors.Is(err, iec104.ErrNotStarted) {
		t.Fatalf("Send after STOPDT: %v", err)
	}
	eventually(t, "state callbacks", func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.states) == 2 && rec.states[0] && !rec.states[1]
	})

	if l.RemoteAddr() == nil || l.LocalAddr() == nil {
		t.Error("addresses")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, l, rec, iec104.ErrClosed)
	if err := l.Send(ctx, []byte{1}); !errors.Is(err, iec104.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
	if err := l.TestFR(ctx); !errors.Is(err, iec104.ErrClosed) {
		t.Fatalf("TestFR after Close: %v", err)
	}
}

func TestControlledStation(t *testing.T) {
	l, p, rec := setup(t, Controlled, fastParams())
	ctx := context.Background()

	if err := l.StartDT(ctx); !errors.Is(err, iec104.ErrProtocol) {
		t.Fatalf("StartDT on controlled station: %v", err)
	}
	p.send(apci.NewU(apci.TestFRAct))
	p.expectU(apci.TestFRCon)

	p.send(apci.NewU(apci.StartDTAct))
	p.expectU(apci.StartDTCon)
	eventually(t, "started", l.Started)
	p.send(apci.NewU(apci.StartDTAct)) // repeated STARTDT is confirmed again
	p.expectU(apci.StartDTCon)

	p.send(apci.NewI(0, 0, []byte{1}))
	eventually(t, "ASDU", func() bool { return rec.count() == 1 })
	if err := l.Send(ctx, []byte{2}); err != nil {
		t.Fatal(err)
	}
	p.expectI(0, 1)
	p.send(apci.NewI(1, 1, []byte{3}))

	p.send(apci.NewU(apci.StopDTAct))
	p.expectS(2) // pending acknowledgement goes out before the confirmation
	p.expectU(apci.StopDTCon)
	eventually(t, "stopped", func() bool { return !l.Started() })

	// Unsolicited confirmations are ignored; the link stays up.
	p.send(apci.NewU(apci.StartDTCon))
	p.send(apci.NewU(apci.StopDTCon))
	p.send(apci.NewU(apci.TestFRCon))
	p.send(apci.NewU(apci.TestFRAct))
	p.expectU(apci.TestFRCon)
	if l.Started() || l.Err() != nil {
		t.Fatalf("started=%v err=%v after unsolicited confirmations", l.Started(), l.Err())
	}
}

func TestTestFR(t *testing.T) {
	l, p, _ := setup(t, Controlling, fastParams())
	errc := make(chan error, 2)
	go func() { errc <- l.TestFR(context.Background()) }()
	p.expectU(apci.TestFRAct)
	go func() { errc <- l.TestFR(context.Background()) }() // joins the pending test
	time.Sleep(50 * time.Millisecond)
	p.send(apci.NewU(apci.TestFRCon))
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("TestFR: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.TestFR(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TestFR with expired context: %v", err)
	}
	p.expectU(apci.TestFRAct)
	// STARTDT from a controlled station is ignored by a controlling one.
	p.send(apci.NewU(apci.StartDTAct))
	p.send(apci.NewU(apci.TestFRCon))
	p.send(apci.NewU(apci.TestFRAct))
	p.expectU(apci.TestFRCon)
	if l.Started() {
		t.Fatal("controlling station started by its peer")
	}
}

func TestAckWindowW(t *testing.T) {
	params := fastParams()
	params.W = 3
	l, p, _ := setup(t, Controlling, params)
	start(t, l, p)
	for i := uint16(0); i < 6; i++ {
		p.send(apci.NewI(i, 0, []byte{byte(i)}))
		if i%3 == 2 {
			p.expectS(i + 1)
		}
	}
}

func TestAckTimerT2(t *testing.T) {
	params := fastParams()
	params.T2 = 150 * time.Millisecond
	l, p, _ := setup(t, Controlling, params)
	start(t, l, p)
	begin := time.Now()
	p.send(apci.NewI(0, 0, []byte{1}))
	p.expectS(1)
	if d := time.Since(begin); d < 100*time.Millisecond || d > 2*time.Second {
		t.Errorf("S frame after %s, want about t2 (150ms)", d)
	}
}

func TestSendWindowK(t *testing.T) {
	params := fastParams()
	params.K, params.W = 2, 1
	l, p, _ := setup(t, Controlling, params)
	start(t, l, p)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := l.Send(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := l.Send(short, []byte{9}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send with full window: %v, want deadline exceeded", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- l.Send(ctx, []byte{2}) }()
	p.expectI(0, 0)
	p.expectI(1, 0)
	p.send(apci.NewS(1)) // frees one slot
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	p.expectI(2, 0)
	if err := l.Send(ctx, make([]byte, apci.MaxASDULength+1)); !errors.Is(err, apci.ErrASDUTooLong) {
		t.Fatalf("oversized ASDU: %v", err)
	}
}

func TestT1UnacknowledgedIFrame(t *testing.T) {
	params := fastParams()
	params.T1, params.T2 = 200*time.Millisecond, 100*time.Millisecond
	l, p, rec := setup(t, Controlling, params)
	start(t, l, p)
	if err := l.Send(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	p.expectI(0, 0)
	waitClosed(t, l, rec, iec104.ErrTimeout)
}

func TestT1UnconfirmedStartDT(t *testing.T) {
	params := fastParams()
	params.T1, params.T2 = 200*time.Millisecond, 100*time.Millisecond
	l, p, rec := setup(t, Controlling, params)
	errc := make(chan error, 1)
	go func() { errc <- l.StartDT(context.Background()) }()
	p.expectU(apci.StartDTAct)
	if err := <-errc; !errors.Is(err, iec104.ErrTimeout) {
		t.Fatalf("StartDT: %v, want ErrTimeout", err)
	}
	waitClosed(t, l, rec, iec104.ErrTimeout)
}

func TestIdleTestT3(t *testing.T) {
	params := fastParams()
	params.T1, params.T2, params.T3 = 300*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	l, p, rec := setup(t, Controlled, params)
	p.expectU(apci.TestFRAct)
	p.send(apci.NewU(apci.TestFRCon))
	p.expectU(apci.TestFRAct) // idle again
	// No confirmation this time: t1 closes the connection.
	waitClosed(t, l, rec, iec104.ErrTimeout)
}

func TestProtocolViolations(t *testing.T) {
	tests := []struct {
		name    string
		started bool
		inject  func(p *peer)
		want    error
	}{
		{"wrong N(S)", true, func(p *peer) { p.send(apci.NewI(5, 0, []byte{1})) }, iec104.ErrProtocol},
		{"N(R) ahead in I frame", true, func(p *peer) { p.send(apci.NewI(0, 3, []byte{1})) }, iec104.ErrProtocol},
		{"N(R) ahead in S frame", true, func(p *peer) { p.send(apci.NewS(7)) }, iec104.ErrProtocol},
		{"I frame while stopped", false, func(p *peer) { p.send(apci.NewI(0, 0, []byte{1})) }, iec104.ErrProtocol},
		{"garbage", true, func(p *peer) { _, _ = p.conn.Write([]byte{0x00, 0x01, 0x02}) }, iec104.ErrProtocol},
		{"bad U frame", true, func(p *peer) { _, _ = p.conn.Write([]byte{0x68, 0x04, 0xFF, 0, 0, 0}) }, iec104.ErrProtocol},
		{"peer closes", true, func(p *peer) { _ = p.conn.Close() }, iec104.ErrConnectionLost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, p, rec := setup(t, Controlling, fastParams())
			if tt.started {
				start(t, l, p)
			}
			tt.inject(p)
			waitClosed(t, l, rec, tt.want)
		})
	}
}

func TestPendingControlFailsOnClose(t *testing.T) {
	l, p, rec := setup(t, Controlling, fastParams())
	errc := make(chan error, 1)
	go func() { errc <- l.StartDT(context.Background()) }()
	p.expectU(apci.StartDTAct)
	_ = p.conn.Close()
	if err := <-errc; !errors.Is(err, iec104.ErrConnectionLost) {
		t.Fatalf("StartDT: %v, want ErrConnectionLost", err)
	}
	waitClosed(t, l, rec, iec104.ErrConnectionLost)
}

func TestStartStopInterlock(t *testing.T) {
	l, p, _ := setup(t, Controlling, fastParams())
	ctx := context.Background()
	startc := make(chan error, 1)
	go func() { startc <- l.StartDT(ctx) }()
	p.expectU(apci.StartDTAct)
	if err := l.StopDT(ctx); !errors.Is(err, iec104.ErrBusy) {
		t.Fatalf("StopDT during STARTDT: %v, want ErrBusy", err)
	}
	p.send(apci.NewU(apci.StartDTCon))
	if err := <-startc; err != nil {
		t.Fatal(err)
	}
	stopc := make(chan error, 1)
	go func() { stopc <- l.StopDT(ctx) }()
	p.expectU(apci.StopDTAct)
	if err := l.StartDT(ctx); !errors.Is(err, iec104.ErrBusy) {
		t.Fatalf("StartDT during STOPDT: %v, want ErrBusy", err)
	}
	// I frames still in flight are accepted until STOPDT con, and
	// acknowledged at once: the peer waits for that before it confirms.
	p.send(apci.NewI(0, 0, []byte{1}))
	p.expectS(1)
	p.send(apci.NewU(apci.StopDTCon))
	if err := <-stopc; err != nil {
		t.Fatal(err)
	}
}

// A controlled station confirms STOPDT only after the controlling station
// has acknowledged every I frame it was sent.
func TestStopDTWaitsForAcknowledgement(t *testing.T) {
	l, p, rec := setup(t, Controlled, fastParams())
	ctx := context.Background()
	p.send(apci.NewU(apci.StartDTAct))
	p.expectU(apci.StartDTCon)
	eventually(t, "started", l.Started)
	for i := 0; i < 3; i++ {
		if err := l.Send(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		p.expectI(uint16(i), 0)
	}

	p.send(apci.NewU(apci.StopDTAct))
	eventually(t, "sending stopped", func() bool { return !l.Started() })
	if err := l.Send(ctx, []byte{9}); !errors.Is(err, iec104.ErrNotStarted) {
		t.Fatalf("Send while STOPDT is pending: %v", err)
	}
	// A partial acknowledgement is not enough.
	p.send(apci.NewS(2))
	_ = p.conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if f, err := apci.ReadFrame(p.conn); err == nil {
		t.Fatalf("peer got %s before it acknowledged everything", f)
	}
	rec.mu.Lock()
	states := len(rec.states)
	rec.mu.Unlock()
	if states != 1 {
		t.Fatalf("%d state changes reported, want only the start", states)
	}
	p.send(apci.NewS(3))
	p.expectU(apci.StopDTCon)
	eventually(t, "stop reported", func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.states) == 2 && !rec.states[1]
	})

	// STARTDT while a STOPDT is pending cancels it.
	p.send(apci.NewU(apci.StartDTAct))
	p.expectU(apci.StartDTCon)
	eventually(t, "started again", l.Started)
	if err := l.Send(ctx, []byte{1}); err != nil {
		t.Fatal(err)
	}
	p.expectI(3, 0)
	p.send(apci.NewU(apci.StopDTAct))
	p.send(apci.NewU(apci.StartDTAct))
	p.expectU(apci.StartDTCon)
	p.send(apci.NewS(4))
	p.send(apci.NewU(apci.TestFRAct))
	p.expectU(apci.TestFRCon) // no STOPDT con in between
	if !l.Started() {
		t.Fatal("STARTDT did not cancel the pending STOPDT")
	}
}

// Without the acknowledgement the pending STOPDT ends in t1.
func TestStopDTPendingTimesOut(t *testing.T) {
	params := fastParams()
	params.T1, params.T2 = 300*time.Millisecond, 100*time.Millisecond
	l, p, rec := setup(t, Controlled, params)
	p.send(apci.NewU(apci.StartDTAct))
	p.expectU(apci.StartDTCon)
	eventually(t, "started", l.Started)
	if err := l.Send(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	p.expectI(0, 0)
	p.send(apci.NewU(apci.StopDTAct))
	waitClosed(t, l, rec, iec104.ErrTimeout)
}

// A callback that stalls must not grow the receive queue without bound.
// First the link stops acknowledging, which stops a conformant peer after k
// frames; a peer that keeps sending regardless is stopped through TCP.
func TestReceiveBackpressure(t *testing.T) {
	params := fastParams()
	params.W = 4
	gate := make(chan struct{})
	l, p, rec := setup(t, Controlling, params, func(r *recorder) { r.gate = gate })
	start(t, l, p)

	const n = hardQueue + 500
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			b, _ := apci.NewI(uint16(i), 0, []byte{byte(i), byte(i >> 8)}).MarshalBinary()
			if _, err := p.conn.Write(b); err != nil {
				return
			}
		}
	}()

	// Acknowledgements stop at the soft limit: the last S frame covers at
	// most the frames that were queued when it was reached.
	var acked uint16
	for acked+uint16(params.W) <= softQueue {
		f := p.read()
		if f.Format != apci.FormatS {
			t.Fatalf("peer got %s, want an S frame", f)
		}
		acked = f.RecvSeq
	}
	eventually(t, "queue to fill", func() bool { return l.queueLen() >= hardQueue })
	time.Sleep(50 * time.Millisecond)
	if q := l.queueLen(); q > hardQueue+2 {
		t.Fatalf("queue grew to %d, limit %d", q, hardQueue)
	}
	_ = p.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if f, err := apci.ReadFrame(p.conn); err == nil {
		t.Fatalf("peer got %s while the link is throttled (last acknowledged %d)", f, acked)
	}

	close(gate)
	<-done
	eventually(t, "all ASDUs", func() bool { return rec.count() == n })
	rec.mu.Lock()
	for i, a := range rec.asdus {
		if int(a[0])|int(a[1])<<8 != i {
			t.Fatalf("ASDU %d out of order", i)
		}
	}
	rec.mu.Unlock()
	// Once the callback caught up everything is acknowledged.
	for acked != n {
		f := p.read()
		if f.Format != apci.FormatS || apci.SeqDiff(f.RecvSeq, acked) > n {
			t.Fatalf("peer got %s after N(R)=%d", f, acked)
		}
		acked = f.RecvSeq
	}
}

// While acknowledgements are withheld the link still processes what the peer
// sends, so a callback blocked in Send on a full window is released.
func TestThrottledLinkStillProcessesAcks(t *testing.T) {
	params := fastParams()
	params.K = 2
	gate := make(chan struct{})
	l, p, rec := setup(t, Controlling, params, func(r *recorder) { r.gate = gate })
	start(t, l, p)
	ctx := context.Background()

	for i := 0; i < softQueue+10; i++ {
		p.send(apci.NewI(uint16(i), 0, []byte{1}))
	}
	eventually(t, "soft limit", func() bool { return l.queueLen() >= softQueue })
	for i := 0; i < 2; i++ {
		if err := l.Send(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- l.Send(ctx, []byte{2}) }() // window full
	// Drain what the link sent; its I frames must not acknowledge more than
	// was acknowledged before the limit.
	var first apci.Frame
	for first = p.read(); first.Format == apci.FormatS; first = p.read() {
	}
	if first.Format != apci.FormatI || first.SendSeq != 0 || first.RecvSeq > softQueue {
		t.Fatalf("peer got %s", first)
	}
	p.expectI(1, first.RecvSeq)
	p.send(apci.NewS(2))
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Send not released by an acknowledgement while throttled")
	}
	close(gate)
	eventually(t, "all ASDUs", func() bool { return rec.count() == softQueue+10 })
}

// Writes that fail end the link and are reported to the caller that
// triggered them.
func TestWriteFailures(t *testing.T) {
	t.Run("send", func(t *testing.T) {
		l, p, rec := setup(t, Controlling, fastParams())
		start(t, l, p)
		_ = l.conn.(*net.TCPConn).CloseWrite()
		if err := l.Send(context.Background(), []byte{1}); !errors.Is(err, iec104.ErrConnectionLost) {
			t.Fatalf("Send on a connection closed for writing: %v", err)
		}
		waitClosed(t, l, rec, iec104.ErrConnectionLost)
	})
	t.Run("control", func(t *testing.T) {
		l, _, rec := setup(t, Controlling, fastParams())
		_ = l.conn.(*net.TCPConn).CloseWrite()
		if err := l.StartDT(context.Background()); !errors.Is(err, iec104.ErrConnectionLost) {
			t.Fatalf("StartDT on a connection closed for writing: %v", err)
		}
		waitClosed(t, l, rec, iec104.ErrConnectionLost)
	})
	t.Run("oversized", func(t *testing.T) {
		l, p, _ := setup(t, Controlling, fastParams())
		start(t, l, p)
		if err := l.Send(context.Background(), make([]byte, apci.MaxASDULength+1)); !errors.Is(err, apci.ErrASDUTooLong) {
			t.Fatalf("oversized ASDU: %v", err)
		}
	})
}

// A context that ends while a request waits for the loop is honoured.
func TestCancelledContexts(t *testing.T) {
	params := fastParams()
	params.K, params.W = 1, 1
	l, p, _ := setup(t, Controlling, params)
	start(t, l, p)
	if err := l.Send(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Send(done, []byte{2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send with a full window and a cancelled context: %v", err)
	}
	// An invalid control function never reaches the wire.
	if err := l.control(context.Background(), apci.StartDTCon); !errors.Is(err, apci.ErrInvalidControl) {
		t.Fatalf("control with a confirmation: %v", err)
	}
}
