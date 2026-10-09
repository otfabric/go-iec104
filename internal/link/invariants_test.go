// SPDX-License-Identifier: MIT

package link

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/internal/logx"
)

// These tests are about ordering: what a link has already done to its own
// state at the moment a frame leaves it, and at the moment a call returns.
// The peer acts on a frame as soon as it has it, so "sent, then updated" is
// a window in which the two sides disagree, however short.

// watched is a connection that looks at every frame its link writes, before
// the frame is on the wire and on the goroutine that writes it.
type watched struct {
	net.Conn
	link  atomic.Pointer[Link]
	check func(l *Link, f apci.Frame) error

	mu   sync.Mutex
	errs []error
}

func (w *watched) Write(b []byte) (int, error) {
	if l := w.link.Load(); l != nil {
		f, err := apci.Parse(b)
		if err == nil {
			err = w.check(l, f)
		} else {
			err = fmt.Errorf("the link wrote something that is not one frame: %w", err)
		}
		if err != nil {
			w.mu.Lock()
			w.errs = append(w.errs, err)
			w.mu.Unlock()
		}
	}
	return w.Conn.Write(b)
}

func (w *watched) violations() []error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]error(nil), w.errs...)
}

// stateAtWrite is the rule for every frame a link sends, by role.
func stateAtWrite(r Role) func(l *Link, f apci.Frame) error {
	role := "controlled"
	if r == Controlling {
		role = "controlling"
	}
	return func(l *Link, f apci.Frame) error {
		started := l.Started()
		switch {
		case f.Format == apci.FormatI && !started:
			return errors.New("an I frame leaves a link that is not started")
		case f.Format != apci.FormatU:
			return nil
		}
		switch f.Function {
		case apci.StartDTCon:
			if r != Controlled || !started {
				return fmt.Errorf("STARTDT con leaves a %s link whose Started() is %v", role, started)
			}
		case apci.StopDTCon:
			if r != Controlled || started {
				return fmt.Errorf("STOPDT con leaves a %s link whose Started() is %v", role, started)
			}
		case apci.StartDTAct, apci.StopDTAct:
			// From STARTDT act until its confirmation, and from STOPDT act
			// on, the controlling station sends no I frames.
			if r != Controlling || started {
				return fmt.Errorf("%s leaves a %s link whose Started() is %v", f.Function, role, started)
			}
		default:
			// Test frames go out in every state.
		}
		return nil
	}
}

// end is one side of a pair of links and what it observed.
type end struct {
	link *Link
	conn *watched

	mu     sync.Mutex
	got    []uint32 // payloads received, in order
	states []bool   // OnState reports, in order
	closed error
	done   chan struct{}
}

func (e *end) snapshot() (got []uint32, states []bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]uint32(nil), e.got...), append([]bool(nil), e.states...)
}

// pair connects a controlling and a controlled link over TCP.
func pair(t *testing.T, params apci.Params) (ctl, ctd *end) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	local, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	remote := <-accepted
	if remote == nil {
		t.Fatal("accept failed")
	}
	mk := func(conn net.Conn, role Role) *end {
		e := &end{conn: &watched{Conn: conn, check: stateAtWrite(role)}, done: make(chan struct{})}
		l := New(e.conn, Config{
			Role:   role,
			Params: params,
			Log:    logx.New(iec104.NopLogger(), "test"),
			OnASDU: func(raw []byte) {
				e.mu.Lock()
				e.got = append(e.got, binary.BigEndian.Uint32(raw))
				e.mu.Unlock()
			},
			OnState: func(started bool) {
				e.mu.Lock()
				e.states = append(e.states, started)
				e.mu.Unlock()
			},
			OnClose: func(err error) {
				e.mu.Lock()
				e.closed = err
				e.mu.Unlock()
				close(e.done)
			},
		})
		e.link = l
		e.conn.link.Store(l)
		return e
	}
	ctd = mk(remote, Controlled)
	ctl = mk(local, Controlling)
	t.Cleanup(func() {
		_ = ctl.link.Close()
		_ = ctd.link.Close()
	})
	return ctl, ctd
}

func payload(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

// The state a controlled station reports has changed before its
// confirmation is on the wire, in both directions, every time.
func TestStateChangesBeforeConfirmation(t *testing.T) {
	ctl, ctd := pair(t, fastParams())
	ctx := context.Background()
	for i := 0; i < 500; i++ {
		if err := ctl.link.StartDT(ctx); err != nil {
			t.Fatalf("cycle %d: StartDT: %v", i, err)
		}
		// The call returned: the confirmation arrived, so both are started.
		if !ctl.link.Started() || !ctd.link.Started() {
			t.Fatalf("cycle %d: after StartDT returned: controlling %v, controlled %v",
				i, ctl.link.Started(), ctd.link.Started())
		}
		// And a frame can go either way at once.
		if err := ctd.link.Send(ctx, payload(uint32(i))); err != nil {
			t.Fatalf("cycle %d: controlled Send right after STARTDT con: %v", i, err)
		}
		if err := ctl.link.Send(ctx, payload(uint32(i))); err != nil {
			t.Fatalf("cycle %d: controlling Send right after STARTDT con: %v", i, err)
		}
		if err := ctl.link.StopDT(ctx); err != nil {
			t.Fatalf("cycle %d: StopDT: %v", i, err)
		}
		if ctl.link.Started() || ctd.link.Started() {
			t.Fatalf("cycle %d: after StopDT returned: controlling %v, controlled %v",
				i, ctl.link.Started(), ctd.link.Started())
		}
		if err := ctd.link.Send(ctx, payload(0)); !errors.Is(err, iec104.ErrNotStarted) {
			t.Fatalf("cycle %d: controlled Send right after STOPDT con: %v", i, err)
		}
		if err := ctl.link.Send(ctx, payload(0)); !errors.Is(err, iec104.ErrNotStarted) {
			t.Fatalf("cycle %d: controlling Send right after STOPDT con: %v", i, err)
		}
	}
	for _, e := range []*end{ctl, ctd} {
		for _, err := range e.conn.violations() {
			t.Error(err)
		}
	}
	// What was sent in a started period arrived, all of it, in order.
	eventually(t, "every frame delivered", func() bool {
		a, _ := ctl.snapshot()
		b, _ := ctd.snapshot()
		return len(a) == 500 && len(b) == 500
	})
	for name, e := range map[string]*end{"controlling": ctl, "controlled": ctd} {
		got, _ := e.snapshot()
		for i, v := range got {
			if v != uint32(i) {
				t.Fatalf("%s: frame %d arrived as %d", name, i, v)
			}
		}
		eventually(t, "every state reported", func() bool { _, s := e.snapshot(); return len(s) == 1000 })
		_, states := e.snapshot()
		for i, s := range states {
			if s != (i%2 == 0) {
				t.Fatalf("%s: state report %d is %v: reports do not alternate from started", name, i, s)
			}
		}
	}
}

// Both applications do what they like, at once: start and stop on one side,
// sending on both. Whatever the interleaving, the two protocol machines stay
// in step: no frame leaves in the wrong state, neither side sees a protocol
// violation, and every frame a Send accepted arrives, once and in order.
func TestRandomStartStopSend(t *testing.T) {
	tight := fastParams()
	tight.K, tight.W = 1, 1
	small := fastParams()
	small.K, small.W = 3, 2
	for name, params := range map[string]apci.Params{"default windows": fastParams(), "k=w=1": tight, "k=3 w=2": small} {
		t.Run(name, func(t *testing.T) {
			for seed := int64(1); seed <= 4; seed++ {
				randomStartStopSend(t, params, seed)
			}
		})
	}
}

func randomStartStopSend(t *testing.T, params apci.Params, seed int64) {
	t.Helper()
	ctl, ctd := pair(t, params)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stop := make(chan struct{})
	var wg, drivers sync.WaitGroup

	// sender sends numbered frames and remembers which were accepted.
	sender := func(e *end, seed int64) *[]uint32 {
		var sent []uint32
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for n := uint32(0); ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				switch err := e.link.Send(ctx, payload(n)); {
				case err == nil:
					sent = append(sent, n)
				case errors.Is(err, iec104.ErrNotStarted):
				default:
					t.Errorf("Send: %v", err)
					return
				}
				if rng.Intn(4) == 0 {
					time.Sleep(time.Duration(rng.Intn(200)) * time.Microsecond)
				}
			}
		}()
		return &sent
	}
	fromCtl := sender(ctl, seed)
	fromCtd := sender(ctd, seed+100)

	// Two drivers race each other over STARTDT and STOPDT.
	var starts, stops atomic.Int64
	for d := int64(0); d < 2; d++ {
		drivers.Add(1)
		go func() {
			defer drivers.Done()
			rng := rand.New(rand.NewSource(seed*10 + d))
			for i := 0; i < 150; i++ {
				var err error
				if rng.Intn(2) == 0 {
					if err = ctl.link.StartDT(ctx); err == nil {
						starts.Add(1)
					}
				} else {
					if err = ctl.link.StopDT(ctx); err == nil {
						stops.Add(1)
					}
				}
				// One transition at a time: the other driver was in the way.
				if err != nil && !errors.Is(err, iec104.ErrBusy) {
					t.Errorf("driver: %v", err)
					return
				}
				time.Sleep(time.Duration(rng.Intn(300)) * time.Microsecond)
			}
		}()
	}
	drivers.Wait()
	// Settle in the started state, let the senders run a little longer, and
	// stop them: everything in flight can then be delivered.
	if err := ctl.link.StartDT(ctx); err != nil {
		t.Fatalf("seed %d: final StartDT: %v", seed, err)
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
	if starts.Load() < 10 || stops.Load() < 10 {
		t.Fatalf("seed %d: only %d starts and %d stops succeeded", seed, starts.Load(), stops.Load())
	}

	for name, e := range map[string]*end{"controlling": ctl, "controlled": ctd} {
		select {
		case <-e.done:
			t.Fatalf("seed %d: the %s link ended: %v", seed, name, e.closed)
		default:
		}
		for _, err := range e.conn.violations() {
			t.Errorf("seed %d: %s: %v", seed, name, err)
		}
	}
	same := func(what string, sent *[]uint32, receiver *end) {
		t.Helper()
		eventually(t, what, func() bool { got, _ := receiver.snapshot(); return len(got) >= len(*sent) })
		got, _ := receiver.snapshot()
		if len(got) != len(*sent) {
			t.Fatalf("seed %d: %s: %d frames accepted by Send, %d delivered", seed, what, len(*sent), len(got))
		}
		for i, v := range got {
			if v != (*sent)[i] {
				t.Fatalf("seed %d: %s: delivery %d is frame %d, want %d", seed, what, i, v, (*sent)[i])
			}
		}
	}
	same("controlling to controlled", fromCtl, ctd)
	same("controlled to controlling", fromCtd, ctl)

	// Both sides lived through the same sequence of settled states.
	eventually(t, "state reports in step", func() bool {
		_, a := ctl.snapshot()
		_, b := ctd.snapshot()
		return len(a) == len(b) && len(a) > 0 && a[len(a)-1]
	})
	_, a := ctl.snapshot()
	_, b := ctd.snapshot()
	for i := range a {
		if a[i] != b[i] || a[i] != (i%2 == 0) {
			t.Fatalf("seed %d: state reports differ or do not alternate: controlling %v, controlled %v", seed, a, b)
		}
	}
	if len(*fromCtl) == 0 || len(*fromCtd) == 0 || len(a) < 3 {
		t.Fatalf("seed %d: the run exercised too little: %d and %d frames, %d state changes",
			seed, len(*fromCtl), len(*fromCtd), len(a))
	}
}

// A link that is going down is not "stopped". Whatever the moment, a Send
// that fails because the connection ended says so, and a control call
// returns the reason the link ended.
func TestSendOnDyingLinkSaysWhy(t *testing.T) {
	for i := 0; i < 200; i++ {
		ctl, ctd := pair(t, fastParams())
		ctx := context.Background()
		if err := ctl.link.StartDT(ctx); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for _, e := range []*end{ctl, ctd} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := uint32(0); ; n++ {
					err := e.link.Send(ctx, payload(n))
					if err == nil {
						continue
					}
					if errors.Is(err, iec104.ErrNotStarted) {
						t.Errorf("iteration %d: Send on a link that is going down: %v", i, err)
					} else if !errors.Is(err, iec104.ErrConnectionLost) && !errors.Is(err, iec104.ErrClosed) {
						t.Errorf("iteration %d: Send: %v", i, err)
					}
					return
				}
			}()
		}
		time.Sleep(time.Duration(i%5) * 100 * time.Microsecond)
		// One side drops the connection under both senders.
		if i%2 == 0 {
			_ = ctd.conn.Close()
		} else {
			_ = ctl.link.Close()
		}
		wg.Wait()
		<-ctl.done
		<-ctd.done
		if err := ctl.link.StartDT(ctx); !errors.Is(err, iec104.ErrConnectionLost) && !errors.Is(err, iec104.ErrClosed) {
			t.Fatalf("iteration %d: StartDT on an ended link: %v", i, err)
		}
		if ctl.link.Started() || ctd.link.Started() {
			t.Fatalf("iteration %d: an ended link says it is started", i)
		}
	}
}

// Close returns when the link has nothing more to say: no callback is in
// progress or follows, unless Close is called from a callback itself.
func TestCloseWaitsForCallbacks(t *testing.T) {
	for i := 0; i < 100; i++ {
		ctl, ctd := pair(t, fastParams())
		ctx := context.Background()
		if err := ctl.link.StartDT(ctx); err != nil {
			t.Fatal(err)
		}
		// The controlled side streams; the controlling side is closed in
		// the middle of receiving.
		go func() {
			for n := uint32(0); ctd.link.Send(ctx, payload(n)) == nil; n++ {
			}
		}()
		time.Sleep(time.Duration(i%4) * 200 * time.Microsecond)
		_ = ctl.link.Close()
		before, states := ctl.snapshot()
		select {
		case <-ctl.done:
		default:
			t.Fatalf("iteration %d: Close returned before OnClose ran", i)
		}
		time.Sleep(2 * time.Millisecond)
		after, statesAfter := ctl.snapshot()
		if len(after) != len(before) || len(statesAfter) != len(states) {
			t.Fatalf("iteration %d: %d ASDUs and %d state reports were delivered after Close returned",
				i, len(after)-len(before), len(statesAfter)-len(states))
		}
		_ = ctd.link.Close()
	}

	// From a callback Close must not wait for itself.
	closedFromCallback := make(chan struct{})
	done := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Write([]byte{0x68, 0x04, 0x43, 0x00, 0x00, 0x00}) // TESTFR act, to get things going
			buf := make([]byte, 64)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var self atomic.Pointer[Link]
	l := New(conn, Config{
		Role: Controlled, Params: fastParams(), Log: logx.New(iec104.NopLogger(), "test"),
		OnClose: func(error) {
			// Closing again from the last callback returns at once.
			_ = self.Load().Close()
			close(closedFromCallback)
		},
	})
	self.Store(l)
	go func() { _ = l.Close(); close(done) }()
	for _, ch := range []chan struct{}{closedFromCallback, done} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("Close from a callback, or Close racing it, never returned")
		}
	}
}
