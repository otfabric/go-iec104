// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// The tests in this file reproduce the findings of an adversarial review of
// the state machines. Each failed when it was written.

// Finding 1 of the state machine review: Session.Close called from the state handler's first notification
// (StateStopped, announced by Session.start on the accept goroutine) never
// returns: Link.Close waits for the dispatcher, the dispatcher waits for
// s.ready, and s.ready is closed only after the notification returns.
func TestOrderingCloseFromInitialStateNotification(t *testing.T) {
	returned := make(chan struct{})
	var once sync.Once
	_, addr := serve(t, server.HandlerFunc(confirmAll),
		server.WithStateHandler(func(s *server.Session, st iec104.State, err error) {
			if st != iec104.StateStopped {
				return
			}
			once.Do(func() {
				// Run the Close on this goroutine, as an application would,
				// but report from a watchdog so the test itself cannot hang.
				go func() {
					select {
					case <-returned:
					case <-time.After(3 * time.Second):
						t.Errorf("Session.Close called from the initial StateStopped notification did not return")
						// Unblock: nothing can, the goroutine is stuck for good.
					}
				}()
				_ = s.Close()
				close(returned)
			})
		}))
	c, err := client.New(addr, client.WithParams(testutil.Params()), client.WithAutoStart(false))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Connect(context.Background())
	defer func() { go func() { _ = c.Close() }() }()
	select {
	case <-returned:
	case <-time.After(4 * time.Second):
		t.Fatal("deadlock: Session.Close in the first state notification")
	}
}

// Finding 2 of the state machine review: after Session.Close is called from the Handler, the ASDUs that were
// already queued for the dispatcher are still handed to the Handler.
func TestOrderingHandlerCalledAfterCloseFromHandler(t *testing.T) {
	var closed atomic.Bool
	var after atomic.Int32
	var first sync.Once
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if closed.Load() {
			after.Add(1)
			return
		}
		first.Do(func() {
			time.Sleep(300 * time.Millisecond) // let the other commands arrive
			_ = s.Close()
			closed.Store(true)
		})
	}))
	c := connect(t, addr)
	for i := 0; i < 5; i++ {
		_ = c.Send(context.Background(), asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: asdu.IOA(100 + i), Value: true}))
	}
	time.Sleep(time.Second)
	if n := after.Load(); n != 0 {
		t.Errorf("Handler was called %d more times after Session.Close returned in the Handler", n)
	}
}

// Finding 7 of the state machine review: the group's bookkeeping follows the dispatcher, the queue pump follows
// the link. A "stopped" notification that is delivered late (the Handler was
// busy while the controlling station did STOPDT and STARTDT) releases the
// events that are in flight in the *new* started period, and the "started"
// that follows sends them again on the same connection: duplicates without
// any loss or switchover.
func TestOrderingLateStoppedDuplicatesEvents(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}))
	rx := &events{}
	c := connect(t, addr, client.WithHandler(rx))
	ctx := context.Background()
	if err := c.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true})); err != nil {
		t.Fatal(err)
	}
	<-entered // the session's dispatcher is now busy in the Handler
	if err := c.StopDT(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	enqueue(t, srv, 1, 3)
	testutil.Eventually(t, "delivery", func() bool { return len(rx.values()) >= 3 })
	close(gate) // before t2: the three events are sent and not yet acknowledged
	time.Sleep(500 * time.Millisecond)
	if got := rx.values(); !isRange(got, 1, 3) {
		t.Errorf("events received: %v, want [1 2 3]", got)
	}
}

// Finding 8 of the state machine review: a second Server.Close that runs while the first one is still waiting
// for a Handler returns at once: "when it returns no handler is running" does
// not hold for it.
func TestOrderingConcurrentServerClose(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	var running atomic.Bool
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		running.Store(true)
		entered <- struct{}{}
		<-gate
		running.Store(false)
	}))
	c := connect(t, addr)
	_ = c.Send(context.Background(), asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true}))
	<-entered
	go func() { _ = srv.Close() }()
	time.Sleep(100 * time.Millisecond) // the first Close is waiting for the Handler
	second := make(chan struct{})
	go func() { _ = srv.Close(); close(second) }()
	select {
	case <-second:
		t.Errorf("the second Server.Close returned while a Handler was still running")
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	select {
	case <-second:
		if running.Load() {
			t.Errorf("the second Server.Close returned while a Handler was still running")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second Server.Close never returned")
	}
}

// goroutineOf identifies the calling goroutine by the header of its stack
// trace.
func goroutineOf() string {
	var buf [40]byte
	n := runtime.Stack(buf[:], false)
	return strings.Fields(string(buf[:n]))[1]
}

// Everything a session's application is told comes from one goroutine, the
// first notification included, and in protocol order.
func TestOrderingSessionCallbacksOnOneGoroutine(t *testing.T) {
	var mu sync.Mutex
	var who []string
	var what []string
	note := func(ev string) {
		mu.Lock()
		who = append(who, goroutineOf())
		what = append(what, ev)
		mu.Unlock()
	}
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		note("asdu")
		_ = s.Confirm(req)
	}), server.WithStateHandler(func(_ *server.Session, st iec104.State, _ error) { note(st.String()) }))
	c := connect(t, addr)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true}); err != nil {
			t.Fatal(err)
		}
		if err := c.StopDT(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.StartDT(ctx); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.Close()
	testutil.Eventually(t, "the session told that it ended", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(what) > 0 && what[len(what)-1] == "disconnected"
	})
	mu.Lock()
	defer mu.Unlock()
	want := "stopped started asdu stopped started asdu stopped started asdu stopped started disconnected"
	if got := strings.Join(what, " "); got != want {
		t.Errorf("the session was told:\n %s\nwant:\n %s", got, want)
	}
	for i, g := range who {
		if g != who[0] {
			t.Errorf("callback %d (%s) ran on goroutine %s, the first on %s", i, what[i], g, who[0])
		}
	}
}

// Server.Close and Session.Close from inside callbacks return; the server
// is closed afterwards and other callers of Close wait for that.
func TestOrderingCloseFromServerCallbacks(t *testing.T) {
	t.Run("Server.Close from a Handler", func(t *testing.T) {
		var srv *server.Server
		returned := make(chan struct{})
		var once sync.Once
		srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
			once.Do(func() {
				_ = srv.Close()
				close(returned)
			})
		}))
		a, b := connect(t, addr), connect(t, addr)
		_ = b
		_ = a.Send(context.Background(), asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true}))
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("Server.Close called from a Handler did not return")
		}
		// A caller outside any callback gets a server that is closed.
		done := make(chan struct{})
		go func() { _ = srv.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Server.Close after the one from the Handler did not return")
		}
		if n := len(srv.Sessions()); n != 0 {
			t.Errorf("%d sessions after Server.Close", n)
		}
	})
	t.Run("Server.Close from the state handler", func(t *testing.T) {
		var srv *server.Server
		returned := make(chan struct{})
		var once sync.Once
		srv, addr := serve(t, server.HandlerFunc(confirmAll),
			server.WithStateHandler(func(_ *server.Session, st iec104.State, _ error) {
				if st == iec104.StateStarted {
					once.Do(func() {
						_ = srv.Close()
						close(returned)
					})
				}
			}))
		c, err := client.New(addr, client.WithParams(testutil.Params()))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		go func() { _ = c.Connect(context.Background()) }()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("Server.Close called from the state handler did not return")
		}
		testutil.Eventually(t, "no sessions", func() bool { return len(srv.Sessions()) == 0 })
	})
}

// Two connections of one group, the Handler of the active one busy: when
// the controlling station moves data transfer to the other, events follow
// at once and are not held until that Handler returns, and none is sent
// twice.
func TestOrderingEventsFollowTheLinkNotTheHandler(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}))
	defer close(gate)
	rxA, rxB := &events{}, &events{}
	a := connect(t, addr, client.WithHandler(rxA))
	b := connect(t, addr, client.WithHandler(rxB), client.WithAutoStart(false))
	ctx := context.Background()
	if err := a.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true})); err != nil {
		t.Fatal(err)
	}
	<-entered // the dispatcher of the first session is busy in the Handler
	enqueue(t, srv, 1, 3)
	testutil.Eventually(t, "events on the first connection", func() bool { return len(rxA.values()) == 3 })
	testutil.Eventually(t, "the first three acknowledged", func() bool { return srv.Pending("default") == 0 })

	// Switch over while that Handler is still running.
	if err := a.StopDT(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	enqueue(t, srv, 4, 6)
	testutil.Eventually(t, "events on the second connection", func() bool { return len(rxB.values()) == 3 })
	time.Sleep(200 * time.Millisecond)
	if got := rxA.values(); !isRange(got, 1, 3) {
		t.Errorf("first connection received %v, want [1 2 3]", got)
	}
	if got := rxB.values(); !isRange(got, 4, 6) {
		t.Errorf("second connection received %v, want [4 5 6]", got)
	}
}

// Stop and start again and again while events flow and the Handler is slow:
// every event arrives once, in order.
func TestOrderingNoDuplicatesAcrossCleanStops(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		time.Sleep(2 * time.Millisecond) // keeps the dispatcher behind the link
		_ = s.Confirm(req)
	}), server.WithEventQueue(10000))
	rx := &events{}
	c := connect(t, addr, client.WithHandler(rx))
	ctx := context.Background()
	const n = 600
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= n; i++ {
			if err := srv.Enqueue(event(i)); err != nil {
				t.Errorf("Enqueue: %v", err)
				return
			}
			if i%20 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	for round := 0; round < 40; round++ {
		// A command keeps the session's dispatcher busy across the stop.
		_ = c.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true}))
		if err := c.StopDT(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.StartDT(ctx); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	testutil.Eventually(t, "every event", func() bool { return len(rx.values()) >= n })
	testutil.Eventually(t, "queue acknowledged", func() bool { return srv.Pending("default") == 0 })
	if got := rx.values(); !isRange(got, 1, n) {
		seen := map[int16]int{}
		dups := 0
		for _, v := range got {
			if seen[v]++; seen[v] == 2 {
				dups++
			}
		}
		t.Errorf("%d events received for %d queued: %d of them more than once, or out of order", len(got), n, dups)
	}
}
