// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"net"
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

// The tests in this file call back into the client from its own callbacks,
// and close it from several places at once. None of it may block, and what
// the application is told must stay in protocol order.

func confirming(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }

// within fails the test when f has not returned in time.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

type states struct {
	mu  sync.Mutex
	got []string
}

func (s *states) add(st iec104.State) {
	s.mu.Lock()
	s.got = append(s.got, st.String())
	s.mu.Unlock()
}

func (s *states) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.got, " ")
}

// The state handler starts data transfer itself, sends a command when told
// it started, stops, and closes when told it stopped again.
func TestReentrantStateHandlerDrivesTheClient(t *testing.T) {
	addr := orderingServe(t, server.HandlerFunc(confirming))
	var c *client.Client
	var log states
	var step atomic.Int32
	errs := make(chan error, 8)
	ready := make(chan struct{})
	ctx := context.Background()
	c, err := client.New(addr, client.WithParams(testutil.Params()), client.WithAutoStart(false),
		client.WithRequestTimeout(3*time.Second),
		client.WithStateHandler(func(st iec104.State, _ error) {
			<-ready
			log.add(st)
			switch {
			case st == iec104.StateStopped && step.CompareAndSwap(0, 1):
				errs <- c.StartDT(ctx)
			case st == iec104.StateStarted && step.CompareAndSwap(1, 2):
				errs <- c.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true}))
				// A request cannot be answered while a callback runs.
				if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 2, Value: true}); !errors.Is(err, iec104.ErrInHandler) {
					t.Errorf("Command from the state handler: %v, want ErrInHandler", err)
				}
				errs <- c.StopDT(ctx)
			case st == iec104.StateStopped && step.CompareAndSwap(2, 3):
				errs <- c.Close()
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	close(ready)
	within(t, "Connect", func() {
		// The handler may have closed the client before Connect returns.
		if err := c.Connect(ctx); err != nil && !errors.Is(err, iec104.ErrClosed) {
			t.Errorf("Connect: %v", err)
		}
	})
	testutil.Eventually(t, "the client closed by its state handler", func() bool {
		return strings.HasSuffix(log.String(), "disconnected")
	})
	within(t, "Close", func() { _ = c.Close() })
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a call from the state handler: %v", err)
		}
	}
	if got, want := log.String(), "connecting stopped started stopped disconnected"; got != want {
		t.Errorf("states %q, want %q", got, want)
	}
}

// Close from the Handler of a reconnecting client: no further connection
// attempt, no further callback, and a later Close from outside returns.
func TestReentrantCloseFromHandlerStopsReconnecting(t *testing.T) {
	var sessions atomic.Int32
	st := newStation(t, server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
		if state == iec104.StateStarted {
			sessions.Add(1)
			_ = s.Send(context.Background(), asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1, Value: true}))
			_ = s.Send(context.Background(), asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 2, Value: true}))
		}
	}))
	var closed atomic.Bool
	var after atomic.Int32
	var log states
	var c *client.Client
	c, err := client.New(st.addr, client.WithParams(testutil.Params()),
		client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 20 * time.Millisecond}),
		client.WithStateHandler(func(s iec104.State, _ error) {
			if closed.Load() && s != iec104.StateDisconnected {
				after.Add(1)
			}
			log.add(s)
		}),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			if closed.Load() {
				after.Add(1)
				return
			}
			closed.Store(true)
			_ = c.Close()
		})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "closed from the Handler", func() bool {
		return strings.HasSuffix(log.String(), "disconnected")
	})
	within(t, "Close", func() { _ = c.Close() })
	time.Sleep(300 * time.Millisecond)
	if n := after.Load(); n != 0 {
		t.Errorf("%d callbacks after Close from the Handler; states: %s", n, &log)
	}
	if n := sessions.Load(); n != 1 {
		t.Errorf("the station saw %d connections, want 1: the client reconnected after Close", n)
	}
	if strings.Count(log.String(), "disconnected") != 1 {
		t.Errorf("states %q: want exactly one disconnected", &log)
	}
	if err := c.Connect(context.Background()); !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("Connect after Close: %v, want ErrClosed", err)
	}
}

// Requests issued while another goroutine stops and starts data transfer
// are answered or fail at once with the reason; none is left to time out,
// and none issued after a restart is failed by the stop before it.
func TestReentrantRequestsAcrossStops(t *testing.T) {
	addr := orderingServe(t, server.HandlerFunc(confirming))
	c := dial(t, addr, client.WithRequestTimeout(4*time.Second))
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var ok, refused atomic.Int32
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				begin := time.Now()
				err := c.Command(ctx, 1, asdu.SingleCommand{IOA: asdu.IOA(100*w + i%50 + 1), Value: true})
				switch {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, iec104.ErrNotStarted):
					refused.Add(1)
					if d := time.Since(begin); d > time.Second {
						t.Errorf("a command failed with %v only after %v", err, d)
					}
				default:
					t.Errorf("Command: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 60; i++ {
		if err := c.StopDT(ctx); err != nil {
			t.Fatalf("StopDT: %v", err)
		}
		if err := c.StartDT(ctx); err != nil {
			t.Fatalf("StartDT: %v", err)
		}
		// After StartDT returned a command goes through.
		if err := c.Command(ctx, 2, asdu.SingleCommand{IOA: 1, Value: true}); err != nil {
			t.Fatalf("Command after StartDT (round %d): %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("%d confirmed, %d refused while stopped", ok.Load(), refused.Load())
	if ok.Load() == 0 {
		t.Error("no command was confirmed")
	}
}

func newGroup(t *testing.T, addrs []string, opts ...client.Option) *client.Group {
	t.Helper()
	opts = append([]client.Option{client.WithParams(testutil.Params()), client.WithRequestTimeout(3 * time.Second),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond})}, opts...)
	g, err := client.NewGroup(addrs, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	return g
}

func startedIn(g *client.Group) (n int) {
	for _, c := range g.Clients() {
		if c.State() == iec104.StateStarted {
			n++
		}
	}
	return n
}

// Switchover with no standby says so and leaves the active connection as
// it is.
func TestReentrantSwitchoverWithoutStandby(t *testing.T) {
	addr := orderingServe(t, server.HandlerFunc(confirming))
	dead := "127.0.0.1:1"
	g := newGroup(t, []string{addr, dead})
	active := g.Active()
	if active == nil {
		t.Fatal("no active connection")
	}
	ctx := context.Background()
	if err := g.Switchover(ctx); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("Switchover without a standby: %v, want ErrNotConnected", err)
	}
	if g.Active() != active || active.State() != iec104.StateStarted {
		t.Errorf("after the failed Switchover the active connection is %v (%v)", g.Active(), active.State())
	}
	if err := g.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true}); err != nil {
		t.Errorf("Command after the failed Switchover: %v", err)
	}
}

// The switch handler calls back into the group: requests, Switchover, and
// in the end Close.
func TestReentrantSwitchHandler(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	var g *client.Group
	ready := make(chan struct{})
	var calls atomic.Int32
	errs := make(chan error, 16)
	closedIn := make(chan struct{})
	ctx := context.Background()
	g = newGroup(t, []string{a, b}, client.WithSwitchHandler(func(active *client.Client) {
		<-ready
		if active == nil {
			return
		}
		switch n := calls.Add(1); {
		case n <= 3:
			errs <- g.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true})
			testutil.Eventually(t, "a standby", func() bool {
				for _, c := range g.Clients() {
					if c.State() == iec104.StateStopped {
						return true
					}
				}
				return false
			})
			errs <- g.Switchover(ctx)
		case n == 4:
			errs <- g.Close()
			close(closedIn)
		}
	}))
	close(ready)
	select {
	case <-closedIn:
	case <-time.After(15 * time.Second):
		t.Fatalf("the switch handler was called %d times, want 4: a call back into the group blocked", calls.Load())
	}
	within(t, "Group.Close", func() { _ = g.Close() })
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a call from the switch handler: %v", err)
		}
	}
	for _, c := range g.Clients() {
		if c.State() != iec104.StateDisconnected {
			t.Errorf("%s is %s after Group.Close", c.Addr(), c.State())
		}
	}
	if err := g.Switchover(ctx); !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("Switchover after Close: %v, want ErrClosed", err)
	}
}

// Close from many goroutines at once, with switchovers and requests in
// flight: every Close returns only when the group is closed.
func TestReentrantConcurrentGroupClose(t *testing.T) {
	for round := 0; round < 15; round++ {
		a := orderingServe(t, server.HandlerFunc(confirming))
		b := orderingServe(t, server.HandlerFunc(confirming))
		var closed atomic.Bool
		var late atomic.Int32
		g := newGroup(t, []string{a, b}, client.WithStateHandler(func(st iec104.State, _ error) {
			if closed.Load() {
				late.Add(1)
			}
		}))
		ctx := context.Background()
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					_ = g.Switchover(ctx)
					_ = g.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true})
				}
			}()
		}
		time.Sleep(time.Duration(round) * 3 * time.Millisecond)
		var closers sync.WaitGroup
		for i := 0; i < 4; i++ {
			closers.Add(1)
			go func() {
				defer closers.Done()
				_ = g.Close()
				for _, c := range g.Clients() {
					if st := c.State(); st != iec104.StateDisconnected {
						t.Errorf("round %d: %s is %s when Group.Close returned", round, c.Addr(), st)
					}
				}
			}()
		}
		within(t, "concurrent Group.Close", closers.Wait)
		closed.Store(true)
		within(t, "requests after Group.Close", wg.Wait)
		time.Sleep(20 * time.Millisecond)
		if n := late.Load(); n != 0 {
			t.Errorf("round %d: %d state notifications after Group.Close returned", round, n)
		}
	}
}

// Switchover again and again, concurrently with requests: exactly one
// connection has data transfer started whenever the group is at rest.
func TestReentrantGroupOneStarted(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	g := newGroup(t, []string{a, b})
	ctx := context.Background()
	testutil.Eventually(t, "a standby", func() bool {
		return startedIn(g) == 1 && g.Clients()[0].State() != iec104.StateDisconnected && g.Clients()[1].State() != iec104.StateDisconnected
	})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = g.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true})
			}
		}
	}()
	for i := 0; i < 40; i++ {
		before := g.Active()
		if err := g.Switchover(ctx); err != nil {
			t.Fatalf("Switchover %d: %v", i, err)
		}
		if g.Active() == before {
			t.Fatalf("Switchover %d returned nil and the active connection did not change", i)
		}
		if n := startedIn(g); n != 1 {
			t.Fatalf("after Switchover %d, %d connections have data transfer started", i, n)
		}
	}
	close(stop)
	wg.Wait()
}

// What the station was told has arrived is given to the Handler: a Close
// from outside the callbacks waits until the Handler has seen all of it,
// however far behind the Handler is.
func TestCloseDeliversWhatWasAcknowledged(t *testing.T) {
	srv, err := server.New(server.HandlerFunc(confirming), server.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	const n = 40
	gate := make(chan struct{})
	entered := make(chan struct{}, n)
	var got []int16
	var mu sync.Mutex
	c := dial(t, ln.Addr().String(), client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
		entered <- struct{}{}
		<-gate
		mu.Lock()
		got = append(got, a.First().(asdu.MeasuredScaled).Value)
		mu.Unlock()
	})))
	for i := 0; i < n; i++ {
		if err := srv.Enqueue(asdu.New(asdu.CauseSpontaneous, 1, asdu.MeasuredScaled{IOA: 1, Value: int16(i)})); err != nil {
			t.Fatal(err)
		}
	}
	<-entered // the Handler is busy with the first event
	testutil.Eventually(t, "every event acknowledged to the station", func() bool { return srv.Pending("default") == 0 })

	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while the Handler was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	within(t, "Close", func() { <-closed })
	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("the Handler was given %d of the %d events the station was told have arrived", len(got), n)
	}
	for i, v := range got {
		if int(v) != i {
			t.Fatalf("event %d arrived at position %d", v, i)
		}
	}
}

// A request from inside the Handler cannot be answered while the Handler
// has not returned: it fails at once and says so, where it used to wait for
// its timeout.
func TestRequestFromHandlerFailsAtOnce(t *testing.T) {
	st := newStation(t, server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
		if state == iec104.StateStarted {
			_ = s.Send(context.Background(), asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1, Value: true}))
		}
	}))
	var c atomic.Pointer[client.Client]
	ready := make(chan struct{})
	got := make(chan error, 4)
	var once sync.Once
	cl := dial(t, st.addr, client.WithRequestTimeout(30*time.Second),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			once.Do(func() {
				<-ready
				ctx := context.Background()
				_, err := c.Load().Interrogate(ctx, 1, asdu.QOIStation)
				got <- err
				got <- c.Load().Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true})
				_, err = c.Load().GetFile(ctx, 1, 1, 1)
				got <- err
				got <- c.Load().Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 3, Value: true}))
			})
		})))
	c.Store(cl)
	close(ready)
	for i, want := range []error{iec104.ErrInHandler, iec104.ErrInHandler, iec104.ErrInHandler, nil} {
		select {
		case err := <-got:
			if !errors.Is(err, want) {
				t.Errorf("call %d from the Handler: %v, want %v", i, err, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("call %d from the Handler did not return", i)
		}
	}
	// From outside the same requests go through.
	if _, err := cl.Interrogate(context.Background(), stationCA, asdu.QOIStation); err != nil {
		t.Errorf("Interrogate from outside the Handler: %v", err)
	}
}

// The state handler re-establishes a connection the station dropped, by
// calling Connect when it is told "disconnected".
func TestReentrantConnectFromStateHandler(t *testing.T) {
	var drop atomic.Bool
	drop.Store(true)
	st := newStation(t, server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
		if state == iec104.StateStarted && drop.CompareAndSwap(true, false) {
			go func() { _ = s.Close() }()
		}
	}))
	var c atomic.Pointer[client.Client]
	ready := make(chan struct{})
	var log states
	errs := make(chan error, 1)
	var once sync.Once
	cl, err := client.New(st.addr, client.WithParams(testutil.Params()), client.WithRequestTimeout(3*time.Second),
		client.WithStateHandler(func(s iec104.State, _ error) {
			<-ready
			log.add(s)
			if s == iec104.StateDisconnected {
				once.Do(func() { errs <- c.Load().Connect(context.Background()) })
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	c.Store(cl)
	close(ready)
	// The station may drop the connection before Connect has returned.
	_ = cl.Connect(context.Background())
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("Connect from the state handler: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Connect from the state handler did not return; states: %s", &log)
	}
	testutil.Eventually(t, "started again", func() bool { return cl.State() == iec104.StateStarted })
	if _, err := cl.Interrogate(context.Background(), stationCA, asdu.QOIStation); err != nil {
		t.Errorf("Interrogate on the connection the state handler made: %v", err)
	}
	within(t, "Close", func() { _ = cl.Close() })
	// The station drops the first connection the moment it is started: a
	// connection that has ended by the time its start would be reported is
	// reported by its loss alone.
	want := "connecting stopped started disconnected connecting stopped started disconnected"
	if got := log.String(); got != want && got != strings.Replace(want, " started", "", 1) {
		t.Errorf("states %q, want %q", got, want)
	}
}

// A state handler that does not return holds up the notifications of its
// own connection and nothing else: the group still switches over and
// serves requests.
func TestGroupNotHeldByAStateHandler(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	gate := make(chan struct{})
	entered := make(chan struct{})
	var stuck atomic.Bool // one call only; a sync.Once would hold the others too
	g := newGroup(t, []string{a, b}, client.WithStateHandler(func(st iec104.State, _ error) {
		if st == iec104.StateStarted && stuck.CompareAndSwap(false, true) {
			close(entered)
			<-gate
		}
	}))
	defer close(gate)
	<-entered
	ctx := context.Background()
	testutil.Eventually(t, "a standby", func() bool {
		for _, c := range g.Clients() {
			if c.State() == iec104.StateStopped {
				return true
			}
		}
		return false
	})
	// The connection whose state handler is stuck may be unable to deliver
	// answers, when it is its own dispatcher that is stuck there; the other
	// one serves requests.
	served := 0
	for i := 0; i < 4; i++ {
		before := g.Active()
		within(t, "Switchover", func() {
			if err := g.Switchover(ctx); err != nil {
				t.Errorf("Switchover %d with a state handler that does not return: %v", i, err)
			}
		})
		if g.Active() == before {
			t.Errorf("Switchover %d did not change the active connection", i)
		}
		if n := startedIn(g); n != 1 {
			t.Errorf("after Switchover %d, %d connections have data transfer started", i, n)
		}
		short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		if err := g.Command(short, 1, asdu.SingleCommand{IOA: asdu.IOA(i + 1), Value: true}); err == nil {
			served++
		}
		cancel()
	}
	if served < 2 {
		t.Errorf("%d of 4 commands were confirmed, want those on the connection whose state handler is not stuck", served)
	}
}

// The Handler is busy on the active connection when that connection is
// lost: the group moves data transfer to the standby at once, not when the
// Handler returns.
func TestGroupFailsOverBehindABusyHandler(t *testing.T) {
	var first atomic.Pointer[server.Session]
	srvA, err := server.New(server.HandlerFunc(confirming), server.WithParams(testutil.Params()),
		server.WithStateHandler(func(s *server.Session, st iec104.State, _ error) {
			if st == iec104.StateStarted {
				first.Store(s)
				_ = s.Send(context.Background(), asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1, Value: true}))
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srvA.Serve(ln) }()
	t.Cleanup(func() { _ = srvA.Close() })
	b := orderingServe(t, server.HandlerFunc(confirming))

	gate := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	g := newGroup(t, []string{ln.Addr().String(), b}, client.WithHandler(client.HandlerFunc(func(*asdu.ASDU) {
		once.Do(func() { close(entered); <-gate })
	})))
	defer close(gate)
	cs := g.Clients()
	testutil.Eventually(t, "both connections", func() bool {
		return cs[0].State() != iec104.StateDisconnected && cs[1].State() != iec104.StateDisconnected
	})
	if g.Active() != cs[0] {
		// The second path was established first.
		if err := g.Switchover(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	<-entered // the Handler is busy on the first connection
	testutil.Eventually(t, "the standby", func() bool { return cs[1].State() == iec104.StateStopped })
	if g.Active() != cs[0] {
		t.Fatalf("the first connection is not the active one")
	}
	_ = first.Load().Close() // the station drops the active connection

	deadline := time.Now().Add(time.Second)
	for g.Active() != cs[1] {
		if time.Now().After(deadline) {
			t.Fatalf("a second after the active connection was lost the group has not switched: active %v, states %s / %s",
				g.Active() == cs[0], cs[0].State(), cs[1].State())
		}
		time.Sleep(5 * time.Millisecond)
	}
	within(t, "Command", func() {
		if err := g.Command(context.Background(), 1, asdu.SingleCommand{IOA: 1, Value: true}); err != nil {
			t.Errorf("Command on the connection the group switched to: %v", err)
		}
	})
}

// When Switchover returns the switch handler has been told, with the
// connection that is now the active one, whichever goroutine told it.
func TestSwitchHandlerToldWhenSwitchoverReturns(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	var calls atomic.Int64
	var last atomic.Pointer[client.Client]
	g := newGroup(t, []string{a, b}, client.WithSwitchHandler(func(active *client.Client) {
		time.Sleep(200 * time.Microsecond) // long enough to be found in the middle of it
		last.Store(active)
		calls.Add(1)
	}))
	ctx := context.Background()
	testutil.Eventually(t, "a standby", func() bool {
		established := 0
		for _, c := range g.Clients() {
			if c.State() != iec104.StateDisconnected {
				established++
			}
		}
		return established == 2 && calls.Load() == 1
	})
	for i := 0; i < 300; i++ {
		before := calls.Load()
		if err := g.Switchover(ctx); err != nil {
			t.Fatalf("Switchover %d: %v", i, err)
		}
		if n := calls.Load() - before; n != 1 {
			t.Fatalf("Switchover %d returned with the switch handler called %d times, want 1", i, n)
		}
		if last.Load() != g.Active() {
			t.Fatalf("Switchover %d: the switch handler was last told of another connection than the active one", i)
		}
	}
}
