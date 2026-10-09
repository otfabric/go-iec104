// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
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

// These tests are about the two state machines staying in step: what each
// side says about itself at the moment a call on the other side returns, and
// the order in which an application is told things. They take no time to
// let a state "settle": where the library promises an order, the check is
// immediate, so that a window of disagreement fails the test instead of
// hiding behind a delay.

// onlySession returns the one session of the station, waiting for it.
func onlySession(t testing.TB, srv *server.Server) *server.Session {
	t.Helper()
	var s *server.Session
	testutil.Eventually(t, "one session", func() bool {
		if all := srv.Sessions(); len(all) == 1 {
			s = all[0]
		}
		return s != nil
	})
	return s
}

// Hundreds of STARTDT/STOPDT cycles: at the return of every call both sides
// agree, and each side acts on it at once.
func TestStartStopStaysInStep(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		var arrived atomic.Int64
		c := l.dial(t, client.WithAutoStart(false), client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			if a.Cause == asdu.CauseSpontaneous {
				arrived.Add(1)
			}
		})))
		session := onlySession(t, l.st.Server)
		event := asdu.New(asdu.CauseSpontaneous, l.ca, asdu.SinglePoint{IOA: 100, Value: true})

		for i := 0; i < 200; i++ {
			if err := c.StartDT(ctx); err != nil {
				t.Fatalf("cycle %d: StartDT: %v", i, err)
			}
			if c.State() != iec104.StateStarted || !session.Started() {
				t.Fatalf("cycle %d: StartDT returned with client %s, session started %v", i, c.State(), session.Started())
			}
			// Both directions work immediately.
			if err := session.Send(ctx, event); err != nil {
				t.Fatalf("cycle %d: Session.Send after STARTDT: %v", i, err)
			}
			if n, err := l.st.Server.Broadcast(ctx, event); n != 1 || err != nil {
				t.Fatalf("cycle %d: Broadcast after STARTDT reached %d sessions: %v", i, n, err)
			}
			if _, err := c.Read(ctx, l.ca, 100); err != nil {
				t.Fatalf("cycle %d: Read after STARTDT: %v", i, err)
			}

			if err := c.StopDT(ctx); err != nil {
				t.Fatalf("cycle %d: StopDT: %v", i, err)
			}
			if c.State() != iec104.StateStopped || session.Started() {
				t.Fatalf("cycle %d: StopDT returned with client %s, session started %v", i, c.State(), session.Started())
			}
			// Everything the station sent before it confirmed has arrived:
			// the confirmation comes after the last I frame.
			if got := arrived.Load(); got != int64(2*(i+1)) {
				t.Fatalf("cycle %d: %d events arrived by the time STOPDT was confirmed, want %d", i, got, 2*(i+1))
			}
			if err := session.Send(ctx, event); !errors.Is(err, iec104.ErrNotStarted) {
				t.Fatalf("cycle %d: Session.Send after STOPDT: %v", i, err)
			}
			if n, _ := l.st.Server.Broadcast(ctx, event); n != 0 {
				t.Fatalf("cycle %d: Broadcast after STOPDT reached %d sessions", i, n)
			}
			if _, err := c.Read(ctx, l.ca, 100); !errors.Is(err, iec104.ErrNotStarted) {
				t.Fatalf("cycle %d: Read after STOPDT: %v", i, err)
			}
			// The link itself is alive in both states.
			if i%20 == 0 {
				if err := c.TestLink(ctx); err != nil {
					t.Fatalf("cycle %d: TestLink while stopped: %v", i, err)
				}
			}
		}
		// Repeating a transition that is already made changes nothing.
		for i := 0; i < 3; i++ {
			if err := c.StopDT(ctx); err != nil || session.Started() {
				t.Fatalf("StopDT while stopped: %v", err)
			}
		}
		for i := 0; i < 3; i++ {
			if err := c.StartDT(ctx); err != nil || !session.Started() {
				t.Fatalf("StartDT while started: %v", err)
			}
		}
	})
}

// trace records what one side is told, as a string of events.
type trace struct {
	mu sync.Mutex
	b  strings.Builder
}

func (tr *trace) add(ev byte) {
	tr.mu.Lock()
	tr.b.WriteByte(ev)
	tr.mu.Unlock()
}

func (tr *trace) String() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.b.String()
}

// sessionGrammar checks the life of one session as its application saw it:
// s(topped), then any number of t(started) periods, each with the a(SDUs)
// handled in it and closed by s, and d(isconnected) last. The station's
// state handler and its Handler run on one goroutine, in protocol order, so
// nothing may be out of place.
func sessionGrammar(tr string) error {
	const (
		begin = iota
		stopped
		started
		ended
	)
	state := begin
	for i := 0; i < len(tr); i++ {
		ev := tr[i]
		ok := false
		switch state {
		case begin:
			ok = ev == 's'
			state = stopped
		case stopped:
			switch ev {
			case 't':
				ok, state = true, started
			case 'd':
				ok, state = true, ended
			}
		case started:
			switch ev {
			case 'a':
				ok = true
			case 's':
				ok, state = true, stopped
			case 'd':
				ok, state = true, ended
			}
		}
		if !ok {
			return fmt.Errorf("event %q at position %d is out of place in %q", ev, i, tr)
		}
	}
	if state != ended {
		return fmt.Errorf("the session never ended: %q", tr)
	}
	return nil
}

// clientGrammar checks the states a client reported: c(onnecting),
// s(topped), t(started), d(isconnected). No state is reported twice in a
// row, data transfer starts only from stopped, and stopped follows
// connecting or started.
func clientGrammar(tr string) error {
	prev := byte('d')
	for i := 0; i < len(tr); i++ {
		ev := tr[i]
		ok := false
		switch ev {
		case 'c':
			ok = prev != 'c'
		case 's':
			ok = prev == 'c' || prev == 't'
		case 't':
			ok = prev == 's'
		case 'd':
			ok = prev != 'd'
		}
		if !ok {
			return fmt.Errorf("state %q after %q at position %d in %q", ev, prev, i, tr)
		}
		prev = ev
	}
	return nil
}

func stateLetter(s iec104.State) byte {
	switch s {
	case iec104.StateConnecting:
		return 'c'
	case iec104.StateStopped:
		return 's'
	case iec104.StateStarted:
		return 't'
	default:
		return 'd'
	}
}

// Connections that come and go while everything else happens: clients start,
// stop, send requests and close at random, the station drops sessions at
// random. Each session and each client is told a story that makes sense,
// and at the end the station is empty.
func TestLifecycleUnderChurn(t *testing.T) {
	var (
		mu       sync.Mutex
		sessions = map[uint64]*trace{}
		late     atomic.Int64 // handler calls for a session that had already ended
	)
	sessionTrace := func(s *server.Session) *trace {
		mu.Lock()
		defer mu.Unlock()
		tr := sessions[s.ID()]
		if tr == nil {
			tr = &trace{}
			sessions[s.ID()] = tr
		}
		return tr
	}
	m := &counters{}
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		tr := sessionTrace(s)
		if strings.HasSuffix(tr.String(), "d") {
			late.Add(1)
		}
		tr.add('a')
		_ = s.Confirm(req)
	}), server.WithMetrics(m), server.WithParams(testutil.Params()),
		server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
			sessionTrace(s).add(stateLetter(state))
		}))

	const clients, rounds = 12, 25
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var clientTraces []*trace
	var requests, confirmed atomic.Int64
	for i := 0; i < clients; i++ {
		tr := &trace{}
		clientTraces = append(clientTraces, tr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(i) + 1))
			for round := 0; round < rounds; round++ {
				c, err := client.Dial(ctx, addr, client.WithParams(testutil.Params()),
					client.WithAutoStart(rng.Intn(2) == 0), client.WithRequestTimeout(2*time.Second),
					client.WithStateHandler(func(s iec104.State, _ error) { tr.add(stateLetter(s)) }))
				if err != nil {
					// The station may drop a session before it is started.
					// Dial has closed the client: its story is complete.
					tr.add('|')
					continue
				}
				for op := 0; op < 1+rng.Intn(12); op++ {
					switch rng.Intn(5) {
					case 0:
						_ = c.StartDT(ctx)
					case 1:
						_ = c.StopDT(ctx)
					case 2:
						_ = c.TestLink(ctx)
					default:
						requests.Add(1)
						if c.Command(ctx, 1, asdu.SingleCommand{IOA: asdu.IOA(i + 1), Value: true}) == nil {
							confirmed.Add(1)
						}
					}
				}
				_ = c.Close()
				if c.State() != iec104.StateDisconnected {
					t.Errorf("client %d: state %s after Close returned", i, c.State())
				}
				// One connection per trace entry: mark the boundary.
				tr.add('|')
			}
		}()
	}
	// The station drops sessions under the clients' feet.
	stop := make(chan struct{})
	var dropper sync.WaitGroup
	dropper.Add(1)
	go func() {
		defer dropper.Done()
		rng := rand.New(rand.NewSource(99))
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Duration(1+rng.Intn(4)) * time.Millisecond):
			}
			if all := srv.Sessions(); len(all) > 0 {
				_ = all[rng.Intn(len(all))].Close()
			}
		}
	}()
	wg.Wait()
	close(stop)
	dropper.Wait()

	// A connection a client has already given up on may still be accepted,
	// told that it exists and then that it ended: wait until the station is
	// empty and every session it ever had has been through all of that.
	testutil.Eventually(t, "every session accounted for and ended", func() bool {
		if len(srv.Sessions()) != 0 {
			return false
		}
		connects, disconnects, _, _, _ := m.Snapshot()
		mu.Lock()
		defer mu.Unlock()
		if connects == 0 || connects != disconnects || len(sessions) != connects {
			return false
		}
		for _, tr := range sessions {
			if !strings.HasSuffix(tr.String(), "d") {
				return false
			}
		}
		return true
	})

	mu.Lock()
	handled := 0
	for id, tr := range sessions {
		s := tr.String()
		if err := sessionGrammar(s); err != nil {
			t.Errorf("session %d: %v", id, err)
		}
		handled += strings.Count(s, "a")
	}
	mu.Unlock()
	if n := late.Load(); n != 0 {
		t.Errorf("%d requests were handled for a session that had already ended", n)
	}
	for i, tr := range clientTraces {
		for n, conn := range strings.Split(strings.TrimSuffix(tr.String(), "|"), "|") {
			if err := clientGrammar(conn); err != nil {
				t.Errorf("client %d, connection %d: %v", i, n, err)
			}
			if conn != "" && !strings.HasSuffix(conn, "d") {
				t.Errorf("client %d, connection %d: closed without a final disconnected: %q", i, n, conn)
			}
		}
	}
	// A confirmation the client got is a request the station handled.
	if int64(handled) < confirmed.Load() {
		t.Errorf("clients got %d confirmations, the station handled %d requests", confirmed.Load(), handled)
	}
	if confirmed.Load() == 0 || handled == 0 {
		t.Errorf("the churn exercised nothing: %d of %d requests confirmed", confirmed.Load(), requests.Load())
	}
}

// Every control call at once on one connection, from many goroutines, and a
// Close in the middle of it: nothing hangs, and whenever the dust settles
// the two sides agree.
func TestConcurrentControl(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := l.dial(t, client.WithRequestTimeout(2*time.Second))
		session := onlySession(t, l.st.Server)

		storm := func(n int) {
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rng := rand.New(rand.NewSource(int64(g)))
					for i := 0; i < n; i++ {
						var err error
						switch rng.Intn(6) {
						case 0:
							err = c.StartDT(ctx)
						case 1:
							err = c.StopDT(ctx)
						case 2:
							err = c.TestLink(ctx)
						case 3:
							_, err = c.Read(ctx, l.ca, 100)
						case 4:
							err = c.Command(ctx, l.ca, asdu.SetpointScaled{IOA: 504, Value: int16(i)})
						default:
							_, err = c.Interrogate(ctx, l.ca, asdu.QOIStation)
						}
						// What may go wrong is being in the wrong state or
						// in another caller's way; nothing else.
						switch {
						case err == nil,
							errors.Is(err, iec104.ErrNotStarted), errors.Is(err, iec104.ErrBusy),
							errors.Is(err, iec104.ErrClosed), errors.Is(err, iec104.ErrNotConnected),
							errors.Is(err, iec104.ErrConnectionLost):
						default:
							t.Errorf("goroutine %d: %v", g, err)
						}
					}
				}()
			}
			wg.Wait()
		}
		for round := 0; round < 5; round++ {
			storm(40)
			// Quiet: the connection survived, and both sides say the same.
			if c.State() != iec104.StateStarted && c.State() != iec104.StateStopped {
				t.Fatalf("round %d: the storm left the client %s", round, c.State())
			}
			if started := c.State() == iec104.StateStarted; started != session.Started() {
				t.Fatalf("round %d: client %s, session started %v", round, c.State(), session.Started())
			}
			// And it is as usable as before.
			if err := c.StartDT(ctx); err != nil {
				t.Fatalf("round %d: StartDT after the storm: %v", round, err)
			}
			if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); err != nil {
				t.Fatalf("round %d: Interrogate after the storm: %v", round, err)
			}
		}

		// Close under load: every call returns.
		done := make(chan struct{})
		go func() { storm(200); close(done) }()
		time.Sleep(5 * time.Millisecond)
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("calls are still blocked after Close")
		}
		testutil.Eventually(t, "the session gone", func() bool { return len(l.st.Server.Sessions()) == 0 })
	})
}

// After Close has returned, an application is told nothing more: on either
// side, whatever was in flight.
func TestNothingAfterClose(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		srv := l.st.Server
		event := asdu.New(asdu.CauseSpontaneous, l.ca, asdu.MeasuredScaled{IOA: 201, Value: 1})

		for round := 0; round < 20; round++ {
			var closed atomic.Bool
			var after atomic.Int64
			c := l.dial(t,
				client.WithHandler(client.HandlerFunc(func(*asdu.ASDU) {
					if closed.Load() {
						after.Add(1)
					}
				})),
				client.WithStateHandler(func(s iec104.State, _ error) {
					if closed.Load() {
						after.Add(1)
					}
				}))
			session := onlySession(t, srv)
			// The station streams while the client closes.
			streaming := make(chan struct{})
			go func() {
				defer close(streaming)
				for session.Send(ctx, event) == nil {
				}
			}()
			time.Sleep(time.Duration(round%5) * time.Millisecond)
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			closed.Store(true)
			if c.State() != iec104.StateDisconnected {
				t.Fatalf("round %d: state %s after Close", round, c.State())
			}
			<-streaming
			testutil.Eventually(t, "the session gone", func() bool { return len(srv.Sessions()) == 0 })
			time.Sleep(5 * time.Millisecond)
			if n := after.Load(); n != 0 {
				t.Fatalf("round %d: %d callbacks after Close returned", round, n)
			}
		}
	})

	// The same for a station: after Server.Close no handler runs and no
	// session is left, while clients were in the middle of requests.
	var closed atomic.Bool
	var after atomic.Int64
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if closed.Load() {
			after.Add(1)
		}
		_ = s.Confirm(req)
	}))
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		c := connect(t, addr, client.WithRequestTimeout(time.Second))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				err := c.Command(ctx, 1, asdu.SingleCommand{IOA: asdu.IOA(i + 1)})
				if err != nil {
					if !errors.Is(err, iec104.ErrConnectionLost) && !errors.Is(err, iec104.ErrNotConnected) {
						t.Errorf("client %d: %v", i, err)
					}
					return
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	closed.Store(true)
	if n := len(srv.Sessions()); n != 0 {
		t.Errorf("%d sessions after Server.Close returned", n)
	}
	wg.Wait()
	time.Sleep(10 * time.Millisecond)
	if n := after.Load(); n != 0 {
		t.Errorf("%d requests handled after Server.Close returned", n)
	}
}

// A redundancy group switching back and forth: at the return of every
// switchover exactly one station has a started session, and it is the one
// the group says is active.
func TestSwitchoverStaysInStep(t *testing.T) {
	a, b := start(t, nil), start(t, nil)
	ctx := context.Background()
	g, err := client.NewGroup([]string{a.st.Loopback(), b.st.Loopback()},
		client.WithParams(testutil.Params()), client.WithRequestTimeout(5*time.Second),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	clients := g.Clients()
	testutil.Eventually(t, "both paths established", func() bool {
		return clients[0].State() != iec104.StateDisconnected && clients[1].State() != iec104.StateDisconnected &&
			clients[0].State() != iec104.StateConnecting && clients[1].State() != iec104.StateConnecting
	})
	byAddr := map[string]*link{a.st.Loopback(): a, b.st.Loopback(): b}
	started := func(l *link) int {
		n := 0
		for _, s := range l.st.Server.Sessions() {
			if s.Started() {
				n++
			}
		}
		return n
	}
	for i := 0; i < 60; i++ {
		if err := g.Switchover(ctx); err != nil {
			t.Fatalf("switchover %d: %v", i, err)
		}
		active := g.Active()
		if active == nil || active.State() != iec104.StateStarted {
			t.Fatalf("switchover %d: no started connection", i)
		}
		for addr, l := range byAddr {
			want := 0
			if addr == active.Addr() {
				want = 1
			}
			if got := started(l); got != want {
				t.Fatalf("switchover %d: station %s has %d started sessions, want %d", i, addr, got, want)
			}
		}
		for _, c := range clients {
			if c != active && c.State() != iec104.StateStopped {
				t.Fatalf("switchover %d: the standby is %s", i, c.State())
			}
		}
		// A request right away goes to the station that is now active.
		if err := g.Command(ctx, a.ca, asdu.SetpointScaled{IOA: 504, Value: int16(i)}); err != nil {
			t.Fatalf("switchover %d: Command: %v", i, err)
		}
		r, err := active.Read(ctx, a.ca, 201)
		if err != nil || r.First().(asdu.MeasuredScaled).Value != int16(i) {
			t.Fatalf("switchover %d: the command did not land on the active station: %v", i, err)
		}
	}
}

// A request that is waiting when data transfer stops is over: the station
// cannot answer it any more. It fails at once, not at its timeout; an answer
// that arrived before the stop is still delivered; and requests of the next
// started period are left alone.
func TestPendingRequestsWhenTransferStops(t *testing.T) {
	var silent atomic.Bool
	var unanswered atomic.Int64
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if silent.Load() {
			unanswered.Add(1)
			return // never answered
		}
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr,
			asdu.MeasuredScaled{IOA: req.First().Address(), Value: 7}))
	}))
	ctx := context.Background()
	c := connect(t, addr, client.WithRequestTimeout(30*time.Second))

	for round := 0; round < 50; round++ {
		// Unanswered requests, then STOPDT.
		silent.Store(true)
		unanswered.Store(0)
		const waiting = 5
		errs := make(chan error, waiting)
		for i := 0; i < waiting; i++ {
			go func() {
				_, err := c.Read(ctx, 1, asdu.IOA(100+i))
				errs <- err
			}()
		}
		testutil.Eventually(t, "the requests at the station", func() bool { return unanswered.Load() == waiting })
		begin := time.Now()
		if err := c.StopDT(ctx); err != nil {
			t.Fatalf("round %d: StopDT: %v", round, err)
		}
		for i := 0; i < waiting; i++ {
			select {
			case err := <-errs:
				if !errors.Is(err, iec104.ErrNotStarted) {
					t.Fatalf("round %d: a request pending at STOPDT returned %v, want ErrNotStarted", round, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("round %d: a request is still waiting %s after STOPDT", round, time.Since(begin))
			}
		}

		// The next started period: its requests are answered, whatever the
		// end of the previous period is still doing.
		silent.Store(false)
		if err := c.StartDT(ctx); err != nil {
			t.Fatalf("round %d: StartDT: %v", round, err)
		}
		for i := 0; i < 5; i++ {
			a, err := c.Read(ctx, 1, asdu.IOA(200+i))
			if err != nil || a.First().(asdu.MeasuredScaled).Value != 7 {
				t.Fatalf("round %d: Read in the new period: %v", round, err)
			}
		}
	}

	// An answer that is already there when the stop comes is not lost: the
	// station confirms the stop after its last I frame.
	lost := 0
	for i := 0; i < 300; i++ {
		got := make(chan error, 1)
		go func() {
			_, err := c.Read(ctx, 1, 300)
			got <- err
		}()
		if i%2 == 0 {
			time.Sleep(time.Duration(i%7) * 50 * time.Microsecond)
		}
		if err := c.StopDT(ctx); err != nil {
			t.Fatal(err)
		}
		switch err := <-got; {
		case err == nil:
		case errors.Is(err, iec104.ErrNotStarted):
			// The stop won: the request never went out, or the station
			// could not answer any more.
			lost++
		default:
			t.Fatalf("iteration %d: Read racing STOPDT: %v", i, err)
		}
		if err := c.StartDT(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if lost == 300 {
		t.Error("no read ever beat the stop: the race was not exercised")
	}
}

// The station drops the connection at the very moment the client closes it.
// Whichever side wins, the client is told once that it is disconnected, and
// nothing after Close has returned.
func TestCloseRacingConnectionLoss(t *testing.T) {
	station, saddr := serve(t, &echo{})
	for i := 0; i < 400; i++ {
		var tr trace
		var closed atomic.Bool
		var after atomic.Int64
		c := connect(t, saddr, client.WithStateHandler(func(s iec104.State, _ error) {
			if closed.Load() {
				after.Add(1)
			}
			tr.add(stateLetter(s))
		}))
		session := onlySession(t, station)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%6) * 20 * time.Microsecond)
			_ = session.Close()
		}()
		time.Sleep(time.Duration(i%5) * 25 * time.Microsecond)
		_ = c.Close()
		closed.Store(true)
		got := tr.String()
		wg.Wait()
		testutil.Eventually(t, "the session gone", func() bool { return len(station.Sessions()) == 0 })
		time.Sleep(time.Millisecond)
		if n := after.Load(); n != 0 {
			t.Fatalf("iteration %d: %d state reports after Close returned (before: %q, after: %q)", i, n, got, tr.String())
		}
		if got != "cstd" {
			t.Fatalf("iteration %d: the client was told %q, want connecting, stopped, started, disconnected", i, got)
		}
	}
}
