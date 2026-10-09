// SPDX-License-Identifier: MIT

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// The chaos test does not look for one bug. It lets everything happen at
// once, for as long as it is given, on a network that delays, fragments and
// cuts connections at random, and checks what must hold whatever the
// interleaving:
//
//   - neither side ever sees a protocol error: the two machines stay in step
//   - every session and every client is told a story that makes sense
//   - a confirmation a client got is for a command the station executed
//   - an answer is the answer to the question that was asked
//   - a file arrives as it was sent, in either direction
//   - no queued event is lost
//   - no call hangs, and after Close nothing is said and nothing is left
//
// E2E_CHAOS_SECONDS sets how long each seed runs (default 2); E2E_CHAOS_SEEDS
// how many seeds (default 3). Soak it with a large number before a release.

// chaosNet makes connections that misbehave the way networks do.
type chaosNet struct {
	rng   *lockedRand
	calm  atomic.Bool // no more faults: let things settle
	mu    sync.Mutex
	conns map[*chaosConn]struct{}
	cuts  atomic.Int64
}

type lockedRand struct {
	mu sync.Mutex
	r  *rand.Rand
}

func (l *lockedRand) Intn(n int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Intn(n)
}

type chaosConn struct {
	net.Conn
	net *chaosNet
}

func (n *chaosNet) wrap(c net.Conn) net.Conn {
	cc := &chaosConn{Conn: c, net: n}
	n.mu.Lock()
	n.conns[cc] = struct{}{}
	n.mu.Unlock()
	return cc
}

func (n *chaosNet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return n.wrap(c), nil
}

// cut closes one connection at random, as a failing link would.
func (n *chaosNet) cut() {
	n.mu.Lock()
	var victim *chaosConn
	if len(n.conns) > 0 {
		i := n.rng.Intn(len(n.conns))
		for c := range n.conns {
			if i == 0 {
				victim = c
				break
			}
			i--
		}
	}
	n.mu.Unlock()
	if victim != nil {
		n.cuts.Add(1)
		_ = victim.Conn.Close()
	}
}

func (c *chaosConn) jitter() {
	if c.net.calm.Load() {
		return
	}
	switch c.net.rng.Intn(12) {
	case 0:
		time.Sleep(time.Duration(c.net.rng.Intn(300)) * time.Microsecond)
	case 1, 2:
		runtime.Gosched()
	}
}

func (c *chaosConn) Read(p []byte) (int, error) {
	c.jitter()
	// Short reads: a frame may arrive in pieces.
	if len(p) > 1 && !c.net.calm.Load() && c.net.rng.Intn(4) == 0 {
		p = p[:1+c.net.rng.Intn(len(p)-1)]
	}
	return c.Conn.Read(p)
}

func (c *chaosConn) Write(p []byte) (int, error) {
	c.jitter()
	// Fragmented writes: a frame may leave in pieces.
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 1 && !c.net.calm.Load() && c.net.rng.Intn(4) == 0 {
			n = 1 + c.net.rng.Intn(n-1)
		}
		m, err := c.Conn.Write(p[:n])
		written += m
		if err != nil {
			return written, err
		}
		p = p[n:]
		if len(p) > 0 {
			c.jitter()
		}
	}
	return written, nil
}

func (c *chaosConn) Close() error {
	c.net.mu.Lock()
	delete(c.net.conns, c)
	c.net.mu.Unlock()
	return c.Conn.Close()
}

type chaosListener struct {
	net.Listener
	net *chaosNet
}

func (l *chaosListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.net.wrap(c), nil
}

// chaosStation is the station of the chaos test and its record of what it
// did.
type chaosStation struct {
	mu       sync.Mutex
	executed map[asdu.IOA]int16 // commands executed, by object
	uploads  map[asdu.IOA][]byte
	sessions map[uint64]*trace
	reasons  []error // why sessions ended
	late     atomic.Int64
}

func chaosFile(ioa asdu.IOA) []byte {
	b := make([]byte, 700+int(ioa)%900)
	for i := range b {
		b[i] = byte((i + int(ioa)) % 251)
	}
	return b
}

func (st *chaosStation) trace(s *server.Session) *trace {
	st.mu.Lock()
	defer st.mu.Unlock()
	tr := st.sessions[s.ID()]
	if tr == nil {
		tr = &trace{}
		st.sessions[s.ID()] = tr
	}
	return tr
}

func (st *chaosStation) OpenFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, name uint16) (server.File, bool) {
	if ioa < 50000 || ioa >= 50100 || name != 1 {
		return server.File{}, false
	}
	return server.NewFile(chaosFile(ioa), 300), true
}

func (st *chaosStation) AcceptFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, _ int) bool {
	return ioa >= 60000
}

func (st *chaosStation) StoreFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, f server.File) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.uploads[ioa] = bytes.Join(f.Sections, nil)
	return nil
}

func (st *chaosStation) handler() server.Handler {
	files := server.NewFileServer(st)
	files.Sink = st
	mux := server.NewMux()
	mux.Handle(files, server.FileTypes...)
	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		ioa := req.First().Address()
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr, asdu.Bitstring32{IOA: ioa, Value: uint32(ioa) * 3}))
	})
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		_ = s.Confirm(req)
		for i := 0; i < 3; i++ {
			_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr, asdu.SinglePoint{IOA: asdu.IOA(i + 1), Value: true}))
		}
		_ = s.Terminate(req)
	})
	mux.HandleFunc(asdu.C_SE_NB_1, func(s *server.Session, req *asdu.ASDU) {
		cmd := req.First().(asdu.SetpointScaled)
		st.mu.Lock()
		st.executed[cmd.IOA] = cmd.Value
		st.mu.Unlock()
		_ = s.Confirm(req)
		_ = s.Terminate(req)
	})
	return server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		tr := st.trace(s)
		if strings.HasSuffix(tr.String(), "d") {
			st.late.Add(1)
		}
		tr.add('a')
		mux.HandleASDU(s, req)
	})
}

// chaosClient is one controlling station and what it was told.
type chaosClient struct {
	idx       int
	c         *client.Client
	tr        trace
	mu        sync.Mutex
	last      iec104.State
	reasons   []error
	confirmed map[asdu.IOA]int16
	events    map[uint32]int
	afterStop atomic.Int64 // callbacks after Close returned
	closed    atomic.Bool
	// stopCalls counts the STOPDT calls of the one goroutine that drives
	// this client; atStart is its value when "started" was last reported.
	// "stopped" after "started" without a call in between is a stop nobody
	// asked for.
	stopCalls, stopDone, atStart atomic.Int64
	inFlight                     bool // a STOPDT call was running when "started" was reported
	prev                         byte
	unasked                      atomic.Int64
}

// reconnectingGrammar is clientGrammar for a client that reconnects: from
// stopped or started it may go back to connecting, and a failed attempt is
// reported as connecting again.
func reconnectingGrammar(tr string) error {
	prev := byte('d')
	for i := 0; i < len(tr); i++ {
		ev := tr[i]
		ok := false
		switch ev {
		case 'c':
			ok = true // from anywhere, also from connecting (a failed attempt)
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

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func TestChaos(t *testing.T) {
	seconds, seeds := envInt("E2E_CHAOS_SECONDS", 2), envInt("E2E_CHAOS_SEEDS", 3)
	if testing.Short() {
		seconds, seeds = 1, 1
	}
	for seed := 1; seed <= seeds; seed++ {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			chaos(t, int64(seed), time.Duration(seconds)*time.Second)
		})
	}
}

func chaos(t *testing.T, seed int64, duration time.Duration) {
	baseline := runtime.NumGoroutine()
	network := &chaosNet{rng: &lockedRand{r: rand.New(rand.NewSource(seed))}, conns: map[*chaosConn]struct{}{}}
	st := &chaosStation{executed: map[asdu.IOA]int16{}, uploads: map[asdu.IOA][]byte{}, sessions: map[uint64]*trace{}}

	// Small windows and short timers, so that flow control and the timers
	// take part; t1 long enough that only a real fault trips it.
	params := apci.Params{K: 4, W: 2, T0: 3 * time.Second, T1: 5 * time.Second, T2: 50 * time.Millisecond, T3: 400 * time.Millisecond}
	srv, err := server.New(st.handler(), server.WithParams(params), server.WithEventQueue(1<<20),
		server.WithStateHandler(func(s *server.Session, state iec104.State, err error) {
			st.trace(s).add(stateLetter(state))
			if state == iec104.StateDisconnected && err != nil {
				st.mu.Lock()
				st.reasons = append(st.reasons, err)
				st.mu.Unlock()
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { _ = srv.Serve(&chaosListener{ln, network}); close(served) }()
	addr := ln.Addr().String()

	const nClients = 6
	var clients []*chaosClient
	newClient := func(idx int) *chaosClient {
		cc := &chaosClient{idx: idx, confirmed: map[asdu.IOA]int16{}, events: map[uint32]int{}}
		c, err := client.New(addr,
			client.WithParams(params), client.WithDialer(network),
			client.WithRequestTimeout(800*time.Millisecond),
			client.WithReconnect(client.Reconnect{MinDelay: 5 * time.Millisecond, MaxDelay: 40 * time.Millisecond}),
			client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
				if cc.closed.Load() {
					cc.afterStop.Add(1)
				}
				if v, ok := a.First().(asdu.Bitstring32); ok && a.Cause == asdu.CauseSpontaneous {
					cc.mu.Lock()
					cc.events[v.Value]++
					cc.mu.Unlock()
				}
			})),
			client.WithStateHandler(func(s iec104.State, err error) {
				if cc.closed.Load() {
					cc.afterStop.Add(1)
				}
				cc.tr.add(stateLetter(s))
				cc.mu.Lock()
				switch letter := stateLetter(s); {
				case letter == 't':
					began := cc.stopCalls.Load()
					cc.atStart.Store(began)
					cc.inFlight = cc.stopDone.Load() != began
				case letter == 's' && cc.prev == 't' && cc.stopCalls.Load() == cc.atStart.Load() && !cc.inFlight:
					cc.unasked.Add(1)
				}
				cc.prev = stateLetter(s)
				cc.last = s
				if err != nil {
					cc.reasons = append(cc.reasons, err)
				}
				cc.mu.Unlock()
			}))
		if err != nil {
			t.Fatal(err)
		}
		cc.c = c
		return cc
	}
	for i := 0; i < nClients; i++ {
		clients = append(clients, newClient(i))
	}
	// Clients closed and replaced during the run; they are checked at the
	// end like the others.
	var retiredMu sync.Mutex
	var retired []*chaosClient

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var hung atomic.Int64
	var ops, okOps atomic.Int64
	// bounded runs one call and reports it when it does not return.
	bounded := func(what string, f func(ctx context.Context) error) error {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- f(ctx) }()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			hung.Add(1)
			t.Errorf("%s did not return", what)
			return errors.New("hung")
		}
	}
	acceptable := func(err error) bool {
		var neg *iec104.NegativeError
		switch {
		case err == nil,
			errors.Is(err, iec104.ErrNotStarted), errors.Is(err, iec104.ErrBusy),
			errors.Is(err, iec104.ErrNotConnected), errors.Is(err, iec104.ErrConnectionLost),
			errors.Is(err, iec104.ErrConnectFailed), errors.Is(err, iec104.ErrClosed),
			errors.Is(err, context.DeadlineExceeded):
			return true
		case errors.As(err, &neg):
			// A transfer cut off and started again elsewhere: the station
			// refuses what no longer fits its state.
			return true
		}
		return false
	}

	for slot := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cc := clients[slot]
			rng := rand.New(rand.NewSource(seed*100 + int64(cc.idx)))
			_ = bounded("Connect", cc.c.Connect)
			seq := int16(0)
			for {
				select {
				case <-stop:
					return
				default:
				}
				ops.Add(1)
				// Now and then the application closes its client, in the
				// middle of whatever the network is doing, and starts over
				// with a new one.
				if rng.Intn(400) == 0 {
					if err := bounded("Close", func(context.Context) error { return cc.c.Close() }); err != nil {
						t.Errorf("client %d: Close: %v", cc.idx, err)
					}
					cc.closed.Store(true)
					if st, told := cc.c.State(), cc.tr.String(); st != iec104.StateDisconnected || !strings.HasSuffix(told, "d") {
						t.Errorf("client %d: after Close returned it is %s and was told %q", cc.idx, st, told)
					}
					retiredMu.Lock()
					retired = append(retired, cc)
					retiredMu.Unlock()
					cc = newClient(cc.idx)
					clients[slot] = cc
					_ = bounded("Connect", cc.c.Connect)
					continue
				}
				c := cc.c
				var err error
				what := ""
				switch rng.Intn(14) {
				case 0:
					what = "StartDT"
					err = bounded(what, c.StartDT)
				case 1:
					what = "StopDT"
					cc.stopCalls.Add(1)
					err = bounded(what, c.StopDT)
					cc.stopDone.Add(1)
				case 2:
					what = "TestLink"
					err = bounded(what, c.TestLink)
				case 3:
					what = "Connect"
					err = bounded(what, c.Connect)
				case 4, 5, 6:
					what = "Read"
					ioa := asdu.IOA(1 + rng.Intn(1000))
					err = bounded(what, func(ctx context.Context) error {
						a, err := c.Read(ctx, 1, ioa)
						if err == nil {
							if v, ok := a.First().(asdu.Bitstring32); !ok || v.IOA != ioa || v.Value != uint32(ioa)*3 {
								t.Errorf("client %d: Read of %d answered %s %+v", cc.idx, ioa, a, a.First())
							}
						}
						return err
					})
				case 7, 8, 9:
					what = "Command"
					seq++
					// An object of this client's own, and a value that tells
					// the commands apart.
					ioa, value := asdu.IOA(100000+cc.idx*1000+rng.Intn(20)), seq
					err = bounded(what, func(ctx context.Context) error {
						return c.Command(ctx, 1, asdu.SetpointScaled{IOA: ioa, Value: value})
					})
					if err == nil {
						cc.mu.Lock()
						cc.confirmed[ioa] = value
						cc.mu.Unlock()
						// The station executed this very command before it
						// confirmed it; nobody else writes this object.
						st.mu.Lock()
						got, ok := st.executed[ioa]
						st.mu.Unlock()
						if !ok || got != value {
							t.Errorf("client %d: command %d on object %d was confirmed; the station has %d (executed: %v)",
								cc.idx, value, ioa, got, ok)
						}
					}
				case 10:
					what = "Interrogate"
					err = bounded(what, func(ctx context.Context) error {
						data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
						if err == nil && len(data) != 3 {
							t.Errorf("client %d: interrogation returned %d ASDUs, want 3", cc.idx, len(data))
						}
						return err
					})
				case 11:
					what = "GetFile"
					ioa := asdu.IOA(50000 + rng.Intn(100))
					err = bounded(what, func(ctx context.Context) error {
						got, err := c.GetFile(ctx, 1, ioa, 1)
						if err == nil && !bytes.Equal(got, chaosFile(ioa)) {
							t.Errorf("client %d: file %d arrived with %d octets that are not its content", cc.idx, ioa, len(got))
						}
						return err
					})
				case 12:
					what = "PutFile"
					ioa := asdu.IOA(60000 + cc.idx*100 + rng.Intn(10))
					data := chaosFile(ioa + asdu.IOA(seq))
					err = bounded(what, func(ctx context.Context) error {
						return c.PutFile(ctx, 1, ioa, 1, data[:len(data)/2], data[len(data)/2:])
					})
					if err == nil {
						st.mu.Lock()
						got := st.uploads[ioa]
						st.mu.Unlock()
						if !bytes.Equal(got, data) {
							t.Errorf("client %d: file %d was acknowledged; the station has %d of %d octets", cc.idx, ioa, len(got), len(data))
						}
					}
				default:
					what = "State"
					_ = c.State()
					time.Sleep(time.Duration(rng.Intn(500)) * time.Microsecond)
				}
				if err == nil {
					okOps.Add(1)
				} else if !acceptable(err) {
					t.Errorf("client %d: %s: %v", cc.idx, what, err)
				}
			}
		}()
	}

	// The station reports events, broadcasts, and drops sessions.
	var enqueued atomic.Uint32
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed * 7))
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Duration(rng.Intn(1500)) * time.Microsecond):
			}
			switch rng.Intn(10) {
			case 0:
				if all := srv.Sessions(); len(all) > 0 {
					_ = all[rng.Intn(len(all))].Close()
				}
			case 1:
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, _ = srv.Broadcast(ctx, asdu.New(asdu.CausePeriodic, 1, asdu.MeasuredScaled{IOA: 9, Value: 1}))
				cancel()
			default:
				n := enqueued.Add(1) - 1
				if err := srv.Enqueue(asdu.New(asdu.CauseSpontaneous, 1, asdu.Bitstring32{IOA: 8, Value: n})); err != nil {
					t.Errorf("Enqueue: %v", err)
				}
			}
		}
	}()
	// The network cuts connections.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed * 13))
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Duration(5+rng.Intn(40)) * time.Millisecond):
				network.cut()
			}
		}
	}()

	time.Sleep(duration)
	close(stop)
	wg.Wait()
	network.calm.Store(true)
	if hung.Load() != 0 {
		t.Fatalf("seed %d: %d calls hung", seed, hung.Load())
	}

	// Let it settle: every client connected and started.
	settle := time.Now().Add(20 * time.Second)
	for _, cc := range clients {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = cc.c.Connect(ctx)
			err := cc.c.StartDT(ctx)
			cancel()
			if err == nil && cc.c.State() == iec104.StateStarted {
				break
			}
			if time.Now().After(settle) {
				t.Fatalf("seed %d: client %d does not come back after the chaos: %v (state %s, told %q)",
					seed, cc.idx, err, cc.c.State(), cc.tr.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Every event is delivered and acknowledged.
	want := enqueued.Load()
	deadline := time.Now().Add(20 * time.Second)
	for srv.Pending("default") != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("seed %d: %d events still pending with every client started", seed, srv.Pending("default"))
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	seen := make([]bool, want)
	retiredMu.Lock()
	everyone := append(append([]*chaosClient(nil), retired...), clients...)
	retiredMu.Unlock()
	for _, cc := range everyone {
		cc.mu.Lock()
		for v := range cc.events {
			if v >= want {
				t.Errorf("seed %d: client %d received event %d that was never queued", seed, cc.idx, v)
				continue
			}
			seen[v] = true
		}
		cc.mu.Unlock()
	}
	lost := 0
	for _, ok := range seen {
		if !ok {
			lost++
		}
	}
	if lost != 0 || srv.Dropped("default") != 0 {
		t.Errorf("seed %d: %d of %d queued events never arrived (dropped: %d)", seed, lost, want, srv.Dropped("default"))
	}

	// What each side was told.
	for _, cc := range everyone {
		if n := cc.unasked.Load(); n != 0 {
			t.Errorf("seed %d: client %d was told %d times that data transfer stopped when it had not stopped it: %q",
				seed, cc.idx, n, cc.tr.String())
		}
	}
	for _, cc := range clients {
		cc.mu.Lock()
		last, reasons := cc.last, append([]error(nil), cc.reasons...)
		cc.mu.Unlock()
		if got := cc.c.State(); got != last {
			t.Errorf("seed %d: client %d is %s, the last state it was told is %s", seed, cc.idx, got, last)
		}
		if err := reconnectingGrammar(cc.tr.String()); err != nil {
			t.Errorf("seed %d: client %d: %v", seed, cc.idx, err)
		}
		for _, err := range reasons {
			if errors.Is(err, iec104.ErrProtocol) || errors.Is(err, iec104.ErrTimeout) {
				t.Errorf("seed %d: client %d lost a connection to %v: the two sides fell out of step", seed, cc.idx, err)
			}
		}
	}

	// Close everything: nothing is said afterwards, nothing is left.
	for _, cc := range clients {
		if err := bounded("Close", func(context.Context) error { return cc.c.Close() }); err != nil {
			t.Errorf("seed %d: client %d: Close: %v", seed, cc.idx, err)
		}
		cc.closed.Store(true)
		if s := cc.c.State(); s != iec104.StateDisconnected {
			t.Errorf("seed %d: client %d is %s after Close", seed, cc.idx, s)
		}
	}
	if err := bounded("Server.Close", func(context.Context) error { return srv.Close() }); err != nil {
		t.Errorf("seed %d: Server.Close: %v", seed, err)
	}
	<-served
	if n := len(srv.Sessions()); n != 0 {
		t.Errorf("seed %d: %d sessions after Server.Close", seed, n)
	}
	time.Sleep(20 * time.Millisecond)
	for _, cc := range everyone {
		if err := reconnectingGrammar(cc.tr.String()); err != nil {
			t.Errorf("seed %d: client %d: %v", seed, cc.idx, err)
		}
		if n := strings.Count(cc.tr.String(), "d"); n > 1+strings.Count(cc.tr.String(), "dc") {
			t.Errorf("seed %d: client %d was told more than once that it is disconnected: %q", seed, cc.idx, cc.tr.String())
		}
		if n := cc.afterStop.Load(); n != 0 {
			t.Errorf("seed %d: client %d got %d callbacks after Close returned", seed, cc.idx, n)
		}
		if tr := cc.tr.String(); !strings.HasSuffix(tr, "d") {
			t.Errorf("seed %d: client %d was not told that it is disconnected: %q", seed, cc.idx, tr)
		}
	}
	st.mu.Lock()
	for id, tr := range st.sessions {
		if err := sessionGrammar(tr.String()); err != nil {
			t.Errorf("seed %d: session %d: %v", seed, id, err)
		}
	}
	for _, err := range st.reasons {
		if errors.Is(err, iec104.ErrProtocol) || errors.Is(err, iec104.ErrTimeout) {
			t.Errorf("seed %d: a session ended with %v: the two sides fell out of step", seed, err)
		}
	}
	nSessions := len(st.sessions)
	st.mu.Unlock()
	if n := st.late.Load(); n != 0 {
		t.Errorf("seed %d: %d requests handled for a session that had ended", seed, n)
	}

	// Goroutines: everything the run started is gone.
	leakDeadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(leakDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+2 {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Errorf("seed %d: %d goroutines before, %d after everything was closed:\n%s", seed, baseline, n, buf)
	}

	if okOps.Load() < 50 || network.cuts.Load() == 0 || nSessions < 3 || want == 0 {
		t.Errorf("seed %d: the run exercised too little: %d of %d calls succeeded, %d cuts, %d sessions, %d events",
			seed, okOps.Load(), ops.Load(), network.cuts.Load(), nSessions, want)
	}
	t.Logf("seed %d: %d calls (%d succeeded), %d connections cut, %d sessions, %d events", seed, ops.Load(), okOps.Load(),
		network.cuts.Load(), nSessions, want)
}
