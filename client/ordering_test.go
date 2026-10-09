// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// The tests in this file reproduce the findings of an adversarial review of
// the state machines. Each failed when it was written.

// Finding 3 of the state machine review: Client.Close called from the Handler returns, reports "disconnected",
// and the Handler is then still called for the ASDUs that were queued.
func TestOrderingHandlerCalledAfterCloseFromHandler(t *testing.T) {
	st := newStation(t, server.WithStateHandler(func(s *server.Session, state iec104.State, err error) {
		if state == iec104.StateStarted {
			go func() {
				for i := 0; i < 5; i++ {
					_ = s.Send(s.Context(), asdu.New(asdu.CauseSpontaneous, stationCA, asdu.SinglePoint{IOA: asdu.IOA(1 + i), Value: true}))
				}
			}()
		}
	}))
	var (
		c      *client.Client
		ready  = make(chan struct{})
		closed atomic.Bool
		after  atomic.Int32
		first  sync.Once
		mu     sync.Mutex
		states []iec104.State
	)
	c, err := client.New(st.addr, client.WithParams(testutil.Params()),
		client.WithStateHandler(func(s iec104.State, err error) {
			mu.Lock()
			states = append(states, s)
			mu.Unlock()
		}),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			<-ready
			if closed.Load() {
				after.Add(1)
				return
			}
			first.Do(func() {
				time.Sleep(300 * time.Millisecond) // let the other ASDUs arrive
				_ = c.Close()
				closed.Store(true)
			})
		})))
	if err != nil {
		t.Fatal(err)
	}
	close(ready)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	mu.Lock()
	t.Logf("states: %v", states)
	mu.Unlock()
	if n := after.Load(); n != 0 {
		t.Errorf("Handler was called %d more times after Client.Close returned (and after 'disconnected')", n)
	}
}

// Finding 4 of the state machine review: Client.Close called from the state handler never returns: emit runs
// with notifyMu held and Close ends with setState, which takes notifyMu.
// The doc comment of Close says it may be called from the state handler
// ("Called from one of them, Close cannot wait for that call").
func TestOrderingCloseFromStateHandler(t *testing.T) {
	st := newStation(t)
	var c *client.Client
	returned := make(chan struct{})
	var once sync.Once
	c, err := client.New(st.addr, client.WithParams(testutil.Params()),
		client.WithStateHandler(func(s iec104.State, err error) {
			if s == iec104.StateStarted {
				once.Do(func() {
					_ = c.Close()
					close(returned)
				})
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Connect(context.Background()) }()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock: Client.Close called from the state handler did not return")
	}
}

// Finding 5 of the state machine review: a Connect that races Close notifies the state handler after Close has
// returned (Connect has passed its closed check, Close runs to completion,
// then Connect reports "connecting" and "disconnected").
func TestOrderingStateAfterCloseRacingConnect(t *testing.T) {
	st := newStation(t)
	late := 0
	for i := 0; i < 3000 && late == 0; i++ {
		var closed atomic.Bool
		var n atomic.Int32
		c, err := client.New(st.addr, client.WithParams(testutil.Params()),
			client.WithStateHandler(func(s iec104.State, err error) {
				if closed.Load() {
					n.Add(1)
					t.Logf("iteration %d: state %s (%v) after Close returned", i, s, err)
				}
			}))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = c.Connect(context.Background()); close(done) }()
		if i%2 == 1 {
			time.Sleep(time.Duration(i%50) * time.Microsecond)
		}
		_ = c.Close()
		closed.Store(true)
		<-done
		late += int(n.Load())
	}
	if late != 0 {
		t.Errorf("%d state notifications after Close returned", late)
	}
}

func orderingServe(t *testing.T, h server.Handler) string {
	t.Helper()
	srv, err := server.New(h, server.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// Finding 9 of the state machine review: the deactivation confirmation of an earlier Deactivate (one the caller
// gave up on) is taken as the positive confirmation of a later activation of
// the same object: mirrored() accepts any of actcon/deactcon/actterm for any
// request cause, and confirmedOnce only filters actterm. The station here
// plays "late deactcon" by answering the activation with a deactcon.
func TestOrderingDeactivationConIsNotAnActivationCon(t *testing.T) {
	addr := orderingServe(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		// The stale answer to an earlier C_SC deactivation; the activation
		// itself is never confirmed.
		_ = s.Reply(req, asdu.CauseDeactivationCon, false)
	}))
	c := dial(t, addr, client.WithRequestTimeout(500*time.Millisecond))
	err := c.Command(context.Background(), 1, asdu.SingleCommand{IOA: 1, Value: true})
	if err == nil {
		t.Errorf("Command (activation) returned nil on a deactivation confirmation")
	}
}

// Finding 10 of the state machine review: a second Client.Close that runs while the first is still waiting for
// the Handler returns at once.
func TestOrderingConcurrentClientClose(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	var running atomic.Bool
	addr := orderingServe(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }))
	c := dial(t, addr, client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
		running.Store(true)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
		running.Store(false)
	})))
	go func() { _ = c.Command(context.Background(), 1, asdu.SingleCommand{IOA: 1, Value: true}) }()
	<-entered
	go func() { _ = c.Close() }()
	time.Sleep(100 * time.Millisecond) // the first Close is waiting for the Handler
	second := make(chan struct{})
	go func() { _ = c.Close(); close(second) }()
	select {
	case <-second:
		t.Errorf("the second Client.Close returned while the Handler was still running")
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	select {
	case <-second:
		if running.Load() {
			t.Errorf("the second Client.Close returned while the Handler was still running")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second Client.Close never returned")
	}
}

// slowStation confirms STARTDT only after delay.
func slowStation(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				for {
					f, err := apci.ReadFrame(conn)
					if err != nil {
						return
					}
					if f.Format != apci.FormatU {
						continue
					}
					var con apci.UFunction
					switch f.Function {
					case apci.StartDTAct:
						time.Sleep(delay)
						con = apci.StartDTCon
					case apci.StopDTAct:
						con = apci.StopDTCon
					case apci.TestFRAct:
						con = apci.TestFRCon
					default:
						continue
					}
					b, _ := apci.NewU(con).MarshalBinary()
					if _, err := conn.Write(b); err != nil && err != io.EOF {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// Finding 11 of the state machine review: Group.start gives up on a connection whose STARTDT is not confirmed
// within the caller's bound (the request timeout when WithRetry is set) and
// starts the next one, but the STARTDT act stays pending on the link until
// t1. When the confirmation arrives after all, two connections of the group
// are started and nothing ever stops the stray one.
func TestOrderingGroupTwoStarted(t *testing.T) {
	slow := slowStation(t, 700*time.Millisecond)
	fast := orderingServe(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }))
	g, err := client.NewGroup([]string{slow, fast},
		client.WithParams(testutil.Params()), // t1 = 2s
		client.WithRequestTimeout(300*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 2}),
		client.WithReconnect(client.Reconnect{MinDelay: 50 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	cs := g.Clients()
	if cs[0].State() != iec104.StateStarted {
		// The fast one won the first start: move over to the slow one.
		t.Logf("Switchover: %v", g.Switchover(ctx))
		time.Sleep(1200 * time.Millisecond)
	}
	started := 0
	for _, c := range cs {
		t.Logf("%s: %s (active: %v)", c.Addr(), c.State(), c == g.Active())
		if c.State() == iec104.StateStarted {
			started++
		}
	}
	if started != 1 {
		t.Errorf("%d connections of the group have data transfer started, want exactly 1", started)
	}
	_ = asdu.Broadcast
}
