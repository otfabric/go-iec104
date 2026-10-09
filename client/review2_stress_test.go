// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"math/rand"
	"net"
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

func stressServe(t *testing.T) (*server.Server, string) {
	t.Helper()
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
	return srv, ln.Addr().String()
}

// Group under switchovers, cuts and requests, then Close: nothing hangs,
// nothing is said after Close, and while it runs the group settles to
// exactly one started connection, which is the active one.
func TestReview2GroupStress(t *testing.T) {
	for round := 0; round < 12; round++ {
		sa, a := stressServe(t)
		sb, b := stressServe(t)
		var closed atomic.Bool
		var lateSwitch, lateState, lateASDU atomic.Int32
		g, err := client.NewGroup([]string{a, b}, client.WithParams(testutil.Params()),
			client.WithRequestTimeout(time.Second),
			client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 30 * time.Millisecond}),
			client.WithSwitchHandler(func(*client.Client) {
				if closed.Load() {
					lateSwitch.Add(1)
				}
			}),
			client.WithStateHandler(func(iec104.State, error) {
				if closed.Load() {
					lateState.Add(1)
				}
			}),
			client.WithHandler(client.HandlerFunc(func(*asdu.ASDU) {
				if closed.Load() {
					lateASDU.Add(1)
				}
			})))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := g.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(seed))
				for {
					select {
					case <-stop:
						return
					default:
					}
					switch rng.Intn(6) {
					case 0:
						_ = g.Switchover(context.Background())
					case 1:
						srv := sa
						if rng.Intn(2) == 0 {
							srv = sb
						}
						for _, s := range srv.Sessions() {
							_ = s.Close()
						}
					default:
						_ = g.Command(context.Background(), 1, asdu.SingleCommand{IOA: 1, Value: true})
					}
					time.Sleep(time.Duration(rng.Intn(5)) * time.Millisecond)
				}
			}(int64(round*10 + w))
		}
		time.Sleep(400 * time.Millisecond)
		close(stop)
		wg.Wait()
		// Quiescence: exactly one started, and it is the active one.
		ok := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			n := 0
			var started *client.Client
			for _, c := range g.Clients() {
				if c.State() == iec104.StateStarted {
					n++
					started = c
				}
			}
			if n == 1 && g.Active() == started {
				ok = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ok {
			var st []string
			for _, c := range g.Clients() {
				st = append(st, c.State().String())
			}
			t.Errorf("round %d: the group did not settle: states %v, active %v", round, st, g.Active() != nil)
		}
		done := make(chan struct{})
		go func() { _ = g.Close(); closed.Store(true); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: Group.Close did not return", round)
		}
		time.Sleep(100 * time.Millisecond)
		if lateSwitch.Load()+lateState.Load()+lateASDU.Load() != 0 {
			t.Errorf("round %d: after Group.Close: %d switch, %d state, %d ASDU callbacks", round,
				lateSwitch.Load(), lateState.Load(), lateASDU.Load())
		}
		_ = sa.Close()
		_ = sb.Close()
	}
}

// Group.Close racing Switchover: is the switch handler called after Close?
func TestReview2GroupCloseRacingSwitchover(t *testing.T) {
	late := 0
	for round := 0; round < 150 && late == 0; round++ {
		_, a := stressServe(t)
		_, b := stressServe(t)
		var closed atomic.Bool
		var lateSwitch atomic.Int32
		g, err := client.NewGroup([]string{a, b}, client.WithParams(testutil.Params()),
			client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 30 * time.Millisecond}),
			client.WithSwitchHandler(func(*client.Client) {
				if closed.Load() {
					lateSwitch.Add(1)
				}
			}))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := g.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		testutil.Eventually(t, "a standby", func() bool {
			for _, c := range g.Clients() {
				if c.State() == iec104.StateStopped {
					return true
				}
			}
			return false
		})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Switchover(context.Background()) }()
		time.Sleep(time.Duration(round%20) * 100 * time.Microsecond)
		_ = g.Close()
		closed.Store(true)
		wg.Wait()
		time.Sleep(5 * time.Millisecond)
		late += int(lateSwitch.Load())
	}
	if late != 0 {
		t.Errorf("the switch handler was called %d times after Group.Close returned", late)
	}
}
