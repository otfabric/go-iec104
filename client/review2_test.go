// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
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

// R2-1: Group.Close called from the state handler of one of the group's
// connections never returns. reconcile holds g.mu across c.startDT, which
// delivers (or waits for the delivery of) the state notification; the
// handler's g.Close begins with g.mu.Lock.
func TestReview2GroupCloseFromStateHandler(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	var g *client.Group
	ready := make(chan struct{})
	returned := make(chan struct{})
	var once sync.Once
	g, err := client.NewGroup([]string{a, b}, client.WithParams(testutil.Params()),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond}),
		client.WithStateHandler(func(st iec104.State, _ error) {
			<-ready
			if st == iec104.StateStarted {
				once.Do(func() {
					_ = g.Close()
					close(returned)
				})
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	close(ready)
	go func() { _ = g.Connect(context.Background()) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: Group.Close called from a connection's state handler did not return")
	}
}

// R2-1b: the same for Group.Switchover from the state handler.
func TestReview2GroupSwitchoverFromStateHandler(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	var g *client.Group
	ready := make(chan struct{})
	returned := make(chan struct{})
	var once sync.Once
	g, err := client.NewGroup([]string{a, b}, client.WithParams(testutil.Params()),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond}),
		client.WithStateHandler(func(st iec104.State, _ error) {
			<-ready
			if st == iec104.StateStarted {
				once.Do(func() {
					_ = g.Switchover(context.Background())
					close(returned)
				})
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { go func() { _ = g.Close() }() })
	close(ready)
	go func() { _ = g.Connect(context.Background()) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: Group.Switchover called from a connection's state handler did not return")
	}
}

// R2-2: Group.Close returns while the switch handler is still running (it
// was being called on the goroutine of a Switchover), and the handler is
// called again after Close has returned.
func TestReview2GroupCloseDoesNotWaitForSwitchHandler(t *testing.T) {
	a := orderingServe(t, server.HandlerFunc(confirming))
	b := orderingServe(t, server.HandlerFunc(confirming))
	var (
		armed   atomic.Bool
		inside  = make(chan struct{})
		release = make(chan struct{})
		running atomic.Int32
		closed  atomic.Bool
		late    atomic.Int32
		once    sync.Once
	)
	g := newGroup(t, []string{a, b}, client.WithSwitchHandler(func(active *client.Client) {
		if closed.Load() {
			late.Add(1)
		}
		if !armed.Load() {
			return
		}
		running.Add(1)
		defer running.Add(-1)
		once.Do(func() { close(inside); <-release })
	}))
	testutil.Eventually(t, "a standby", func() bool {
		for _, c := range g.Clients() {
			if c.State() == iec104.StateStopped {
				return true
			}
		}
		return false
	})
	armed.Store(true)
	go func() { _ = g.Switchover(context.Background()) }() // delivers the switch on this goroutine
	<-inside
	done := make(chan struct{})
	go func() { _ = g.Close(); close(done) }()
	select {
	case <-done:
		t.Errorf("Group.Close returned while the switch handler was still running (%d calls)", running.Load())
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	within(t, "Group.Close", func() { <-done })
	closed.Store(true)
	if n := running.Load(); n != 0 {
		t.Errorf("Group.Close returned while the switch handler was still running")
	}
	time.Sleep(200 * time.Millisecond)
	if n := late.Load(); n != 0 {
		t.Errorf("the switch handler was called %d times after Group.Close returned", n)
	}
}

// R2-4: a request from the state handler worked or ran into its timeout,
// depending on the goroutine that happened to deliver the notification. It
// now fails at once, every time, and says why.
func TestReview2RequestFromStateHandlerIsARace(t *testing.T) {
	addr := orderingServe(t, server.HandlerFunc(confirming))
	for i := 0; i < 60; i++ {
		var c *client.Client
		res := make(chan error, 1)
		ready := make(chan struct{})
		var once sync.Once
		c, err := client.New(addr, client.WithParams(testutil.Params()), client.WithRequestTimeout(5*time.Second),
			client.WithStateHandler(func(st iec104.State, _ error) {
				<-ready
				if st == iec104.StateStarted {
					once.Do(func() { res <- c.Command(context.Background(), 1, asdu.SingleCommand{IOA: 1, Value: true}) })
				}
			}))
		if err != nil {
			t.Fatal(err)
		}
		close(ready)
		begin := time.Now()
		_ = c.Connect(context.Background())
		if err := <-res; !errors.Is(err, iec104.ErrInHandler) {
			t.Errorf("round %d: Command from the state handler: %v, want ErrInHandler", i, err)
		}
		if d := time.Since(begin); d > 2*time.Second {
			t.Errorf("round %d: took %v", i, d)
		}
		_ = c.Close()
	}
}

type dialCounter struct{ n atomic.Int32 }

func (d *dialCounter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.n.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// R2-5: how often does a group dial an address that refuses connections?
func TestReview2GroupRedialRate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	d := &dialCounter{}
	g, err := client.NewGroup([]string{dead}, client.WithParams(testutil.Params()), client.WithDialer(d),
		client.WithReconnect(client.Reconnect{MinDelay: 200 * time.Millisecond, MaxDelay: time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = g.Connect(ctx)
	_ = g.Close()
	n := d.n.Load()
	t.Logf("%d dial attempts in 2s with MinDelay 200ms", n)
	if n > 15 {
		t.Errorf("%d dial attempts in 2s with MinDelay 200ms: the group redials without delay", n)
	}
}
