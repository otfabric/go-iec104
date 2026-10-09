// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// events collects the scaled values a client receives, in order.
type events struct {
	mu   sync.Mutex
	seen []int16
}

func (e *events) HandleASDU(a *asdu.ASDU) {
	if v, ok := a.First().(asdu.MeasuredScaled); ok && a.Cause == asdu.CauseSpontaneous {
		e.mu.Lock()
		e.seen = append(e.seen, v.Value)
		e.mu.Unlock()
	}
}

func (e *events) values() []int16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]int16(nil), e.seen...)
}

func event(i int) *asdu.ASDU {
	return asdu.New(asdu.CauseSpontaneous, 1, asdu.MeasuredScaled{IOA: 1, Value: int16(i)})
}

func enqueue(t *testing.T, srv *server.Server, from, to int) {
	t.Helper()
	for i := from; i <= to; i++ {
		if err := srv.Enqueue(event(i)); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
}

func isRange(got []int16, from, to int) bool {
	if len(got) != to-from+1 {
		return false
	}
	for i, v := range got {
		if int(v) != from+i {
			return false
		}
	}
	return true
}

// Events enqueued while no controlling station is connected are delivered,
// in order, to the first one that starts data transfer.
func TestEventQueueBuffersWithoutClient(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll))
	enqueue(t, srv, 1, 50)
	if n := srv.Pending("default"); n != 50 {
		t.Fatalf("Pending = %d, want 50", n)
	}

	// A connection that is not started gets nothing.
	standby := &events{}
	connect(t, addr, client.WithHandler(standby), client.WithAutoStart(false))
	time.Sleep(100 * time.Millisecond)
	if len(standby.values()) != 0 || srv.Pending("default") != 50 {
		t.Fatalf("a connection in STOPDT received %d events", len(standby.values()))
	}

	rx := &events{}
	c := connect(t, addr, client.WithHandler(rx))
	testutil.Eventually(t, "delivery", func() bool { return len(rx.values()) == 50 })
	if !isRange(rx.values(), 1, 50) {
		t.Errorf("events out of order: %v", rx.values())
	}
	// Acknowledged events leave the queue.
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("default") == 0 })

	// Live events follow, and a handler's replies are not held up by them.
	enqueue(t, srv, 51, 60)
	if err := c.TestCommand(context.Background(), 1); err != nil {
		t.Errorf("TestCommand: %v", err)
	}
	testutil.Eventually(t, "live events", func() bool { return isRange(rx.values(), 1, 60) })
	if len(standby.values()) != 0 {
		t.Error("the standby connection received queued events")
	}
	if srv.Pending("no-such-group") != 0 || srv.Dropped("no-such-group") != 0 || srv.Dropped("default") != 0 {
		t.Error("Pending/Dropped bookkeeping")
	}
	if err := srv.Enqueue(&asdu.ASDU{Type: asdu.M_SP_NA_1, Cause: 99}); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("Enqueue of an unencodable ASDU: %v", err)
	}
}

// An event that was sent but not acknowledged when its connection went away
// is sent again on the next one.
func TestEventQueueResendsUnacknowledged(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll))
	enqueue(t, srv, 1, 5)

	// A controlling station that starts data transfer, takes the I frames
	// and disappears without acknowledging any of them.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := apci.NewU(apci.StartDTAct).MarshalBinary()
	if _, err := conn.Write(start); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := 0
	for got < 5 {
		f, err := apci.ReadFrame(conn)
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		if f.Format == apci.FormatI {
			got++
		}
	}
	if n := srv.Pending("default"); n != 5 {
		t.Fatalf("Pending = %d after sending without acknowledgement, want 5", n)
	}
	_ = conn.Close()
	testutil.Eventually(t, "session gone", func() bool { return len(srv.Sessions()) == 0 })

	rx := &events{}
	connect(t, addr, client.WithHandler(rx))
	testutil.Eventually(t, "redelivery", func() bool { return len(rx.values()) == 5 })
	if !isRange(rx.values(), 1, 5) {
		t.Errorf("redelivered %v, want 1..5 in order", rx.values())
	}
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("default") == 0 })
}

// Within a redundancy group events go to the one started connection and
// follow a switchover.
func TestEventQueueFollowsSwitchover(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll))
	rx := &events{}
	// A client-side redundancy group over two connections to this server.
	g, err := client.NewGroup([]string{addr, addr},
		client.WithParams(testutil.Params()), client.WithHandler(rx),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	ctx := context.Background()
	if err := g.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "both connections", func() bool { return len(srv.Sessions()) == 2 })
	for _, s := range srv.Sessions() {
		if s.Group() != "default" {
			t.Errorf("session in group %q", s.Group())
		}
	}

	enqueue(t, srv, 1, 20)
	testutil.Eventually(t, "events on the first connection", func() bool { return isRange(rx.values(), 1, 20) })

	testutil.Eventually(t, "standby", func() bool {
		for _, c := range g.Clients() {
			if c != g.Active() && c.State() == iec104.StateStopped {
				return true
			}
		}
		return false
	})
	if err := g.Switchover(ctx); err != nil {
		t.Fatalf("Switchover: %v", err)
	}
	enqueue(t, srv, 21, 40)
	testutil.Eventually(t, "events after switchover", func() bool { return len(rx.values()) >= 40 })
	// Nothing is lost and nothing arrives out of order; an event that was
	// in flight during the switchover may arrive twice.
	last := int16(0)
	seen := map[int16]bool{}
	for _, v := range rx.values() {
		if v < last {
			t.Fatalf("event %d after %d", v, last)
		}
		last = v
		seen[v] = true
	}
	if len(seen) != 40 {
		t.Errorf("%d distinct events, want 40", len(seen))
	}
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("default") == 0 })
}

func TestEventQueueOverflow(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll), server.WithEventQueue(3),
		server.WithLogger(iec104.NopLogger()))
	enqueue(t, srv, 1, 5)
	if p, d := srv.Pending("default"), srv.Dropped("default"); p != 3 || d != 2 {
		t.Fatalf("Pending %d, Dropped %d; want 3 and 2", p, d)
	}
	rx := &events{}
	connect(t, addr, client.WithHandler(rx))
	testutil.Eventually(t, "delivery", func() bool { return len(rx.values()) == 3 })
	if !isRange(rx.values(), 3, 5) {
		t.Errorf("received %v, want the three newest", rx.values())
	}
}

func TestRedundancyGroups(t *testing.T) {
	for _, bad := range [][]server.Option{
		{server.WithEventQueue(-1)},
		{server.WithRedundancyGroups(server.RedundancyGroup{Name: ""})},
		{server.WithRedundancyGroups(server.RedundancyGroup{Name: "a"}, server.RedundancyGroup{Name: "a"})},
		{server.WithRedundancyGroups(server.RedundancyGroup{Name: "a", Allow: []string{"not-an-address"}})},
	} {
		if _, err := server.New(nil, bad...); !errors.Is(err, iec104.ErrInvalidOption) {
			t.Errorf("error = %v, want ErrInvalidOption", err)
		}
	}

	// The first group that allows the client's address takes it; each
	// group has its own queue.
	srv, addr := serve(t, server.HandlerFunc(confirmAll), server.WithRedundancyGroups(
		server.RedundancyGroup{Name: "elsewhere", Allow: []string{"192.0.2.0/24", "2001:db8::1"}},
		server.RedundancyGroup{Name: "local", Allow: []string{"127.0.0.1"}},
		server.RedundancyGroup{Name: "rest"},
	))
	enqueue(t, srv, 1, 4)
	rx := &events{}
	connect(t, addr, client.WithHandler(rx))
	testutil.Eventually(t, "session", func() bool { return len(srv.Sessions()) == 1 })
	if g := srv.Sessions()[0].Group(); g != "local" {
		t.Errorf("session in group %q, want local", g)
	}
	testutil.Eventually(t, "delivery", func() bool { return isRange(rx.values(), 1, 4) })
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("local") == 0 })
	// The other groups keep their copy for their own controlling stations.
	if srv.Pending("elsewhere") != 4 || srv.Pending("rest") != 4 {
		t.Errorf("Pending elsewhere=%d rest=%d, want 4 each", srv.Pending("elsewhere"), srv.Pending("rest"))
	}

	// A client no group allows is turned away.
	strict, saddr := serve(t, server.HandlerFunc(confirmAll), server.WithLogger(iec104.NopLogger()),
		server.WithRedundancyGroups(server.RedundancyGroup{Name: "elsewhere", Allow: []string{"192.0.2.7"}}))
	conn, err := net.Dial("tcp", saddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("a client outside every redundancy group was served")
	}
	if len(strict.Sessions()) != 0 {
		t.Error("a client outside every redundancy group became a session")
	}

	closed, _ := server.New(nil)
	_ = closed.Close()
	if err := closed.Enqueue(event(1)); !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("Enqueue after Close: %v", err)
	}
}
