// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// proxy forwards TCP connections to a server. Cut silences the connections
// it carries without closing them, as a path that fails does: neither end
// sees a FIN. Connections made after that are forwarded again.
type proxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []*proxied
}

type proxied struct {
	mu   sync.Mutex
	cut  bool
	ends []net.Conn
}

func (p *proxied) silenced() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cut
}

func newProxy(t *testing.T, upstream string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.conns {
			for _, e := range c.ends {
				_ = e.Close()
			}
		}
	})
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = down.Close()
				continue
			}
			c := &proxied{ends: []net.Conn{down, up}}
			p.mu.Lock()
			p.conns = append(p.conns, c)
			p.mu.Unlock()
			go c.pipe(up, down)
			go c.pipe(down, up)
		}
	}()
	return p
}

// pipe copies from src to dst until either closes, and discards what it
// reads once the connection is cut.
func (p *proxied) pipe(dst, src net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.silenced() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if !p.silenced() {
		_ = dst.Close()
		_ = src.Close()
	}
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

// cut silences every connection the proxy carries now.
func (p *proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.mu.Lock()
		c.cut = true
		c.mu.Unlock()
	}
}

// startedSessions returns the sessions of srv with data transfer started.
func startedSessions(srv *server.Server) []*server.Session {
	var out []*server.Session
	for _, s := range srv.Sessions() {
		if s.Started() {
			out = append(out, s)
		}
	}
	return out
}

// established reports whether every connection of g is up.
func established(g *client.Group) bool {
	for _, c := range g.Clients() {
		if st := c.State(); st != iec104.StateStopped && st != iec104.StateStarted {
			return false
		}
	}
	return true
}

// A standby of a declared group that loses its connection and comes back
// rejoins in STOPDT: the active connection keeps data transfer, and its
// events arrive once each, in order.
func TestReconnectingStandbyDoesNotEvictActive(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll), server.WithLogger(iec104.NopLogger()),
		server.WithRedundancyGroups(server.RedundancyGroup{Name: "scada"}))
	rx := &events{}
	g, err := client.NewGroup([]string{addr, addr},
		client.WithParams(testutil.Params()), client.WithHandler(rx), client.WithLogger(iec104.NopLogger()),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "active and standby", func() bool {
		return len(srv.Sessions()) == 2 && len(startedSessions(srv)) == 1 && established(g)
	})
	active := startedSessions(srv)[0]
	activeClient := g.Active()
	enqueue(t, srv, 1, 10)
	testutil.Eventually(t, "events before the reconnect", func() bool { return isRange(rx.values(), 1, 10) })

	// The station drops the standby; the group re-establishes it.
	for _, s := range srv.Sessions() {
		if s != active {
			_ = s.Close()
		}
	}
	testutil.Eventually(t, "the standby back", func() bool {
		for _, s := range srv.Sessions() {
			if s != active && s.Err() == nil {
				return len(srv.Sessions()) == 2 && established(g)
			}
		}
		return false
	})
	// Give a STARTDT on the new connection, if one were sent, time to land.
	time.Sleep(200 * time.Millisecond)

	if got := startedSessions(srv); len(got) != 1 || got[0] != active {
		t.Fatalf("started sessions after the standby came back: %d, want only the active one", len(got))
	}
	if active.Err() != nil {
		t.Errorf("the active session ended: %v", active.Err())
	}
	if g.Active() != activeClient {
		t.Error("the group switched over when its standby came back")
	}
	enqueue(t, srv, 11, 20)
	testutil.Eventually(t, "events after the reconnect", func() bool { return len(rx.values()) >= 20 })
	if !isRange(rx.values(), 1, 20) {
		t.Errorf("received %v, want 1..20 once each", rx.values())
	}
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("scada") == 0 })
}

// When the path of the active connection fails silently, the station still
// holds that session started. The group fails over: the STARTDT of the
// standby takes over and closes the stale session. The lost connection then
// comes back as a standby and does not take data transfer back.
func TestFailoverThenRejoinDoesNotEvict(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll), server.WithLogger(iec104.NopLogger()),
		server.WithRedundancyGroups(server.RedundancyGroup{Name: "scada"}))
	// Each connection has its own path, and the active one's fails.
	paths := []*proxy{newProxy(t, addr), newProxy(t, addr)}
	rx := &events{}
	// t3 makes the client notice a path that has gone quiet; the station
	// sends no test frames, so it keeps the stale session until taken over.
	params := testutil.Params()
	params.T1 = time.Second
	params.T3 = 300 * time.Millisecond
	g, err := client.NewGroup([]string{paths[0].addr(), paths[1].addr()},
		client.WithParams(params), client.WithHandler(rx), client.WithLogger(iec104.NopLogger()),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "active and standby", func() bool {
		return len(srv.Sessions()) == 2 && len(startedSessions(srv)) == 1 && established(g)
	})
	lost, other := g.Clients()[0], g.Clients()[1]
	cut := paths[0]
	if g.Active() != lost {
		lost, other, cut = other, lost, paths[1]
	}
	stale := startedSessions(srv)[0]
	enqueue(t, srv, 1, 5)
	testutil.Eventually(t, "events before the failure", func() bool { return isRange(rx.values(), 1, 5) })
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("scada") == 0 })

	cut.cut()
	testutil.Eventually(t, "failover", func() bool { return g.Active() == other })
	testutil.Eventually(t, "the stale session closed", func() bool { return stale.Err() != nil })
	var next *server.Session
	testutil.Eventually(t, "one started session", func() bool {
		got := startedSessions(srv)
		if len(got) != 1 || got[0] == stale {
			return false
		}
		next = got[0]
		return true
	})

	// The lost connection is dialed again through the proxy and rejoins.
	testutil.Eventually(t, "the lost connection back", func() bool {
		return len(srv.Sessions()) == 2 && established(g)
	})
	time.Sleep(200 * time.Millisecond)
	if got := startedSessions(srv); len(got) != 1 || got[0] != next {
		t.Fatalf("started sessions after the rejoin: %d, want only the one that took over", len(got))
	}
	if next.Err() != nil {
		t.Errorf("the session that took over ended: %v", next.Err())
	}
	if g.Active() != other {
		t.Error("data transfer went back to the connection that returned")
	}
	if st := lost.State(); st != iec104.StateStopped {
		t.Errorf("the returned connection is %v, want a standby", st)
	}
	enqueue(t, srv, 6, 10)
	testutil.Eventually(t, "events after the rejoin", func() bool { return isRange(rx.values(), 1, 10) })
	testutil.Eventually(t, "acknowledgement", func() bool { return srv.Pending("scada") == 0 })
}
