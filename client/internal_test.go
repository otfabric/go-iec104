// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

// These tests hold the client at a named point inside one of its
// transitions and do, in that window, exactly the thing that must not go
// wrong there. A race that a stress test hits once in a thousand runs is
// constructed here every time.

func withFailpoint(f func(name string)) Option {
	return func(o *options) { o.failpoint = f }
}

type stateLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *stateLog) add(st iec104.State, _ error) {
	s.mu.Lock()
	s.b.WriteByte(st.String()[0]) // c, s(tarted/topped) are told apart below
	if st == iec104.StateStarted {
		s.b.WriteByte('+')
	}
	s.mu.Unlock()
}

func (s *stateLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func station(t *testing.T) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }))
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

// The connection is lost and, before the client has reported that, the
// application closes the client. Close must wait for the report: the
// application is told once that it is disconnected, and not after Close.
func TestCloseWhileLossIsBeingReported(t *testing.T) {
	srv, addr := station(t)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var log stateLog
	c, err := Dial(context.Background(), addr, WithStateHandler(log.add),
		withFailpoint(func(name string) {
			if name == "link-detached" {
				once.Do(func() { close(reached) })
				<-release
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	// The station drops the connection; the client stops in the window.
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.Sessions()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for _, s := range srv.Sessions() {
		_ = s.Close()
	}
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never noticed the lost connection")
	}

	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatalf("Close returned while the loss of the connection was still being reported (told so far: %q)", log.String())
	case <-time.After(100 * time.Millisecond):
	}
	before := log.String()
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close never returned")
	}
	told := log.String()
	time.Sleep(20 * time.Millisecond)
	if after := log.String(); after != told {
		t.Fatalf("told %q when Close returned and %q afterwards", told, after)
	}
	// connecting, stopped, started, disconnected: each once.
	if told != "css+d" {
		t.Fatalf("the application was told %q (before the release: %q), want connecting, stopped, started, disconnected", told, before)
	}
	if c.State() != iec104.StateDisconnected {
		t.Fatalf("state %s after Close", c.State())
	}
}

// The same window with a client that reconnects: Close in the window must
// not leave a reconnect loop behind, nor a connection.
func TestCloseWhileLossIsBeingReportedWithReconnect(t *testing.T) {
	srv, addr := station(t)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var log stateLog
	c, err := Dial(context.Background(), addr, WithStateHandler(log.add),
		WithReconnect(Reconnect{MinDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}),
		withFailpoint(func(name string) {
			if name == "link-detached" {
				once.Do(func() { close(reached) })
				<-release
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.Sessions()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for _, s := range srv.Sessions() {
		_ = s.Close()
	}
	<-reached
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close never returned")
	}
	told := log.String()
	time.Sleep(50 * time.Millisecond)
	if after := log.String(); after != told || !strings.HasSuffix(told, "d") || strings.Count(told, "d") != 1 {
		t.Fatalf("told %q when Close returned and %q afterwards; want one disconnected, last", told, after)
	}
	if n := len(srv.Sessions()); n != 0 {
		t.Fatalf("%d sessions at the station after the client was closed: it reconnected", n)
	}
	if c.State() != iec104.StateDisconnected {
		t.Fatalf("state %s after Close", c.State())
	}
}
