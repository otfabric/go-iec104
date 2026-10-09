// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
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

func serve(t *testing.T, h server.Handler, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(h, append([]server.Option{server.WithParams(testutil.Params())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; !errors.Is(err, server.ErrServerClosed) {
			t.Errorf("Serve returned %v, want ErrServerClosed", err)
		}
	})
	return srv, ln.Addr().String()
}

func connect(t *testing.T, addr string, opts ...client.Option) *client.Client {
	t.Helper()
	opts = append([]client.Option{client.WithParams(testutil.Params()), client.WithRequestTimeout(3 * time.Second)}, opts...)
	c, err := client.Dial(context.Background(), addr, opts...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func cause(t *testing.T, err error) asdu.Cause {
	t.Helper()
	var neg *iec104.NegativeError
	if !errors.As(err, &neg) {
		t.Fatalf("error = %v, want *iec104.NegativeError", err)
	}
	return neg.Cause()
}

func confirmAll(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }

func TestNilHandlerRejectsEverything(t *testing.T) {
	_, addr := serve(t, nil)
	c := connect(t, addr)
	err := c.Command(context.Background(), 1, asdu.SingleCommand{IOA: 1})
	if got := cause(t, err); got != asdu.CauseUnknownType {
		t.Errorf("cause = %s, want unknown-type", got)
	}
}

func TestCommonAddressFilter(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []asdu.CommonAddr
	)
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		mu.Lock()
		seen = append(seen, req.CommonAddr)
		mu.Unlock()
		_ = s.Confirm(req)
	}), server.WithCommonAddrs(1, 2))
	c := connect(t, addr)
	ctx := context.Background()

	for _, ca := range []asdu.CommonAddr{1, 2, asdu.Broadcast} {
		if err := c.TestCommand(ctx, ca); err != nil {
			t.Errorf("station %d: %v", ca, err)
		}
	}
	if got := cause(t, c.TestCommand(ctx, 3)); got != asdu.CauseUnknownCommonAddr {
		t.Errorf("cause = %s, want unknown-common-address", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Errorf("handler saw stations %v, want 1, 2 and broadcast only", seen)
	}
}

func TestMux(t *testing.T) {
	var mux server.Mux // the zero Mux is usable
	mux.HandleFunc(asdu.C_SC_NA_1, confirmAll)
	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr,
			asdu.SinglePoint{IOA: req.First().Address(), Value: true}))
	})
	mux.HandleFunc(asdu.F_SC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		_ = s.Reply(req, asdu.CauseFileTransfer, false)
	})
	_, addr := serve(t, &mux)
	got := make(chan *asdu.ASDU, 16)
	c := connect(t, addr, client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) { got <- a })))
	ctx := context.Background()
	next := func() *asdu.ASDU {
		t.Helper()
		select {
		case a := <-got:
			return a
		case <-time.After(3 * time.Second):
			t.Fatal("no answer")
			return nil
		}
	}

	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1}); err != nil {
		t.Fatalf("registered type: %v", err)
	}
	next()
	if got := cause(t, c.Command(ctx, 1, asdu.DoubleCommand{IOA: 1, Value: asdu.DoubleOn})); got != asdu.CauseUnknownType {
		t.Errorf("unregistered type: cause %s", got)
	}
	next()
	if a, err := c.Read(ctx, 1, 77); err != nil || a.First().Address() != 77 {
		t.Errorf("Read: %v, %v", a, err)
	}
	next()

	// Causes that are not valid in control direction never reach the handler.
	for _, bad := range []*asdu.ASDU{
		asdu.New(asdu.CauseSpontaneous, 1, asdu.SingleCommand{IOA: 1}),
		asdu.New(asdu.CauseActivation, 1, asdu.Read{IOA: 1}),
	} {
		if err := c.Send(ctx, bad); err != nil {
			t.Fatal(err)
		}
		if a := next(); a.Cause != asdu.CauseUnknownCause || !a.Negative || a.Type != bad.Type {
			t.Errorf("%s: answered with %s", bad, a)
		}
	}
	// File transfer types are passed through with whatever cause they carry.
	if err := c.Send(ctx, asdu.New(asdu.CauseFileTransfer, 1, asdu.FileCall{IOA: 9, Name: 1, Qualifier: asdu.FileSelect})); err != nil {
		t.Fatal(err)
	}
	a := next()
	if call, ok := a.First().(asdu.FileCall); !ok || a.Type != asdu.F_SC_NA_1 || a.Cause != asdu.CauseFileTransfer ||
		call.Name != 1 || call.Qualifier != asdu.FileSelect {
		t.Errorf("file transfer echo: %s %+v", a, a.First())
	}

	// Handlers can be replaced and removed at run time.
	mux.Handle(nil, asdu.C_SC_NA_1)
	if got := cause(t, c.Command(ctx, 1, asdu.SingleCommand{IOA: 1})); got != asdu.CauseUnknownType {
		t.Errorf("removed handler: cause %s", got)
	}
}

func TestSessionReplies(t *testing.T) {
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		switch req.First().Address() {
		case 1:
			_ = s.Confirm(req)
			_ = s.Terminate(req)
		case 2:
			_ = s.Negative(req)
		default:
			_ = s.Reject(req, asdu.CauseUnknownIOA)
		}
	}))
	got := make(chan *asdu.ASDU, 16)
	c := connect(t, addr, client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) { got <- a })))
	ctx := context.Background()

	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1}); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a.Cause != asdu.CauseActivationCon || a.Negative {
		t.Errorf("confirmation: %s", a)
	}
	if a := <-got; a.Cause != asdu.CauseActivationTerm {
		t.Errorf("termination: %s", a)
	}
	if err := c.Deactivate(ctx, 1, asdu.SingleCommand{IOA: 1}); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a.Cause != asdu.CauseDeactivationCon {
		t.Errorf("deactivation confirmation: %s", a)
	}
	if got := cause(t, c.Command(ctx, 1, asdu.SingleCommand{IOA: 2})); got != asdu.CauseActivationCon {
		t.Errorf("negative: cause %s", got)
	}
	if got := cause(t, c.Deactivate(ctx, 1, asdu.SingleCommand{IOA: 2})); got != asdu.CauseDeactivationCon {
		t.Errorf("negative deactivation: cause %s", got)
	}
	if got := cause(t, c.Command(ctx, 1, asdu.SingleCommand{IOA: 3})); got != asdu.CauseUnknownIOA {
		t.Errorf("reject: cause %s", got)
	}
}

type stateEvent struct {
	id    uint64
	state iec104.State
	err   error
}

func TestSessionLifecycle(t *testing.T) {
	events := make(chan stateEvent, 16)
	m := &testutil.Metrics{}
	srv, addr := serve(t, server.HandlerFunc(confirmAll),
		server.WithMetrics(m), server.WithLogger(iec104.NopLogger()),
		server.WithStateHandler(func(s *server.Session, state iec104.State, err error) {
			events <- stateEvent{s.ID(), state, err}
		}))
	expect := func(want iec104.State) stateEvent {
		t.Helper()
		select {
		case ev := <-events:
			if ev.state != want {
				t.Fatalf("state %s, want %s", ev.state, want)
			}
			return ev
		case <-time.After(3 * time.Second):
			t.Fatalf("no %s notification", want)
			return stateEvent{}
		}
	}
	ctx := context.Background()

	c := connect(t, addr, client.WithAutoStart(false))
	first := expect(iec104.StateStopped)
	testutil.Eventually(t, "session", func() bool { return len(srv.Sessions()) == 1 })
	sess := srv.Sessions()[0]
	if sess.ID() != first.id || sess.Started() || sess.Err() != nil {
		t.Fatalf("new session: id=%d started=%v err=%v", sess.ID(), sess.Started(), sess.Err())
	}
	if sess.RemoteAddr() == nil || sess.LocalAddr().String() != addr || sess.Conn() == nil {
		t.Error("session addresses")
	}
	if err := sess.Send(ctx, asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1})); !errors.Is(err, iec104.ErrNotStarted) {
		t.Errorf("Send in STOPDT: %v, want ErrNotStarted", err)
	}
	if n, err := srv.Broadcast(ctx, asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1})); n != 0 || err != nil {
		t.Errorf("Broadcast with no started session: %d, %v", n, err)
	}
	if _, err := srv.Broadcast(ctx, &asdu.ASDU{Type: asdu.M_SP_NA_1, Cause: 99}); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("Broadcast of an unencodable ASDU: %v", err)
	}
	if err := sess.Send(ctx, &asdu.ASDU{Type: asdu.M_SP_NA_1, Cause: 99}); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("Send of an unencodable ASDU: %v", err)
	}

	if err := c.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	expect(iec104.StateStarted)
	if !sess.Started() {
		t.Error("session not started")
	}
	if err := c.StopDT(ctx); err != nil {
		t.Fatal(err)
	}
	expect(iec104.StateStopped)

	select {
	case <-sess.Context().Done():
		t.Fatal("session context cancelled while connected")
	default:
	}
	_ = c.Close()
	if ev := expect(iec104.StateDisconnected); !errors.Is(ev.err, iec104.ErrConnectionLost) {
		t.Errorf("disconnect reason: %v, want ErrConnectionLost", ev.err)
	}
	<-sess.Context().Done()
	if !errors.Is(sess.Err(), iec104.ErrConnectionLost) {
		t.Errorf("Err = %v", sess.Err())
	}
	testutil.Eventually(t, "session removed", func() bool { return len(srv.Sessions()) == 0 })

	// A session closed by the server ends without an error.
	connect(t, addr)
	expect(iec104.StateStopped)
	expect(iec104.StateStarted)
	testutil.Eventually(t, "second session", func() bool { return len(srv.Sessions()) == 1 })
	sess = srv.Sessions()[0]
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if ev := expect(iec104.StateDisconnected); ev.err != nil || sess.Err() != nil {
		t.Errorf("server-side close reported %v / %v", ev.err, sess.Err())
	}
	testutil.Eventually(t, "metrics", func() bool {
		c, d, _, _, _ := m.Snapshot()
		return c == 2 && d == 2
	})
}

func TestBroadcast(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll))
	type rx struct {
		mu sync.Mutex
		n  int
	}
	counts := make([]*rx, 3)
	for i := range counts {
		r := &rx{}
		counts[i] = r
		opts := []client.Option{client.WithHandler(client.HandlerFunc(func(*asdu.ASDU) {
			r.mu.Lock()
			r.n++
			r.mu.Unlock()
		}))}
		if i == 2 {
			opts = append(opts, client.WithAutoStart(false)) // a standby connection
		}
		connect(t, addr, opts...)
	}
	testutil.Eventually(t, "sessions", func() bool {
		started := 0
		for _, s := range srv.Sessions() {
			if s.Started() {
				started++
			}
		}
		return len(srv.Sessions()) == 3 && started == 2
	})
	for i := 0; i < 50; i++ {
		n, err := srv.Broadcast(context.Background(), asdu.New(asdu.CauseSpontaneous, 1,
			asdu.MeasuredScaled{IOA: 1, Value: int16(i)}))
		if n != 2 || err != nil {
			t.Fatalf("Broadcast %d: %d sessions, %v", i, n, err)
		}
	}
	testutil.Eventually(t, "delivery", func() bool {
		counts[0].mu.Lock()
		counts[1].mu.Lock()
		defer counts[0].mu.Unlock()
		defer counts[1].mu.Unlock()
		return counts[0].n == 50 && counts[1].n == 50
	})
	counts[2].mu.Lock()
	defer counts[2].mu.Unlock()
	if counts[2].n != 0 {
		t.Errorf("standby connection received %d ASDUs", counts[2].n)
	}
}

func TestConnectionLimits(t *testing.T) {
	var allow sync.Map
	srv, addr := serve(t, server.HandlerFunc(confirmAll), server.WithMaxSessions(1),
		server.WithLogger(iec104.NopLogger()),
		server.WithAccept(func(remote net.Addr) bool {
			_, denied := allow.Load("deny")
			return !denied
		}))
	connect(t, addr)
	testutil.Eventually(t, "session", func() bool { return len(srv.Sessions()) == 1 })

	// Over the limit: the connection is closed before any exchange.
	refused := func() {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Error("connection over the limit was served")
		}
	}
	refused()
	if len(srv.Sessions()) != 1 {
		t.Errorf("%d sessions, want 1", len(srv.Sessions()))
	}
	_ = srv.Sessions()[0].Close()
	testutil.Eventually(t, "slot freed", func() bool { return len(srv.Sessions()) == 0 })
	allow.Store("deny", true)
	refused()
	if len(srv.Sessions()) != 0 {
		t.Error("filtered connection became a session")
	}
}

func TestHandlerPanicClosesSession(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if req.First().Address() == 666 {
			panic("boom")
		}
		_ = s.Confirm(req)
	}), server.WithLogger(iec104.NopLogger()))
	c := connect(t, addr)
	ctx := context.Background()
	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 666}); !errors.Is(err, iec104.ErrConnectionLost) {
		t.Errorf("command that panics the handler: %v, want ErrConnectionLost", err)
	}
	testutil.Eventually(t, "session closed", func() bool { return len(srv.Sessions()) == 0 })
	// The server itself keeps serving.
	c2 := connect(t, addr)
	if err := c2.Command(ctx, 1, asdu.SingleCommand{IOA: 1}); err != nil {
		t.Errorf("server after a handler panic: %v", err)
	}
}

func TestUndecodableASDUIsDropped(t *testing.T) {
	m := &testutil.Metrics{}
	_, addr := serve(t, server.HandlerFunc(confirmAll), server.WithMetrics(m), server.WithLogger(iec104.NopLogger()))
	c := connect(t, addr, client.WithASDUParams(asdu.Params{CauseSize: 2, CommonAddrSize: 2, IOASize: 2}))
	if err := c.Send(context.Background(), asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1})); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "decode error metric", func() bool {
		_, _, _, _, bad := m.Snapshot()
		return bad == 1
	})
	// The session survives.
	if err := c.TestLink(context.Background()); err != nil {
		t.Errorf("TestLink after a bad ASDU: %v", err)
	}
}

func TestServerLifecycle(t *testing.T) {
	if _, err := server.New(nil, server.WithParams(apci.Params{K: 1, W: 2})); !errors.Is(err, apci.ErrInvalidParams) {
		t.Errorf("invalid params: %v", err)
	}
	if _, err := server.New(nil, server.WithASDUParams(asdu.Params{})); !errors.Is(err, asdu.ErrInvalidParams) {
		t.Errorf("invalid ASDU params: %v", err)
	}
	if _, err := server.New(nil, server.WithMaxSessions(-1)); !errors.Is(err, iec104.ErrInvalidOption) {
		t.Errorf("negative session limit: %v, want ErrInvalidOption", err)
	}

	srv, err := server.New(server.HandlerFunc(confirmAll), server.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Addr() != nil {
		t.Error("Addr before listening")
	}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe("127.0.0.1:0") }()
	testutil.Eventually(t, "listener", func() bool { return srv.Addr() != nil })
	addr := srv.Addr().String()

	c := connect(t, addr)
	if err := c.TestCommand(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("ListenAndServe returned %v", err)
	}
	testutil.Eventually(t, "client disconnected", func() bool { return c.State() == iec104.StateDisconnected })
	if err := srv.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := srv.Serve(ln); !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("Serve after Close: %v", err)
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
		t.Error("Serve after Close left the listener open")
	}

	// A listener that fails makes Serve return the error.
	srv2, _ := server.New(nil)
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_ = ln2.Close()
	if err := srv2.Serve(ln2); err == nil || errors.Is(err, server.ErrServerClosed) {
		t.Errorf("Serve on a closed listener: %v", err)
	}
	if err := srv2.ListenAndServe("256.0.0.1:1"); err == nil {
		t.Error("ListenAndServe on an invalid address succeeded")
	}
}

func TestMutualTLS(t *testing.T) {
	serverTLS, clientTLS := testutil.TLSConfigs(t)
	// The same self-signed certificate doubles as the client identity.
	serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	serverTLS.ClientCAs = clientTLS.RootCAs
	clientTLS.Certificates = serverTLS.Certificates

	peer := make(chan string, 1)
	srv, err := server.New(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if tc, ok := s.Conn().(*tls.Conn); ok && len(tc.ConnectionState().PeerCertificates) > 0 {
			peer <- tc.ConnectionState().PeerCertificates[0].Subject.CommonName
		}
		_ = s.Confirm(req)
	}), server.WithParams(testutil.Params()), server.WithTLS(serverTLS))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe("127.0.0.1:0") }()
	defer func() { _ = srv.Close() }()
	testutil.Eventually(t, "listener", func() bool { return srv.Addr() != nil })

	c := connect(t, srv.Addr().String(), client.WithTLS(clientTLS))
	if err := c.TestCommand(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if cn := <-peer; cn != "go-iec104 test" {
		t.Errorf("peer certificate CN = %q", cn)
	}
}

// A peer that connects to a TLS server and never starts the handshake must
// not hold a session, and must not keep the server from closing.
func TestTLSHandshakeIsBounded(t *testing.T) {
	serverTLS, _ := testutil.TLSConfigs(t)
	p := testutil.Params()
	p.T0 = 300 * time.Millisecond
	srv, err := server.New(nil, server.WithParams(p), server.WithTLS(serverTLS), server.WithLogger(iec104.NopLogger()))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe("127.0.0.1:0") }()
	defer func() { _ = srv.Close() }()
	testutil.Eventually(t, "listener", func() bool { return srv.Addr() != nil })

	silent := func() net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	conn := silent()
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	begin := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil || time.Since(begin) > 2*time.Second {
		t.Errorf("silent peer not disconnected after t0: err=%v after %s", err, time.Since(begin))
	}
	if n := len(srv.Sessions()); n != 0 {
		t.Errorf("%d sessions for a peer that never completed the handshake", n)
	}

	// Close does not wait for a handshake in progress.
	conn2 := silent()
	defer func() { _ = conn2.Close() }()
	time.Sleep(50 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		_ = srv.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Close hangs on a pending TLS handshake")
	}
}

// A handler that answers each request with several ASDUs falls behind a
// client sending as fast as its window allows. The session must throttle
// the client rather than time out.
func TestBurstWithSlowHandler(t *testing.T) {
	reason := make(chan error, 1)
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		time.Sleep(200 * time.Microsecond)
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseReturnRemote, 1, asdu.SinglePoint{IOA: 1, Value: true}))
		_ = s.Terminate(req)
	}), server.WithStateHandler(func(_ *server.Session, st iec104.State, err error) {
		if st == iec104.StateDisconnected && err != nil {
			select {
			case reason <- err:
			default:
			}
		}
	}))
	var (
		mu  sync.Mutex
		got int
	)
	c := connect(t, addr, client.WithHandler(client.HandlerFunc(func(*asdu.ASDU) {
		mu.Lock()
		got++
		mu.Unlock()
	})))

	const n = 1500
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: asdu.IOA(i + 1), Value: true}))
		cancel()
		if err != nil {
			select {
			case r := <-reason:
				t.Fatalf("send %d: %v (session ended: %v)", i, err, r)
			default:
				t.Fatalf("send %d: %v", i, err)
			}
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		mu.Lock()
		done := got == 3*n
		have := got
		mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("received %d of %d answers", have, 3*n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type handled struct {
	iec104.NopMetrics
	mu    sync.Mutex
	types []asdu.TypeID
	bad   bool
}

func (h *handled) OnHandled(remote net.Addr, t asdu.TypeID, cause asdu.Cause, d time.Duration) {
	h.mu.Lock()
	h.types = append(h.types, t)
	if remote == nil || cause != asdu.CauseActivation || d < 20*time.Millisecond {
		h.bad = true
	}
	h.mu.Unlock()
}

func TestHandlerMetricsAndStructuredLog(t *testing.T) {
	m := &handled{}
	var buf bytes.Buffer
	var bufMu sync.Mutex
	logger := iec104.NewSlogFieldLogger(slog.NewJSONHandler(lockedWriter{&bufMu, &buf}, nil)).With("site", "north")
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		time.Sleep(25 * time.Millisecond)
		if req.First().Address() == 666 {
			panic("boom")
		}
		_ = s.Confirm(req)
	}), server.WithMetrics(m), server.WithLogger(logger))
	c := connect(t, addr)
	if err := c.TestCommand(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	// A handler that panics is measured as well.
	_ = c.Command(context.Background(), 1, asdu.SingleCommand{IOA: 666})

	testutil.Eventually(t, "handler metrics", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.types) == 2
	})
	m.mu.Lock()
	if m.types[0] != asdu.C_TS_TA_1 || m.types[1] != asdu.C_SC_NA_1 || m.bad {
		t.Errorf("handler metrics: %v, bad=%v", m.types, m.bad)
	}
	m.mu.Unlock()

	testutil.Eventually(t, "panic logged", func() bool {
		bufMu.Lock()
		defer bufMu.Unlock()
		return strings.Contains(buf.String(), `"msg":"handler panic"`)
	})
	bufMu.Lock()
	out := buf.String()
	bufMu.Unlock()
	for _, want := range []string{
		`"msg":"listening"`, `"component":"iec104.server"`, `"site":"north"`,
		`"msg":"session connected"`, `"session":1`, `"panic":"boom"`, `"level":"ERROR"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("server log misses %s:\n%s", want, out)
		}
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
