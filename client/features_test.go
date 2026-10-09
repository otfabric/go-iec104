// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
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

// requestLog records the callbacks of iec104.RequestMetrics.
type requestLog struct {
	iec104.NopMetrics
	mu       sync.Mutex
	requests []asdu.TypeID
	retries  []int
	done     []error
	remotes  []net.Addr
}

func (r *requestLog) OnRequest(remote net.Addr, t asdu.TypeID, _ asdu.CommonAddr) {
	r.mu.Lock()
	r.requests = append(r.requests, t)
	r.remotes = append(r.remotes, remote)
	r.mu.Unlock()
}

func (r *requestLog) OnRetry(_ net.Addr, _ asdu.TypeID, _ asdu.CommonAddr, attempt int, _ error) {
	r.mu.Lock()
	r.retries = append(r.retries, attempt)
	r.mu.Unlock()
}

func (r *requestLog) OnRequestDone(_ net.Addr, _ asdu.TypeID, _ asdu.CommonAddr, d time.Duration, err error) {
	r.mu.Lock()
	if d <= 0 {
		err = errors.New("non-positive duration")
	}
	r.done = append(r.done, err)
	r.mu.Unlock()
}

func (r *requestLog) snapshot() (requests, retries, done int, last error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.done) > 0 {
		last = r.done[len(r.done)-1]
	}
	return len(r.requests), len(r.retries), len(r.done), last
}

// flaky is a station that ignores the first requests of each type.
type flaky struct {
	mu     sync.Mutex
	ignore int
	seen   map[asdu.TypeID]int
	srv    *server.Server
	addr   string
}

func newFlaky(t *testing.T, ignore int, opts ...server.Option) *flaky {
	t.Helper()
	f := &flaky{ignore: ignore, seen: map[asdu.TypeID]int{}}
	h := server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		f.mu.Lock()
		f.seen[req.Type]++
		n := f.seen[req.Type]
		f.mu.Unlock()
		if n <= f.ignore {
			return
		}
		switch req.Type {
		case asdu.C_RD_NA_1:
			_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr,
				asdu.MeasuredScaled{IOA: req.First().Address(), Value: int16(n)}))
		case asdu.C_IC_NA_1:
			_ = s.Confirm(req)
			_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr, asdu.SinglePoint{IOA: 1, Value: true}))
			_ = s.Terminate(req)
		case asdu.C_SC_NA_1:
			if req.First().Address() == 2 {
				_ = s.Negative(req)
				return
			}
			_ = s.Confirm(req)
		default:
			_ = s.Confirm(req)
		}
	})
	srv, err := server.New(h, append([]server.Option{server.WithParams(testutil.Params())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.srv, f.addr = srv, ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *flaky) count(t asdu.TypeID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[t]
}

func TestRetryOfIdempotentRequests(t *testing.T) {
	st := newFlaky(t, 2)
	m := &requestLog{}
	c := dial(t, st.addr, client.WithMetrics(m), client.WithRequestTimeout(150*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 4, Backoff: 10 * time.Millisecond}))
	ctx := context.Background()

	// The first two reads go unanswered; the third attempt succeeds.
	a, err := c.Read(ctx, 1, 10)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v := a.First().(asdu.MeasuredScaled).Value; v != 3 || st.count(asdu.C_RD_NA_1) != 3 {
		t.Errorf("answered by attempt %d, station saw %d reads", v, st.count(asdu.C_RD_NA_1))
	}
	requests, retries, done, last := m.snapshot()
	if requests != 1 || retries != 2 || done != 1 || last != nil {
		t.Errorf("metrics: %d requests, %d retries, %d done, last error %v", requests, retries, done, last)
	}
	if m.remotes[0] == nil || m.remotes[0].String() != st.addr {
		t.Errorf("metrics remote = %v, want %s", m.remotes[0], st.addr)
	}

	// An interrogation is retried too, and returns only the data of the
	// attempt that succeeded.
	data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
	if err != nil || len(data) != 1 || st.count(asdu.C_IC_NA_1) != 3 {
		t.Errorf("Interrogate: %d ASDUs, %v, station saw %d", len(data), err, st.count(asdu.C_IC_NA_1))
	}

	// A command is never repeated: the station saw it once.
	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unanswered command: %v, want deadline exceeded", err)
	}
	if n := st.count(asdu.C_SC_NA_1); n != 1 {
		t.Errorf("station saw the command %d times, want 1", n)
	}
	// Neither is a clock synchronization or a counter freeze.
	_ = c.ClockSync(ctx, 1, time.Now())
	_, _ = c.CounterInterrogate(ctx, 1, asdu.CounterGeneral, asdu.FreezeWithReset)
	if st.count(asdu.C_CS_NA_1) != 1 || st.count(asdu.C_CI_NA_1) != 1 {
		t.Errorf("clock sync sent %d times, counter freeze %d times, want 1 each",
			st.count(asdu.C_CS_NA_1), st.count(asdu.C_CI_NA_1))
	}
	// A plain counter read is: one attempt was used up above.
	if _, err := c.CounterInterrogate(ctx, 1, asdu.CounterGeneral, asdu.FreezeRead); err != nil && st.count(asdu.C_CI_NA_1) < 3 {
		t.Errorf("counter read not retried: %v after %d attempts", err, st.count(asdu.C_CI_NA_1))
	}
}

func TestRetryStopsWhereItShould(t *testing.T) {
	st := newFlaky(t, 0)
	m := &requestLog{}
	c := dial(t, st.addr, client.WithMetrics(m), client.WithRequestTimeout(100*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 5, Backoff: 10 * time.Millisecond}))

	// A refusal is an answer, not a failure of the transport.
	var neg *iec104.NegativeError
	if err := c.Command(context.Background(), 1, asdu.SingleCommand{IOA: 2}); !errors.As(err, &neg) {
		t.Fatalf("refused command: %v", err)
	}

	// The caller's context ends the retries, whatever is left of them.
	silent := newFlaky(t, 1000)
	c2 := dial(t, silent.addr, client.WithMetrics(m), client.WithRequestTimeout(60*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 100, Backoff: 20 * time.Millisecond}))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err := c2.Read(ctx, 1, 10)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(begin) > 2*time.Second {
		t.Errorf("Read against a silent station: %v after %s", err, time.Since(begin))
	}
	if n := silent.count(asdu.C_RD_NA_1); n < 2 || n > 6 {
		t.Errorf("silent station saw %d reads in 300ms with 60ms attempts", n)
	}

	// The attempts are exhausted: the last error is returned.
	c3 := dial(t, silent.addr, client.WithRequestTimeout(40*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 2, Backoff: 5 * time.Millisecond}))
	before := silent.count(asdu.C_IC_NA_1)
	if _, err := c3.Interrogate(context.Background(), 1, asdu.QOIStation); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Interrogate: %v", err)
	}
	if n := silent.count(asdu.C_IC_NA_1) - before; n != 2 {
		t.Errorf("%d attempts, want 2", n)
	}

	// Closing the client ends a retry that is waiting.
	c4 := dial(t, silent.addr, client.WithRequestTimeout(40*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 100, Backoff: time.Hour}))
	errc := make(chan error, 1)
	go func() { _, err := c4.Read(context.Background(), 1, 10); errc <- err }()
	time.Sleep(150 * time.Millisecond)
	_ = c4.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("Read succeeded on a closed client")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not end the retry")
	}
}

// A request that fails because the connection dropped succeeds once the
// client has reconnected.
func TestRetryAcrossReconnect(t *testing.T) {
	st := newFlaky(t, 0)
	c := dial(t, st.addr,
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond}),
		client.WithRetry(client.Retry{Attempts: 20, Backoff: 20 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}))
	testutil.Eventually(t, "session", func() bool { return len(st.srv.Sessions()) == 1 })
	_ = st.srv.Sessions()[0].Close()
	testutil.Eventually(t, "loss noticed", func() bool { return c.State() != iec104.StateStarted })
	if _, err := c.Read(context.Background(), 1, 10); err != nil {
		t.Fatalf("Read across a reconnect: %v", err)
	}
}

func TestCancellation(t *testing.T) {
	st := newFlaky(t, 1000)
	c := dial(t, st.addr)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := c.Interrogate(ctx, 1, asdu.QOIStation); errc <- err }()
	testutil.Eventually(t, "request at the station", func() bool { return st.count(asdu.C_IC_NA_1) == 1 })
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled Interrogate: %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not end the request")
	}
	// The connection is unaffected and the request slot is free again.
	if c.State() != iec104.StateStarted {
		t.Errorf("state after cancellation: %s", c.State())
	}
	if err := c.TestLink(context.Background()); err != nil {
		t.Errorf("TestLink after cancellation: %v", err)
	}
	done, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := c.Interrogate(done, 1, asdu.QOIStation); !errors.Is(err, context.Canceled) {
		t.Errorf("Interrogate with a cancelled context: %v", err)
	}
	if err := c.Connect(done); !errors.Is(err, iec104.ErrBusy) {
		t.Errorf("Connect on a connected client: %v", err)
	}
}

func TestStartHandler(t *testing.T) {
	st := newFlaky(t, 0)
	var (
		mu       sync.Mutex
		runs     int
		results  []int
		contexts []context.Context
	)
	c := dial(t, st.addr,
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond}),
		client.WithStartHandler(func(ctx context.Context, c *client.Client) {
			// What a controlling station does on a fresh connection.
			data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
			mu.Lock()
			runs++
			contexts = append(contexts, ctx)
			if err == nil {
				results = append(results, len(data))
			}
			mu.Unlock()
		}))
	count := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return runs, len(results)
	}
	testutil.Eventually(t, "start handler after Connect", func() bool { r, ok := count(); return r == 1 && ok == 1 })

	_ = st.srv.Sessions()[0].Close()
	testutil.Eventually(t, "start handler after reconnect", func() bool { r, ok := count(); return r == 2 && ok == 2 })
	mu.Lock()
	first := contexts[0]
	mu.Unlock()
	select {
	case <-first.Done():
	case <-time.After(2 * time.Second):
		t.Error("the context of the first connection was not cancelled when it ended")
	}

	// Not called without data transfer.
	var standby atomic.Int64
	c2 := dial(t, st.addr, client.WithAutoStart(false),
		client.WithStartHandler(func(context.Context, *client.Client) { standby.Add(1) }))
	time.Sleep(100 * time.Millisecond)
	if standby.Load() != 0 || c2.State() != iec104.StateStopped {
		t.Errorf("start handler ran %d times on a connection in STOPDT", standby.Load())
	}
	_ = c
}

func TestStructuredLogging(t *testing.T) {
	st := newFlaky(t, 0)

	// A slog handler receives fields, not formatted strings.
	var buf syncBuffer
	logger := iec104.NewSlogLogger(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := dial(t, st.addr, client.WithLogger(logger))
	type traceKey struct{}
	if _, err := c.Read(context.WithValue(context.Background(), traceKey{}, "abc"), 1, 10); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		entries = append(entries, e)
	}
	find := func(msg string, match func(map[string]any) bool) map[string]any {
		for _, e := range entries {
			if e["msg"] == msg && (match == nil || match(e)) {
				return e
			}
		}
		t.Errorf("no log entry %q with the expected fields in:\n%s", msg, buf.String())
		return map[string]any{}
	}
	e := find("connection state", func(e map[string]any) bool { return e["state"] == "started" })
	if e["component"] != "iec104.client" || e["remote"] != st.addr || e["level"] != "INFO" {
		t.Errorf("state entry: %v", e)
	}
	find("frame sent", func(e map[string]any) bool { return e["format"] == "U" && e["function"] == "STARTDT act" })
	find("frame received", func(e map[string]any) bool { return e["format"] == "I" && e["ns"] == 0.0 })
	e = find("request", func(e map[string]any) bool { return e["type"] == "C_RD_NA_1" })
	if e["ca"] != 1.0 || e["duration"] == nil || e["error"] != nil {
		t.Errorf("request entry: %v", e)
	}

	// At info level the per-frame entries are not even built.
	buf.Reset()
	c = dial(t, st.addr, client.WithLogger(iec104.NewSlogLogger(slog.NewJSONHandler(&buf, nil))))
	_ = c.Close()
	if strings.Contains(buf.String(), "frame") || !strings.Contains(buf.String(), `"state":"started"`) {
		t.Errorf("info-level log:\n%s", buf.String())
	}

	// A printf-style logger gets the same information as one line.
	buf.Reset()
	c = dial(t, st.addr, client.WithLogger(iec104.NewStdLogger(log.New(&buf, "", 0))))
	_ = c.Close()
	want := "INFO  iec104 client remote=" + st.addr + ": connection state state=started"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("printf-style log misses %q:\n%s", want, buf.String())
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	s.b.Reset()
	s.mu.Unlock()
}

func TestGroup(t *testing.T) {
	a, b := newFlaky(t, 0), newFlaky(t, 0)
	var (
		mu       sync.Mutex
		switches []string
	)
	col := &collector{}
	g, err := client.NewGroup([]string{a.addr, b.addr},
		client.WithParams(testutil.Params()),
		client.WithRequestTimeout(2*time.Second),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond}),
		client.WithHandler(col),
		client.WithSwitchHandler(func(active *client.Client) {
			mu.Lock()
			if active == nil {
				switches = append(switches, "")
			} else {
				switches = append(switches, active.Addr())
			}
			mu.Unlock()
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	ctx := context.Background()

	if _, err := g.Interrogate(ctx, 1, asdu.QOIStation); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("request before Connect: %v", err)
	}
	if err := g.Switchover(ctx); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("Switchover before Connect: %v", err)
	}
	if err := g.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	clients := g.Clients()
	if len(clients) != 2 || g.Active() == nil {
		t.Fatalf("%d clients, active %v", len(clients), g.Active() != nil)
	}
	// Whichever path was established first is the active one; name the
	// stations accordingly for the rest of the test.
	if g.Active() == clients[1] {
		a, b = b, a
		clients[0], clients[1] = clients[1], clients[0]
	}
	// Exactly one connection is started; the other is an established standby.
	testutil.Eventually(t, "standby established", func() bool { return clients[1].State() == iec104.StateStopped })
	testutil.Eventually(t, "sessions", func() bool { return len(a.srv.Sessions()) == 1 && len(b.srv.Sessions()) == 1 })
	if !a.srv.Sessions()[0].Started() || b.srv.Sessions()[0].Started() {
		t.Error("data transfer is not started on exactly the first connection")
	}

	// Every request method goes to the active connection.
	if data, err := g.Interrogate(ctx, 1, asdu.QOIStation); err != nil || len(data) != 1 {
		t.Errorf("Interrogate: %v", err)
	}
	if _, err := g.Read(ctx, 1, 10); err != nil {
		t.Errorf("Read: %v", err)
	}
	for name, err := range map[string]error{
		"Command":      g.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true}),
		"Deactivate":   g.Deactivate(ctx, 1, asdu.SingleCommand{IOA: 1, Select: true}),
		"ClockSync":    g.ClockSync(ctx, 1, time.Now()),
		"TestCommand":  g.TestCommand(ctx, 1),
		"ResetProcess": g.ResetProcess(ctx, 1, asdu.ResetProcessGeneral),
		"Send":         g.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.ParameterActivation{IOA: 1})),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := g.CounterInterrogate(ctx, 1, asdu.CounterGeneral, asdu.FreezeRead); err == nil {
		t.Error("CounterInterrogate against a station that never terminates it succeeded")
	}
	if b.count(asdu.C_IC_NA_1) != 0 || a.count(asdu.C_IC_NA_1) != 1 {
		t.Error("requests did not all go to the active connection")
	}

	// The active path fails: the standby takes over.
	_ = a.srv.Close()
	testutil.Eventually(t, "failover", func() bool { return g.Active() == clients[1] })
	if _, err := g.Interrogate(ctx, 1, asdu.QOIStation); err != nil {
		t.Errorf("Interrogate after failover: %v", err)
	}
	if b.count(asdu.C_IC_NA_1) != 1 {
		t.Error("the request after failover did not reach the second station")
	}
	if err := g.Switchover(ctx); !errors.Is(err, iec104.ErrNotConnected) || g.Active() != clients[1] {
		t.Errorf("Switchover without a standby: %v", err)
	}

	// The failed path returns: it becomes the standby, and a manual
	// switchover moves data transfer back.
	ln, err := net.Listen("tcp", a.addr)
	if err != nil {
		t.Skipf("cannot listen on %s again: %v", a.addr, err)
	}
	back, _ := server.New(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }),
		server.WithParams(testutil.Params()))
	go func() { _ = back.Serve(ln) }()
	defer func() { _ = back.Close() }()
	testutil.Eventually(t, "first path back as standby", func() bool { return clients[0].State() == iec104.StateStopped })
	if g.Active() != clients[1] {
		t.Error("a returning path must not take data transfer back by itself")
	}
	if err := g.Switchover(ctx); err != nil {
		t.Fatalf("Switchover: %v", err)
	}
	if g.Active() != clients[0] || clients[1].State() != iec104.StateStopped {
		t.Errorf("after Switchover: active %v, former active %s", g.Active().Addr(), clients[1].State())
	}
	if err := g.TestCommand(ctx, 1); err != nil {
		t.Errorf("TestCommand after Switchover: %v", err)
	}

	mu.Lock()
	got := strings.Join(switches, " > ")
	mu.Unlock()
	if want := a.addr + " > " + b.addr + " > " + a.addr; got != want {
		t.Errorf("switch handler saw %q, want %q", got, want)
	}

	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if g.Active() != nil || clients[0].State() != iec104.StateDisconnected {
		t.Error("group not shut down by Close")
	}
	for name, err := range map[string]error{
		"Connect": g.Connect(ctx), "Switchover": g.Switchover(ctx), "TestCommand": g.TestCommand(ctx, 1),
	} {
		if !errors.Is(err, iec104.ErrClosed) {
			t.Errorf("%s after Close: %v, want ErrClosed", name, err)
		}
	}
	if err := g.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestGroupErrors(t *testing.T) {
	if _, err := client.NewGroup(nil); !errors.Is(err, iec104.ErrInvalidOption) {
		t.Errorf("group without addresses: %v", err)
	}
	if _, err := client.NewGroup([]string{"192.0.2.1"}, client.WithASDUParams(asdu.Params{})); !errors.Is(err, asdu.ErrInvalidParams) {
		t.Errorf("group with invalid parameters: %v", err)
	}

	// Nothing listens: Connect gives up with the context, the group keeps trying.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	var nothing atomic.Int64
	g, err := client.NewGroup([]string{addr}, client.WithParams(testutil.Params()),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond}),
		client.WithSwitchHandler(func(c *client.Client) {
			if c == nil {
				nothing.Add(1)
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := g.Connect(ctx); !errors.Is(err, iec104.ErrConnectFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Connect with no station: %v", err)
	}
	if nothing.Load() != 0 {
		t.Error("switch handler reported a change although there never was an active connection")
	}

	// The station appears later: the group finds it.
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s again: %v", addr, err)
	}
	srv, _ := server.New(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }),
		server.WithParams(testutil.Params()))
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	if err := g.Connect(context.Background()); err != nil {
		t.Fatalf("Connect once the station is up: %v", err)
	}
	if err := g.TestCommand(context.Background(), 1); err != nil {
		t.Errorf("TestCommand: %v", err)
	}
}
