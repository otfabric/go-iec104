// SPDX-License-Identifier: MIT

package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/station"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// errBox collects errors reported from callbacks.
type errBox struct {
	mu   sync.Mutex
	errs []error
}

func (b *errBox) add(err error) {
	b.mu.Lock()
	b.errs = append(b.errs, err)
	b.mu.Unlock()
}

// has reports whether one of the collected errors is target.
func (b *errBox) has(target error) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, err := range b.errs {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// states records the state changes of one side of a connection.
type states struct {
	mu   sync.Mutex
	seen []string
}

func (s *states) add(state iec104.State, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := state.String()
	if err != nil {
		entry += "!"
	}
	s.seen = append(s.seen, entry)
}

func (s *states) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.seen, " ")
}

// counters implements every metrics interface.
type counters struct {
	testutil.Metrics
	requests, done, failed, retries, handled atomic.Int64
}

func (c *counters) OnRequest(net.Addr, asdu.TypeID, asdu.CommonAddr) { c.requests.Add(1) }
func (c *counters) OnRequestDone(_ net.Addr, _ asdu.TypeID, _ asdu.CommonAddr, _ time.Duration, err error) {
	c.done.Add(1)
	if err != nil {
		c.failed.Add(1)
	}
}
func (c *counters) OnRetry(net.Addr, asdu.TypeID, asdu.CommonAddr, int, error) { c.retries.Add(1) }
func (c *counters) OnHandled(net.Addr, asdu.TypeID, asdu.Cause, time.Duration) { c.handled.Add(1) }

// syncBuffer is a log sink both sides can write to.
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

// The state callbacks, the log and the metrics of both sides tell the same
// story about one connection.
func TestStatesLogsAndMetrics(t *testing.T) {
	var srvStates, cliStates states
	var sessionEnd errBox
	srvLog, cliLog := &syncBuffer{}, &syncBuffer{}
	srvM, cliM := &counters{}, &counters{}
	debug := &slog.HandlerOptions{Level: slog.LevelDebug}
	l := start(t, []server.Option{
		server.WithStateHandler(func(_ *server.Session, s iec104.State, err error) {
			if err != nil {
				sessionEnd.add(err)
			}
			srvStates.add(s, err)
		}),
		server.WithLogger(iec104.NewSlogLogger(slog.NewTextHandler(srvLog, debug))),
		server.WithMetrics(srvM),
	},
		client.WithStateHandler(cliStates.add),
		client.WithLogger(iec104.NewSlogLogger(slog.NewTextHandler(cliLog, debug))),
		client.WithMetrics(cliM),
		client.WithAutoStart(false))
	ctx := context.Background()
	c := l.dial(t)
	if err := c.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); err != nil {
		t.Fatal(err)
	}
	if err := c.Command(ctx, l.ca, asdu.SingleCommand{IOA: 999}); err == nil {
		t.Fatal("command to an unknown object succeeded")
	}
	if err := c.StopDT(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(srvStates.String(), "disconnected") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// The controlling station hung up: for the station that is a lost
	// connection; for the client, which closed it, there is no error.
	if got, want := srvStates.String(), "stopped started stopped disconnected!"; got != want {
		t.Errorf("station states: %s, want %s", got, want)
	}
	if !sessionEnd.has(iec104.ErrConnectionLost) {
		t.Errorf("the session ended with %v, want ErrConnectionLost", sessionEnd.errs)
	}
	if got := cliStates.String(); !strings.HasSuffix(got, "stopped started stopped disconnected") {
		t.Errorf("client states: %s", got)
	}

	// Every frame one side sent, the other received.
	testutil.Eventually(t, "both sides counted the disconnect", func() bool {
		_, d1, _, _, _ := srvM.Snapshot()
		_, d2, _, _, _ := cliM.Snapshot()
		return d1 == 1 && d2 == 1
	})
	sc, _, ssent, srecv, sbad := srvM.Snapshot()
	cc, _, csent, crecv, cbad := cliM.Snapshot()
	if sc != 1 || cc != 1 || ssent != crecv || csent != srecv || sbad+cbad != 0 || ssent == 0 || csent == 0 {
		t.Errorf("frames: station sent %d received %d, client sent %d received %d; connects %d/%d, bad %d/%d",
			ssent, srecv, csent, crecv, sc, cc, sbad, cbad)
	}
	if r, d, f := cliM.requests.Load(), cliM.done.Load(), cliM.failed.Load(); r != 2 || d != 2 || f != 1 {
		t.Errorf("client requests: %d begun, %d done, %d failed; want 2, 2, 1", r, d, f)
	}
	if h := srvM.handled.Load(); h != 2 {
		t.Errorf("station handled %d ASDUs, want 2", h)
	}
	for name, log := range map[string]string{"station": srvLog.String(), "client": cliLog.String()} {
		if !strings.Contains(log, "level=") || strings.Count(log, "\n") < 3 {
			t.Errorf("%s log:\n%s", name, log)
		}
	}
}

// Requests that only read are repeated when the station does not answer;
// commands never are.
func TestRetry(t *testing.T) {
	var reads, commands atomic.Int64
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		switch req.Type {
		case asdu.C_RD_NA_1:
			if reads.Add(1) < 3 {
				return // lost in the station
			}
			_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr, asdu.MeasuredScaled{IOA: req.First().Address(), Value: 42}))
		case asdu.C_IC_NA_1:
			// Confirmed, never terminated.
			_ = s.Confirm(req)
		default:
			commands.Add(1)
		}
	}))
	m := &counters{}
	c := connect(t, addr, client.WithMetrics(m), client.WithRequestTimeout(150*time.Millisecond),
		client.WithRetry(client.Retry{Attempts: 4, Backoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond}))
	ctx := context.Background()

	a, err := c.Read(ctx, 1, 7)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, ok := a.First().(asdu.MeasuredScaled); !ok || v.Value != 42 || reads.Load() != 3 || m.retries.Load() != 2 {
		t.Errorf("Read: %s after %d attempts and %d retries", a, reads.Load(), m.retries.Load())
	}

	err = c.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true})
	if !errors.Is(err, context.DeadlineExceeded) || commands.Load() != 1 {
		t.Errorf("unanswered command: %v, sent %d times; want one attempt and a deadline error", err, commands.Load())
	}

	// Every attempt of an interrogation that is never terminated times out.
	before := m.retries.Load()
	if _, err := c.Interrogate(ctx, 1, asdu.QOIStation); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("interrogation without termination: %v", err)
	}
	if got := m.retries.Load() - before; got != 3 {
		t.Errorf("%d retries of the interrogation, want 3", got)
	}
	// The connection survived all of it.
	if err := c.TestLink(ctx); err != nil {
		t.Errorf("TestLink: %v", err)
	}
}

// Who may connect: the session limit, the accept filter and the redundancy
// groups.
func TestAdmission(t *testing.T) {
	ctx := context.Background()
	refused := func(t *testing.T, addr string) {
		t.Helper()
		dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		c, err := client.Dial(dctx, addr, client.WithParams(testutil.Params()))
		if err == nil {
			_ = c.Close()
			t.Error("a connection that must be refused was established and started")
		}
	}
	t.Run("session limit", func(t *testing.T) {
		srv, addr := serve(t, &echo{}, server.WithMaxSessions(2))
		a, _ := connect(t, addr), connect(t, addr)
		refused(t, addr)
		// A place that comes free can be taken again.
		_ = a.Close()
		testutil.Eventually(t, "one session left", func() bool { return len(srv.Sessions()) == 1 })
		connect(t, addr)
	})
	t.Run("accept filter", func(t *testing.T) {
		var asked atomic.Int64
		_, addr := serve(t, &echo{}, server.WithAccept(func(remote net.Addr) bool {
			return asked.Add(1) > 1 && remote.(*net.TCPAddr).IP.IsLoopback()
		}))
		refused(t, addr)
		connect(t, addr)
	})
	t.Run("redundancy groups", func(t *testing.T) {
		_, addr := serve(t, &echo{}, server.WithRedundancyGroups(
			server.RedundancyGroup{Name: "elsewhere", Allow: []string{"192.0.2.0/24"}}))
		refused(t, addr)

		srv, addr := serve(t, &echo{}, server.WithRedundancyGroups(
			server.RedundancyGroup{Name: "elsewhere", Allow: []string{"192.0.2.0/24", "198.51.100.7"}},
			server.RedundancyGroup{Name: "local", Allow: []string{"127.0.0.0/8"}},
			server.RedundancyGroup{Name: "rest"}))
		connect(t, addr)
		testutil.Eventually(t, "the session", func() bool { return len(srv.Sessions()) == 1 })
		if g := srv.Sessions()[0].Group(); g != "local" {
			t.Errorf("a loopback client is in group %q, want local", g)
		}
	})
}

// A full event queue drops its oldest events and says so.
func TestEventQueueOverflow(t *testing.T) {
	l := start(t, []server.Option{server.WithEventQueue(10)})
	srv := l.st.Server
	for i := 1; i <= 25; i++ {
		if err := srv.Enqueue(asdu.New(asdu.CauseSpontaneous, l.ca, asdu.MeasuredScaled{IOA: 201, Value: int16(i)})); err != nil {
			t.Fatal(err)
		}
	}
	if p, d := srv.Pending("default"), srv.Dropped("default"); p != 10 || d != 15 {
		t.Fatalf("Pending %d, Dropped %d; want 10 and 15", p, d)
	}
	rec := &recorder{}
	l.dial(t, client.WithHandler(rec), client.WithParams(apci.Params{W: 1}))
	testutil.Eventually(t, "the ten that were kept", func() bool { return len(rec.all()) == 10 })
	for i, a := range rec.all() {
		if v := a.First().(asdu.MeasuredScaled).Value; int(v) != 16+i {
			t.Fatalf("event %d has value %d, want %d", i, v, 16+i)
		}
	}
	testutil.Eventually(t, "the queue acknowledged", func() bool { return srv.Pending("default") == 0 })
	if err := srv.Enqueue(nil); err == nil {
		t.Error("Enqueue(nil) succeeded")
	}
}

// Broadcast reaches the started sessions only; a session exposes what the
// application needs to know about its controlling station.
func TestBroadcastAndSessions(t *testing.T) {
	l := start(t, nil)
	srv := l.st.Server
	ctx := context.Background()
	recs := []*recorder{{}, {}, {}}
	l.dial(t, client.WithHandler(recs[0]))
	l.dial(t, client.WithHandler(recs[1]))
	l.dial(t, client.WithHandler(recs[2]), client.WithAutoStart(false))
	testutil.Eventually(t, "three sessions, two started", func() bool {
		n := 0
		for _, s := range srv.Sessions() {
			if s.Started() {
				n++
			}
		}
		return len(srv.Sessions()) == 3 && n == 2
	})

	ev := asdu.New(asdu.CauseSpontaneous, l.ca, asdu.DoublePoint{IOA: 101, Value: asdu.DoubleOff, Time: asdu.Now()})
	n, err := srv.Broadcast(ctx, ev)
	if n != 2 || err != nil {
		t.Fatalf("Broadcast = %d, %v; want 2 sessions", n, err)
	}
	testutil.Eventually(t, "the event on both started connections", func() bool {
		return len(recs[0].all()) == 1 && len(recs[1].all()) == 1
	})
	if len(recs[2].all()) != 0 {
		t.Error("the stopped connection received the broadcast")
	}

	ids := map[uint64]bool{}
	for _, s := range srv.Sessions() {
		ids[s.ID()] = true
		remote, ok := s.RemoteAddr().(*net.TCPAddr)
		if !ok || !remote.IP.IsLoopback() || s.LocalAddr() == nil || s.Conn() == nil || s.Err() != nil ||
			s.Context().Err() != nil || s.Group() != "default" {
			t.Errorf("session %d: remote %v local %v err %v group %q", s.ID(), s.RemoteAddr(), s.LocalAddr(), s.Err(), s.Group())
		}
	}
	if len(ids) != 3 {
		t.Errorf("session IDs are not distinct: %v", ids)
	}

	// The station closes one session: its client sees the connection lost.
	var closed *server.Session
	for _, s := range srv.Sessions() {
		if s.Started() {
			closed = s
			break
		}
	}
	_ = closed.Close()
	testutil.Eventually(t, "two sessions left", func() bool { return len(srv.Sessions()) == 2 })
	select {
	case <-closed.Context().Done():
	case <-time.After(2 * time.Second):
		t.Error("the context of a closed session is still alive")
	}
	if err := closed.Send(ctx, ev); err == nil {
		t.Error("Send on a closed session succeeded")
	}
	n, err = srv.Broadcast(ctx, ev)
	if n != 1 || err != nil {
		t.Errorf("Broadcast after the close = %d, %v; want 1", n, err)
	}
}

// Every request method of a redundancy group, and a switchover between two
// living stations.
func TestGroupRequests(t *testing.T) {
	a, b := start(t, nil), start(t, nil)
	ctx := context.Background()
	var switches atomic.Int64
	rec := &recorder{}
	g, err := client.NewGroup([]string{a.st.Loopback(), b.st.Loopback()},
		client.WithParams(testutil.Params()), client.WithRequestTimeout(5*time.Second), client.WithHandler(rec),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond}),
		client.WithSwitchHandler(func(*client.Client) { switches.Add(1) }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	clients := g.Clients()
	if g.Active() == clients[1] {
		a, b = b, a
		clients[0], clients[1] = clients[1], clients[0]
	}
	testutil.Eventually(t, "the standby", func() bool { return clients[1].State() == iec104.StateStopped })
	ca := a.ca

	exercise := func(what string, l *link) {
		t.Helper()
		data, err := g.Interrogate(ctx, ca, asdu.QOIStation)
		if err != nil || !station.SameObserved(station.Observe(t, data), l.fx.Expected(false)) {
			t.Errorf("%s: Interrogate: %v", what, err)
		}
		if data, err := g.CounterInterrogate(ctx, ca, asdu.CounterGeneral, asdu.FreezeRead); err != nil || len(data) != 1 {
			t.Errorf("%s: CounterInterrogate: %v", what, err)
		}
		if _, err := g.Read(ctx, ca, 100); err != nil {
			t.Errorf("%s: Read: %v", what, err)
		}
		when := time.Date(2026, 1, 2, 3, 4, 5, 6e6, time.UTC)
		if err := g.ClockSync(ctx, ca, when); err != nil || !l.st.ClockTime().Equal(when) {
			t.Errorf("%s: ClockSync: %v, station clock %v", what, err, l.st.ClockTime())
		}
		if err := g.TestCommand(ctx, ca); err != nil {
			t.Errorf("%s: TestCommand: %v", what, err)
		}
		negative(t, g.ResetProcess(ctx, ca, asdu.ResetProcessGeneral), asdu.CauseUnknownType)
		sel := asdu.SingleCommand{IOA: 510, Value: true, Select: true}
		if err := g.Command(ctx, ca, sel); err != nil {
			t.Errorf("%s: select: %v", what, err)
		}
		if err := g.Deactivate(ctx, ca, sel); err != nil {
			t.Errorf("%s: Deactivate: %v", what, err)
		}
		f := l.fx.Files[0]
		if got, err := g.GetFile(ctx, ca, f.IOA, f.Name); err != nil || !bytes.Equal(got, f.Content()) {
			t.Errorf("%s: GetFile: %v", what, err)
		}
		// Deliver a file, find it in the directory, fetch it back.
		up := station.FirstUploadIOA + 5
		note := []byte("delivered over " + what)
		if err := g.PutFile(ctx, ca, up, 2, note[:5], note[5:]); err != nil {
			t.Errorf("%s: PutFile: %v", what, err)
		}
		dir, err := g.ListFiles(ctx, ca, 0)
		if err != nil || len(dir) != len(l.fx.Files)+1 || dir[len(dir)-1].IOA != up || int(dir[len(dir)-1].Length) != len(note) {
			t.Errorf("%s: ListFiles: %d entries, %v", what, len(dir), err)
		}
		if got, err := g.GetFile(ctx, ca, up, 2); err != nil || !bytes.Equal(got, note) {
			t.Errorf("%s: fetching the delivered file: %q, %v", what, got, err)
		}
		if got, ok := l.st.Uploaded(up); !ok || !bytes.Equal(got, note) {
			t.Errorf("%s: the file is not at the station the group is started on", what)
		}
		rec.reset()
		if err := g.Send(ctx, asdu.New(asdu.CauseActivation, ca, asdu.ParameterActivation{IOA: 1})); err != nil {
			t.Errorf("%s: Send: %v", what, err)
		}
		rec.find(t, "the mirror of the raw send", func(a *asdu.ASDU) bool { return a.Type == asdu.P_AC_NA_1 && a.Negative })
	}
	exercise("first path", a)

	// A set point on the first station tells the two apart afterwards.
	if err := g.Command(ctx, ca, asdu.SetpointScaled{IOA: 504, Value: 99}); err != nil {
		t.Fatal(err)
	}
	before := switches.Load()
	if err := g.Switchover(ctx); err != nil {
		t.Fatalf("Switchover: %v", err)
	}
	if g.Active() != clients[1] || switches.Load() != before+1 {
		t.Fatalf("after Switchover: active is the old path %v, %d switch callbacks", g.Active() == clients[0], switches.Load()-before)
	}
	if clients[0].State() != iec104.StateStopped || clients[1].State() != iec104.StateStarted {
		t.Errorf("after Switchover: old path %s, new path %s", clients[0].State(), clients[1].State())
	}
	r, err := g.Read(ctx, ca, 201)
	if err != nil {
		t.Fatal(err)
	}
	if v := station.Observe(t, []*asdu.ASDU{r})[0].Value; v != 1234.0 {
		t.Errorf("after Switchover the group reads %v: still the first station", v)
	}
	exercise("second path", b)

	// And back.
	if err := g.Switchover(ctx); err != nil || g.Active() != clients[0] {
		t.Fatalf("second Switchover: %v", err)
	}
	if r, err := g.Read(ctx, ca, 201); err != nil || station.Observe(t, []*asdu.ASDU{r})[0].Value != 99.0 {
		t.Errorf("back on the first station: %v", err)
	}
}

// What a caller sees when a request cannot complete, and that the
// connection is none the worse for it.
func TestRequestFailures(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var readsSeen atomic.Int64
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		switch o := req.First().(type) {
		case asdu.SingleCommand:
			if o.IOA == 1 {
				return // never answered
			}
			_ = s.Confirm(req)
		case asdu.Read:
			readsSeen.Add(1)
			go func() { // answered late, from outside the handler
				<-release
				_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr, asdu.SinglePoint{IOA: o.IOA, Value: true}))
			}()
		}
	}))
	c := connect(t, addr, client.WithRequestTimeout(200*time.Millisecond))
	ctx := context.Background()

	// The request timeout.
	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unanswered command: %v", err)
	}
	// The caller's deadline and the caller's cancellation.
	dctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	err := c.Command(dctx, 1, asdu.SingleCommand{IOA: 1})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("command with a deadline: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if err := c.Command(cctx, 1, asdu.SingleCommand{IOA: 1}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled command: %v", err)
	}
	// Two requests whose answers could not be told apart.
	long, cancelLong := context.WithTimeout(ctx, 5*time.Second)
	defer cancelLong()
	first := make(chan error, 1)
	go func() {
		_, err := c.Read(long, 1, 50)
		first <- err
	}()
	testutil.Eventually(t, "the first read at the station", func() bool { return readsSeen.Load() == 1 })
	if _, err := c.Read(ctx, 1, 50); !errors.Is(err, iec104.ErrBusy) {
		t.Errorf("a second read of the same object: %v, want ErrBusy", err)
	}
	// Requests for other objects are not held up by the pending one.
	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 2}); err != nil {
		t.Errorf("command while a read is pending: %v", err)
	}
	once.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Errorf("the pending read: %v", err)
	}
	// An ASDU that cannot be encoded never reaches the wire.
	if err := c.Command(ctx, 1, asdu.DoubleCommand{IOA: 3, Value: 9}); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("command with an impossible value: %v", err)
	}
	if err := c.Command(ctx, 1, asdu.SinglePoint{IOA: 3}); !errors.Is(err, asdu.ErrTypeMismatch) {
		t.Errorf("Command with a monitoring object: %v", err)
	}
	if err := c.Command(ctx, 1, nil); err == nil {
		t.Error("Command(nil) succeeded")
	}
	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 2}); err != nil {
		t.Errorf("command after all the failures: %v", err)
	}

	// The station shuts down under a pending request.
	pending := make(chan error, 1)
	go func() {
		pending <- c.Command(long, 1, asdu.SingleCommand{IOA: 1})
	}()
	time.Sleep(50 * time.Millisecond)
	_ = srv.Close()
	select {
	case err := <-pending:
		if !errors.Is(err, iec104.ErrConnectionLost) {
			t.Errorf("request pending at shutdown: %v, want ErrConnectionLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the pending request outlived the station")
	}
	testutil.Eventually(t, "the client disconnected", func() bool { return c.State() == iec104.StateDisconnected })
	if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 2}); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("command without a connection: %v", err)
	}
}

// A handler that panics costs its session, not the station.
func TestHandlerPanic(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if req.First().Address() == 13 {
			panic("unlucky")
		}
		_ = s.Confirm(req)
	}))
	ctx := context.Background()
	victim, bystander := connect(t, addr, client.WithRequestTimeout(2*time.Second)), connect(t, addr)
	if err := victim.Command(ctx, 1, asdu.SingleCommand{IOA: 13}); !errors.Is(err, iec104.ErrConnectionLost) {
		t.Errorf("command whose handler panics: %v, want ErrConnectionLost", err)
	}
	testutil.Eventually(t, "one session left", func() bool { return len(srv.Sessions()) == 1 })
	if err := bystander.Command(ctx, 1, asdu.SingleCommand{IOA: 1}); err != nil {
		t.Errorf("another session after the panic: %v", err)
	}
	if err := connect(t, addr).Command(ctx, 1, asdu.SingleCommand{IOA: 1}); err != nil {
		t.Errorf("a new session after the panic: %v", err)
	}
}

// TLS with client certificates, through ListenAndServe.
func TestMutualTLS(t *testing.T) {
	srvTLS, cliTLS := testutil.TLSConfigs(t)
	srvTLS.ClientAuth = tls.RequireAndVerifyClientCert
	srvTLS.ClientCAs = cliTLS.RootCAs
	srv, err := server.New(&echo{}, server.WithTLS(srvTLS), server.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe("127.0.0.1:0") }()
	t.Cleanup(func() { _ = srv.Close() })
	testutil.Eventually(t, "the listener", func() bool { return srv.Addr() != nil })
	addr := srv.Addr().String()
	ctx := context.Background()

	withCert := cliTLS.Clone()
	withCert.Certificates = srvTLS.Certificates
	rec := &recorder{}
	c := connect(t, addr, client.WithTLS(withCert), client.WithHandler(rec))
	if err := c.Send(ctx, asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1, Value: true})); err != nil {
		t.Fatal(err)
	}
	rec.find(t, "the echo over mutual TLS", func(a *asdu.ASDU) bool { return a.Type == asdu.M_SP_NA_1 })
	testutil.Eventually(t, "the session", func() bool { return len(srv.Sessions()) == 1 })
	if tc, ok := srv.Sessions()[0].Conn().(*tls.Conn); !ok || len(tc.ConnectionState().PeerCertificates) != 1 {
		t.Error("the session does not expose the client certificate")
	}

	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for name, cfg := range map[string]*tls.Config{"no certificate": cliTLS, "plain TCP": nil} {
		opts := []client.Option{client.WithParams(testutil.Params())}
		if cfg != nil {
			opts = append(opts, client.WithTLS(cfg))
		}
		if bad, err := client.Dial(short, addr, opts...); err == nil {
			_ = bad.Close()
			t.Errorf("%s: connected and started", name)
		}
	}
	_, untrusted := testutil.TLSConfigs(t)
	if bad, err := client.Dial(short, addr, client.WithTLS(untrusted)); err == nil {
		_ = bad.Close()
		t.Error("a client that does not trust the station connected")
	}
	if n := len(srv.Sessions()); n != 1 {
		t.Errorf("%d sessions after the refused attempts", n)
	}
}

// What a station sends on its own: end of initialization when data transfer
// starts, then spontaneous and cyclic data, interleaved with a request.
func TestUnsolicited(t *testing.T) {
	const events = 200
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr, asdu.SinglePoint{IOA: 1, Value: true}))
		_ = s.Terminate(req)
	}), server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
		if state != iec104.StateStarted {
			return
		}
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInitialized, 1, asdu.EndOfInitialization{Cause: asdu.InitLocalPowerOn}))
		go func() {
			for i := 0; i < events; i++ {
				cause := asdu.CauseSpontaneous
				if i%2 == 1 {
					cause = asdu.CausePeriodic
				}
				if s.Send(s.Context(), asdu.New(cause, 1, asdu.MeasuredScaled{IOA: 5, Value: int16(i)})) != nil {
					return
				}
			}
		}()
	}))
	rec := &recorder{}
	c := connect(t, addr, client.WithHandler(rec))
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
		if err != nil || len(data) != 1 {
			t.Fatalf("Interrogate %d amid unsolicited data: %d ASDUs, %v", i, len(data), err)
		}
	}
	testutil.Eventually(t, "every event", func() bool {
		n := 0
		for _, a := range rec.all() {
			if a.Type == asdu.M_ME_NB_1 {
				n++
			}
		}
		return n == events
	})
	all := rec.all()
	if all[0].Type != asdu.M_EI_NA_1 || all[0].Cause != asdu.CauseInitialized {
		t.Errorf("first ASDU is %s, want the end of initialization", all[0])
	}
	next := 0
	for _, a := range all {
		if v, ok := a.First().(asdu.MeasuredScaled); ok {
			if int(v.Value) != next {
				t.Fatalf("event %d arrived as %d", next, v.Value)
			}
			next++
		}
	}
}

// STOPDT and STARTDT in the middle of a stream of queued events: nothing is
// lost, nothing arrives out of order.
func TestStopDuringEventStream(t *testing.T) {
	tight := apci.DefaultParams()
	tight.K, tight.W = 1, 1
	for name, p := range map[string]apci.Params{"default windows": apci.DefaultParams(), "k=w=1": tight} {
		t.Run(name, func(t *testing.T) { stopDuringEventStream(t, p) })
	}
}

func stopDuringEventStream(t *testing.T, p apci.Params) {
	{
		const events = 3000
		// The queue holds the whole stream: nothing may be dropped.
		l := start(t, []server.Option{server.WithEventQueue(events), server.WithParams(p)}, client.WithParams(p))
		srv := l.st.Server
		var mu sync.Mutex
		var got []int
		c := l.dial(t, client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			if v, ok := a.First().(asdu.Bitstring32); ok {
				mu.Lock()
				got = append(got, int(v.Value))
				mu.Unlock()
			}
		})))
		ctx := context.Background()
		feeding := make(chan struct{})
		go func() {
			defer close(feeding)
			for i := 0; i < events; i++ {
				if err := srv.Enqueue(asdu.New(asdu.CauseSpontaneous, l.ca, asdu.Bitstring32{IOA: 103, Value: uint32(i)})); err != nil {
					t.Errorf("Enqueue %d: %v", i, err)
					return
				}
				if i%100 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}()
		for round := 0; round < 8; round++ {
			time.Sleep(3 * time.Millisecond)
			if err := c.StopDT(ctx); err != nil {
				t.Fatalf("StopDT %d: %v", round, err)
			}
			mu.Lock()
			stopped := len(got)
			mu.Unlock()
			time.Sleep(3 * time.Millisecond)
			mu.Lock()
			if len(got) != stopped {
				t.Errorf("round %d: %d events arrived while data transfer was stopped", round, len(got)-stopped)
			}
			mu.Unlock()
			if err := c.StartDT(ctx); err != nil {
				t.Fatalf("StartDT %d: %v", round, err)
			}
		}
		<-feeding
		testutil.Eventually(t, "every event", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(got) > 0 && got[len(got)-1] == events-1
		})
		mu.Lock()
		defer mu.Unlock()
		seen := make([]int, events)
		last := -1
		for _, v := range got {
			seen[v]++
			if v < last {
				t.Fatalf("event %d after event %d", v, last)
			}
			last = v
		}
		missing, repeated := 0, 0
		for _, n := range seen {
			switch {
			case n == 0:
				missing++
			case n > 1:
				repeated++
			}
		}
		if missing != 0 || repeated != 0 {
			t.Errorf("%d events missing, %d delivered more than once", missing, repeated)
		}
		if d := srv.Dropped("default"); d != 0 {
			t.Errorf("%d events dropped", d)
		}
	}
}

// Many requests at once on one connection: every answer goes to the request
// it belongs to.
func TestConcurrentRequestsOnOneConnection(t *testing.T) {
	_, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		ioa := req.First().Address()
		switch req.Type {
		case asdu.C_RD_NA_1:
			_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr, asdu.Bitstring32{IOA: ioa, Value: uint32(ioa) * 3}))
		default:
			// Odd objects refuse; even ones execute and terminate.
			if ioa%2 == 1 {
				_ = s.Negative(req)
				return
			}
			_ = s.Confirm(req)
			_ = s.Terminate(req)
		}
	}))
	c := connect(t, addr)
	ctx := context.Background()
	const workers, rounds = 32, 100
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioa := asdu.IOA(1000 + w)
			for i := 0; i < rounds; i++ {
				a, err := c.Read(ctx, 1, ioa)
				if err != nil {
					t.Errorf("worker %d: Read: %v", w, err)
					return
				}
				if v := a.First().(asdu.Bitstring32); v.IOA != ioa || v.Value != uint32(ioa)*3 {
					t.Errorf("worker %d read %+v", w, v)
					return
				}
				err = c.Command(ctx, 1, asdu.SetpointScaled{IOA: ioa, Value: int16(i)})
				var neg *iec104.NegativeError
				if refused := errors.As(err, &neg); refused != (ioa%2 == 1) || (err != nil && !refused) {
					t.Errorf("worker %d: command to object %d: %v", w, ioa, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// One server, several stations: requests are routed by common address.
func TestSeveralStations(t *testing.T) {
	mux := server.NewMux()
	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr,
			asdu.MeasuredScaled{IOA: req.First().Address(), Value: int16(req.CommonAddr) * 100}))
	})
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		// A broadcast interrogation is answered by every station in turn.
		stations := []asdu.CommonAddr{req.CommonAddr}
		if req.CommonAddr == asdu.Broadcast {
			stations = []asdu.CommonAddr{1, 2, 3}
		}
		for _, ca := range stations {
			_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, ca, asdu.SinglePoint{IOA: asdu.IOA(ca), Value: true}))
		}
		last := *req
		last.CommonAddr = stations[len(stations)-1]
		_ = s.Confirm(&last)
		_ = s.Terminate(&last)
	})
	_, addr := serve(t, mux, server.WithCommonAddrs(1, 2, 3))
	c := connect(t, addr)
	ctx := context.Background()
	for _, ca := range []asdu.CommonAddr{1, 2, 3} {
		a, err := c.Read(ctx, ca, 9)
		if err != nil {
			t.Fatalf("Read from station %d: %v", ca, err)
		}
		if v := a.First().(asdu.MeasuredScaled); a.CommonAddr != ca || v.Value != int16(ca)*100 {
			t.Errorf("station %d answered %s %+v", ca, a, v)
		}
	}
	_, err := c.Read(ctx, 4, 9)
	negative(t, err, asdu.CauseUnknownCommonAddr)
	data, err := c.Interrogate(ctx, asdu.Broadcast, asdu.QOIStation)
	if err != nil || len(data) != 3 {
		t.Errorf("broadcast interrogation: %d ASDUs, %v; want one of each station", len(data), err)
	}
}

// blackhole is a dialer whose connections can go silent: nothing is
// delivered in either direction any more, and neither side is told. It is
// what a failed link looks like to TCP for the first minutes.
type blackhole struct {
	silent atomic.Bool
	dials  atomic.Int64
}

type blackholeConn struct {
	net.Conn
	hole *blackhole
	dead atomic.Bool
}

func (b *blackhole) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	b.dials.Add(1)
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &blackholeConn{Conn: conn, hole: b}, nil
}

func (c *blackholeConn) Write(p []byte) (int, error) {
	if c.hole.silent.Load() {
		c.dead.Store(true)
	}
	if c.dead.Load() {
		return len(p), nil // sent, as far as the sender can tell
	}
	return c.Conn.Write(p)
}

// Close on a dead link does not reach the other side either: no FIN gets
// through. The station must find out by its own timers, so the connection
// is only really closed well after they have expired.
func (c *blackholeConn) Close() error {
	if c.hole.silent.Load() {
		c.dead.Store(true)
	}
	if !c.dead.Load() {
		return c.Conn.Close()
	}
	// Ends a Read in progress, locally.
	_ = c.SetReadDeadline(time.Now())
	time.AfterFunc(3*time.Second, func() { _ = c.Conn.Close() })
	return nil
}

func (c *blackholeConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil || (!c.dead.Load() && !c.hole.silent.Load()) {
			return n, err
		}
		c.dead.Store(true) // what arrives on a dead link is lost
	}
}

// The link goes silent without closing: both sides find out through their
// timers (t3 and t1), report a timeout and, once the link is back, the
// client reconnects.
func TestSilentLink(t *testing.T) {
	p := apci.Params{T1: 400 * time.Millisecond, T2: 100 * time.Millisecond, T3: 200 * time.Millisecond}
	var srvEnd, cliErr errBox
	var cliStates states
	hole := &blackhole{}
	l := start(t, []server.Option{server.WithParams(p),
		server.WithStateHandler(func(_ *server.Session, s iec104.State, err error) {
			if s == iec104.StateDisconnected && err != nil {
				srvEnd.add(err)
			}
		})},
		client.WithParams(p), client.WithDialer(hole),
		client.WithStateHandler(func(s iec104.State, err error) {
			if err != nil {
				cliErr.add(err)
			}
			cliStates.add(s, err)
		}),
		client.WithReconnect(client.Reconnect{MinDelay: 50 * time.Millisecond, MaxDelay: 100 * time.Millisecond}))
	ctx := context.Background()
	c := l.dial(t)
	if c.Addr() != l.st.Loopback() {
		t.Errorf("Addr = %s", c.Addr())
	}
	if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); err != nil {
		t.Fatal(err)
	}

	hole.silent.Store(true)
	// A request into the silence fails when the client gives up on the link.
	begin := time.Now()
	_, err := c.Read(ctx, l.ca, 100)
	if !errors.Is(err, iec104.ErrTimeout) && !errors.Is(err, iec104.ErrConnectionLost) {
		t.Errorf("request on a silent link: %v, want ErrTimeout", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("the client took %s to give up with t1 = 400ms", d)
	}
	testutil.Eventually(t, "the client reported the timeout", func() bool { return cliErr.has(iec104.ErrTimeout) })
	testutil.Eventually(t, "the station reported the timeout", func() bool { return srvEnd.has(iec104.ErrTimeout) })

	// While the link is down every new connection dies the same way.
	time.Sleep(300 * time.Millisecond)
	hole.silent.Store(false)
	testutil.Eventually(t, "the client is back", func() bool {
		if c.State() != iec104.StateStarted {
			return false
		}
		rctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_, err := c.Read(rctx, l.ca, 100)
		return err == nil
	})
	// The sessions of the dead connections are gone: each ended by the
	// station's own timers, as no close gets through a silent link.
	testutil.Eventually(t, "the station kept the one session that is alive", func() bool {
		return len(l.st.Server.Sessions()) == 1
	})
	if hole.dials.Load() < 2 {
		t.Errorf("%d dials: the client did not reconnect", hole.dials.Load())
	}
	// A client that reconnects goes straight to "connecting", with the reason.
	if got := cliStates.String(); !strings.Contains(got, "started connecting!") || !strings.HasSuffix(got, "started") {
		t.Errorf("client states: %s", got)
	}
}

// New and Connect, as the two steps Dial combines.
func TestConnectInTwoSteps(t *testing.T) {
	l := start(t, nil)
	ctx := context.Background()
	c, err := client.New(l.st.Loopback(), client.WithAutoStart(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.State() != iec104.StateDisconnected {
		t.Errorf("state before Connect: %s", c.State())
	}
	if err := c.StartDT(ctx); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("StartDT before Connect: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); err == nil {
		t.Error("a second Connect on an established connection succeeded")
	}
	if err := c.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.StartDT(ctx); err != nil {
		t.Errorf("a second StartDT: %v", err)
	}
	if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); err != nil {
		t.Error(err)
	}
	// Closed for good: Close is idempotent and nothing works afterwards.
	if err := c.Close(); err != nil {
		t.Error(err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := c.Connect(ctx); !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("Connect after Close: %v", err)
	}
	if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("Interrogate after Close: %v", err)
	}

	// Options that cannot work are refused before anything is dialled.
	if _, err := client.New(l.st.Loopback(), client.WithParams(apci.Params{K: 4, W: 9})); !errors.Is(err, apci.ErrInvalidParams) {
		t.Errorf("w > k: %v", err)
	}
	if _, err := server.New(nil, server.WithParams(apci.Params{T1: time.Second, T2: 2 * time.Second})); !errors.Is(err, apci.ErrInvalidParams) {
		t.Errorf("t2 > t1: %v", err)
	}
	// Nothing listens.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	if _, err := client.Dial(ctx, dead); !errors.Is(err, iec104.ErrConnectFailed) {
		t.Errorf("Dial to a closed port: %v", err)
	}
}

// Several controlling stations, each issuing every kind of request at once
// on its connection, against one station: every request returns what it
// returns alone. A request that takes an ASDU meant for another one, on
// either side, shows up as a wrong result or a protocol violation.
func TestEveryRequestAtOnce(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		const clients, rounds = 4, 12
		points := len(l.fx.Expected(false))
		counters := len(l.fx.Expected(true))
		small, large := l.fx.Files[0], l.fx.Files[len(l.fx.Files)-1]

		var wg sync.WaitGroup
		for i := 0; i < clients; i++ {
			c := l.dial(t, client.WithRequestTimeout(20*time.Second))
			upload := station.FirstUploadIOA + 500 + asdu.IOA(i)
			data := bytes.Repeat([]byte{byte(i + 1), 0x33}, 1500+i)
			kinds := map[string]func() error{
				"Interrogate": func() error {
					got, err := c.Interrogate(ctx, l.ca, asdu.QOIStation)
					if err == nil && len(station.Observe(t, got)) != points {
						err = fmt.Errorf("%d values, want %d", len(station.Observe(t, got)), points)
					}
					return err
				},
				"CounterInterrogate": func() error {
					got, err := c.CounterInterrogate(ctx, l.ca, asdu.CounterGeneral, asdu.FreezeRead)
					if err == nil && len(station.Observe(t, got)) != counters {
						err = fmt.Errorf("%d counters, want %d", len(station.Observe(t, got)), counters)
					}
					return err
				},
				"Read": func() error {
					a, err := c.Read(ctx, l.ca, 103)
					if err == nil && (a.Type != asdu.M_BO_NA_1 || a.First().Address() != 103) {
						err = fmt.Errorf("got %s", a)
					}
					return err
				},
				"Read counter": func() error {
					a, err := c.Read(ctx, l.ca, 300)
					if err == nil && a.Type != asdu.M_IT_NA_1 {
						err = fmt.Errorf("got %s", a)
					}
					return err
				},
				"Command":     func() error { return c.Command(ctx, l.ca, asdu.SetpointScaled{IOA: 504, Value: 77}) },
				"TestCommand": func() error { return c.TestCommand(ctx, l.ca) },
				"GetFile": func() error {
					got, err := c.GetFile(ctx, l.ca, large.IOA, large.Name)
					if err == nil && !bytes.Equal(got, large.Content()) {
						err = fmt.Errorf("%d octets that are not the file", len(got))
					}
					return err
				},
				"GetFile small": func() error {
					got, err := c.GetFile(ctx, l.ca, small.IOA, small.Name)
					if err == nil && !bytes.Equal(got, small.Content()) {
						err = fmt.Errorf("%d octets that are not the file", len(got))
					}
					return err
				},
				"PutFile": func() error {
					if err := c.PutFile(ctx, l.ca, upload, 1, data[:1000], data[1000:]); err != nil {
						return err
					}
					if got, ok := l.st.Uploaded(upload); !ok || !bytes.Equal(got, data) {
						return fmt.Errorf("the station holds %d octets that are not what was delivered", len(got))
					}
					return nil
				},
				"ListFiles": func() error {
					dir, err := c.ListFiles(ctx, l.ca, 0)
					if err != nil {
						return err
					}
					if len(dir) < len(l.fx.Files) || dir[0].IOA != small.IOA {
						return fmt.Errorf("directory of %d entries, first %d", len(dir), dir[0].IOA)
					}
					return nil
				},
			}
			for name, run := range kinds {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for round := 0; round < rounds; round++ {
						if err := run(); err != nil {
							t.Errorf("client %d, %s, round %d: %v", i, name, round, err)
							return
						}
					}
				}()
			}
		}
		wg.Wait()
	})
}
