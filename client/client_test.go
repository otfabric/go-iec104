// SPDX-License-Identifier: MIT

package client_test

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

const (
	ioaSwitch     = 6001 // accepts commands
	ioaInterlock  = 6002 // answers with a negative confirmation
	ioaSilent     = 6003 // never answers
	ioaSlow       = 6004 // answers after a delay
	ioaMeasurand  = 4001
	stationCA     = 1
	measurandBase = 49.5
)

// station is a small controlled station used as the peer of the client.
type station struct {
	*server.Server
	addr string

	mu       sync.Mutex
	commands []*asdu.ASDU
	clock    time.Time
}

func (st *station) recorded() []*asdu.ASDU {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]*asdu.ASDU(nil), st.commands...)
}

func newStation(t *testing.T, opts ...server.Option) *station {
	t.Helper()
	st := &station{}
	mux := server.NewMux()

	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		qoi := req.First().(asdu.Interrogation).Qualifier
		if qoi != asdu.QOIStation && qoi != asdu.QOIGroup(2) {
			_ = s.Negative(req)
			return
		}
		_ = s.Confirm(req)
		points := &asdu.ASDU{Type: asdu.M_SP_NA_1, Sequence: true, Cause: qoi.Cause(), CommonAddr: stationCA}
		for i := 0; i < 40; i++ {
			points.Objects = append(points.Objects, asdu.SinglePoint{IOA: asdu.IOA(1000 + i), Value: i%2 == 0})
		}
		_ = s.Send(s.Context(), points)
		_ = s.Send(s.Context(), asdu.New(qoi.Cause(), stationCA,
			asdu.MeasuredFloat{IOA: ioaMeasurand, Value: measurandBase},
			asdu.MeasuredFloat{IOA: ioaMeasurand + 1, Value: 230}))
		// Spontaneous data interleaved with the answer is not part of it.
		_ = s.Send(s.Context(), asdu.New(asdu.CauseSpontaneous, stationCA, asdu.SinglePoint{IOA: 1, Value: true}))
		_ = s.Terminate(req)
	})

	mux.HandleFunc(asdu.C_CI_NA_1, func(s *server.Session, req *asdu.ASDU) {
		obj := req.First().(asdu.CounterInterrogation)
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(obj.Cause(), stationCA, asdu.IntegratedTotal{IOA: 8001, Value: 12345, Sequence: 1}))
		_ = s.Terminate(req)
	})

	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		if req.First().Address() != ioaMeasurand {
			_ = s.Reject(req, asdu.CauseUnknownIOA)
			return
		}
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, stationCA, asdu.MeasuredFloat{IOA: ioaMeasurand, Value: measurandBase}))
	})

	mux.HandleFunc(asdu.C_CS_NA_1, func(s *server.Session, req *asdu.ASDU) {
		st.mu.Lock()
		st.clock = req.First().(asdu.ClockSync).Time.Time
		st.mu.Unlock()
		_ = s.Confirm(req)
	})
	mux.HandleFunc(asdu.C_TS_TA_1, func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) })
	mux.HandleFunc(asdu.C_RP_NA_1, func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) })

	mux.Handle(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		st.mu.Lock()
		st.commands = append(st.commands, req)
		st.mu.Unlock()
		switch req.First().Address() {
		case ioaSwitch:
			_ = s.Confirm(req)
			if req.Cause == asdu.CauseActivation {
				_ = s.Terminate(req)
			}
		case ioaInterlock:
			_ = s.Negative(req)
		case ioaSilent:
		case ioaSlow:
			go func() {
				time.Sleep(200 * time.Millisecond)
				_ = s.Confirm(req)
			}()
		default:
			_ = s.Reject(req, asdu.CauseUnknownIOA)
		}
	}), server.ProcessCommands...)

	srv, err := server.New(mux, append([]server.Option{server.WithParams(testutil.Params())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st.Server = srv
	st.addr = ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return st
}

// collector is a client.Handler that records what it receives.
type collector struct {
	mu    sync.Mutex
	asdus []*asdu.ASDU
}

func (c *collector) HandleASDU(a *asdu.ASDU) {
	c.mu.Lock()
	c.asdus = append(c.asdus, a)
	c.mu.Unlock()
}

func (c *collector) find(match func(a *asdu.ASDU) bool) *asdu.ASDU {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.asdus {
		if match(a) {
			return a
		}
	}
	return nil
}

func dial(t *testing.T, addr string, opts ...client.Option) *client.Client {
	t.Helper()
	opts = append([]client.Option{client.WithParams(testutil.Params()), client.WithRequestTimeout(3 * time.Second)}, opts...)
	c, err := client.Dial(context.Background(), addr, opts...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func negativeCause(t *testing.T, err error) asdu.Cause {
	t.Helper()
	var neg *iec104.NegativeError
	if !errors.As(err, &neg) {
		t.Fatalf("error = %v, want *iec104.NegativeError", err)
	}
	if neg.Error() == "" || neg.ASDU == nil {
		t.Fatal("NegativeError without detail")
	}
	return neg.Cause()
}

func TestInterrogate(t *testing.T) {
	st := newStation(t)
	col := &collector{}
	c := dial(t, st.addr, client.WithHandler(col), client.WithOriginator(9))
	ctx := context.Background()

	if c.State() != iec104.StateStarted || c.Addr() != st.addr {
		t.Fatalf("state %s addr %s", c.State(), c.Addr())
	}
	data, err := c.Interrogate(ctx, stationCA, asdu.QOIStation)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	if len(data) != 2 {
		t.Fatalf("got %d ASDUs, want 2 (spontaneous data must not be collected)", len(data))
	}
	if data[0].Type != asdu.M_SP_NA_1 || len(data[0].Objects) != 40 || !data[0].Sequence ||
		data[0].Objects[39].Address() != 1039 {
		t.Errorf("first ASDU: %s", data[0])
	}
	if f := data[1].Objects[0].(asdu.MeasuredFloat); f.IOA != ioaMeasurand || f.Value != measurandBase {
		t.Errorf("measurand: %+v", f)
	}

	// The handler sees everything: confirmation, data, spontaneous, termination.
	testutil.Eventually(t, "termination at the handler", func() bool {
		return col.find(func(a *asdu.ASDU) bool {
			return a.Type == asdu.C_IC_NA_1 && a.Cause == asdu.CauseActivationTerm && a.Originator == 9
		}) != nil
	})
	if col.find(func(a *asdu.ASDU) bool { return a.Cause == asdu.CauseSpontaneous }) == nil {
		t.Error("spontaneous ASDU did not reach the handler")
	}

	// A group interrogation is answered with the cause of its group.
	data, err = c.Interrogate(ctx, stationCA, asdu.QOIGroup(2))
	if err != nil || len(data) != 2 || data[0].Cause != asdu.CauseInterrogatedGroup1+1 {
		t.Fatalf("group interrogation: %d ASDUs, %v", len(data), err)
	}
	// Broadcast: answers come from the station's own address.
	if data, err = c.Interrogate(ctx, asdu.Broadcast, asdu.QOIStation); err != nil || len(data) != 2 {
		t.Fatalf("broadcast interrogation: %d ASDUs, %v", len(data), err)
	}
	// A group the station does not have is refused.
	_, err = c.Interrogate(ctx, stationCA, asdu.QOIGroup(7))
	if got := negativeCause(t, err); got != asdu.CauseActivationCon {
		t.Errorf("negative confirmation cause = %s", got)
	}

	totals, err := c.CounterInterrogate(ctx, stationCA, asdu.CounterGeneral, asdu.FreezeRead)
	if err != nil || len(totals) != 1 || totals[0].Objects[0].(asdu.IntegratedTotal).Value != 12345 {
		t.Fatalf("CounterInterrogate: %v, %v", totals, err)
	}
	if totals, err = c.CounterInterrogate(ctx, stationCA, asdu.CounterGroup1, asdu.FreezeRead); err != nil ||
		len(totals) != 1 || totals[0].Cause != asdu.CauseCounterGroup1 {
		t.Fatalf("CounterInterrogate group: %v, %v", totals, err)
	}
}

func TestCommands(t *testing.T) {
	st := newStation(t)
	c := dial(t, st.addr)
	ctx := context.Background()

	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch, Value: true, Select: true}); err != nil {
		t.Fatalf("select: %v", err)
	}
	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch, Value: true}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	when := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	if err := c.Command(ctx, stationCA, asdu.SetpointFloat{IOA: ioaSwitch, Value: 42.5, Time: asdu.At(when)}); err != nil {
		t.Fatalf("set point: %v", err)
	}
	if err := c.Deactivate(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch, Value: true, Select: true}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	got := st.recorded()
	if len(got) != 4 {
		t.Fatalf("station saw %d commands, want 4", len(got))
	}
	if cmd := got[0].First().(asdu.SingleCommand); !cmd.Select || !cmd.Value || got[0].Type != asdu.C_SC_NA_1 {
		t.Errorf("select: %+v", cmd)
	}
	if sp := got[2].First().(asdu.SetpointFloat); got[2].Type != asdu.C_SE_TC_1 || sp.Value != 42.5 || !sp.Time.Equal(when) {
		t.Errorf("set point: %s %+v", got[2].Type, sp)
	}
	if got[3].Cause != asdu.CauseDeactivation {
		t.Errorf("deactivation cause: %s", got[3].Cause)
	}

	err := c.Command(ctx, stationCA, asdu.DoubleCommand{IOA: ioaInterlock, Value: asdu.DoubleOn})
	if got := negativeCause(t, err); got != asdu.CauseActivationCon {
		t.Errorf("interlocked command: cause %s", got)
	}
	err = c.Command(ctx, stationCA, asdu.SingleCommand{IOA: 1})
	if got := negativeCause(t, err); got != asdu.CauseUnknownIOA {
		t.Errorf("unknown object: cause %s", got)
	}

	if err := c.Command(ctx, stationCA, asdu.SinglePoint{IOA: 1}); !errors.Is(err, asdu.ErrTypeMismatch) {
		t.Errorf("monitor object as command: %v", err)
	}
	if err := c.Command(ctx, stationCA, nil); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("nil command: %v", err)
	}
	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch, Qualifier: 99}); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("unencodable command: %v", err)
	}
}

func TestSystemCommands(t *testing.T) {
	st := newStation(t)
	c := dial(t, st.addr)
	ctx := context.Background()

	a, err := c.Read(ctx, stationCA, ioaMeasurand)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if f := a.First().(asdu.MeasuredFloat); a.Cause != asdu.CauseRequest || f.Value != measurandBase {
		t.Errorf("Read: %s %+v", a, f)
	}
	_, err = c.Read(ctx, stationCA, 1)
	if got := negativeCause(t, err); got != asdu.CauseUnknownIOA {
		t.Errorf("Read of unknown object: cause %s", got)
	}

	now := time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)
	if err := c.ClockSync(ctx, stationCA, now); err != nil {
		t.Fatalf("ClockSync: %v", err)
	}
	st.mu.Lock()
	clock := st.clock
	st.mu.Unlock()
	if !clock.Equal(now) {
		t.Errorf("station clock = %v, want %v", clock, now)
	}
	for i := 0; i < 2; i++ {
		if err := c.TestCommand(ctx, stationCA); err != nil {
			t.Fatalf("TestCommand: %v", err)
		}
	}
	if err := c.ResetProcess(ctx, stationCA, asdu.ResetProcessGeneral); err != nil {
		t.Fatalf("ResetProcess: %v", err)
	}
	if err := c.TestLink(ctx); err != nil {
		t.Fatalf("TestLink: %v", err)
	}
}

func TestUnknownTypeIsMirrored(t *testing.T) {
	st := newStation(t)
	col := &collector{}
	c := dial(t, st.addr, client.WithHandler(col))
	ctx := context.Background()

	// A parameter type the station has no handler for, and a private type.
	if err := c.Send(ctx, asdu.New(asdu.CauseActivation, stationCA, asdu.ParameterActivation{IOA: 1, Qualifier: 1})); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, &asdu.ASDU{Type: 200, Cause: asdu.CauseActivation, CommonAddr: stationCA,
		Raw: []byte{1, 2, 3, 4}, RawCount: 1}); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []asdu.TypeID{asdu.P_AC_NA_1, 200} {
		testutil.Eventually(t, "mirror of "+typ.String(), func() bool {
			return col.find(func(a *asdu.ASDU) bool {
				return a.Type == typ && a.Cause == asdu.CauseUnknownType && a.Negative
			}) != nil
		})
	}
	// A valid type with a cause that makes no sense in control direction.
	if err := c.Send(ctx, asdu.New(asdu.CauseSpontaneous, stationCA, asdu.SingleCommand{IOA: ioaSwitch})); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "unknown cause mirror", func() bool {
		return col.find(func(a *asdu.ASDU) bool { return a.Cause == asdu.CauseUnknownCause && a.Negative }) != nil
	})
	if err := c.Send(ctx, &asdu.ASDU{Type: asdu.M_SP_NA_1, Cause: 99}); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("unencodable ASDU: %v", err)
	}
}

func TestPendingRequests(t *testing.T) {
	st := newStation(t)
	c := dial(t, st.addr)
	ctx := context.Background()

	// The same request cannot be pending twice: its answers would be ambiguous.
	errc := make(chan error, 1)
	go func() { errc <- c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSlow}) }()
	testutil.Eventually(t, "command at the station", func() bool { return len(st.recorded()) == 1 })
	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSlow}); !errors.Is(err, iec104.ErrBusy) {
		t.Errorf("duplicate request: %v, want ErrBusy", err)
	}
	// A different object is independent.
	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch}); err != nil {
		t.Errorf("concurrent command on another object: %v", err)
	}
	if err := <-errc; err != nil {
		t.Errorf("slow command: %v", err)
	}

	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := c.Command(short, stationCA, asdu.SingleCommand{IOA: ioaSilent}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unanswered command: %v, want deadline exceeded", err)
	}
	// The slot is free again after the timeout.
	go func() { errc <- c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSilent}) }()
	testutil.Eventually(t, "second silent command", func() bool { return len(st.recorded()) == 4 })
	_ = c.Close()
	if err := <-errc; !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("request pending at Close: %v, want ErrClosed", err)
	}
	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch}); !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("request after Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestRequestTimeoutOption(t *testing.T) {
	st := newStation(t)
	c := dial(t, st.addr, client.WithRequestTimeout(100*time.Millisecond))
	begin := time.Now()
	err := c.Command(context.Background(), stationCA, asdu.SingleCommand{IOA: ioaSilent})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(begin) > 2*time.Second {
		t.Errorf("error %v after %s", err, time.Since(begin))
	}
}

func TestStartStop(t *testing.T) {
	st := newStation(t)
	var (
		mu     sync.Mutex
		states []iec104.State
	)
	c, err := client.New(st.addr,
		client.WithParams(testutil.Params()),
		client.WithAutoStart(false),
		client.WithStateHandler(func(s iec104.State, _ error) {
			mu.Lock()
			states = append(states, s)
			mu.Unlock()
		}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.StartDT(ctx); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("StartDT before Connect: %v", err)
	}
	if _, err := c.Interrogate(ctx, stationCA, asdu.QOIStation); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("Interrogate before Connect: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); !errors.Is(err, iec104.ErrBusy) {
		t.Errorf("second Connect: %v, want ErrBusy", err)
	}
	if c.State() != iec104.StateStopped {
		t.Fatalf("state after Connect without auto start: %s", c.State())
	}
	if _, err := c.Interrogate(ctx, stationCA, asdu.QOIStation); !errors.Is(err, iec104.ErrNotStarted) {
		t.Errorf("Interrogate in STOPDT: %v", err)
	}
	if err := c.TestLink(ctx); err != nil {
		t.Errorf("TestLink in STOPDT: %v", err)
	}
	if err := c.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Interrogate(ctx, stationCA, asdu.QOIStation); err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	if err := c.StopDT(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, asdu.New(asdu.CauseActivation, stationCA, asdu.SingleCommand{IOA: 1})); !errors.Is(err, iec104.ErrNotStarted) {
		t.Errorf("Send in STOPDT: %v", err)
	}
	_ = c.Close()
	for _, f := range []func() error{
		func() error { return c.Connect(ctx) }, func() error { return c.StartDT(ctx) },
		func() error { return c.StopDT(ctx) }, func() error { return c.TestLink(ctx) },
		func() error { return c.Send(ctx, asdu.New(asdu.CauseActivation, 1, asdu.Read{})) },
	} {
		if err := f(); !errors.Is(err, iec104.ErrClosed) {
			t.Errorf("after Close: %v, want ErrClosed", err)
		}
	}

	want := []iec104.State{iec104.StateConnecting, iec104.StateStopped, iec104.StateStarted,
		iec104.StateStopped, iec104.StateDisconnected}
	testutil.Eventually(t, "state sequence", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(states) == len(want)
	})
	mu.Lock()
	defer mu.Unlock()
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("states = %v, want %v", states, want)
		}
	}
}

func TestConnectErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := client.New("127.0.0.1", client.WithParams(apci.Params{K: 1, W: 2})); !errors.Is(err, apci.ErrInvalidParams) {
		t.Errorf("invalid params: %v", err)
	}
	if _, err := client.New("127.0.0.1", client.WithASDUParams(asdu.Params{})); !errors.Is(err, asdu.ErrInvalidParams) {
		t.Errorf("invalid ASDU params: %v", err)
	}
	if _, err := client.Dial(ctx, "127.0.0.1", client.WithParams(apci.Params{K: 1, W: 2})); err == nil {
		t.Error("Dial with invalid params succeeded")
	}
	c, _ := client.New("192.0.2.1")
	if c.Addr() != "192.0.2.1:2404" {
		t.Errorf("default port: %s", c.Addr())
	}
	c, _ = client.New("[2001:db8::1]:102")
	if c.Addr() != "[2001:db8::1]:102" {
		t.Errorf("explicit port: %s", c.Addr())
	}

	// Nothing listens on a port that was just released.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	var last error
	c, err := client.New(addr, client.WithParams(testutil.Params()),
		client.WithStateHandler(func(_ iec104.State, err error) { last = err }))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); err == nil {
		t.Fatal("Connect to a closed port succeeded")
	}
	if c.State() != iec104.StateDisconnected || last == nil {
		t.Errorf("state %s, handler error %v", c.State(), last)
	}
	if _, err := client.Dial(ctx, addr, client.WithParams(testutil.Params())); err == nil {
		t.Error("Dial to a closed port succeeded")
	}

	// A peer that accepts but never confirms STARTDT: bounded by the context.
	ln, _ = net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
		}
	}()
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	c, _ = client.New(ln.Addr().String(), client.WithParams(testutil.Params()))
	if err := c.Connect(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Connect to a mute peer: %v, want deadline exceeded", err)
	}
	if c.State() != iec104.StateDisconnected {
		t.Errorf("state after failed STARTDT: %s", c.State())
	}
	// The client is reusable after a failed attempt.
	st := newStation(t)
	c2, _ := client.New(st.addr, client.WithParams(testutil.Params()))
	defer func() { _ = c2.Close() }()
	if err := c2.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	// Close interrupts a connection attempt in progress.
	c3, _ := client.New(ln.Addr().String(), client.WithParams(testutil.Params()))
	errc := make(chan error, 1)
	go func() { errc <- c3.Connect(ctx) }()
	time.Sleep(100 * time.Millisecond)
	_ = c3.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("Connect succeeded although the client was closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not interrupt Connect")
	}
}

func TestSpontaneousAndMetrics(t *testing.T) {
	st := newStation(t)
	col := &collector{}
	m := &testutil.Metrics{}
	c := dial(t, st.addr, client.WithHandler(col), client.WithMetrics(m),
		client.WithLogger(iec104.NopLogger()))

	testutil.Eventually(t, "session started", func() bool {
		ss := st.Sessions()
		return len(ss) == 1 && ss[0].Started()
	})
	n, err := st.Broadcast(context.Background(), asdu.New(asdu.CauseSpontaneous, stationCA,
		asdu.MeasuredFloat{IOA: ioaMeasurand, Value: 50.01, Time: asdu.Now()}))
	if err != nil || n != 1 {
		t.Fatalf("Broadcast: %d, %v", n, err)
	}
	testutil.Eventually(t, "spontaneous ASDU", func() bool {
		return col.find(func(a *asdu.ASDU) bool { return a.Type == asdu.M_ME_TF_1 }) != nil
	})
	_ = c.Close()
	testutil.Eventually(t, "disconnect metric", func() bool {
		_, d, _, _, _ := m.Snapshot()
		return d == 1
	})
	connects, _, sent, received, bad := m.Snapshot()
	if connects != 1 || sent < 1 || received < 2 || bad != 0 || m.LastDisconnect != nil {
		t.Errorf("metrics: connects=%d sent=%d received=%d bad=%d last=%v", connects, sent, received, bad, m.LastDisconnect)
	}
}

func TestUndecodableASDUIsDropped(t *testing.T) {
	// The station uses a two-octet information object address: what it
	// sends does not parse under the IEC 104 layout.
	st := newStation(t, server.WithASDUParams(asdu.Params{CauseSize: 2, CommonAddrSize: 2, IOASize: 2}))
	m := &testutil.Metrics{}
	col := &collector{}
	dial(t, st.addr, client.WithMetrics(m), client.WithHandler(col), client.WithLogger(iec104.NopLogger()))
	testutil.Eventually(t, "session started", func() bool {
		ss := st.Sessions()
		return len(ss) == 1 && ss[0].Started()
	})
	if _, err := st.Broadcast(context.Background(), asdu.New(asdu.CauseSpontaneous, stationCA, asdu.SinglePoint{IOA: 1})); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "decode error metric", func() bool {
		_, _, _, _, bad := m.Snapshot()
		return bad == 1
	})
	if col.find(func(*asdu.ASDU) bool { return true }) != nil {
		t.Error("undecodable ASDU reached the handler")
	}
}

func TestTLS(t *testing.T) {
	serverTLS, clientTLS := testutil.TLSConfigs(t)
	srv, err := server.New(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }),
		server.WithParams(testutil.Params()), server.WithTLS(serverTLS))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe("127.0.0.1:0") }()
	defer func() { _ = srv.Close() }()
	testutil.Eventually(t, "listener", func() bool { return srv.Addr() != nil })

	c := dial(t, srv.Addr().String(), client.WithTLS(clientTLS))
	if err := c.TestCommand(context.Background(), 1); err != nil {
		t.Fatalf("TestCommand over TLS: %v", err)
	}
	c2, _ := client.New("192.0.2.1", client.WithTLS(clientTLS))
	if c2.Addr() != "192.0.2.1:19998" {
		t.Errorf("default TLS port: %s", c2.Addr())
	}

	// A client that does not trust the certificate fails to connect.
	_, untrusted := testutil.TLSConfigs(t)
	if _, err := client.Dial(context.Background(), srv.Addr().String(),
		client.WithParams(testutil.Params()), client.WithTLS(untrusted)); err == nil {
		t.Error("handshake with an untrusted certificate succeeded")
	}
}

type countingDialer struct {
	mu sync.Mutex
	n  int
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.n++
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (d *countingDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}

func TestReconnect(t *testing.T) {
	st := newStation(t)
	d := &countingDialer{}
	var (
		mu       sync.Mutex
		states   []iec104.State
		failures int
	)
	c := dial(t, st.addr, client.WithDialer(d),
		client.WithLogger(iec104.NopLogger()),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond}),
		client.WithStateHandler(func(s iec104.State, err error) {
			mu.Lock()
			states = append(states, s)
			if s == iec104.StateConnecting && err != nil {
				failures++
			}
			mu.Unlock()
		}))
	ctx := context.Background()

	// The station drops the session: the client comes back by itself.
	testutil.Eventually(t, "session", func() bool { return len(st.Sessions()) == 1 })
	_ = st.Sessions()[0].Close()
	testutil.Eventually(t, "reconnect", func() bool { return d.count() >= 2 && c.State() == iec104.StateStarted })
	if _, err := c.Interrogate(ctx, stationCA, asdu.QOIStation); err != nil {
		t.Fatalf("Interrogate after reconnect: %v", err)
	}

	// The station goes away entirely: attempts fail and back off, requests
	// are refused, and the client recovers when the station returns.
	_ = st.Close()
	testutil.Eventually(t, "failed attempts", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return failures >= 3
	})
	if err := c.Command(ctx, stationCA, asdu.SingleCommand{IOA: ioaSwitch}); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("request while disconnected: %v, want ErrNotConnected", err)
	}
	if c.State() != iec104.StateConnecting {
		t.Errorf("state while reconnecting: %s", c.State())
	}
	if err := c.Connect(ctx); !errors.Is(err, iec104.ErrBusy) {
		t.Errorf("Connect while reconnecting: %v, want ErrBusy", err)
	}

	ln, err := net.Listen("tcp", st.addr)
	if err != nil {
		t.Skipf("cannot listen on %s again: %v", st.addr, err)
	}
	srv, _ := server.New(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(req) }),
		server.WithParams(testutil.Params()))
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	testutil.Eventually(t, "recovery", func() bool { return c.State() == iec104.StateStarted })
	if err := c.TestCommand(ctx, stationCA); err != nil {
		t.Fatalf("TestCommand after recovery: %v", err)
	}

	// Close ends the reconnect loop for good.
	_ = srv.Close()
	testutil.Eventually(t, "connecting again", func() bool { return c.State() == iec104.StateConnecting })
	_ = c.Close()
	if c.State() != iec104.StateDisconnected {
		t.Errorf("state after Close: %s", c.State())
	}
	n := d.count()
	time.Sleep(250 * time.Millisecond)
	if d.count() != n {
		t.Error("client kept dialing after Close")
	}
}

func TestRequestFailsWhenConnectionDrops(t *testing.T) {
	st := newStation(t)
	c := dial(t, st.addr)
	errc := make(chan error, 1)
	go func() { errc <- c.Command(context.Background(), stationCA, asdu.SingleCommand{IOA: ioaSilent}) }()
	testutil.Eventually(t, "command at the station", func() bool { return len(st.recorded()) == 1 })
	_ = st.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, iec104.ErrConnectionLost) {
			t.Errorf("pending request: %v, want ErrConnectionLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending request not released")
	}
	testutil.Eventually(t, "disconnected", func() bool { return c.State() == iec104.StateDisconnected })
}

// Close returns with the client settled: state, pending requests and all.
func TestCloseIsSynchronous(t *testing.T) {
	st := newStation(t)
	for i := 0; i < 20; i++ {
		c := dial(t, st.addr)
		_ = c.Close()
		if s := c.State(); s != iec104.StateDisconnected {
			t.Fatalf("state right after Close: %s", s)
		}
	}
	testutil.Eventually(t, "sessions gone", func() bool { return len(st.Sessions()) == 0 })
	c := dial(t, st.addr)
	testutil.Eventually(t, "session", func() bool { return len(st.Sessions()) == 1 })
	sess := st.Sessions()[0]
	_ = sess.Close()
	if n := len(st.Sessions()); n != 0 {
		t.Fatalf("%d sessions right after Session.Close", n)
	}
	_ = c
}
