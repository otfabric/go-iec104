//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
)

// recorder keeps every ASDU the client's handler receives.
type recorder struct {
	mu    sync.Mutex
	asdus []*asdu.ASDU
}

func (r *recorder) HandleASDU(a *asdu.ASDU) {
	r.mu.Lock()
	r.asdus = append(r.asdus, a)
	r.mu.Unlock()
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.asdus = nil
	r.mu.Unlock()
}

// find returns the first recorded ASDU that satisfies match, waiting for it.
func (r *recorder) find(t testing.TB, what string, match func(*asdu.ASDU) bool) *asdu.ASDU {
	t.Helper()
	var found *asdu.ASDU
	eventually(t, 5*time.Second, what, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, a := range r.asdus {
			if match(a) {
				found = a
				return true
			}
		}
		return false
	})
	return found
}

// frames counts U frames by function, in both directions.
type frames struct {
	iec104.NopMetrics
	mu       sync.Mutex
	received map[apci.UFunction]int
	sent     map[apci.UFunction]int
	sFrames  atomic.Int64
}

func (f *frames) OnFrameReceived(_ net.Addr, fr apci.Frame, _ int) {
	if fr.Format != apci.FormatU {
		return
	}
	f.mu.Lock()
	if f.received == nil {
		f.received = map[apci.UFunction]int{}
	}
	f.received[fr.Function]++
	f.mu.Unlock()
}

func (f *frames) OnFrameSent(_ net.Addr, fr apci.Frame, _ int) {
	switch fr.Format {
	case apci.FormatS:
		f.sFrames.Add(1)
	case apci.FormatU:
		f.mu.Lock()
		if f.sent == nil {
			f.sent = map[apci.UFunction]int{}
		}
		f.sent[fr.Function]++
		f.mu.Unlock()
	case apci.FormatI:
	}
}

func (f *frames) count(received bool, fn apci.UFunction) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if received {
		return f.received[fn]
	}
	return f.sent[fn]
}

func dial(t testing.TB, addr string, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, append([]client.Option{client.WithRequestTimeout(5 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatalf("Dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func negative(t testing.TB, err error, want asdu.Cause) {
	t.Helper()
	var neg *iec104.NegativeError
	if !errors.As(err, &neg) {
		t.Errorf("error = %v, want a negative answer with cause %s", err, want)
		return
	}
	if neg.Cause() != want {
		t.Errorf("negative answer with cause %s, want %s", neg.Cause(), want)
	}
}

// forEachServer runs f against a fresh reference server of every adapter.
func forEachServer(t *testing.T, f func(t *testing.T, a adapter, fx *fixture, srv *refServer), serverArgs ...string) {
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			f(t, a, loadFixture(t, a), startServer(t, a, serverArgs...))
		})
	}
}

// TestClientInterrogation: what go-iec104 decodes from a reference station
// is the fixture, value by value.
func TestClientInterrogation(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		c := dial(t, srv.addr)
		ca := fx.Station.CommonAddr

		data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}
		if got, want := observe(t, data), fx.expected(false); !sameObserved(got, want) {
			t.Errorf("interrogation:\n got  %v\n want %v", got, want)
		}
		for _, d := range data {
			if d.Cause != asdu.CauseInterrogatedStation || d.CommonAddr != ca || d.Negative || d.Test {
				t.Errorf("unexpected header: %s", d)
			}
		}
		srv.waitEvent(t, "interrogation", func(e event) bool {
			return e["event"] == "interrogation" && e["qoi"] == 20.0 && e["accepted"] == true
		})

		// The broadcast address is answered by the station under its own address.
		data, err = c.Interrogate(ctx, asdu.Broadcast, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate (broadcast): %v", err)
		}
		if got, want := observe(t, data), fx.expected(false); !sameObserved(got, want) {
			t.Errorf("broadcast interrogation:\n got  %v\n want %v", got, want)
		}

		totals, err := c.CounterInterrogate(ctx, ca, asdu.CounterGeneral, asdu.FreezeRead)
		if err != nil {
			t.Fatalf("CounterInterrogate: %v", err)
		}
		if got, want := observe(t, totals), fx.expected(true); !sameObserved(got, want) {
			t.Errorf("counter interrogation:\n got  %v\n want %v", got, want)
		}
		if seq := totals[0].Objects[0].(asdu.IntegratedTotal).Sequence; seq != fx.point(300).Sequence {
			t.Errorf("counter sequence number %d, want %d", seq, fx.point(300).Sequence)
		}

		// Refusals: a group the station does not have, a counter request it
		// does not support, a station that does not exist.
		_, err = c.Interrogate(ctx, ca, asdu.QOIGroup(1))
		negative(t, err, asdu.CauseActivationCon)
		_, err = c.CounterInterrogate(ctx, ca, asdu.CounterGeneral, asdu.FreezeWithoutReset)
		negative(t, err, asdu.CauseActivationCon)
		_, err = c.Interrogate(ctx, ca+6, asdu.QOIStation)
		negative(t, err, asdu.CauseUnknownCommonAddr)
	})
}

func TestClientRead(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		c := dial(t, srv.addr)
		ca := fx.Station.CommonAddr

		for _, p := range fx.Points {
			got, err := c.Read(ctx, ca, p.IOA)
			if err != nil {
				t.Errorf("Read %d: %v", p.IOA, err)
				continue
			}
			want := observed{p.IOA, p.Type, p.Value, joinFlags(p.Quality)}
			if obs := observe(t, []*asdu.ASDU{got}); len(obs) != 1 || obs[0] != want || got.Cause != asdu.CauseRequest {
				t.Errorf("Read %d: got %v (%s), want %v", p.IOA, obs, got, want)
			}
		}
		_, err := c.Read(ctx, ca, 999)
		negative(t, err, asdu.CauseUnknownIOA)
	})
}

func TestClientSystemCommands(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		c := dial(t, srv.addr)
		ca := fx.Station.CommonAddr

		// The station receives the time go-iec104 encoded, to the millisecond.
		when := time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)
		if err := c.ClockSync(ctx, ca, when); err != nil {
			t.Fatalf("ClockSync: %v", err)
		}
		srv.waitEvent(t, "clock-sync", func(e event) bool {
			return e["event"] == "clock-sync" && e["time"] == "2026-10-09T15:35:12.345Z"
		})
		// A local time is sent as the same instant in UTC.
		zone := time.FixedZone("UTC+5:30", 5*3600+1800)
		if err := c.ClockSync(ctx, ca, time.Date(2031, 2, 28, 23, 59, 59, 999e6, zone)); err != nil {
			t.Fatalf("ClockSync: %v", err)
		}
		srv.waitEvent(t, "clock-sync", func(e event) bool {
			return e["event"] == "clock-sync" && e["time"] == "2031-02-28T18:29:59.999Z"
		})

		for i := 0; i < 3; i++ {
			if err := c.TestCommand(ctx, ca); err != nil {
				t.Fatalf("TestCommand: %v", err)
			}
		}
		if err := c.TestLink(ctx); err != nil {
			t.Fatalf("TestLink: %v", err)
		}
	})
}

func TestClientCommands(t *testing.T) {
	stamp := asdu.At(time.Now())
	tests := []struct {
		name    string
		command asdu.InformationObject
		target  asdu.IOA
		// what the target reports afterwards
		report asdu.TypeID
		cause  asdu.Cause
		value  any
	}{
		{"single off", asdu.SingleCommand{IOA: 500, Value: false}, 100, asdu.M_SP_TB_1, asdu.CauseReturnRemote, false},
		{"single with time and qualifier", asdu.SingleCommand{IOA: 500, Value: false, Qualifier: asdu.QualifierLongPulse, Time: stamp},
			100, asdu.M_SP_TB_1, asdu.CauseReturnRemote, false},
		{"double off", asdu.DoubleCommand{IOA: 501, Value: asdu.DoubleOff}, 101, asdu.M_DP_TB_1, asdu.CauseSpontaneous, 1.0},
		{"double with time", asdu.DoubleCommand{IOA: 501, Value: asdu.DoubleOff, Time: stamp}, 101, asdu.M_DP_TB_1, asdu.CauseSpontaneous, 1.0},
		{"step higher", asdu.StepCommand{IOA: 505, Value: asdu.StepHigher}, 102, asdu.M_ST_TB_1, asdu.CauseReturnRemote, 6.0},
		{"step lower with time", asdu.StepCommand{IOA: 505, Value: asdu.StepLower, Time: stamp}, 102, asdu.M_ST_TB_1, asdu.CauseReturnRemote, 4.0},
		{"set point normalized", asdu.SetpointNormalized{IOA: 503, Value: -12345}, 200, asdu.M_ME_TD_1, asdu.CauseReturnRemote, -12345.0},
		{"set point normalized, extremes", asdu.SetpointNormalized{IOA: 503, Value: -32768, Time: stamp}, 200, asdu.M_ME_TD_1, asdu.CauseReturnRemote, -32768.0},
		{"set point scaled", asdu.SetpointScaled{IOA: 504, Value: -7}, 201, asdu.M_ME_TE_1, asdu.CauseReturnRemote, -7.0},
		{"set point scaled with time", asdu.SetpointScaled{IOA: 504, Value: 32767, Time: stamp}, 201, asdu.M_ME_TE_1, asdu.CauseReturnRemote, 32767.0},
		{"set point float", asdu.SetpointFloat{IOA: 502, Value: 49.5}, 202, asdu.M_ME_TF_1, asdu.CauseReturnRemote, 49.5},
		{"set point float with time", asdu.SetpointFloat{IOA: 502, Value: -0.125, Time: stamp}, 202, asdu.M_ME_TF_1, asdu.CauseReturnRemote, -0.125},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
				ctx := context.Background()
				rec := &recorder{}
				c := dial(t, srv.addr, client.WithHandler(rec))
				ca := fx.Station.CommonAddr
				sent := asdu.New(asdu.CauseActivation, ca, tt.command).Type

				if err := c.Command(ctx, ca, tt.command); err != nil {
					t.Fatalf("Command: %v", err)
				}
				// The station reports the new state of the target, time tagged.
				rep := rec.find(t, "report of the target", func(a *asdu.ASDU) bool { return a.Type == tt.report })
				obs := observe(t, []*asdu.ASDU{rep})
				if rep.Cause != tt.cause || len(obs) != 1 || obs[0].IOA != tt.target || obs[0].Value != tt.value {
					t.Errorf("report %s %v, want cause %s, object %d = %v", rep, obs, tt.cause, tt.target, tt.value)
				}
				// ...followed by the termination of the command.
				rec.find(t, "activation termination", func(a *asdu.ASDU) bool {
					return a.Type == sent && a.Cause == asdu.CauseActivationTerm
				})
				// The station saw the command the way it was meant.
				srv.waitEvent(t, "command", func(e event) bool {
					return e["event"] == "command" && e["type"] == sent.String() && e["outcome"] == "executed" &&
						e["ioa"] == float64(tt.command.Address()) && e["select"] == false
				})
				// And a later read agrees.
				got, err := c.Read(ctx, ca, tt.target)
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
				if obs := observe(t, []*asdu.ASDU{got}); len(obs) != 1 || obs[0].Value != tt.value {
					t.Errorf("read after command: %v, want %v", obs, tt.value)
				}
			})
		})
	}
}

func TestClientSelectBeforeOperate(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		rec := &recorder{}
		c := dial(t, srv.addr, client.WithHandler(rec))
		ca := fx.Station.CommonAddr
		// Object 510 only executes after a select.
		execute := asdu.SingleCommand{IOA: 510, Value: false}
		sel := execute
		sel.Select = true

		negative(t, c.Command(ctx, ca, execute), asdu.CauseActivationCon)

		if err := c.Command(ctx, ca, sel); err != nil {
			t.Fatalf("select: %v", err)
		}
		srv.waitEvent(t, "select", func(e event) bool { return e["event"] == "command" && e["outcome"] == "selected" })
		if err := c.Command(ctx, ca, execute); err != nil {
			t.Fatalf("execute after select: %v", err)
		}
		rec.find(t, "report", func(a *asdu.ASDU) bool { return a.Type == asdu.M_SP_TB_1 })

		// The selection was consumed.
		negative(t, c.Command(ctx, ca, execute), asdu.CauseActivationCon)

		// A selection can be cancelled, after which the execute is refused.
		if err := c.Command(ctx, ca, sel); err != nil {
			t.Fatalf("select: %v", err)
		}
		if err := c.Deactivate(ctx, ca, sel); err != nil {
			t.Fatalf("deactivate: %v", err)
		}
		srv.waitEvent(t, "deactivation", func(e event) bool { return e["event"] == "command" && e["outcome"] == "deactivated" })
		negative(t, c.Command(ctx, ca, execute), asdu.CauseActivationCon)
	})
}

func TestClientRefusals(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		rec := &recorder{}
		c := dial(t, srv.addr, client.WithHandler(rec))
		ca := fx.Station.CommonAddr

		// No such object, an object of another command type, no such station.
		negative(t, c.Command(ctx, ca, asdu.SingleCommand{IOA: 999, Value: true}), asdu.CauseUnknownIOA)
		negative(t, c.Command(ctx, ca, asdu.DoubleCommand{IOA: 500, Value: asdu.DoubleOn}), asdu.CauseUnknownIOA)
		negative(t, c.Command(ctx, ca+6, asdu.SingleCommand{IOA: 500, Value: true}), asdu.CauseUnknownCommonAddr)
		// A double command state the standard does not permit.
		negative(t, c.Command(ctx, ca, asdu.DoubleCommand{IOA: 501, Value: asdu.DoubleIndeterminate}), asdu.CauseActivationCon)

		// A type neither station implements is mirrored as unknown.
		rec.reset()
		if err := c.Send(ctx, asdu.New(asdu.CauseActivation, ca, asdu.ParameterActivation{IOA: 1, Qualifier: 1})); err != nil {
			t.Fatal(err)
		}
		rec.find(t, "unknown type mirror", func(a *asdu.ASDU) bool {
			return a.Type == asdu.P_AC_NA_1 && a.Cause == asdu.CauseUnknownType && a.Negative
		})
		// A cause that makes no sense for a command.
		rec.reset()
		if err := c.Send(ctx, asdu.New(asdu.CauseSpontaneous, ca, asdu.SingleCommand{IOA: 500, Value: true})); err != nil {
			t.Fatal(err)
		}
		rec.find(t, "unknown cause mirror", func(a *asdu.ASDU) bool {
			return a.Type == asdu.C_SC_NA_1 && a.Cause == asdu.CauseUnknownCause && a.Negative
		})

		// None of this disturbed the connection.
		if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
			t.Errorf("Interrogate after the refusals: %v", err)
		}
	})
}

// TestClientDataTransfer: STOPDT and STARTDT against a reference station.
func TestClientDataTransfer(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		c := dial(t, srv.addr, client.WithAutoStart(false))
		ca := fx.Station.CommonAddr

		if c.State() != iec104.StateStopped {
			t.Fatalf("state %s, want stopped", c.State())
		}
		if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); !errors.Is(err, iec104.ErrNotStarted) {
			t.Errorf("Interrogate before STARTDT: %v", err)
		}
		// The link is supervised while stopped.
		if err := c.TestLink(ctx); err != nil {
			t.Errorf("TestLink while stopped: %v", err)
		}
		for round := 0; round < 3; round++ {
			if err := c.StartDT(ctx); err != nil {
				t.Fatalf("StartDT: %v", err)
			}
			srv.waitEvent(t, "data-transfer-started", func(e event) bool { return e["event"] == "data-transfer-started" })
			data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
			if err != nil || !sameObserved(observe(t, data), fx.expected(false)) {
				t.Fatalf("Interrogate in round %d: %v", round, err)
			}
			if err := c.StopDT(ctx); err != nil {
				t.Fatalf("StopDT: %v", err)
			}
			if c.State() != iec104.StateStopped {
				t.Fatalf("state %s after STOPDT", c.State())
			}
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		srv.waitEvent(t, "connection-closed", func(e event) bool { return e["event"] == "connection-closed" })
	})
}

// TestClientFlowControl runs with the smallest windows on both sides: the
// station may have one unacknowledged I frame outstanding, so every frame of
// an interrogation has to be acknowledged before the next one is sent.
func TestClientFlowControl(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		m := &frames{}
		params := apci.DefaultParams()
		params.K, params.W = 1, 1
		c := dial(t, srv.addr, client.WithParams(params), client.WithMetrics(m))
		ca := fx.Station.CommonAddr

		for i := 0; i < 5; i++ {
			data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
			if err != nil {
				t.Fatalf("Interrogate %d with k=1 w=1: %v", i, err)
			}
			if !sameObserved(observe(t, data), fx.expected(false)) {
				t.Fatalf("Interrogate %d returned other data", i)
			}
		}
		if n := m.sFrames.Load(); n < 20 {
			t.Errorf("only %d S frames sent; with w=1 every received I frame needs one", n)
		}
		// A burst of commands, each waiting for the previous acknowledgement.
		for i := 0; i < 20; i++ {
			if err := c.Command(ctx, ca, asdu.SetpointScaled{IOA: 504, Value: int16(i)}); err != nil {
				t.Fatalf("Command %d: %v", i, err)
			}
		}
	}, "--k", "1", "--w", "1")
}

// TestClientIdleTest: the timers. The station sends TESTFR after t3 and
// closes the connection if go-iec104 does not confirm within t1; go-iec104
// sends its own TESTFR and closes if the station does not confirm.
func TestClientIdleTest(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		ca := fx.Station.CommonAddr

		// go-iec104 with the idle test disabled: only the station's TESTFR.
		m := &frames{}
		params := apci.DefaultParams()
		params.T3 = 0
		c := dial(t, srv.addr, client.WithParams(params), client.WithMetrics(m))
		eventually(t, 15*time.Second, "two TESTFR act from the station, each confirmed", func() bool {
			return m.count(true, apci.TestFRAct) >= 2 && m.count(false, apci.TestFRCon) >= 2
		})
		if got := m.count(false, apci.TestFRAct); got != 0 {
			t.Errorf("go-iec104 sent %d TESTFR act with its idle test disabled", got)
		}
		if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
			t.Errorf("Interrogate after the station's idle tests: %v", err)
		}
		_ = c.Close()

		// go-iec104 with a shorter t3 than the station: its own TESTFR.
		m = &frames{}
		params = apci.Params{T1: 2 * time.Second, T2: time.Second, T3: time.Second}
		c = dial(t, srv.addr, client.WithParams(params), client.WithMetrics(m))
		eventually(t, 15*time.Second, "TESTFR con from the station", func() bool { return m.count(true, apci.TestFRCon) >= 3 })
		if c.State() != iec104.StateStarted {
			t.Errorf("state %s after go-iec104's idle tests", c.State())
		}
		if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
			t.Errorf("Interrogate after go-iec104's idle tests: %v", err)
		}
	}, "--t1", "2", "--t2", "1", "--t3", "3")
}

// TestClientReconnect: the station goes away and comes back.
func TestClientReconnect(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ctx := context.Background()
		ca := fx.Station.CommonAddr
		var lost atomic.Int64
		c := dial(t, srv.addr,
			client.WithReconnect(client.Reconnect{MinDelay: 100 * time.Millisecond, MaxDelay: time.Second}),
			client.WithStateHandler(func(s iec104.State, err error) {
				if s == iec104.StateConnecting && err != nil {
					lost.Add(1)
				}
			}))
		if err := c.Command(ctx, ca, asdu.SetpointScaled{IOA: 504, Value: 77}); err != nil {
			t.Fatal(err)
		}

		srv.restart(t)
		eventually(t, 5*time.Second, "loss of the connection", func() bool { return lost.Load() > 0 })
		eventually(t, 30*time.Second, "reconnect", func() bool { return c.State() == iec104.StateStarted })

		// The restarted station is back at the fixture: sequence numbers
		// start over and the set point from before is gone.
		data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate after reconnect: %v", err)
		}
		if got, want := observe(t, data), fx.expected(false); !sameObserved(got, want) {
			t.Errorf("after reconnect:\n got  %v\n want %v", got, want)
		}
	})
}

// TestClientConcurrentSessions: several go-iec104 clients on one station.
func TestClientConcurrentSessions(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		ca := fx.Station.CommonAddr
		const clients, rounds = 4, 10
		var wg sync.WaitGroup
		errs := make(chan error, clients)
		for i := 0; i < clients; i++ {
			c := dial(t, srv.addr)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := 0; r < rounds; r++ {
					data, err := c.Interrogate(context.Background(), ca, asdu.QOIStation)
					if err != nil {
						errs <- err
						return
					}
					if !sameObserved(observe(t, data), fx.expected(false)) {
						errs <- errors.New("interrogation returned other data")
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// TestClientGroup: a redundancy group whose paths end in two different
// implementations. Exactly one connection is started; when its station goes
// away the other takes over, and a switchover moves data transfer back.
func TestClientGroup(t *testing.T) {
	all := adapters(t)
	first, second := all[0], all[len(all)-1]
	fx := loadFixture(t, first)
	ca := fx.Station.CommonAddr
	idle := []string{"--t1", "2", "--t2", "1", "--t3", "2"}
	srvA, srvB := startServer(t, first, idle...), startServer(t, second, idle...)
	ctx := context.Background()

	// The stations run short timers, so the group must acknowledge within
	// their t1: its t2 has to be shorter.
	g, err := client.NewGroup([]string{srvA.addr, srvB.addr},
		client.WithParams(apci.Params{T1: 2 * time.Second, T2: time.Second, T3: 20 * time.Second}),
		client.WithRequestTimeout(5*time.Second),
		client.WithReconnect(client.Reconnect{MinDelay: 100 * time.Millisecond, MaxDelay: time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	clients := g.Clients()
	if g.Active() == clients[1] {
		srvA, srvB = srvB, srvA
		clients[0], clients[1] = clients[1], clients[0]
	}
	eventually(t, 10*time.Second, "standby established", func() bool { return clients[1].State() == iec104.StateStopped })

	interrogate := func(what string) {
		t.Helper()
		data, err := g.Interrogate(ctx, ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate %s: %v", what, err)
		}
		if got, want := observe(t, data), fx.expected(false); !sameObserved(got, want) {
			t.Errorf("%s:\n got  %v\n want %v", what, got, want)
		}
	}
	started := func(s *refServer) int {
		n := 0
		for _, e := range s.events(t) {
			switch e["event"] {
			case "data-transfer-started":
				n++
			case "data-transfer-stopped", "connection-closed":
				n = 0
			}
		}
		return n
	}
	interrogate("on the first path")
	// The standby is connected, supervised and not started.
	if started(srvA) != 1 || started(srvB) != 0 {
		t.Errorf("started connections: active station %d, standby station %d", started(srvA), started(srvB))
	}
	// A standby outlives the stations' idle test (t3 = 2s, t1 = 2s).
	time.Sleep(5 * time.Second)
	if clients[1].State() != iec104.StateStopped {
		t.Fatalf("standby is %s after five idle seconds", clients[1].State())
	}

	srvA.restart(t)
	eventually(t, 15*time.Second, "failover", func() bool { return g.Active() == clients[1] })
	interrogate("after failover")

	eventually(t, 30*time.Second, "first path back as standby", func() bool { return clients[0].State() == iec104.StateStopped })
	if err := g.Switchover(ctx); err != nil {
		t.Fatalf("Switchover: %v", err)
	}
	if g.Active() != clients[0] {
		t.Fatal("Switchover did not move data transfer to the standby")
	}
	interrogate("after switchover")
	srvB.waitEvent(t, "data-transfer-stopped", func(e event) bool { return e["event"] == "data-transfer-stopped" })
}
