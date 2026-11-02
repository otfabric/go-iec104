//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
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
	"github.com/otfabric/go-iec104/internal/station"
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

// count returns how many recorded ASDUs satisfy match.
func (r *recorder) count(match func(*asdu.ASDU) bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, a := range r.asdus {
		if match(a) {
			n++
		}
	}
	return n
}

func anyASDU(*asdu.ASDU) bool { return true }

func spontaneous(a *asdu.ASDU) bool { return a.Cause == asdu.CauseSpontaneous }

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
		if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
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
		if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
			t.Errorf("broadcast interrogation:\n got  %v\n want %v", got, want)
		}

		totals, err := c.CounterInterrogate(ctx, ca, asdu.CounterGeneral, asdu.FreezeRead)
		if err != nil {
			t.Fatalf("CounterInterrogate: %v", err)
		}
		if got, want := station.Observe(t, totals), fx.Expected(true); !station.SameObserved(got, want) {
			t.Errorf("counter interrogation:\n got  %v\n want %v", got, want)
		}
		if seq := totals[0].Objects[0].(asdu.IntegratedTotal).Sequence; seq != fx.Point(300).Sequence {
			t.Errorf("counter sequence number %d, want %d", seq, fx.Point(300).Sequence)
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

		if a.knownReadBug(t) {
			if _, err := c.Read(ctx, ca, fx.Points[0].IOA); err == nil {
				t.Errorf("known bug of %s did not reproduce: the read was answered", a.name)
			}
			t.Skipf("known bug of %s: it closes the connection on a read command", a.name)
		}
		for _, p := range fx.Points {
			got, err := c.Read(ctx, ca, p.IOA)
			if err != nil {
				t.Errorf("Read %d: %v", p.IOA, err)
				continue
			}
			want := station.Observed{IOA: p.IOA, Type: p.Type, Value: p.Value, Quality: station.JoinFlags(p.Quality)}
			if obs := station.Observe(t, []*asdu.ASDU{got}); len(obs) != 1 || obs[0] != want || got.Cause != asdu.CauseRequest {
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
				if sent.HasTimeTag() {
					a.need(t, featTimeTaggedCommands)
				}

				if err := c.Command(ctx, ca, tt.command); err != nil {
					t.Fatalf("Command: %v", err)
				}
				// The station reports the new state of the target, time tagged.
				rep := rec.find(t, "report of the target", func(a *asdu.ASDU) bool { return a.Type == tt.report })
				obs := station.Observe(t, []*asdu.ASDU{rep})
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
				if a.knownReadBug(t) {
					t.Logf("not read back: %s closes the connection on a read command", a.name)
					return
				}
				got, err := c.Read(ctx, ca, tt.target)
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
				if obs := station.Observe(t, []*asdu.ASDU{got}); len(obs) != 1 || obs[0].Value != tt.value {
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

// TestClientFileTransfer: go-iec104 downloads the files of a reference
// station and gets the content the fixture defines.
func TestClientFileTransfer(t *testing.T) {
	forEachServer(t, func(t *testing.T, a adapter, fx *fixture, srv *refServer) {
		a.need(t, featFileServer)
		if len(fx.Files) == 0 {
			t.Fatalf("%s declares a file server but its fixture has no files", a.name)
		}
		ctx := context.Background()
		rec := &recorder{}
		c := dial(t, srv.addr, client.WithHandler(rec))
		ca := fx.Station.CommonAddr

		for _, f := range fx.Files {
			rec.reset()
			got, err := c.GetFile(ctx, ca, f.IOA, f.Name)
			if err != nil {
				t.Fatalf("GetFile %d: %v", f.IOA, err)
			}
			if !bytes.Equal(got, f.Content()) {
				t.Errorf("file %d: got %d octets that are not the %d of the fixture", f.IOA, len(got), f.Size)
			}
			// The station announced the sections the fixture describes.
			sections := 0
			rec.mu.Lock()
			for _, a := range rec.asdus {
				if _, ok := a.First().(asdu.SectionReady); ok {
					sections++
				}
			}
			rec.mu.Unlock()
			if want := (f.Size + f.SectionSize - 1) / f.SectionSize; sections != want {
				t.Errorf("file %d: %d sections, want %d", f.IOA, sections, want)
			}
			// ...and saw its file acknowledged.
			srv.waitEvent(t, "file-transfer", func(e event) bool {
				return e["event"] == "file-transfer" && e["ioa"] == float64(f.IOA) && e["success"] == true
			})
		}

		// A file the station does not have, and a known file under another name.
		_, err := c.GetFile(ctx, ca, 39999, 1)
		negative(t, err, asdu.CauseUnknownIOA)
		_, err = c.GetFile(ctx, ca, fx.Files[0].IOA, fx.Files[0].Name+8)
		negative(t, err, asdu.CauseUnknownIOA)

		// The connection is as usable as before.
		if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
			t.Errorf("Interrogate after the transfers: %v", err)
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
			if a.has(t, featDataTransferEvents) {
				srv.waitEvent(t, "data-transfer-started", func(e event) bool { return e["event"] == "data-transfer-started" })
			}
			data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
			if err != nil || !station.SameObserved(station.Observe(t, data), fx.Expected(false)) {
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
			if !station.SameObserved(station.Observe(t, data), fx.Expected(false)) {
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
		if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
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
					if !station.SameObserved(station.Observe(t, data), fx.Expected(false)) {
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
	// The test counts the stations' STARTDT and STOPDT events.
	var all []adapter
	for _, a := range adapters(t) {
		if a.has(t, featDataTransferEvents) {
			all = append(all, a)
		}
	}
	if len(all) == 0 {
		skipNoReference(t, "no reference reports data transfer events")
	}
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
		if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
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

// startExtended runs the reference server of a with the fixture extended.
func startExtended(t *testing.T, a adapter, extra ...string) (*fixture, *refServer) {
	t.Helper()
	return loadExtended(t, a), startServer(t, a, append(append([]string{}, extendedFlags...), extra...)...)
}

// TestClientGroups: go-iec104 interrogates the groups of a reference station.
func TestClientGroups(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx, srv := startExtended(t, a)
		ctx := context.Background()
		c := dial(t, srv.addr)
		ca := fx.Station.CommonAddr

		for _, group := range []int{1, 2, 3, 16} {
			want := fx.ExpectedGroup(group)
			if len(want) == 0 {
				t.Fatalf("fixture extended has no point in group %d", group)
			}
			data, err := c.Interrogate(ctx, ca, asdu.QOIGroup(group))
			if err != nil {
				t.Fatalf("Interrogate group %d: %v", group, err)
			}
			if got := station.Observe(t, data); !station.SameObserved(got, want) {
				t.Errorf("group %d:\n got  %v\n want %v", group, got, want)
			}
			for _, d := range data {
				if d.Cause != asdu.Cause(20+group) || d.CommonAddr != ca || d.Negative || d.Test {
					t.Errorf("group %d: unexpected header: %s", group, d)
				}
			}
			qoi := float64(20 + group)
			srv.waitEvent(t, "interrogation", func(e event) bool {
				return e["event"] == "interrogation" && e["qoi"] == qoi && e["accepted"] == true
			})
		}

		// The station interrogation still has every point but the counter.
		data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}
		if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
			t.Errorf("interrogation:\n got  %v\n want %v", got, want)
		}

		data, err = c.Interrogate(ctx, asdu.Broadcast, asdu.QOIGroup(1))
		if err != nil {
			t.Fatalf("Interrogate group 1 (broadcast): %v", err)
		}
		if got, want := station.Observe(t, data), fx.ExpectedGroup(1); !station.SameObserved(got, want) {
			t.Errorf("broadcast:\n got  %v\n want %v", got, want)
		}

		// A group without points, and a station that does not exist.
		if len(fx.ExpectedGroup(10)) != 0 {
			t.Fatal("fixture extended has a point in group 10")
		}
		_, err = c.Interrogate(ctx, ca, asdu.QOIGroup(10))
		negative(t, err, asdu.CauseActivationCon)
		_, err = c.Interrogate(ctx, ca+6, asdu.QOIGroup(1))
		negative(t, err, asdu.CauseUnknownCommonAddr)
	}, extendedFeatures...)
}

// TestClientBitstringQuality: go-iec104 decodes the value and the quality of
// M_BO_NA_1 from a reference station, flag by flag.
func TestClientBitstringQuality(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx, srv := startExtended(t, a)
		ctx := context.Background()
		c := dial(t, srv.addr)
		ca := fx.Station.CommonAddr

		var want []station.Observed
		for _, o := range fx.Expected(false) {
			if o.Type == "M_BO_NA_1" {
				want = append(want, o)
			}
		}
		if len(want) != 3 || want[0].Quality != "" || want[1].Quality != "OV IV" || want[2].Quality != "BL SB NT" {
			t.Fatalf("fixture extended changed: %v", want)
		}
		data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}
		var got []station.Observed
		for _, d := range data {
			if d.Type == asdu.M_BO_NA_1 {
				got = append(got, station.Observe(t, []*asdu.ASDU{d})...)
			}
		}
		if !station.SameObserved(got, want) {
			t.Errorf("interrogation:\n got  %v\n want %v", got, want)
		}

		if a.knownReadBug(t) {
			t.Log("not reading: a station of this stack closes the connection on a read")
			return
		}
		for _, w := range want {
			d, err := c.Read(ctx, ca, w.IOA)
			if err != nil {
				t.Fatalf("Read %d: %v", w.IOA, err)
			}
			if got := station.Observe(t, []*asdu.ASDU{d}); len(got) != 1 || got[0] != w {
				t.Errorf("read %d: got %v, want %v", w.IOA, got, w)
			}
		}
	}, featBitstringQ)
}

// sectionsOf splits content into sections of the given size.
func sectionsOf(content []byte, size int) [][]byte {
	var out [][]byte
	for len(content) > size {
		out = append(out, content[:size])
		content = content[size:]
	}
	return append(out, content)
}

// TestClientUpload: go-iec104 sends a file to a reference station. The event of
// the station says what arrived, and it can be fetched again and is in the
// directory where the station can do that.
func TestClientUpload(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx, srv := startExtended(t, a)
		ctx := context.Background()
		c := dial(t, srv.addr)
		ca := fx.Station.CommonAddr
		if len(fx.Uploads) == 0 {
			t.Fatal("fixture extended has no uploads")
		}
		up := fx.Uploads[0]

		// A second upload to the same address replaces the first.
		for _, size := range []int{1000, 5000, up.MaxSize} {
			content := fileContent(up.IOA, size)
			if err := c.PutFile(ctx, ca, up.IOA, up.Name, sectionsOf(content, 2048)...); err != nil {
				t.Fatalf("PutFile of %d octets: %v", size, err)
			}
			hash := fileHash(up.IOA, size)
			srv.waitEvent(t, "file-received", func(e event) bool {
				return e["event"] == "file-received" && e["ioa"] == float64(up.IOA) && e["name"] == float64(up.Name) &&
					e["length"] == float64(size) && e["sha256"] == hash && e["success"] == true
			})
			if a.has(t, featFileServer) {
				got, err := c.GetFile(ctx, ca, up.IOA, up.Name)
				if err != nil {
					t.Fatalf("GetFile of the file sent: %v", err)
				}
				if !bytes.Equal(got, content) {
					t.Errorf("the file reads back as %d octets that are not the %d sent", len(got), size)
				}
			}
		}
		if a.has(t, featDirectoryServer) {
			entries, err := c.ListFiles(ctx, ca, 0)
			if err != nil {
				t.Fatalf("ListFiles: %v", err)
			}
			last := entries[len(entries)-1]
			if last.IOA != up.IOA || last.Name != up.Name || int(last.Length) != up.MaxSize ||
				last.Status != asdu.FileLastOfDirectory {
				t.Errorf("last entry of the directory: %+v, want the file sent", last)
			}
		}

		// Refusals: a place that is not one, another name, too long, a file
		// that can only be fetched.
		received := func() int {
			n := 0
			for _, e := range srv.events(t) {
				if e["event"] == "file-received" {
					n++
				}
			}
			return n
		}
		before := received()
		for _, r := range []struct {
			name string
			ioa  asdu.IOA
			nof  uint16
			size int
		}{
			{"unknown address", 39999, up.Name, 1000},
			{"wrong name", up.IOA, up.Name + 8, 1000},
			{"too large", up.IOA, up.Name, up.MaxSize + 1},
			{"read-only file", fx.Files[0].IOA, fx.Files[0].Name, 1000},
		} {
			err := c.PutFile(ctx, ca, r.ioa, r.nof, sectionsOf(fileContent(r.ioa, r.size), 2048)...)
			t.Run(r.name, func(t *testing.T) { negative(t, err, asdu.CauseUnknownIOA) })
		}
		if got := received(); got != before {
			t.Errorf("%d file-received events after the refusals, want %d", got, before)
		}

		// The connection is as usable as before.
		if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
			t.Errorf("Interrogate after the transfers: %v", err)
		}
	}, append([]string{featUploadServer}, extendedFeatures...)...)
}

// TestClientDirectory: go-iec104 lists the files of a reference station.
func TestClientDirectory(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		for _, tt := range []struct {
			name  string
			fx    func() *fixture
			flags []string
			needs []string
		}{
			{"baseline", func() *fixture { return loadFixture(t, a) }, nil, nil},
			{"extended", func() *fixture { return loadExtended(t, a) }, extendedFlags, extendedFeatures},
		} {
			t.Run(tt.name, func(t *testing.T) {
				a.need(t, tt.needs...)
				fx := tt.fx()
				srv := startServer(t, a, tt.flags...)
				c := dial(t, srv.addr)
				entries, err := c.ListFiles(context.Background(), fx.Station.CommonAddr, 0)
				if err != nil {
					t.Fatalf("ListFiles: %v", err)
				}
				if len(entries) != len(fx.Files) {
					t.Fatalf("%d entries, want %d: %+v", len(entries), len(fx.Files), entries)
				}
				for i, f := range fx.Files {
					e := entries[i]
					var status uint8
					if i == len(fx.Files)-1 {
						status = asdu.FileLastOfDirectory
					}
					if e.IOA != f.IOA || e.Name != f.Name || int(e.Length) != f.Size || e.Status != status {
						t.Errorf("entry %d: %+v, want file %d, name %d, %d octets, status %#x",
							i, e, f.IOA, f.Name, f.Size, status)
					}
				}
			})
		}
	}, featDirectoryServer)
}

// settle is how long a test watches a connection on which nothing may arrive.
const settle = 500 * time.Millisecond

// redundancyEvent checks the event a redundancy group queued: the single point
// with the lowest address, with the value it had, without time tag.
func redundancyEvent(t *testing.T, fx *fixture, ev *asdu.ASDU, value bool) {
	t.Helper()
	sp, ok := ev.First().(asdu.SinglePoint)
	if !ok || ev.Type != asdu.M_SP_NA_1 || len(ev.Objects) != 1 || ev.Originator != 0 || ev.CommonAddr != fx.Station.CommonAddr {
		t.Fatalf("queued event: %s", ev)
	}
	if want := fx.Expected(false)[0]; sp.IOA != want.IOA || sp.Value != value || sp.Quality != 0 {
		t.Errorf("queued event: %+v, want point %d = %v, quality good", sp, want.IOA, value)
	}
}

// TestClientRedundancy: two go-iec104 clients against a reference station in a
// redundancy group, switching over with STOPDT and by taking over. What happens
// to the connection taken over is left to the stack, closed or open: the test
// holds only that nothing arrives on it.
func TestClientRedundancy(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		t.Run("stopdt", func(t *testing.T) {
			fx, srv := startExtended(t, a, "--redundancy-group")
			srv.waitEvent(t, "ready", func(e event) bool { return e["event"] == "ready" && e["redundancyGroup"] == true })
			ca := fx.Station.CommonAddr
			first, second := &recorder{}, &recorder{}
			primary := dial(t, srv.addr, client.WithHandler(first))
			standby := dial(t, srv.addr, client.WithHandler(second), client.WithAutoStart(false))

			data, err := primary.Interrogate(ctx, ca, asdu.QOIStation)
			if err != nil {
				t.Fatalf("Interrogate on the primary: %v", err)
			}
			if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
				t.Errorf("primary:\n got  %v\n want %v", got, want)
			}
			// The event carries the state of the station.
			if err := primary.Command(ctx, ca, asdu.SingleCommand{IOA: 500, Value: false}); err != nil {
				t.Fatalf("Command: %v", err)
			}
			if err := primary.StopDT(ctx); err != nil {
				t.Fatalf("StopDT: %v", err)
			}
			seen := first.count(anyASDU)
			if n := second.count(anyASDU); n != 0 {
				t.Errorf("%d ASDUs on the standby before its STARTDT", n)
			}

			if err := standby.StartDT(ctx); err != nil {
				t.Fatalf("StartDT: %v", err)
			}
			redundancyEvent(t, fx, second.find(t, "the queued event", spontaneous), false)
			data, err = standby.Interrogate(ctx, ca, asdu.QOIStation)
			if err != nil {
				t.Fatalf("Interrogate on the standby: %v", err)
			}
			want := fx.Expected(false)
			want[0].Value = false
			if got := station.Observe(t, data); !station.SameObserved(got, want) {
				t.Errorf("standby:\n got  %v\n want %v", got, want)
			}
			time.Sleep(settle)
			if n := second.count(spontaneous); n != 1 {
				t.Errorf("%d events on the standby, want 1", n)
			}
			if n := first.count(anyASDU); n != seen {
				t.Errorf("%d ASDUs on the primary after its STOPDT", n-seen)
			}
			// A connection in STOPDT stays up, whatever the other one does.
			if st := primary.State(); st != iec104.StateStopped {
				t.Errorf("the primary is %v, want it up and stopped", st)
			}
		})
		t.Run("takeover", func(t *testing.T) {
			fx, srv := startExtended(t, a, "--redundancy-group")
			ca := fx.Station.CommonAddr
			first, second, third := &recorder{}, &recorder{}, &recorder{}
			primary := dial(t, srv.addr, client.WithHandler(first))
			standby := dial(t, srv.addr, client.WithHandler(second), client.WithAutoStart(false))
			if _, err := primary.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
				t.Fatalf("Interrogate on the primary: %v", err)
			}
			seen := first.count(anyASDU)

			if err := standby.StartDT(ctx); err != nil {
				t.Fatalf("StartDT: %v", err)
			}
			data, err := standby.Interrogate(ctx, ca, asdu.QOIStation)
			if err != nil {
				t.Fatalf("Interrogate on the standby: %v", err)
			}
			if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
				t.Errorf("standby:\n got  %v\n want %v", got, want)
			}
			time.Sleep(settle)
			if n := second.count(spontaneous); n != 0 {
				t.Errorf("%d events on the standby: a takeover queues nothing", n)
			}

			// Asking on the old connection gets no answer, by whatever means.
			short, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if _, err := primary.Interrogate(short, ca, asdu.QOIStation); err == nil {
				t.Error("an interrogation on the connection taken over was answered")
			}

			// The queue does not go back to it: the event of this STOPDT goes
			// to the next connection that starts.
			if err := standby.StopDT(ctx); err != nil {
				t.Fatalf("StopDT: %v", err)
			}
			time.Sleep(settle)
			if n := first.count(anyASDU); n != seen {
				t.Errorf("%d ASDUs on the connection taken over", n-seen)
			}
			next := dial(t, srv.addr, client.WithHandler(third), client.WithAutoStart(false))
			if err := next.StartDT(ctx); err != nil {
				t.Fatalf("StartDT on a third connection: %v", err)
			}
			redundancyEvent(t, fx, third.find(t, "the queued event", spontaneous), true)
		})
		t.Run("no group", func(t *testing.T) {
			// Without the flag every connection is on its own: no queue, and
			// both can be started.
			fx, srv := startExtended(t, a)
			ca := fx.Station.CommonAddr
			rec := &recorder{}
			primary := dial(t, srv.addr)
			other := dial(t, srv.addr, client.WithHandler(rec), client.WithAutoStart(false))
			if err := primary.StopDT(ctx); err != nil {
				t.Fatalf("StopDT: %v", err)
			}
			if err := other.StartDT(ctx); err != nil {
				t.Fatalf("StartDT: %v", err)
			}
			time.Sleep(settle)
			if n := rec.count(anyASDU); n != 0 {
				t.Errorf("%d ASDUs without a group", n)
			}
			if err := primary.StartDT(ctx); err != nil {
				t.Fatalf("StartDT again: %v", err)
			}
			for _, c := range []*client.Client{primary, other} {
				if _, err := c.Interrogate(ctx, ca, asdu.QOIStation); err != nil {
					t.Errorf("Interrogate: %v", err)
				}
			}
		})
	}, append([]string{featRedundServer}, extendedFeatures...)...)
}
