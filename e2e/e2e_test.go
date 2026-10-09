// SPDX-License-Identifier: MIT

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
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

// recorder keeps the ASDUs a client receives.
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

func (r *recorder) all() []*asdu.ASDU {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*asdu.ASDU(nil), r.asdus...)
}

// find waits for an ASDU that satisfies match.
func (r *recorder) find(t testing.TB, what string, match func(*asdu.ASDU) bool) *asdu.ASDU {
	t.Helper()
	var found *asdu.ASDU
	testutil.Eventually(t, what, func() bool {
		for _, a := range r.all() {
			if match(a) {
				found = a
				return true
			}
		}
		return false
	})
	return found
}

// link is a station and how to reach it.
type link struct {
	st   *station.Station
	fx   *station.Fixture
	ca   asdu.CommonAddr
	opts []client.Option
}

func (l *link) dial(t testing.TB, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	all := append([]client.Option{client.WithRequestTimeout(5 * time.Second)}, l.opts...)
	c, err := client.Dial(ctx, l.st.Loopback(), append(all, opts...)...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// start serves the baseline fixture; the options apply to the station and
// to every client dialled through the link.
func start(t testing.TB, srvOpts []server.Option, cliOpts ...client.Option) *link {
	t.Helper()
	fx := station.Baseline(t)
	return &link{st: station.Start(t, fx, srvOpts...), fx: fx, ca: fx.Station.CommonAddr, opts: cliOpts}
}

// transports runs f over every way the two sides can be connected.
func transports(t *testing.T, f func(t *testing.T, l *link)) {
	t.Run("tcp", func(t *testing.T) { f(t, start(t, nil)) })
	t.Run("tls", func(t *testing.T) {
		srvTLS, cliTLS := testutil.TLSConfigs(t)
		fx := station.Baseline(t)
		f(t, &link{st: station.StartTLS(t, fx, srvTLS), fx: fx, ca: fx.Station.CommonAddr,
			opts: []client.Option{client.WithTLS(cliTLS)}})
	})
	t.Run("k=w=1", func(t *testing.T) {
		// One I frame outstanding at a time in each direction.
		p := apci.DefaultParams()
		p.K, p.W = 1, 1
		f(t, start(t, []server.Option{server.WithParams(p)}, client.WithParams(p)))
	})
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

// What the client decodes is the fixture, value by value, quality by quality.
func TestInterrogation(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		rec := &recorder{}
		c := l.dial(t, client.WithHandler(rec), client.WithOriginator(7))

		data, err := c.Interrogate(ctx, l.ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}
		if got, want := station.Observe(t, data), l.fx.Expected(false); !station.SameObserved(got, want) {
			t.Errorf("interrogation:\n got  %v\n want %v", got, want)
		}
		for _, a := range data {
			if a.Cause != asdu.CauseInterrogatedStation || a.CommonAddr != l.ca || a.Originator != 7 || a.Type.HasTimeTag() {
				t.Errorf("unexpected data ASDU %s", a)
			}
		}
		// Confirmation and termination frame the data, and reach the handler.
		all := rec.all()
		if n := len(all); n != len(data)+2 || all[0].Cause != asdu.CauseActivationCon || all[n-1].Cause != asdu.CauseActivationTerm {
			t.Errorf("handler saw %d ASDUs for %d data ASDUs: %v", n, len(data), all)
		}

		// The broadcast address is answered with the station's own.
		data, err = c.Interrogate(ctx, asdu.Broadcast, asdu.QOIStation)
		if err != nil || !station.SameObserved(station.Observe(t, data), l.fx.Expected(false)) {
			t.Errorf("Interrogate broadcast: %v", err)
		}

		counters, err := c.CounterInterrogate(ctx, l.ca, asdu.CounterGeneral, asdu.FreezeRead)
		if err != nil {
			t.Fatalf("CounterInterrogate: %v", err)
		}
		if got, want := station.Observe(t, counters), l.fx.Expected(true); !station.SameObserved(got, want) {
			t.Errorf("counter interrogation:\n got  %v\n want %v", got, want)
		}

		// What the station does not serve.
		_, err = c.Interrogate(ctx, l.ca, asdu.QOIGroup(1))
		negative(t, err, asdu.CauseActivationCon)
		_, err = c.CounterInterrogate(ctx, l.ca, asdu.CounterGeneral, asdu.FreezeResetOnly)
		negative(t, err, asdu.CauseActivationCon)
		_, err = c.Interrogate(ctx, l.ca+6, asdu.QOIStation)
		negative(t, err, asdu.CauseUnknownCommonAddr)
	})
}

func TestRead(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		c := l.dial(t)
		for _, p := range l.fx.Points {
			a, err := c.Read(ctx, l.ca, p.IOA)
			if err != nil {
				t.Fatalf("Read %d: %v", p.IOA, err)
			}
			want := station.Observed{IOA: p.IOA, Type: p.Type, Value: p.Value, Quality: station.JoinFlags(p.Quality)}
			if got := station.Observe(t, []*asdu.ASDU{a}); a.Cause != asdu.CauseRequest || len(got) != 1 || got[0] != want {
				t.Errorf("Read %d: %s %v, want %v", p.IOA, a, got, want)
			}
		}
		_, err := c.Read(ctx, l.ca, 999)
		negative(t, err, asdu.CauseUnknownIOA)
	})
}

func TestSystemCommands(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		c := l.dial(t)
		// CP56Time2a has millisecond resolution.
		when := time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)
		if err := c.ClockSync(ctx, l.ca, when); err != nil {
			t.Fatalf("ClockSync: %v", err)
		}
		if got := l.st.ClockTime(); !got.Equal(when) {
			t.Errorf("station clock set to %v, want %v", got, when)
		}
		for i := 0; i < 3; i++ {
			if err := c.TestCommand(ctx, l.ca); err != nil {
				t.Fatalf("TestCommand %d: %v", i, err)
			}
		}
		if err := c.TestLink(ctx); err != nil {
			t.Fatalf("TestLink: %v", err)
		}
		// The station serves no reset process command.
		negative(t, c.ResetProcess(ctx, l.ca, asdu.ResetProcessGeneral), asdu.CauseUnknownType)
	})
}

func TestCommands(t *testing.T) {
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
		{"set point normalized, extreme, with time", asdu.SetpointNormalized{IOA: 503, Value: -32768, Time: stamp}, 200, asdu.M_ME_TD_1, asdu.CauseReturnRemote, -32768.0},
		{"set point scaled", asdu.SetpointScaled{IOA: 504, Value: -7}, 201, asdu.M_ME_TE_1, asdu.CauseReturnRemote, -7.0},
		{"set point scaled with time", asdu.SetpointScaled{IOA: 504, Value: 32767, Time: stamp}, 201, asdu.M_ME_TE_1, asdu.CauseReturnRemote, 32767.0},
		{"set point float", asdu.SetpointFloat{IOA: 502, Value: 49.5}, 202, asdu.M_ME_TF_1, asdu.CauseReturnRemote, 49.5},
		{"set point float with time", asdu.SetpointFloat{IOA: 502, Value: -0.125, Time: stamp}, 202, asdu.M_ME_TF_1, asdu.CauseReturnRemote, -0.125},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := start(t, nil)
			ctx := context.Background()
			rec := &recorder{}
			c := l.dial(t, client.WithHandler(rec))
			sent := asdu.New(asdu.CauseActivation, l.ca, tt.command).Type
			if err := c.Command(ctx, l.ca, tt.command); err != nil {
				t.Fatalf("Command: %v", err)
			}
			// The station reports the new state of the target with a current time tag...
			rep := rec.find(t, "report of the target", func(a *asdu.ASDU) bool { return a.Type == tt.report })
			obs := station.Observe(t, []*asdu.ASDU{rep})
			if rep.Cause != tt.cause || len(obs) != 1 || obs[0].IOA != tt.target || obs[0].Value != tt.value {
				t.Errorf("report %s %v, want cause %s, object %d = %v", rep, obs, tt.cause, tt.target, tt.value)
			}
			// ...followed by the termination of the command.
			rec.find(t, "activation termination", func(a *asdu.ASDU) bool {
				return a.Type == sent && a.Cause == asdu.CauseActivationTerm
			})
			// A later read agrees, on this connection and on another.
			for _, reader := range []*client.Client{c, l.dial(t)} {
				got, err := reader.Read(ctx, l.ca, tt.target)
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
				if obs := station.Observe(t, []*asdu.ASDU{got}); len(obs) != 1 || obs[0].Value != tt.value {
					t.Errorf("read after command: %v, want %v", obs, tt.value)
				}
			}
		})
	}
}

func TestSelectBeforeOperate(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		rec := &recorder{}
		c := l.dial(t, client.WithHandler(rec))
		// Object 510 only executes after a select.
		execute := asdu.SingleCommand{IOA: 510, Value: false}
		sel := execute
		sel.Select = true

		negative(t, c.Command(ctx, l.ca, execute), asdu.CauseActivationCon)
		if err := c.Command(ctx, l.ca, sel); err != nil {
			t.Fatalf("select: %v", err)
		}
		if err := c.Command(ctx, l.ca, execute); err != nil {
			t.Fatalf("execute after select: %v", err)
		}
		rec.find(t, "report", func(a *asdu.ASDU) bool { return a.Type == asdu.M_SP_TB_1 })
		// The selection was consumed.
		negative(t, c.Command(ctx, l.ca, execute), asdu.CauseActivationCon)

		// A selection can be cancelled, after which the execute is refused.
		if err := c.Command(ctx, l.ca, sel); err != nil {
			t.Fatalf("select: %v", err)
		}
		if err := c.Deactivate(ctx, l.ca, sel); err != nil {
			t.Fatalf("deactivate: %v", err)
		}
		negative(t, c.Command(ctx, l.ca, execute), asdu.CauseActivationCon)

		// A selection made on one connection holds for another.
		if err := c.Command(ctx, l.ca, sel); err != nil {
			t.Fatalf("select: %v", err)
		}
		if err := l.dial(t).Command(ctx, l.ca, execute); err != nil {
			t.Errorf("execute on another connection: %v", err)
		}
	})
}

func TestRefusals(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		rec := &recorder{}
		c := l.dial(t, client.WithHandler(rec))

		// No such object, an object of another command type, no such station.
		negative(t, c.Command(ctx, l.ca, asdu.SingleCommand{IOA: 999, Value: true}), asdu.CauseUnknownIOA)
		negative(t, c.Command(ctx, l.ca, asdu.DoubleCommand{IOA: 500, Value: asdu.DoubleOn}), asdu.CauseUnknownIOA)
		negative(t, c.Command(ctx, l.ca+6, asdu.SingleCommand{IOA: 500, Value: true}), asdu.CauseUnknownCommonAddr)
		// A double command state the standard does not permit.
		negative(t, c.Command(ctx, l.ca, asdu.DoubleCommand{IOA: 501, Value: asdu.DoubleIndeterminate}), asdu.CauseActivationCon)
		// A step beyond the end of the range: 58 steps up from 5 reach 63.
		for i := 0; i < 58; i++ {
			if err := c.Command(ctx, l.ca, asdu.StepCommand{IOA: 505, Value: asdu.StepHigher}); err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
		}
		negative(t, c.Command(ctx, l.ca, asdu.StepCommand{IOA: 505, Value: asdu.StepHigher}), asdu.CauseActivationCon)

		// A type the station does not implement is mirrored as unknown.
		rec.reset()
		if err := c.Send(ctx, asdu.New(asdu.CauseActivation, l.ca, asdu.ParameterActivation{IOA: 1, Qualifier: 1})); err != nil {
			t.Fatal(err)
		}
		rec.find(t, "unknown type mirror", func(a *asdu.ASDU) bool {
			return a.Type == asdu.P_AC_NA_1 && a.Cause == asdu.CauseUnknownType && a.Negative
		})
		// A cause that makes no sense for a command.
		if err := c.Send(ctx, asdu.New(asdu.CauseSpontaneous, l.ca, asdu.SingleCommand{IOA: 500, Value: true})); err != nil {
			t.Fatal(err)
		}
		rec.find(t, "unknown cause mirror", func(a *asdu.ASDU) bool {
			return a.Type == asdu.C_SC_NA_1 && a.Cause == asdu.CauseUnknownCause && a.Negative
		})

		// None of this disturbed the connection or the station.
		data, err := c.Interrogate(ctx, l.ca, asdu.QOIStation)
		if err != nil {
			t.Fatalf("Interrogate after the refusals: %v", err)
		}
		for _, o := range station.Observe(t, data) {
			if o.IOA == 100 && o.Value != true {
				t.Errorf("a refused command changed point 100 to %v", o.Value)
			}
		}
	})
}

func TestFileTransfer(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		if len(l.fx.Files) == 0 {
			t.Fatal("the baseline fixture has no files")
		}
		rec := &recorder{}
		c := l.dial(t, client.WithHandler(rec))
		for _, f := range l.fx.Files {
			rec.reset()
			got, err := c.GetFile(ctx, l.ca, f.IOA, f.Name)
			if err != nil {
				t.Fatalf("GetFile %d: %v", f.IOA, err)
			}
			if !bytes.Equal(got, f.Content()) {
				t.Errorf("file %d: got %d octets that are not the %d of the fixture", f.IOA, len(got), f.Size)
			}
			sections := 0
			for _, a := range rec.all() {
				if _, ok := a.First().(asdu.SectionReady); ok {
					sections++
				}
			}
			if want := (f.Size + f.SectionSize - 1) / f.SectionSize; sections != want {
				t.Errorf("file %d: %d sections, want %d", f.IOA, sections, want)
			}
		}
		_, err := c.GetFile(ctx, l.ca, 39999, 1)
		negative(t, err, asdu.CauseUnknownIOA)
		_, err = c.GetFile(ctx, l.ca, l.fx.Files[0].IOA, l.fx.Files[0].Name+8)
		negative(t, err, asdu.CauseUnknownIOA)

		// Files and requests at the same time on one connection.
		var wg sync.WaitGroup
		for _, f := range l.fx.Files {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got, err := c.GetFile(ctx, l.ca, f.IOA, f.Name); err != nil || !bytes.Equal(got, f.Content()) {
					t.Errorf("concurrent GetFile %d: %d octets, %v", f.IOA, len(got), err)
				}
			}()
		}
		for i := 0; i < 5; i++ {
			if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); err != nil {
				t.Errorf("Interrogate during the transfers: %v", err)
			}
		}
		wg.Wait()
	})
}

// STOPDT and STARTDT: requests fail while stopped, the link stays supervised.
func TestDataTransfer(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		c := l.dial(t, client.WithAutoStart(false))
		session := func() *server.Session {
			t.Helper()
			var s *server.Session
			testutil.Eventually(t, "one session", func() bool {
				if all := l.st.Server.Sessions(); len(all) == 1 {
					s = all[0]
				}
				return s != nil
			})
			return s
		}()

		if c.State() != iec104.StateStopped || session.Started() {
			t.Fatalf("client %s, session started %v; want both stopped", c.State(), session.Started())
		}
		if _, err := c.Interrogate(ctx, l.ca, asdu.QOIStation); !errors.Is(err, iec104.ErrNotStarted) {
			t.Errorf("Interrogate before STARTDT: %v", err)
		}
		if err := session.Send(ctx, asdu.New(asdu.CauseSpontaneous, l.ca, asdu.SinglePoint{IOA: 100})); !errors.Is(err, iec104.ErrNotStarted) {
			t.Errorf("Session.Send before STARTDT: %v", err)
		}
		if err := c.TestLink(ctx); err != nil {
			t.Errorf("TestLink while stopped: %v", err)
		}
		for round := 0; round < 3; round++ {
			if err := c.StartDT(ctx); err != nil {
				t.Fatalf("StartDT: %v", err)
			}
			testutil.Eventually(t, "session started", session.Started)
			data, err := c.Interrogate(ctx, l.ca, asdu.QOIStation)
			if err != nil || !station.SameObserved(station.Observe(t, data), l.fx.Expected(false)) {
				t.Fatalf("Interrogate in round %d: %v", round, err)
			}
			if err := c.StopDT(ctx); err != nil {
				t.Fatalf("StopDT: %v", err)
			}
			if c.State() != iec104.StateStopped || session.Started() {
				t.Fatalf("after STOPDT: client %s, session started %v", c.State(), session.Started())
			}
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(t, "session gone", func() bool { return len(l.st.Server.Sessions()) == 0 })
	})
}

// An idle connection is kept alive by test frames, whichever side's t3 is
// shorter, and stays usable.
func TestIdleConnection(t *testing.T) {
	short := apci.Params{T1: 2 * time.Second, T2: 500 * time.Millisecond, T3: 300 * time.Millisecond}
	long := apci.Params{T1: 2 * time.Second, T2: 500 * time.Millisecond, T3: time.Minute}
	for _, tc := range []struct {
		name     string
		srv, cli apci.Params
	}{{"station tests", short, long}, {"client tests", long, short}, {"both test", short, short}} {
		t.Run(tc.name, func(t *testing.T) {
			tm := &testutil.Metrics{}
			l := start(t, []server.Option{server.WithParams(tc.srv)}, client.WithParams(tc.cli), client.WithMetrics(tm))
			c := l.dial(t)
			time.Sleep(1500 * time.Millisecond)
			if c.State() != iec104.StateStarted {
				t.Fatalf("state %s after idling", c.State())
			}
			if _, _, sent, received, _ := tm.Snapshot(); sent+received < 8 {
				t.Errorf("only %d frames in 1.5s with t3 = 300ms: the idle test did not run", sent+received)
			}
			if _, err := c.Interrogate(context.Background(), l.ca, asdu.QOIStation); err != nil {
				t.Errorf("Interrogate after idling: %v", err)
			}
		})
	}
}

// The station drops the connection; the client reconnects, starts data
// transfer again and runs its start handler.
func TestReconnect(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		starts := make(chan int, 8)
		c := l.dial(t,
			client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond}),
			client.WithStartHandler(func(ctx context.Context, c *client.Client) {
				data, _ := c.Interrogate(ctx, l.ca, asdu.QOIStation)
				starts <- len(station.Observe(t, data))
			}))
		want := len(l.fx.Expected(false))
		for round := 0; round < 3; round++ {
			select {
			case n := <-starts:
				if n != want {
					t.Fatalf("round %d: the start handler's interrogation returned %d objects, want %d", round, n, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("round %d: the start handler did not run", round)
			}
			if _, err := c.Read(ctx, l.ca, 100); err != nil {
				t.Fatalf("round %d: Read: %v", round, err)
			}
			for _, s := range l.st.Server.Sessions() {
				_ = s.Close()
			}
		}
	})
}

// Many controlling stations at once, each doing everything.
func TestConcurrentSessions(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		ctx := context.Background()
		const n = 8
		file := l.fx.Files[len(l.fx.Files)-1]
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			c := l.dial(t)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for round := 0; round < 3; round++ {
					data, err := c.Interrogate(ctx, l.ca, asdu.QOIStation)
					if err != nil || len(station.Observe(t, data)) != len(l.fx.Expected(false)) {
						t.Errorf("client %d: Interrogate: %v", i, err)
					}
					if a, err := c.Read(ctx, l.ca, 300); err != nil || a.Type != asdu.M_IT_NA_1 {
						t.Errorf("client %d: Read: %v", i, err)
					}
					if got, err := c.GetFile(ctx, l.ca, file.IOA, file.Name); err != nil || !bytes.Equal(got, file.Content()) {
						t.Errorf("client %d: GetFile: %v", i, err)
					}
					// Everyone writes the same set point: the last value is known.
					if err := c.Command(ctx, l.ca, asdu.SetpointScaled{IOA: 504, Value: 77}); err != nil {
						t.Errorf("client %d: Command: %v", i, err)
					}
				}
			}()
		}
		wg.Wait()
		if got := len(l.st.Server.Sessions()); got != n {
			t.Errorf("%d sessions, want %d", got, n)
		}
		a, err := l.dial(t).Read(ctx, l.ca, 201)
		if err != nil {
			t.Fatal(err)
		}
		if obs := station.Observe(t, []*asdu.ASDU{a}); len(obs) != 1 || obs[0].Value != 77.0 {
			t.Errorf("set point after %d writers: %v", n, obs)
		}
	})
}

// Events queued while no controlling station is connected arrive in order;
// what a connection did not acknowledge goes to the next one.
func TestEventQueue(t *testing.T) {
	transports(t, func(t *testing.T, l *link) {
		srv := l.st.Server
		event := func(i int) *asdu.ASDU {
			return asdu.New(asdu.CauseSpontaneous, l.ca, asdu.MeasuredScaled{IOA: 201, Value: int16(i), Time: asdu.Now()})
		}
		values := func(r *recorder) (out []int) {
			for _, a := range r.all() {
				if v, ok := a.First().(asdu.MeasuredScaled); ok && a.Cause == asdu.CauseSpontaneous {
					out = append(out, int(v.Value))
				}
			}
			return out
		}
		const n = 40
		for i := 1; i <= n; i++ {
			if err := srv.Enqueue(event(i)); err != nil {
				t.Fatal(err)
			}
		}
		if got := srv.Pending("default"); got != n {
			t.Fatalf("Pending = %d, want %d", got, n)
		}

		// A connection that is not started gets nothing.
		standby := &recorder{}
		l.dial(t, client.WithHandler(standby), client.WithAutoStart(false))
		first := &recorder{}
		c := l.dial(t, client.WithHandler(first))
		testutil.Eventually(t, "every queued event", func() bool { return len(values(first)) == n })
		for i, v := range values(first) {
			if v != i+1 {
				t.Fatalf("event %d arrived as %d: %v", i+1, v, values(first))
			}
		}
		testutil.Eventually(t, "the queue acknowledged", func() bool { return srv.Pending("default") == 0 })
		if len(values(standby)) != 0 {
			t.Errorf("the stopped connection received %d events", len(values(standby)))
		}

		// With the controlling station gone, events wait for the next one.
		_ = c.Close()
		testutil.Eventually(t, "the started session gone", func() bool { return len(srv.Sessions()) == 1 })
		for i := n + 1; i <= n+5; i++ {
			if err := srv.Enqueue(event(i)); err != nil {
				t.Fatal(err)
			}
		}
		second := &recorder{}
		l.dial(t, client.WithHandler(second))
		testutil.Eventually(t, "the later events", func() bool { return len(values(second)) == 5 })
		if got := values(second); got[0] != n+1 || got[4] != n+5 {
			t.Errorf("second controlling station got %v", got)
		}
		if d := srv.Dropped("default"); d != 0 {
			t.Errorf("%d events dropped", d)
		}
	})
}

// A client-side redundancy group over two go-iec104 stations: one
// connection started, failover when its station goes away, switchover back.
func TestRedundancyGroup(t *testing.T) {
	a, b := start(t, nil), start(t, nil)
	ctx := context.Background()
	g, err := client.NewGroup([]string{a.st.Loopback(), b.st.Loopback()},
		client.WithParams(testutil.Params()),
		client.WithRequestTimeout(5*time.Second),
		client.WithReconnect(client.Reconnect{MinDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	clients := g.Clients()
	if g.Active() == clients[1] {
		a, b = b, a
		clients[0], clients[1] = clients[1], clients[0]
	}
	started := func(l *link) int {
		n := 0
		for _, s := range l.st.Server.Sessions() {
			if s.Started() {
				n++
			}
		}
		return n
	}
	testutil.Eventually(t, "standby established", func() bool { return clients[1].State() == iec104.StateStopped })
	if started(a) != 1 || started(b) != 0 {
		t.Fatalf("started sessions: active station %d, standby station %d", started(a), started(b))
	}

	// A command through the group lands on the active station only.
	if err := g.Command(ctx, a.ca, asdu.SetpointScaled{IOA: 504, Value: 11}); err != nil {
		t.Fatalf("Command: %v", err)
	}
	if got, err := g.GetFile(ctx, a.ca, a.fx.Files[0].IOA, a.fx.Files[0].Name); err != nil || !bytes.Equal(got, a.fx.Files[0].Content()) {
		t.Errorf("GetFile through the group: %v", err)
	}
	value := func(what string) float64 {
		t.Helper()
		r, err := g.Read(ctx, a.ca, 201)
		if err != nil {
			t.Fatalf("Read %s: %v", what, err)
		}
		return station.Observe(t, []*asdu.ASDU{r})[0].Value.(float64)
	}
	if v := value("on the first path"); v != 11 {
		t.Errorf("set point on the active station = %v, want 11", v)
	}

	// The active station goes away: the standby takes over, with its own state.
	_ = a.st.Server.Close()
	testutil.Eventually(t, "failover", func() bool { return g.Active() == clients[1] })
	testutil.Eventually(t, "the second station started", func() bool { return started(b) == 1 })
	if v := value("after failover"); v != 1234 {
		t.Errorf("set point on the second station = %v, want the fixture's 1234", v)
	}
	// No standby is left: a switchover fails and changes nothing.
	if err := g.Switchover(ctx); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("Switchover without a standby: %v", err)
	}
	if v := value("after the refused switchover"); v != 1234 {
		t.Errorf("Read after the refused switchover = %v", v)
	}
}

// Server-side redundancy groups: every group has its own queue and its own
// active connection.
func TestServerRedundancyGroups(t *testing.T) {
	// Both clients come from loopback: a group cannot tell them apart by
	// address, so the test checks one group with two connections, which is
	// the redundant control centre case.
	// A short t2, so that the last events are acknowledged without waiting
	// for the window to fill.
	p := apci.DefaultParams()
	p.T2 = 200 * time.Millisecond
	l := start(t, []server.Option{server.WithRedundancyGroups(server.RedundancyGroup{Name: "scada"})}, client.WithParams(p))
	srv := l.st.Server
	ctx := context.Background()
	value := func(r *recorder) (out []int) {
		for _, a := range r.all() {
			if v, ok := a.First().(asdu.MeasuredScaled); ok && a.Cause == asdu.CauseSpontaneous {
				out = append(out, int(v.Value))
			}
		}
		return out
	}
	enqueue := func(i int) {
		t.Helper()
		if err := srv.Enqueue(asdu.New(asdu.CauseSpontaneous, l.ca, asdu.MeasuredScaled{IOA: 201, Value: int16(i)})); err != nil {
			t.Fatal(err)
		}
	}
	ra, rb := &recorder{}, &recorder{}
	ca := l.dial(t, client.WithHandler(ra))
	cb := l.dial(t, client.WithHandler(rb), client.WithAutoStart(false))
	for _, s := range srv.Sessions() {
		if s.Group() != "scada" {
			t.Errorf("session in group %q", s.Group())
		}
	}
	enqueue(1)
	testutil.Eventually(t, "event 1 on the started connection", func() bool { return fmt.Sprint(value(ra)) == "[1]" })

	// The control centre switches over: STOPDT on one path, STARTDT on the other.
	if err := ca.StopDT(ctx); err != nil {
		t.Fatal(err)
	}
	enqueue(2)
	if err := cb.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	enqueue(3)
	testutil.Eventually(t, "events 2 and 3 on the new path", func() bool { return fmt.Sprint(value(rb)) == "[2 3]" })
	if got := value(ra); fmt.Sprint(got) != "[1]" {
		t.Errorf("the stopped path received %v", got)
	}
	testutil.Eventually(t, "queue acknowledged", func() bool { return srv.Pending("scada") == 0 })
}

// The IEC 60870-5-101 field sizes on both sides: one-octet cause (no
// originator), one-octet common address, two-octet object address.
func TestNarrowParameters(t *testing.T) {
	p := asdu.Params{CauseSize: 1, CommonAddrSize: 1, IOASize: 2}
	l := start(t, []server.Option{server.WithASDUParams(p)}, client.WithASDUParams(p))
	ctx := context.Background()
	c := l.dial(t)
	data, err := c.Interrogate(ctx, l.ca, asdu.QOIStation)
	if err != nil || !station.SameObserved(station.Observe(t, data), l.fx.Expected(false)) {
		t.Fatalf("Interrogate: %v", err)
	}
	if err := c.Command(ctx, l.ca, asdu.SetpointFloat{IOA: 502, Value: 1.5, Time: asdu.Now()}); err != nil {
		t.Fatalf("Command: %v", err)
	}
	f := l.fx.Files[0]
	if got, err := c.GetFile(ctx, l.ca, f.IOA, f.Name); err != nil || !bytes.Equal(got, f.Content()) {
		t.Errorf("GetFile: %v", err)
	}
	// An address that does not fit two octets never leaves the client.
	if _, err := c.Read(ctx, l.ca, 70000); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("Read of an address beyond two octets: %v", err)
	}
	// A client with other field sizes cannot talk to this station.
	other, err := client.Dial(ctx, l.st.Loopback(), client.WithRequestTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if _, err := other.Interrogate(ctx, l.ca, asdu.QOIStation); err == nil {
		t.Error("an interrogation with three-octet addresses was answered by a station with two-octet ones")
	}
}
