// SPDX-License-Identifier: MIT

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// echo is a station that sends every ASDU it receives straight back. What
// the controlling station sends therefore crosses the wire twice, encoded
// and decoded once by each side: the client's encoder against the server's
// decoder on the way out, the server's encoder against the client's decoder
// on the way back.
type echo struct {
	mu   sync.Mutex
	seen []*asdu.ASDU
	keep bool
}

func (e *echo) HandleASDU(s *server.Session, a *asdu.ASDU) {
	if e.keep {
		e.mu.Lock()
		e.seen = append(e.seen, a)
		e.mu.Unlock()
	}
	_ = s.Send(s.Context(), a)
}

func (e *echo) received() []*asdu.ASDU {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*asdu.ASDU(nil), e.seen...)
}

// serve runs a server with h on loopback and returns it with its address.
func serve(t testing.TB, h server.Handler, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(h, opts...)
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

func connect(t testing.TB, addr string, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, append([]client.Option{client.WithRequestTimeout(5 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var stamp = time.Date(2026, 2, 28, 23, 59, 59, 999e6, time.UTC)

// tagged are the kinds that exist with and without a time tag, every field
// set to something other than its zero value.
func tagged(tag asdu.Timestamp) []asdu.InformationObject {
	q := asdu.QualityInvalid | asdu.QualitySubstituted
	return []asdu.InformationObject{
		asdu.SinglePoint{IOA: 1, Value: true, Quality: q, Time: tag},
		asdu.DoublePoint{IOA: 2, Value: asdu.DoubleIndeterminate, Quality: q, Time: tag},
		asdu.StepPosition{IOA: 3, Value: -64, Transient: true, Quality: q | asdu.QualityOverflow, Time: tag},
		asdu.Bitstring32{IOA: 4, Value: 0xDEADBEEF, Quality: q, Time: tag},
		asdu.MeasuredNormalized{IOA: 5, Value: -32768, Quality: q, Time: tag},
		asdu.MeasuredScaled{IOA: 6, Value: 32767, Quality: q, Time: tag},
		asdu.MeasuredFloat{IOA: 7, Value: 3.5, Quality: q, Time: tag},
		asdu.IntegratedTotal{IOA: 8, Value: math.MinInt32, Sequence: 31, Carry: true, Adjusted: true, Invalid: true, Time: tag},
		asdu.ProtectionEvent{IOA: 9, State: asdu.DoubleOn, Quality: asdu.QualityElapsedInvalid | asdu.QualityInvalid, Elapsed: 1234, Time: tag},
		asdu.ProtectionStart{IOA: 10, Events: asdu.StartGeneral | asdu.StartL2 | asdu.StartReverse, Quality: asdu.QualityBlocked, Duration: 500, Time: tag},
		asdu.ProtectionOutput{IOA: 11, Circuits: asdu.OutputGeneral | asdu.OutputL3, Quality: asdu.QualityNotTopical, Operating: 65535, Time: tag},
		asdu.SingleCommand{IOA: 12, Value: true, Qualifier: 31, Select: true, Time: tag},
		asdu.DoubleCommand{IOA: 13, Value: asdu.DoubleOff, Qualifier: asdu.QualifierShortPulse, Time: tag},
		asdu.StepCommand{IOA: 14, Value: asdu.StepHigher, Qualifier: asdu.QualifierPersistent, Select: true, Time: tag},
		asdu.SetpointNormalized{IOA: 15, Value: 16384, Qualifier: 127, Select: true, Time: tag},
		asdu.SetpointScaled{IOA: 16, Value: -1, Qualifier: 1, Time: tag},
		asdu.SetpointFloat{IOA: 17, Value: -0.25, Select: true, Time: tag},
		asdu.BitstringCommand{IOA: 18, Value: 0x01020304, Time: tag},
		asdu.TestCommand{IOA: 0, Counter: 0x1234, Time: tag},
	}
}

// untagged are the kinds that exist in one form only.
func untagged() []asdu.InformationObject {
	return []asdu.InformationObject{
		asdu.PackedSinglePoints{IOA: 20, Status: 0xA5A5, Changed: 0x00FF, Quality: asdu.QualityOverflow},
		asdu.EndOfInitialization{Cause: asdu.InitLocalReset},
		asdu.Interrogation{Qualifier: asdu.QOIGroup(16)},
		asdu.CounterInterrogation{Request: asdu.CounterGroup4, Freeze: asdu.FreezeResetOnly},
		asdu.Read{IOA: 0xFFFFFF},
		asdu.ResetProcess{Qualifier: asdu.ResetPendingEvents},
		asdu.DelayAcquisition{Delay: 4711},
		asdu.ParameterNormalized{IOA: 21, Value: 100, Qualifier: asdu.ParameterThreshold | asdu.ParameterChange},
		asdu.ParameterScaled{IOA: 22, Value: -100, Qualifier: asdu.ParameterHighLimit},
		asdu.ParameterFloat{IOA: 23, Value: 1e6, Qualifier: asdu.ParameterSmoothing | asdu.ParameterNotInOperation},
		asdu.ParameterActivation{IOA: 24, Qualifier: asdu.ActivateCyclic},
		asdu.FileReady{IOA: 30, Name: 0x1234, Length: asdu.MaxFileLength, Qualifier: asdu.FileNegative | 1},
		asdu.SectionReady{IOA: 31, Name: 1, Section: 2, Length: 4096, Qualifier: asdu.FileNegative},
		asdu.FileCall{IOA: 32, Name: 1, Section: 2, Qualifier: asdu.SectionRequest},
		asdu.FileLastSegment{IOA: 33, Name: 1, Section: 2, Qualifier: asdu.LastSectionNoDeactivation, Checksum: 0xA5},
		asdu.FileAck{IOA: 34, Name: 1, Section: 2, Qualifier: asdu.AckSectionPositive},
		asdu.ClockSync{Time: asdu.At(stamp)},
		asdu.FileDirectoryEntry{IOA: 40, Name: 7, Length: 1000, Status: asdu.FileLastOfDirectory | 3, Time: asdu.At(stamp)},
		asdu.FileQueryLog{IOA: 41, Name: 7, Start: asdu.At(stamp.Add(-time.Hour)), Stop: asdu.At(stamp)},
		asdu.FileSegment{IOA: 50, Name: 7, Section: 1, Data: bytes.Repeat([]byte{0x5A}, asdu.MaxSegmentLength)},
		asdu.FileSegment{IOA: 51, Name: 7, Section: 1, Data: []byte{1}},
	}
}

// messages builds every ASDU of the matrix: each type identification the
// codec models, in the variants the wire format distinguishes.
func messages(t *testing.T) []*asdu.ASDU {
	t.Helper()
	var out []*asdu.ASDU
	flags := 0
	add := func(a *asdu.ASDU) {
		// Spread the header variants over the matrix.
		flags++
		a.Originator = uint8(flags)
		a.Test = flags%3 == 0
		a.Negative = flags%5 == 0
		out = append(out, a)
	}
	plain := func(obj asdu.InformationObject) {
		add(asdu.New(asdu.CauseSpontaneous, 0x0102, obj))
	}
	for _, obj := range tagged(asdu.Timestamp{}) {
		if asdu.TypeOf(obj).HasTimeTag() {
			continue // protection events and the test command have no untagged form
		}
		plain(obj)
		// Two objects, with addresses apart (SQ = 0).
		add(asdu.New(asdu.CauseBackground, 65534, obj, obj))
	}
	full := asdu.Timestamp{Time: stamp, Invalid: true, Substituted: true, SummerTime: true}
	for _, obj := range tagged(full) {
		plain(obj)
	}
	for _, obj := range tagged(asdu.At(stamp)) {
		add(asdu.New(asdu.CauseReturnRemote, 1, obj, obj, obj))
	}
	for _, obj := range untagged() {
		plain(obj)
	}

	// The CP24Time2a variants and M_ME_ND_1 are chosen explicitly.
	cp24 := asdu.Timestamp{Time: time.Date(1, 1, 1, 0, 59, 59, 999e6, time.UTC), Invalid: true}
	samples := tagged(cp24)
	for id, i := range map[asdu.TypeID]int{
		asdu.M_SP_TA_1: 0, asdu.M_DP_TA_1: 1, asdu.M_ST_TA_1: 2, asdu.M_BO_TA_1: 3, asdu.M_ME_TA_1: 4, asdu.M_ME_TB_1: 5,
		asdu.M_ME_TC_1: 6, asdu.M_IT_TA_1: 7, asdu.M_EP_TA_1: 8, asdu.M_EP_TB_1: 9, asdu.M_EP_TC_1: 10,
	} {
		add(&asdu.ASDU{Type: id, Cause: asdu.CauseSpontaneous, CommonAddr: 1, Objects: []asdu.InformationObject{samples[i]}})
	}
	add(&asdu.ASDU{Type: asdu.M_ME_ND_1, Cause: asdu.CausePeriodic, CommonAddr: 1,
		Objects: []asdu.InformationObject{asdu.MeasuredNormalized{IOA: 5, Value: 77}}})

	// Sequences of elements (SQ = 1): one address, consecutive objects.
	seq := func(n int, at func(i int) asdu.InformationObject) {
		a := asdu.New(asdu.CauseInterrogatedStation, 1)
		for i := 0; i < n; i++ {
			a.Objects = append(a.Objects, at(i))
		}
		a.Type, a.Sequence = asdu.TypeOf(a.Objects[0]), true
		add(a)
	}
	seq(127, func(i int) asdu.InformationObject { return asdu.SinglePoint{IOA: asdu.IOA(1000 + i), Value: i%2 == 0} })
	seq(48, func(i int) asdu.InformationObject {
		return asdu.MeasuredFloat{IOA: asdu.IOA(0xFFFF00 + i), Value: float32(i) / 8}
	})
	seq(20, func(i int) asdu.InformationObject {
		return asdu.MeasuredScaled{IOA: asdu.IOA(70000 + i), Value: int16(-i), Time: asdu.At(stamp.Add(time.Duration(i) * time.Millisecond))}
	})
	seq(8, func(i int) asdu.InformationObject {
		return asdu.FileDirectoryEntry{IOA: asdu.IOA(300 + i), Name: uint16(i), Length: uint32(i) * 1000, Time: asdu.At(stamp)}
	})
	// As many objects as an APDU holds without a sequence.
	big := asdu.New(asdu.CauseInterrogatedStation, 1)
	for i := 0; i < 60; i++ {
		big.Objects = append(big.Objects, asdu.SinglePoint{IOA: asdu.IOA(i * 7919), Value: i%3 == 0})
	}
	big.Type = asdu.TypeOf(big.Objects[0])
	add(big)

	// Types the codec does not model travel as raw payload: the private
	// range and a reserved type.
	add(&asdu.ASDU{Type: 200, Cause: asdu.CauseSpontaneous, CommonAddr: 9, Raw: []byte{1, 2, 3, 4, 5, 6, 7}, RawCount: 1})
	add(&asdu.ASDU{Type: 255, Cause: asdu.CauseActivation, CommonAddr: 9, Sequence: true, Raw: bytes.Repeat([]byte{0xEE}, 243), RawCount: 127})
	add(&asdu.ASDU{Type: 41, Cause: asdu.CauseSpontaneous, CommonAddr: 9, Raw: []byte{0xAB}, RawCount: 3})
	return out
}

// Every type identification, in both directions, through both codecs and
// both protocol machines.
func TestWireMatrix(t *testing.T) {
	msgs := messages(t)
	covered := map[asdu.TypeID]bool{}
	for _, m := range msgs {
		covered[m.Type] = true
	}
	for id := 0; id < 256; id++ {
		if asdu.TypeID(id).Supported() && !covered[asdu.TypeID(id)] {
			t.Errorf("%s is not in the matrix", asdu.TypeID(id))
		}
	}

	for _, tc := range []struct {
		name string
		p    apci.Params
	}{{"default windows", apci.DefaultParams()}, {"k=w=1", func() apci.Params { p := apci.DefaultParams(); p.K, p.W = 1, 1; return p }()}} {
		t.Run(tc.name, func(t *testing.T) {
			station := &echo{keep: true}
			_, addr := serve(t, station, server.WithParams(tc.p))
			rec := &recorder{}
			c := connect(t, addr, client.WithHandler(rec), client.WithParams(tc.p))
			ctx := context.Background()
			for _, m := range msgs {
				if err := c.Send(ctx, m); err != nil {
					t.Fatalf("Send %s: %v", m, err)
				}
			}
			testutil.Eventually(t, "every ASDU back", func() bool { return len(rec.all()) == len(msgs) })
			there, back := station.received(), rec.all()
			for i, want := range msgs {
				if !reflect.DeepEqual(there[i], want) {
					t.Errorf("%s as the station decoded it:\n got  %+v\n want %+v", want.Type, there[i], want)
				}
				if !reflect.DeepEqual(back[i], want) {
					t.Errorf("%s as the client decoded the echo:\n got  %+v\n want %+v", want.Type, back[i], want)
				}
			}
		})
	}
}

// The field sizes of IEC 60870-5-101 and a time zone other than UTC, on
// both sides.
func TestWireMatrixOtherParameters(t *testing.T) {
	zone := time.FixedZone("plant", 5*3600+1800)
	for _, p := range []asdu.Params{
		{CauseSize: 1, CommonAddrSize: 1, IOASize: 1},
		{CauseSize: 1, CommonAddrSize: 2, IOASize: 2},
		{CauseSize: 2, CommonAddrSize: 1, IOASize: 3},
		{CauseSize: 2, CommonAddrSize: 2, IOASize: 3, Location: zone},
	} {
		t.Run(fmt.Sprintf("cot%d ca%d ioa%d", p.CauseSize, p.CommonAddrSize, p.IOASize), func(t *testing.T) {
			station := &echo{keep: true}
			_, addr := serve(t, station, server.WithASDUParams(p))
			rec := &recorder{}
			c := connect(t, addr, client.WithHandler(rec), client.WithASDUParams(p))
			ctx := context.Background()
			var sent []*asdu.ASDU
			for _, m := range messages(t) {
				// Keep what fits the field sizes.
				if p.CauseSize == 1 {
					m.Originator = 0
				}
				if p.CommonAddrSize == 1 {
					m.CommonAddr = m.CommonAddr%254 + 1
				}
				if _, err := m.Encode(p); err != nil {
					continue
				}
				if p.Location != nil {
					relocate(m, p.Location)
				}
				sent = append(sent, m)
				if err := c.Send(ctx, m); err != nil {
					t.Fatalf("Send %s: %v", m, err)
				}
			}
			if len(sent) < 30 {
				t.Fatalf("only %d ASDUs fit these parameters", len(sent))
			}
			testutil.Eventually(t, "every ASDU back", func() bool { return len(rec.all()) == len(sent) })
			there, back := station.received(), rec.all()
			for i, want := range sent {
				if !reflect.DeepEqual(there[i], want) || !reflect.DeepEqual(back[i], want) {
					t.Errorf("%s:\n station %+v\n client  %+v\n want    %+v", want.Type, there[i], back[i], want)
				}
			}
		})
	}
}

// relocate moves the time tags of a into loc, which is where a decoder with
// that location puts them.
func relocate(a *asdu.ASDU, loc *time.Location) {
	for i, obj := range a.Objects {
		v := reflect.New(reflect.TypeOf(obj)).Elem()
		v.Set(reflect.ValueOf(obj))
		for j := 0; j < v.NumField(); j++ {
			ts, ok := v.Field(j).Interface().(asdu.Timestamp)
			if !ok || ts.IsZero() {
				continue
			}
			wall := ts.In(loc)
			if ts.Year() > 1 {
				ts.Time = wall
			} else {
				// Only minute, second and millisecond are on the wire.
				ts.Time = time.Date(1, 1, 1, 0, wall.Minute(), wall.Second(), wall.Nanosecond(), loc)
			}
			v.Field(j).Set(reflect.ValueOf(ts))
		}
		a.Objects[i] = v.Interface().(asdu.InformationObject)
	}
}

// More I frames in each direction than the 15-bit sequence numbers count:
// both protocol machines wrap around, under continuous acknowledgement.
func TestSequenceNumberWrap(t *testing.T) {
	if testing.Short() {
		t.Skip("sends 40000 ASDUs")
	}
	const n = 40000
	var got, bad int
	var mu sync.Mutex
	done := make(chan struct{})
	h := client.HandlerFunc(func(a *asdu.ASDU) {
		mu.Lock()
		defer mu.Unlock()
		if v, ok := a.First().(asdu.Bitstring32); !ok || int(v.Value) != got {
			bad++
		}
		if got++; got == n {
			close(done)
		}
	})
	_, addr := serve(t, &echo{})
	c := connect(t, addr, client.WithHandler(h))
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if err := c.Send(ctx, asdu.New(asdu.CauseSpontaneous, 1, asdu.Bitstring32{IOA: 1, Value: uint32(i)})); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("%d of %d ASDUs came back", got, n)
	}
	if bad != 0 {
		t.Errorf("%d ASDUs out of order or changed", bad)
	}
	if _, err := c.Interrogate(ctx, 1, asdu.QOIStation); err == nil {
		// The echo mirrors the activation: not an answer, but the link works.
		t.Log("interrogation after the wrap answered")
	}
	if err := c.TestLink(ctx); err != nil {
		t.Errorf("TestLink after %d frames: %v", n, err)
	}
}
