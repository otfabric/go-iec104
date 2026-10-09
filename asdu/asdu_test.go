// SPDX-License-Identifier: MIT

package asdu

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ts is 2026-10-09 15:35:12.345 UTC, a Friday.
var (
	ts     = time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)
	tsCP56 = []byte{0x39, 0x30, 0x23, 0x0F, 0xA9, 0x0A, 0x1A}
	tsCP24 = []byte{0x39, 0x30, 0x23}
)

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestVectors(t *testing.T) {
	tests := []struct {
		name string
		asdu *ASDU
		wire []byte
	}{
		{"station interrogation",
			New(CauseActivation, 1, Interrogation{Qualifier: QOIStation}),
			[]byte{0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14}},
		{"single point",
			New(CauseSpontaneous, 1, SinglePoint{IOA: 100, Value: true}),
			[]byte{0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01}},
		{"single point invalid with originator, negative, test",
			&ASDU{Type: M_SP_NA_1, Cause: CauseSpontaneous, Negative: true, Test: true, Originator: 7, CommonAddr: 0x1234,
				Objects: []InformationObject{SinglePoint{IOA: 0x030201, Quality: QualityInvalid | QualityBlocked}}},
			[]byte{0x01, 0x01, 0xC3, 0x07, 0x34, 0x12, 0x01, 0x02, 0x03, 0x90}},
		{"float sequence",
			&ASDU{Type: M_ME_NC_1, Sequence: true, Cause: CauseInterrogatedStation, CommonAddr: 1,
				Objects: []InformationObject{
					MeasuredFloat{IOA: 4001, Value: 1},
					MeasuredFloat{IOA: 4002, Value: -2.5, Quality: QualityOverflow},
				}},
			[]byte{0x0D, 0x82, 0x14, 0x00, 0x01, 0x00, 0xA1, 0x0F, 0x00,
				0x00, 0x00, 0x80, 0x3F, 0x00,
				0x00, 0x00, 0x20, 0xC0, 0x01}},
		{"double point CP56",
			New(CauseSpontaneous, 2, DoublePoint{IOA: 5, Value: DoubleOn, Time: At(ts)}),
			cat([]byte{0x1F, 0x01, 0x03, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x02}, tsCP56)},
		{"scaled CP24",
			&ASDU{Type: M_ME_TB_1, Cause: CauseSpontaneous, CommonAddr: 1,
				Objects: []InformationObject{MeasuredScaled{IOA: 9, Value: -2, Quality: QualityNotTopical,
					Time: Timestamp{Time: time.Date(1, 1, 1, 0, 35, 12, 345e6, time.UTC)}}}},
			cat([]byte{0x0C, 0x01, 0x03, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0xFE, 0xFF, 0x40}, tsCP24)},
		{"single command select long pulse",
			New(CauseActivation, 1, SingleCommand{IOA: 6001, Value: true, Qualifier: QualifierLongPulse, Select: true}),
			[]byte{0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, 0x71, 0x17, 0x00, 0x89}},
		{"clock sync",
			New(CauseActivation, 1, ClockSync{Time: At(ts)}),
			cat([]byte{0x67, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, tsCP56)},
		{"counter interrogation",
			New(CauseActivation, 1, CounterInterrogation{Request: CounterGeneral, Freeze: FreezeWithReset}),
			[]byte{0x65, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x85}},
		{"integrated total",
			New(CauseCounterGeneral, 1, IntegratedTotal{IOA: 1, Value: -1, Sequence: 3, Carry: true, Invalid: true}),
			[]byte{0x0F, 0x01, 0x25, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xA3}},
		{"step position",
			New(CauseSpontaneous, 1, StepPosition{IOA: 1, Value: -64, Transient: true}),
			[]byte{0x05, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xC0, 0x00}},
		{"end of initialization",
			New(CauseInitialized, 1, EndOfInitialization{Cause: InitRemoteReset, LocalChange: true}),
			[]byte{0x46, 0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x82}},
		{"read",
			New(CauseRequest, 1, Read{IOA: 0x112233}),
			[]byte{0x66, 0x01, 0x05, 0x00, 0x01, 0x00, 0x33, 0x22, 0x11}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.asdu.Encode(IEC104)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if !bytes.Equal(got, tt.wire) {
				t.Fatalf("wire = % X\nwant   % X", got, tt.wire)
			}
			back, err := Decode(tt.wire, IEC104)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !reflect.DeepEqual(back, tt.asdu) {
				t.Fatalf("decoded %+v\nwant    %+v", back, tt.asdu)
			}
		})
	}
}

// samples returns one representative object per kind.
func samples(tag Timestamp) []InformationObject {
	q := QualityInvalid | QualitySubstituted
	return []InformationObject{
		SinglePoint{IOA: 1, Value: true, Quality: q, Time: tag},
		DoublePoint{IOA: 2, Value: DoubleIndeterminate, Quality: q, Time: tag},
		StepPosition{IOA: 3, Value: 63, Quality: q | QualityOverflow, Time: tag},
		Bitstring32{IOA: 4, Value: 0xDEADBEEF, Quality: q, Time: tag},
		MeasuredNormalized{IOA: 5, Value: -32768, Quality: q, Time: tag},
		MeasuredScaled{IOA: 6, Value: 32767, Quality: q, Time: tag},
		MeasuredFloat{IOA: 7, Value: 3.5, Quality: q, Time: tag},
		IntegratedTotal{IOA: 8, Value: math.MinInt32, Sequence: 31, Adjusted: true, Time: tag},
		ProtectionEvent{IOA: 9, State: DoubleOn, Quality: QualityElapsedInvalid | QualityInvalid, Elapsed: 1234, Time: tag},
		ProtectionStart{IOA: 10, Events: StartGeneral | StartL2 | StartReverse, Quality: QualityBlocked, Duration: 500, Time: tag},
		ProtectionOutput{IOA: 11, Circuits: OutputGeneral | OutputL3, Quality: QualityNotTopical, Operating: 65535, Time: tag},
		SingleCommand{IOA: 12, Value: true, Qualifier: 31, Select: true, Time: tag},
		DoubleCommand{IOA: 13, Value: DoubleOff, Qualifier: QualifierShortPulse, Time: tag},
		StepCommand{IOA: 14, Value: StepHigher, Qualifier: QualifierPersistent, Select: true, Time: tag},
		SetpointNormalized{IOA: 15, Value: 16384, Qualifier: 127, Select: true, Time: tag},
		SetpointScaled{IOA: 16, Value: -1, Qualifier: 1, Time: tag},
		SetpointFloat{IOA: 17, Value: -0.25, Select: true, Time: tag},
		BitstringCommand{IOA: 18, Value: 0x01020304, Time: tag},
		TestCommand{IOA: 0, Counter: 0x1234, Time: tag},
	}
}

// untagged are the kinds that exist in one form only.
func untagged() []InformationObject {
	return []InformationObject{
		PackedSinglePoints{IOA: 20, Status: 0xA5A5, Changed: 0x00FF, Quality: QualityOverflow},
		EndOfInitialization{Cause: InitLocalReset},
		Interrogation{Qualifier: QOIGroup(16)},
		CounterInterrogation{Request: CounterGroup4, Freeze: FreezeResetOnly},
		Read{IOA: 0xFFFFFF},
		ResetProcess{Qualifier: ResetPendingEvents},
		DelayAcquisition{Delay: 4711},
		ParameterNormalized{IOA: 21, Value: 100, Qualifier: ParameterThreshold | ParameterChange},
		ParameterScaled{IOA: 22, Value: -100, Qualifier: ParameterHighLimit},
		ParameterFloat{IOA: 23, Value: 1e6, Qualifier: ParameterSmoothing | ParameterNotInOperation},
		ParameterActivation{IOA: 24, Qualifier: ActivateCyclic},
	}
}

func roundTrip(t *testing.T, a *ASDU, p Params) {
	t.Helper()
	wire, err := a.Encode(p)
	if err != nil {
		t.Fatalf("%s: Encode: %v", a, err)
	}
	back, err := Decode(wire, p)
	if err != nil {
		t.Fatalf("%s: Decode: %v", a, err)
	}
	if !reflect.DeepEqual(back, a) {
		t.Fatalf("%s: decoded %+v\nwant %+v", a.Type, back.Objects, a.Objects)
	}
	d := registry[a.Type]
	if want := p.headerSize() + len(a.Objects)*(p.IOASize+d.size+d.tag.size()); len(wire) != want {
		t.Fatalf("%s: %d octets on the wire, registry says %d", a.Type, len(wire), want)
	}
}

func TestRoundTripAllTypes(t *testing.T) {
	seen := map[TypeID]bool{}
	run := func(objs []InformationObject) {
		for _, obj := range objs {
			a := New(CauseSpontaneous, 0x0102, obj, obj)
			if seen[a.Type] {
				t.Errorf("TypeOf(%T) = %s chosen twice", obj, a.Type)
			}
			seen[a.Type] = true
			roundTrip(t, a, IEC104)
		}
	}
	var plain []InformationObject
	for _, obj := range samples(Timestamp{}) {
		// Protection events exist with a time tag only.
		if defaultTypes[obj.kind()][0] != 0 {
			plain = append(plain, obj)
		}
	}
	run(plain)
	run(samples(Timestamp{Time: ts, Invalid: true, Substituted: true, SummerTime: true}))
	run(untagged())
	run([]InformationObject{ClockSync{Time: At(ts)}})

	// The CP24Time2a variants and M_ME_ND_1 are never picked by TypeOf.
	cp24 := Timestamp{Time: time.Date(1, 1, 1, 0, 59, 59, 999e6, time.UTC), Invalid: true}
	explicit := map[TypeID]InformationObject{M_ME_ND_1: MeasuredNormalized{IOA: 5, Value: 77}}
	for _, obj := range samples(cp24) {
		for id, d := range registry {
			if d != nil && d.kind == obj.kind() && d.tag == tagCP24 {
				explicit[TypeID(id)] = obj
			}
		}
	}
	for id, obj := range explicit {
		seen[id] = true
		roundTrip(t, &ASDU{Type: id, Cause: CauseSpontaneous, CommonAddr: 1, Objects: []InformationObject{obj}}, IEC104)
	}

	for id, d := range registry {
		if d != nil && !seen[TypeID(id)] {
			t.Errorf("%s has no round-trip coverage", d.name)
		}
	}
}

func TestTypeOf(t *testing.T) {
	tests := []struct {
		obj  InformationObject
		want TypeID
	}{
		{SinglePoint{}, M_SP_NA_1},
		{SinglePoint{Time: At(ts)}, M_SP_TB_1},
		{MeasuredNormalized{}, M_ME_NA_1},
		{MeasuredFloat{Time: At(ts)}, M_ME_TF_1},
		{ProtectionEvent{}, M_EP_TD_1},
		{ProtectionStart{Time: At(ts)}, M_EP_TE_1},
		{ProtectionOutput{}, M_EP_TF_1},
		{SetpointFloat{}, C_SE_NC_1},
		{SetpointFloat{Time: At(ts)}, C_SE_TC_1},
		{ClockSync{}, C_CS_NA_1},
		{TestCommand{}, C_TS_NA_1},
		{TestCommand{Time: At(ts)}, C_TS_TA_1},
		{PackedSinglePoints{}, M_PS_NA_1},
	}
	for _, tt := range tests {
		if got := TypeOf(tt.obj); got != tt.want {
			t.Errorf("TypeOf(%T) = %s, want %s", tt.obj, got, tt.want)
		}
	}
	if New(CauseSpontaneous, 1).Type != 0 {
		t.Error("New without objects should leave Type zero")
	}
}

func TestSequenceEncoding(t *testing.T) {
	a := &ASDU{Type: M_SP_NA_1, Sequence: true, Cause: CauseInterrogatedStation, CommonAddr: 1}
	for i := 0; i < MaxObjects; i++ {
		a.Objects = append(a.Objects, SinglePoint{IOA: IOA(1000 + i), Value: i%2 == 0})
	}
	wire, err := a.Encode(IEC104)
	if err != nil {
		t.Fatal(err)
	}
	if want := 6 + 3 + MaxObjects; len(wire) != want {
		t.Fatalf("len = %d, want %d", len(wire), want)
	}
	back, err := Decode(wire, IEC104)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, a) {
		t.Fatal("sequence round trip mismatch")
	}

	a.Objects[5] = SinglePoint{IOA: 9999}
	if _, err := a.Encode(IEC104); !errors.Is(err, ErrNotSequential) {
		t.Errorf("gap in sequence: %v, want ErrNotSequential", err)
	}
}

func TestEncodeErrors(t *testing.T) {
	many := make([]InformationObject, MaxObjects+1)
	for i := range many {
		many[i] = SinglePoint{IOA: IOA(i)}
	}
	big := make([]InformationObject, 30)
	for i := range big {
		big[i] = MeasuredFloat{IOA: IOA(i), Time: At(ts)}
	}
	tests := []struct {
		name string
		a    *ASDU
		p    Params
		want error
	}{
		{"too many objects", New(CauseSpontaneous, 1, many...), IEC104, ErrInvalidValue},
		{"too long", New(CauseSpontaneous, 1, big...), IEC104, ErrTooLong},
		{"type mismatch", &ASDU{Type: M_DP_NA_1, Objects: []InformationObject{SinglePoint{}}}, IEC104, ErrTypeMismatch},
		{"nil object", &ASDU{Type: M_DP_NA_1, Objects: []InformationObject{nil}}, IEC104, ErrTypeMismatch},
		{"unsupported type", &ASDU{Type: 200, Objects: []InformationObject{SinglePoint{}}}, IEC104, ErrUnsupportedType},
		{"cause", &ASDU{Type: M_SP_NA_1, Cause: 64}, IEC104, ErrInvalidValue},
		{"negative raw count", &ASDU{Type: 200, Raw: []byte{1}, RawCount: -1}, IEC104, ErrInvalidValue},
		{"ioa too wide", New(CauseSpontaneous, 1, SinglePoint{IOA: 1 << 24}), IEC104, ErrInvalidValue},
		{"ioa too wide for 2 octets", New(CauseSpontaneous, 1, SinglePoint{IOA: 1 << 16}),
			Params{CauseSize: 1, CommonAddrSize: 1, IOASize: 2}, ErrInvalidValue},
		{"common address too wide", New(CauseSpontaneous, 256, SinglePoint{}),
			Params{CauseSize: 1, CommonAddrSize: 1, IOASize: 2}, ErrInvalidValue},
		{"bad params", New(CauseSpontaneous, 1, SinglePoint{}), Params{}, ErrInvalidParams},
		{"double state", New(CauseSpontaneous, 1, DoublePoint{Value: 4}), IEC104, ErrInvalidValue},
		{"step position high", New(CauseSpontaneous, 1, StepPosition{Value: 64}), IEC104, ErrInvalidValue},
		{"step position low", New(CauseSpontaneous, 1, StepPosition{Value: -65}), IEC104, ErrInvalidValue},
		{"counter sequence", New(CauseSpontaneous, 1, IntegratedTotal{Sequence: 32}), IEC104, ErrInvalidValue},
		{"event state", New(CauseSpontaneous, 1, ProtectionEvent{State: 4}), IEC104, ErrInvalidValue},
		{"command qualifier", New(CauseActivation, 1, SingleCommand{Qualifier: 32}), IEC104, ErrInvalidValue},
		{"double command state", New(CauseActivation, 1, DoubleCommand{Value: 4}), IEC104, ErrInvalidValue},
		{"double command qualifier", New(CauseActivation, 1, DoubleCommand{Qualifier: 32}), IEC104, ErrInvalidValue},
		{"step command state", New(CauseActivation, 1, StepCommand{Value: 4}), IEC104, ErrInvalidValue},
		{"setpoint qualifier", New(CauseActivation, 1, SetpointScaled{Qualifier: 128}), IEC104, ErrInvalidValue},
		{"setpoint normalized qualifier", New(CauseActivation, 1, SetpointNormalized{Qualifier: 128}), IEC104, ErrInvalidValue},
		{"setpoint float qualifier", New(CauseActivation, 1, SetpointFloat{Qualifier: 128}), IEC104, ErrInvalidValue},
		{"cause of initialization", New(CauseInitialized, 1, EndOfInitialization{Cause: 128}), IEC104, ErrInvalidValue},
		{"counter request", New(CauseActivation, 1, CounterInterrogation{Request: 64}), IEC104, ErrInvalidValue},
		{"counter freeze", New(CauseActivation, 1, CounterInterrogation{Freeze: 4}), IEC104, ErrInvalidValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := []byte{0xAA}
			out, err := tt.a.AppendEncode(prefix, tt.p)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if !bytes.Equal(out, prefix) {
				t.Errorf("failed encode left % X in the buffer", out)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		p    Params
		want error
	}{
		{"empty", nil, IEC104, ErrMalformed},
		{"short header", []byte{0x01, 0x01, 0x03, 0x00, 0x01}, IEC104, ErrMalformed},
		{"truncated object", []byte{0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00}, IEC104, ErrMalformed},
		{"trailing octets", []byte{0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01, 0x00}, IEC104, ErrMalformed},
		{"count mismatch", []byte{0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01}, IEC104, ErrMalformed},
		{"sequence mismatch", []byte{0x01, 0x82, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01}, IEC104, ErrMalformed},
		{"too long", make([]byte, 250), IEC104, ErrTooLong},
		{"sequence past the address range", []byte{0x01, 0x82, 0x03, 0x00, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0x01, 0x00}, IEC104, ErrMalformed},
		{"bad params", []byte{1, 2, 3}, Params{CauseSize: 3, CommonAddrSize: 2, IOASize: 3}, ErrInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.wire, tt.p); !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRawTypes(t *testing.T) {
	wire := []byte{0x7D, 0x01, 0x0D, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	a, err := Decode(wire, IEC104)
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != F_SG_NA_1 || a.Objects != nil || a.RawCount != 1 || a.Len() != 1 ||
		!bytes.Equal(a.Raw, wire[6:]) || a.First() != nil {
		t.Fatalf("raw decode: %+v", a)
	}
	if a.Type.Supported() || a.Type.String() != "F_SG_NA_1" || a.Type.Description() != "Segment" {
		t.Errorf("type metadata: %s %q", a.Type, a.Type.Description())
	}
	wire[6] = 0 // Decode must not alias its input
	if a.Raw[0] != 0xAA {
		t.Error("Raw aliases the input")
	}
	wire[6] = 0xAA
	back, err := a.Reply(CauseUnknownType, true).Encode(IEC104)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), wire...)
	want[2] = 0x40 | byte(CauseUnknownType)
	if !bytes.Equal(back, want) {
		t.Errorf("mirror = % X, want % X", back, want)
	}

	// Private type with no objects at all.
	b, err := (&ASDU{Type: 200, Cause: CauseSpontaneous, CommonAddr: 1}).Encode(IEC104)
	if err != nil || !bytes.Equal(b, []byte{200, 0, 3, 0, 1, 0}) {
		t.Errorf("empty private ASDU: % X, %v", b, err)
	}
}

func TestIEC101Layout(t *testing.T) {
	p := Params{CauseSize: 1, CommonAddrSize: 1, IOASize: 2}
	a := New(CauseSpontaneous, 5, MeasuredScaled{IOA: 0x1234, Value: 10})
	wire, err := a.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x0B, 0x01, 0x03, 0x05, 0x34, 0x12, 0x0A, 0x00, 0x00}; !bytes.Equal(wire, want) {
		t.Fatalf("wire = % X, want % X", wire, want)
	}
	roundTrip(t, a, p)
	roundTrip(t, New(CauseSpontaneous, 5, SinglePoint{IOA: 0xFF, Value: true}), Params{CauseSize: 2, CommonAddrSize: 2, IOASize: 1})

	if !p.IsBroadcast(0xFF) || p.IsBroadcast(0xFFFF) || !IEC104.IsBroadcast(Broadcast) || IEC104.IsBroadcast(0xFF) {
		t.Error("IsBroadcast")
	}
	for _, bad := range []Params{
		{CauseSize: 0, CommonAddrSize: 1, IOASize: 1}, {CauseSize: 1, CommonAddrSize: 3, IOASize: 1},
		{CauseSize: 1, CommonAddrSize: 1, IOASize: 4}, {CauseSize: 1, CommonAddrSize: 1, IOASize: 1, MaxSize: -1},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalidParams) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestTimestamps(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	p := IEC104.In(cet)
	a := New(CauseSpontaneous, 1, SinglePoint{IOA: 1, Time: At(ts)})
	wire, err := a.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if wire[13] != 16 {
		t.Errorf("hour on the wire = %d, want 16 (local time)", wire[13])
	}
	back, err := Decode(wire, p)
	if err != nil {
		t.Fatal(err)
	}
	got := back.Objects[0].(SinglePoint).Time
	if !got.Equal(ts) || got.Location() != cet {
		t.Errorf("decoded %v, want %v in CET", got, ts)
	}

	// Sunday is day of week 7, not 0.
	sunday := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	b := appendCP56(nil, At(sunday), time.UTC)
	if b[4]>>5 != 7 || b[4]&0x1F != 11 {
		t.Errorf("day octet = 0x%02X", b[4])
	}

	// Two-digit year pivot.
	for yy, want := range map[byte]int{0: 2000, 69: 2069, 70: 1970, 99: 1999} {
		got := parseCP56([]byte{0, 0, 0, 0, 1, 1, yy}, time.UTC)
		if got.Year() != want {
			t.Errorf("year %d decoded as %d, want %d", yy, got.Year(), want)
		}
	}

	// A zero time under a CP56Time2a type goes out flagged invalid.
	wire, err = (&ASDU{Type: M_SP_TB_1, Cause: CauseSpontaneous, CommonAddr: 1,
		Objects: []InformationObject{SinglePoint{IOA: 1}}}).Encode(IEC104)
	if err != nil {
		t.Fatal(err)
	}
	back, _ = Decode(wire, IEC104)
	if got := back.Objects[0].(SinglePoint).Time; !got.Invalid {
		t.Errorf("zero time decoded as %+v, want Invalid", got)
	}

	// Dates that do not exist decode to the zero time, flagged invalid.
	for _, bad := range [][]byte{
		{0x60, 0xEA, 0, 0, 1, 1, 26}, // 60000 ms
		{0, 0, 60, 0, 1, 1, 26},      // minute 60
		{0, 0, 0, 24, 1, 1, 26},      // hour 24
		{0, 0, 0, 0, 0, 1, 26},       // day 0
		{0, 0, 0, 0, 30, 2, 26},      // 30 February
		{0, 0, 0, 0, 1, 0, 26},       // month 0
		{0, 0, 0, 0, 1, 13, 26},      // month 13
		{0, 0, 0, 0, 1, 1, 100},      // year 100
	} {
		if got := parseCP56(bad, time.UTC); !got.IsZero() || !got.Invalid {
			t.Errorf("% X decoded as %+v, want zero and Invalid", bad, got)
		}
	}
	if got := parseCP24([]byte{0x60, 0xEA, 0}, time.UTC); !got.Invalid {
		t.Errorf("CP24 with 60000 ms not flagged invalid: %+v", got)
	}

	if n := Now(); n.IsZero() || n.Invalid {
		t.Error("Now")
	}
}

func TestElements(t *testing.T) {
	if !QualityGood.Good() || QualityInvalid.Good() {
		t.Error("Good")
	}
	q := QualityInvalid | QualityNotTopical
	if !q.Has(QualityInvalid) || q.Has(QualityBlocked) || q.Has(QualityInvalid|QualityBlocked) {
		t.Error("Has")
	}
	for q, want := range map[Quality]string{
		0: "good", QualityInvalid | QualityNotTopical: "NT|IV",
		QualityOverflow | QualityElapsedInvalid | QualityBlocked | QualitySubstituted: "OV|EI|BL|SB", 0x02: "0x02",
	} {
		if got := q.String(); got != want {
			t.Errorf("Quality(%#x).String() = %q, want %q", uint8(q), got, want)
		}
	}
	for s, want := range map[DoubleState]string{
		DoubleIntermediate: "intermediate", DoubleOff: "off", DoubleOn: "on",
		DoubleIndeterminate: "indeterminate", 9: "DoubleState(9)",
	} {
		if s.String() != want {
			t.Errorf("DoubleState %d = %q", s, s.String())
		}
	}
	for f, want := range map[float64]Normalized{0: 0, 0.5: 16384, -1: -32768, 1: 32767, 2: 32767, -2: -32768, math.NaN(): 0} {
		if got := NormalizedFromFloat(f); got != want {
			t.Errorf("NormalizedFromFloat(%v) = %d, want %d", f, got, want)
		}
	}
	if Normalized(-32768).Float64() != -1 || Normalized(16384).Float64() != 0.5 {
		t.Error("Normalized.Float64")
	}
	if QOIGroup(3) != 23 || QOIGroup(3).Cause() != CauseInterrogatedGroup1+2 {
		t.Error("QOIGroup")
	}
	if (CounterInterrogation{Request: CounterGeneral}).Cause() != CauseCounterGeneral ||
		(CounterInterrogation{Request: 2}).Cause() != CauseCounterGroup1+1 {
		t.Error("CounterInterrogation.Cause")
	}
	for i := int8(-64); i < 64; i++ {
		if got := vti(byte(i) & 0x7F); got != i {
			t.Fatalf("vti(%d) = %d", i, got)
		}
		if i == 63 {
			break
		}
	}
}

func TestMetadata(t *testing.T) {
	if M_ME_NC_1.String() != "M_ME_NC_1" || M_ME_TF_1.Description() != "Measured value, short floating point with CP56Time2a" {
		t.Errorf("%s / %q", M_ME_NC_1, M_ME_TF_1.Description())
	}
	if TypeID(250).String() != "TypeID(250)" || TypeID(250).Description() != "" || !TypeID(250).IsPrivate() || M_SP_NA_1.IsPrivate() {
		t.Error("unknown type metadata")
	}
	if !M_SP_TB_1.HasTimeTag() || M_SP_NA_1.HasTimeTag() || !C_CS_NA_1.HasTimeTag() || TypeID(250).HasTimeTag() {
		t.Error("HasTimeTag")
	}
	if !C_SC_NA_1.InControlDirection() || !C_IC_NA_1.InControlDirection() || !P_AC_NA_1.InControlDirection() ||
		M_EI_NA_1.InControlDirection() || M_SP_NA_1.InControlDirection() || F_SG_NA_1.InControlDirection() {
		t.Error("InControlDirection")
	}
	if !C_BO_TA_1.IsProcessCommand() || C_IC_NA_1.IsProcessCommand() {
		t.Error("IsProcessCommand")
	}
	for c, want := range map[Cause]string{
		CauseSpontaneous: "spontaneous", CauseInterrogatedStation: "interrogated-station",
		CauseInterrogatedGroup1 + 4: "interrogated-group-5", CauseCounterGroup4: "counter-group-4",
		CauseUnknownIOA: "unknown-ioa", 60: "Cause(60)",
	} {
		if c.String() != want {
			t.Errorf("Cause %d = %q, want %q", c, c.String(), want)
		}
	}
	if !CauseUnknownType.IsUnknown() || !CauseUnknownIOA.IsUnknown() || CauseActivationCon.IsUnknown() {
		t.Error("IsUnknown")
	}
	a := &ASDU{Type: C_SC_NA_1, Sequence: true, Cause: CauseActivationCon, Negative: true, Test: true, Originator: 3,
		CommonAddr: 7, Objects: []InformationObject{SingleCommand{IOA: 1}}}
	if got, want := a.String(), "C_SC_NA_1 activation-con ca=7 n=1 oa=3 negative test sq"; got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
	r := a.Reply(CauseActivationTerm, false)
	if r.Cause != CauseActivationTerm || r.Negative || a.Cause != CauseActivationCon || !a.Negative {
		t.Error("Reply must copy")
	}
	if !strings.Contains((&ASDU{Type: 130, Raw: []byte{1}, RawCount: 4}).String(), "n=4") {
		t.Error("String of raw ASDU")
	}
}

func FuzzDecode(f *testing.F) {
	for _, obj := range append(append(samples(Timestamp{}), samples(At(ts))...), untagged()...) {
		b, err := New(CauseSpontaneous, 1, obj).Encode(IEC104)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0x0D, 0x82, 0x14, 0x00, 0x01, 0x00, 0xA1, 0x0F, 0x00, 0, 0, 0x80, 0x3F, 0, 0, 0, 0x20, 0xC0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Decode(b, IEC104)
		if err != nil {
			return
		}
		// What decodes must encode, and the encoding must be a fixed point:
		// reserved bits are dropped on the first pass and nothing after.
		first, err := a.Encode(IEC104)
		if err != nil {
			t.Fatalf("re-encode of %s: %v", a, err)
		}
		if len(first) != len(b) {
			t.Fatalf("re-encode changed the length: %d != %d", len(first), len(b))
		}
		a2, err := Decode(first, IEC104)
		if err != nil {
			t.Fatalf("decode of re-encoded %s: %v", a, err)
		}
		second, err := a2.Encode(IEC104)
		if err != nil {
			t.Fatalf("second encode: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("not a fixed point:\n% X\n% X", first, second)
		}
	})
}

func BenchmarkEncode(b *testing.B) {
	a := &ASDU{Type: M_ME_NC_1, Cause: CauseSpontaneous, CommonAddr: 1}
	for i := 0; i < 20; i++ {
		a.Objects = append(a.Objects, MeasuredFloat{IOA: IOA(i), Value: float32(i)})
	}
	buf := make([]byte, 0, 249)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := a.AppendEncode(buf[:0], IEC104); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	a := &ASDU{Type: M_ME_TF_1, Cause: CauseSpontaneous, CommonAddr: 1}
	for i := 0; i < 15; i++ {
		a.Objects = append(a.Objects, MeasuredFloat{IOA: IOA(i), Value: float32(i), Time: At(ts)})
	}
	wire, err := a.Encode(IEC104)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(wire, IEC104); err != nil {
			b.Fatal(err)
		}
	}
}
