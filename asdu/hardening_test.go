// SPDX-License-Identifier: MIT

package asdu

import (
	"errors"
	"math"
	"testing"
	"time"
)

// The conversions gosec flagged (G115) are masked or range-checked where
// they happen. These tests pin the values at the edges of each range.

func TestQOIGroupRange(t *testing.T) {
	for n := -1; n <= 18; n++ {
		got := QOIGroup(n)
		switch {
		case n >= 1 && n <= 16:
			if want := QOIStation + QOI(n); got != want {
				t.Errorf("QOIGroup(%d) = %d, want %d", n, got, want)
			}
		case got != 0:
			t.Errorf("QOIGroup(%d) = %d, want 0", n, got)
		}
	}
	if QOIGroup(1) != QOIGroup1 || QOIGroup(16) != QOIGroup16 {
		t.Error("QOIGroup(1) or QOIGroup(16) differ from the constants")
	}
	for _, n := range []int{math.MinInt, 256 + 1, 236, math.MaxInt} {
		if got := QOIGroup(n); got != 0 {
			t.Errorf("QOIGroup(%d) = %d, want 0", n, got)
		}
	}
}

func TestVTIAllValues(t *testing.T) {
	for b := range 256 {
		want := int8(b&0x7F<<1) >> 1 // 7-bit two's complement, bit 7 ignored
		if got := vti(byte(b)); got != want || got < -64 || got > 63 {
			t.Fatalf("vti(0x%02X) = %d, want %d", b, got, want)
		}
	}
	// Every value of the range survives the encoder.
	for v := int8(-64); v <= 63; v++ {
		a := New(CauseSpontaneous, 1, StepPosition{IOA: 1, Value: v})
		roundTrip(t, a, IEC104)
	}
}

func TestSignedIntegersAtTheirLimits(t *testing.T) {
	for _, v := range []int16{math.MinInt16, -32767, -256, -255, -129, -128, -1, 0, 1, 127, 128, 255, 256, math.MaxInt16} {
		if got := i16(appendI16(nil, v)); got != v {
			t.Errorf("i16(appendI16(%d)) = %d", v, got)
		}
		for _, obj := range []InformationObject{
			MeasuredScaled{IOA: 1, Value: v},
			MeasuredNormalized{IOA: 1, Value: Normalized(v)},
			SetpointScaled{IOA: 1, Value: v},
			SetpointNormalized{IOA: 1, Value: Normalized(v)},
			ParameterScaled{IOA: 1, Value: v},
			ParameterNormalized{IOA: 1, Value: Normalized(v)},
		} {
			roundTrip(t, New(CauseSpontaneous, 1, obj), IEC104)
		}
	}
	for _, v := range []int32{math.MinInt32, -1 << 24, -65536, -1, 0, 1, 1 << 24, math.MaxInt32} {
		if got := i32(appendI32(nil, v)); got != v {
			t.Errorf("i32(appendI32(%d)) = %d", v, got)
		}
		roundTrip(t, New(CauseSpontaneous, 1, IntegratedTotal{IOA: 1, Value: v, Sequence: 31}), IEC104)
	}
	// Little-endian two's complement on the wire.
	if b := appendI32(nil, -2); string(b) != "\xfe\xff\xff\xff" {
		t.Errorf("appendI32(-2) = % X", b)
	}
	if b := appendI16(nil, Normalized(math.MinInt16)); string(b) != "\x00\x80" {
		t.Errorf("appendI16(-32768) = % X", b)
	}
}

func TestCP56YearWindow(t *testing.T) {
	for _, c := range []struct {
		year    int
		invalid bool
		octet   byte
	}{
		{-5, true, 95}, {-100, true, 0}, {1, true, 1}, {1969, true, 69}, {1970, false, 70},
		{1999, false, 99}, {2000, false, 0}, {2069, false, 69}, {2070, true, 70}, {9999, true, 99},
	} {
		ts := time.Date(c.year, 3, 4, 5, 6, 7, 0, time.UTC)
		b := appendCP56(nil, At(ts), time.UTC)
		if b[6] != c.octet {
			t.Errorf("year %d: year octet %d, want %d", c.year, b[6], c.octet)
		}
		if invalid := b[2]&0x80 != 0; invalid != c.invalid {
			t.Errorf("year %d: invalid flag %v, want %v", c.year, invalid, c.invalid)
		}
		back := parseCP56(b, time.UTC)
		if !c.invalid && !back.Equal(ts) {
			t.Errorf("year %d decoded as %v", c.year, back.Time)
		}
		if back.Invalid != c.invalid {
			t.Errorf("year %d: decoded Invalid = %v, want %v", c.year, back.Invalid, c.invalid)
		}
	}
	// The window is the local year: 2069-12-31 23:30 UTC is 2070 in CET.
	cet := time.FixedZone("CET", 3600)
	b := appendCP56(nil, At(time.Date(2069, 12, 31, 23, 30, 0, 0, time.UTC)), cet)
	if b[2]&0x80 == 0 || b[6] != 70 {
		t.Errorf("2070 local time: % X, want invalid and year 70", b)
	}
}

func TestFileSegmentLengthLimit(t *testing.T) {
	ok := FileSegment{IOA: 1, Name: 1, Section: 1, Data: make([]byte, 255)}
	if _, err := ok.body(nil, nil); err != nil {
		t.Errorf("255-octet segment: %v", err)
	}
	long := FileSegment{IOA: 1, Name: 1, Section: 1, Data: make([]byte, 256)}
	if _, err := long.body(nil, nil); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("256-octet segment: %v, want ErrInvalidValue", err)
	}
	for _, n := range []uint32{MaxFileLength + 1, math.MaxUint32} {
		if _, err := appendFileLength(nil, n); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("length %d: %v, want ErrInvalidValue", n, err)
		}
	}
	if b, err := appendFileLength(nil, MaxFileLength); err != nil || string(b) != "\xff\xff\xff" {
		t.Errorf("length %d: % X, %v", MaxFileLength, b, err)
	}
}

func TestCommonAddressAndIOAWidths(t *testing.T) {
	p1 := Params{CauseSize: 1, CommonAddrSize: 1, IOASize: 1, MaxSize: 249}
	if _, err := New(CauseSpontaneous, 0x100, SinglePoint{IOA: 1}).Encode(p1); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("common address 256 in one octet: %v", err)
	}
	if _, err := New(CauseSpontaneous, 1, SinglePoint{IOA: 0x100}).Encode(p1); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("address 256 in one octet: %v", err)
	}
	if _, err := New(CauseSpontaneous, 1, SinglePoint{IOA: 1 << 24}).Encode(IEC104); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("address 2^24 in three octets: %v", err)
	}
	roundTrip(t, New(CauseSpontaneous, 0xFF, SinglePoint{IOA: 0xFF}), p1)
	roundTrip(t, New(CauseSpontaneous, 0xFFFF, SinglePoint{IOA: 1<<24 - 1}), IEC104)
}

// FuzzSignedValues encodes the signed and step values of every type that
// carries one and decodes them back: two's complement must survive intact.
func FuzzSignedValues(f *testing.F) {
	f.Add(int16(math.MinInt16), int32(math.MinInt32), byte(0x40))
	f.Add(int16(-1), int32(-1), byte(0x7F))
	f.Add(int16(math.MaxInt16), int32(math.MaxInt32), byte(0x3F))
	f.Fuzz(func(t *testing.T, v16 int16, v32 int32, step byte) {
		for _, obj := range []InformationObject{
			MeasuredScaled{IOA: 7, Value: v16},
			MeasuredNormalized{IOA: 7, Value: Normalized(v16)},
			SetpointScaled{IOA: 7, Value: v16, Qualifier: 1},
			ParameterScaled{IOA: 7, Value: v16},
			IntegratedTotal{IOA: 7, Value: v32},
			StepPosition{IOA: 7, Value: vti(step)},
		} {
			roundTrip(t, New(CauseSpontaneous, 1, obj), IEC104)
		}
	})
}

// FuzzCP56 encodes arbitrary instants: inside 1970..2069 they come back to
// the millisecond, outside they come back flagged invalid; the reserved bits
// stay clear either way.
func FuzzCP56(f *testing.F) {
	f.Add(int64(0), int16(0))
	f.Add(time.Date(2069, 12, 31, 23, 59, 59, 999e6, time.UTC).Unix(), int16(0))
	f.Add(time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC).Unix(), int16(60))
	f.Add(int64(math.MinInt64/4), int16(-720))
	f.Fuzz(func(t *testing.T, sec int64, offsetMinutes int16) {
		loc := time.FixedZone("x", int(offsetMinutes%(26*60))*60)
		ts := time.Unix(sec, 0).In(loc)
		b := appendCP56(nil, At(ts), loc)
		if len(b) != sizeCP56 {
			t.Fatalf("%d octets", len(b))
		}
		if b[2]&0x40 != 0 || b[3]&0x60 != 0 || b[5]&0xF0 != 0 || b[6]&0x80 != 0 {
			t.Fatalf("%v: reserved bits set: % X", ts, b)
		}
		back := parseCP56(b, loc)
		inWindow := ts.Year() >= 1970 && ts.Year() <= 2069
		if back.Invalid == inWindow {
			t.Fatalf("%v: Invalid = %v", ts, back.Invalid)
		}
		if inWindow && !back.Equal(ts) {
			t.Fatalf("%v decoded as %v", ts, back.Time)
		}
	})
}
