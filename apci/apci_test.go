// SPDX-License-Identifier: MIT

package apci

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestFrameVectors(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		wire  []byte
		str   string
	}{
		{"STARTDT act", NewU(StartDTAct), []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}, "U STARTDT act"},
		{"STARTDT con", NewU(StartDTCon), []byte{0x68, 0x04, 0x0B, 0x00, 0x00, 0x00}, "U STARTDT con"},
		{"STOPDT act", NewU(StopDTAct), []byte{0x68, 0x04, 0x13, 0x00, 0x00, 0x00}, "U STOPDT act"},
		{"STOPDT con", NewU(StopDTCon), []byte{0x68, 0x04, 0x23, 0x00, 0x00, 0x00}, "U STOPDT con"},
		{"TESTFR act", NewU(TestFRAct), []byte{0x68, 0x04, 0x43, 0x00, 0x00, 0x00}, "U TESTFR act"},
		{"TESTFR con", NewU(TestFRCon), []byte{0x68, 0x04, 0x83, 0x00, 0x00, 0x00}, "U TESTFR con"},
		{"S frame", NewS(5), []byte{0x68, 0x04, 0x01, 0x00, 0x0A, 0x00}, "S N(R)=5"},
		{"S frame high", NewS(0x7FFF), []byte{0x68, 0x04, 0x01, 0x00, 0xFE, 0xFF}, "S N(R)=32767"},
		{"I frame", NewI(2, 300, []byte{0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14}),
			[]byte{0x68, 0x0E, 0x04, 0x00, 0x58, 0x02, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14},
			"I N(S)=2 N(R)=300 len=10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.frame.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if !bytes.Equal(got, tt.wire) {
				t.Fatalf("wire = % X, want % X", got, tt.wire)
			}
			if tt.frame.Len() != len(tt.wire) {
				t.Errorf("Len = %d, want %d", tt.frame.Len(), len(tt.wire))
			}
			if s := tt.frame.String(); s != tt.str {
				t.Errorf("String = %q, want %q", s, tt.str)
			}
			for _, parse := range []func() (Frame, error){
				func() (Frame, error) { return Parse(tt.wire) },
				func() (Frame, error) { return ReadFrame(bytes.NewReader(tt.wire)) },
			} {
				f, err := parse()
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if f.Format != tt.frame.Format || f.SendSeq != tt.frame.SendSeq || f.RecvSeq != tt.frame.RecvSeq ||
					f.Function != tt.frame.Function || !bytes.Equal(f.ASDU, tt.frame.ASDU) {
					t.Errorf("parsed %+v, want %+v", f, tt.frame)
				}
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{"short", []byte{0x68, 0x04, 0x07}, ErrInvalidLength},
		{"bad start", []byte{0x69, 0x04, 0x07, 0x00, 0x00, 0x00}, ErrInvalidStart},
		{"length too small", []byte{0x68, 0x03, 0x07, 0x00, 0x00, 0x00}, ErrInvalidLength},
		{"length mismatch", []byte{0x68, 0x05, 0x07, 0x00, 0x00, 0x00}, ErrInvalidLength},
		{"U with payload", []byte{0x68, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00}, ErrInvalidLength},
		{"S with payload", []byte{0x68, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}, ErrInvalidLength},
		{"U two functions", []byte{0x68, 0x04, 0x0F, 0x00, 0x00, 0x00}, ErrInvalidControl},
		{"U no function", []byte{0x68, 0x04, 0x03, 0x00, 0x00, 0x00}, ErrInvalidControl},
		{"U trailing bits", []byte{0x68, 0x04, 0x07, 0x00, 0x02, 0x00}, ErrInvalidControl},
		{"S malformed", []byte{0x68, 0x04, 0x01, 0x01, 0x00, 0x00}, ErrInvalidControl},
		{"S odd N(R)", []byte{0x68, 0x04, 0x01, 0x00, 0x01, 0x00}, ErrInvalidControl},
		{"I odd N(R)", []byte{0x68, 0x04, 0x00, 0x00, 0x01, 0x00}, ErrInvalidControl},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.wire); !errors.Is(err, tt.want) {
				t.Errorf("Parse error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReadFrameErrors(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Errorf("empty stream: %v, want io.EOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x68})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated header: %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x68, 0x04, 0x07})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated body: %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x68, 0x04})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("missing body: %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x00, 0x04})); !errors.Is(err, ErrInvalidStart) {
		t.Errorf("bad start: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x68, 0x02})); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("bad length: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x68, 0xFE})); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("length 254: %v", err)
	}

	// Two frames back to back: ReadFrame must not read past the first.
	r := bytes.NewReader([]byte{0x68, 0x04, 0x07, 0, 0, 0, 0x68, 0x04, 0x0B, 0, 0, 0})
	for _, want := range []UFunction{StartDTAct, StartDTCon} {
		f, err := ReadFrame(r)
		if err != nil || f.Function != want {
			t.Fatalf("ReadFrame = %v, %v; want %s", f, err, want)
		}
	}
}

func TestMarshalErrors(t *testing.T) {
	if _, err := NewI(0, 0, make([]byte, MaxASDULength+1)).MarshalBinary(); !errors.Is(err, ErrASDUTooLong) {
		t.Errorf("oversized ASDU: %v", err)
	}
	if b, err := NewI(0, 0, make([]byte, MaxASDULength)).MarshalBinary(); err != nil || len(b) != MaxFrameLength {
		t.Errorf("max ASDU: len %d, err %v", len(b), err)
	}
	for _, f := range []Frame{
		{Format: FormatU, Function: 0x0F},
		{Format: FormatI, SendSeq: SeqModulus},
		{Format: FormatS, RecvSeq: SeqModulus},
		{Format: 9},
	} {
		if _, err := f.MarshalBinary(); !errors.Is(err, ErrInvalidControl) {
			t.Errorf("%+v: error = %v, want ErrInvalidControl", f, err)
		}
	}
	if s := (Frame{Format: 9}).String(); s != "Format(9)" {
		t.Errorf("String = %q", s)
	}
	if s := UFunction(0x0F).String(); s != "UFunction(0x0F)" {
		t.Errorf("String = %q", s)
	}
}

func TestUFunction(t *testing.T) {
	for act, con := range map[UFunction]UFunction{StartDTAct: StartDTCon, StopDTAct: StopDTCon, TestFRAct: TestFRCon} {
		if !act.IsAct() || con.IsAct() {
			t.Errorf("IsAct wrong for %s/%s", act, con)
		}
		if act.Confirmation() != con {
			t.Errorf("%s.Confirmation() = %s", act, act.Confirmation())
		}
		if con.Confirmation() != 0 {
			t.Errorf("%s.Confirmation() != 0", con)
		}
	}
	if FormatI.String() != "I" || FormatS.String() != "S" || FormatU.String() != "U" {
		t.Error("Format.String")
	}
}

func TestSequence(t *testing.T) {
	if SeqNext(0) != 1 || SeqNext(SeqMask) != 0 {
		t.Error("SeqNext")
	}
	if SeqDiff(3, 1) != 2 || SeqDiff(1, SeqMask) != 2 || SeqDiff(5, 5) != 0 {
		t.Error("SeqDiff")
	}
	tests := []struct {
		nr, ack, next uint16
		n             int
		ok            bool
	}{
		{5, 5, 5, 0, true},
		{5, 3, 8, 2, true},
		{8, 3, 8, 5, true},
		{9, 3, 8, 0, false},
		{2, 3, 8, 0, false},
		{1, SeqMask - 1, 2, 3, true}, // across the wrap
		{3, SeqMask - 1, 2, 0, false},
	}
	for _, tt := range tests {
		n, ok := SeqAcks(tt.nr, tt.ack, tt.next)
		if n != tt.n || ok != tt.ok {
			t.Errorf("SeqAcks(%d, %d, %d) = %d, %v; want %d, %v", tt.nr, tt.ack, tt.next, n, ok, tt.n, tt.ok)
		}
	}
}

func TestParams(t *testing.T) {
	d := DefaultParams()
	if err := d.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	if got := (Params{}).WithDefaults(); got != (Params{K: 12, W: 8, T0: 30 * time.Second, T1: 15 * time.Second, T2: 10 * time.Second}) {
		t.Errorf("WithDefaults = %+v", got)
	}
	bad := []func(*Params){
		func(p *Params) { p.K = 0 },
		func(p *Params) { p.K = SeqModulus },
		func(p *Params) { p.W = 0 },
		func(p *Params) { p.W = p.K + 1 },
		func(p *Params) { p.T0 = 0 },
		func(p *Params) { p.T1 = -1 },
		func(p *Params) { p.T2 = p.T1 },
		func(p *Params) { p.T2 = 0 },
		func(p *Params) { p.T3 = -1 },
	}
	for i, mutate := range bad {
		p := d
		mutate(&p)
		if err := p.Validate(); !errors.Is(err, ErrInvalidParams) {
			t.Errorf("case %d: error = %v, want ErrInvalidParams", i, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00})
	f.Add([]byte{0x68, 0x04, 0x01, 0x00, 0x0A, 0x00})
	f.Add([]byte{0x68, 0x0E, 0x04, 0x00, 0x58, 0x02, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Parse(b)
		rf, rerr := ReadFrame(bytes.NewReader(b))
		if err != nil {
			return
		}
		if rerr != nil {
			t.Fatalf("Parse accepted what ReadFrame rejected: %v", rerr)
		}
		out, err := fr.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("round trip: % X != % X", out, b)
		}
		if rf.Format != fr.Format || !bytes.Equal(rf.ASDU, fr.ASDU) {
			t.Fatalf("ReadFrame and Parse disagree")
		}
	})
}

func BenchmarkParseI(b *testing.B) {
	wire, _ := NewI(1, 2, make([]byte, 100)).MarshalBinary()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendI(b *testing.B) {
	f := NewI(1, 2, make([]byte, 100))
	buf := make([]byte, 0, MaxFrameLength)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := f.AppendBinary(buf[:0]); err != nil {
			b.Fatal(err)
		}
	}
}
