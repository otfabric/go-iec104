// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-iec104/asdu"
)

// ASC is the ASDU segmentation control octet that follows the data unit
// identifier of every segment of a security message: FIN in bit 8 (last
// segment), FIR in bit 7 (first segment) and a sequence number of 0 to 63.
type ASC struct {
	FIN, FIR bool
	Seq      uint8
}

// Byte encodes the octet.
func (a ASC) Byte() byte {
	b := a.Seq & 0x3f
	if a.FIR {
		b |= 0x40
	}
	if a.FIN {
		b |= 0x80
	}
	return b
}

// ParseASC decodes the octet.
func ParseASC(b byte) ASC { return ASC{FIN: b&0x80 != 0, FIR: b&0x40 != 0, Seq: b & 0x3f} }

// Segment cuts a whole security message into wire ASDUs of at most max
// octets: each the data unit identifier, an ASC octet and the next part of
// the fields. seq numbers the first segment; the number after the last one
// is returned. A message that fits is one segment with FIR and FIN set.
func Segment(msg []byte, p asdu.Params, max int, seq uint8) ([][]byte, uint8, error) {
	n := headerLen(p)
	if len(msg) < n {
		return nil, seq, fmt.Errorf("%w: %d octets", ErrMessage, len(msg))
	}
	room := max - n - 1
	if room < 1 {
		return nil, seq, fmt.Errorf("%w: ASDU size %d leaves no room for data", ErrConfig, max)
	}
	head, rest := msg[:n], msg[n:]
	seq &= 0x3f
	var out [][]byte
	for first := true; first || len(rest) > 0; first = false {
		k := min(room, len(rest))
		s := make([]byte, 0, n+1+k)
		s = append(s, head...)
		s = append(s, ASC{FIR: first, FIN: k == len(rest), Seq: seq}.Byte())
		s = append(s, rest[:k]...)
		out = append(out, s)
		rest = rest[k:]
		seq = (seq + 1) & 0x3f
	}
	return out, seq, nil
}

// reassembler joins the segments of received security messages, one series
// at a time, as the segment reception state machine of IEC TS 60870-5-7
// describes: a series starts with FIR and continues with consecutive
// numbers and the same data unit identifier; a repeated segment is ignored;
// anything else abandons the series. discarded is called for every segment
// or series that is dropped.
type reassembler struct {
	p         asdu.Params
	busy      bool
	head      []byte // data unit identifier of the series
	last      []byte // the previous segment, as received
	seq       uint8
	buf       []byte
	discarded func()
}

func (r *reassembler) reset() { r.busy, r.head, r.last, r.buf = false, nil, nil, nil }

func (r *reassembler) discard() {
	if r.discarded != nil {
		r.discarded()
	}
}

// add takes one segment and returns the whole message when it completes one.
func (r *reassembler) add(seg []byte) []byte {
	n := headerLen(r.p)
	if len(seg) < n+1 {
		r.discard()
		return nil
	}
	head, asc, data := seg[:n], ParseASC(seg[n]), seg[n+1:]
	begin := func() {
		r.head = append(r.head[:0], head...)
		r.buf = append(r.buf[:0], data...)
		r.last = append(r.last[:0], seg...)
		r.seq = asc.Seq
		r.busy = true
	}
	finish := func() []byte {
		out := append(append(make([]byte, 0, len(r.head)+len(r.buf)), r.head...), r.buf...)
		r.reset()
		return out
	}
	if asc.FIR {
		if r.busy && bytes.Equal(seg, r.last) {
			return nil // the first segment again
		}
		if r.busy {
			r.discard() // the series in progress is abandoned for the new one
		}
		begin()
		if asc.FIN {
			return finish()
		}
		return nil
	}
	if !r.busy {
		r.discard()
		return nil
	}
	switch {
	case !bytes.Equal(head, r.head):
		r.discard()
		r.reset()
	case asc.Seq == r.seq && bytes.Equal(seg, r.last):
		// The same segment again: dropped without losing the series.
	case asc.Seq == (r.seq+1)&0x3f:
		r.buf = append(r.buf, data...)
		r.last = append(r.last[:0], seg...)
		r.seq = asc.Seq
		if asc.FIN {
			return finish()
		}
	default:
		r.discard()
		r.reset()
	}
	return nil
}

// AssociationOf returns the AIM, the controlling station's half of the
// association ID, of a received wire ASDU: every security message carries
// it first, so the first segment of one names the association it belongs
// to. ok is false for anything else, a later segment included. A
// controlled station that serves several controlling stations uses it to
// pick the Endpoint for a connection.
func AssociationOf(raw []byte, p asdu.Params) (aim uint16, ok bool) {
	if p == (asdu.Params{}) {
		p = asdu.IEC104
	}
	if checkParams(p) != nil {
		return 0, false
	}
	n := headerLen(p)
	if len(raw) < n+3 || !asdu.TypeID(raw[0]).IsSecurity() || !ParseASC(raw[n]).FIR {
		return 0, false
	}
	aim = binary.LittleEndian.Uint16(raw[n+1:])
	return aim, aim != 0
}
