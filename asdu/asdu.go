// SPDX-License-Identifier: MIT

package asdu

import (
	"fmt"
	"strings"
)

// ASDU is one Application Service Data Unit: the data unit identifier and
// the information objects it carries.
type ASDU struct {
	// Type is the type identification. Every object in Objects must be of
	// a kind this type can carry.
	Type TypeID

	// Sequence is the SQ bit. When set, the objects are encoded as one
	// address followed by a sequence of information elements, and their
	// addresses must be consecutive. Sequence encoding is more compact but
	// is only meaningful for types without a time tag.
	Sequence bool

	// Cause is the cause of transmission.
	Cause Cause

	// Negative is the P/N bit: a negative confirmation.
	Negative bool

	// Test is the T bit: the ASDU was generated under test conditions.
	Test bool

	// Originator is the originator address. It is on the wire only when
	// [Params.CauseSize] is 2.
	Originator uint8

	// CommonAddr is the common address of ASDU, the station address.
	CommonAddr CommonAddr

	// Objects are the information objects. It is nil for a type this
	// package does not model; see Raw.
	Objects []InformationObject

	// Raw is the undecoded payload after the data unit identifier of an
	// ASDU whose type is not [TypeID.Supported]: file transfer and private
	// types. RawCount is the number of objects its variable structure
	// qualifier announces. On encode Raw is used when Objects is empty.
	Raw      []byte
	RawCount int
}

// New returns an ASDU carrying objs, with the type identification taken
// from the first object by [TypeOf]. Set [ASDU.Type] afterwards to choose
// another variant, such as M_ME_ND_1 or a CP24Time2a type.
func New(cause Cause, ca CommonAddr, objs ...InformationObject) *ASDU {
	a := &ASDU{Cause: cause, CommonAddr: ca, Objects: objs}
	if len(objs) > 0 {
		a.Type = TypeOf(objs[0])
	}
	return a
}

// Reply returns a copy of a with the given cause of transmission and P/N
// bit: the mirrored ASDU a controlled station sends to confirm, reject or
// terminate a command. The objects are shared with a.
func (a *ASDU) Reply(cause Cause, negative bool) *ASDU {
	r := *a
	r.Cause = cause
	r.Negative = negative
	return &r
}

// Len returns the number of information objects, or RawCount for an ASDU
// carried as raw payload.
func (a *ASDU) Len() int {
	if len(a.Objects) == 0 && len(a.Raw) > 0 {
		return a.RawCount
	}
	return len(a.Objects)
}

// First returns the first information object, or nil when there is none.
func (a *ASDU) First() InformationObject {
	if len(a.Objects) == 0 {
		return nil
	}
	return a.Objects[0]
}

// String returns a one-line description for logs, for example
// "M_ME_NC_1 spontaneous ca=1 n=2".
func (a *ASDU) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s ca=%d n=%d", a.Type, a.Cause, a.CommonAddr, a.Len())
	if a.Originator != 0 {
		fmt.Fprintf(&sb, " oa=%d", a.Originator)
	}
	if a.Negative {
		sb.WriteString(" negative")
	}
	if a.Test {
		sb.WriteString(" test")
	}
	if a.Sequence {
		sb.WriteString(" sq")
	}
	return sb.String()
}

// Encode returns the wire encoding of a under the layout p.
func (a *ASDU) Encode(p Params) ([]byte, error) {
	return a.AppendEncode(nil, p)
}

// AppendEncode appends the wire encoding of a under the layout p to b.
func (a *ASDU) AppendEncode(b []byte, p Params) ([]byte, error) {
	if a == nil {
		return b, fmt.Errorf("%w: nil ASDU", ErrInvalidValue)
	}
	if err := p.Validate(); err != nil {
		return b, err
	}
	start := len(b)
	n := a.Len()
	switch {
	case n > MaxObjects:
		return b, fmt.Errorf("%w: %d information objects, max %d", ErrInvalidValue, n, MaxObjects)
	case n < 0:
		return b, fmt.Errorf("%w: negative object count", ErrInvalidValue)
	case a.Cause > 63:
		return b, fmt.Errorf("%w: cause of transmission %d, want 0..63", ErrInvalidValue, a.Cause)
	case p.CommonAddrSize == 1 && a.CommonAddr > 0xFF:
		return b, fmt.Errorf("%w: common address %d does not fit one octet", ErrInvalidValue, a.CommonAddr)
	}

	b = append(b, byte(a.Type), byte(n)|bit(a.Sequence, 0x80),
		byte(a.Cause)|bit(a.Negative, 0x40)|bit(a.Test, 0x80))
	if p.CauseSize == 2 {
		b = append(b, a.Originator)
	}
	b = append(b, byte(a.CommonAddr))
	if p.CommonAddrSize == 2 {
		b = append(b, byte(a.CommonAddr>>8))
	}

	if len(a.Objects) == 0 {
		b = append(b, a.Raw...)
	} else {
		d := registry[a.Type]
		if d == nil {
			return b[:start], fmt.Errorf("%w: %s", ErrUnsupportedType, a.Type)
		}
		maxIOA := IOA(1)<<(8*p.IOASize) - 1
		loc := p.location()
		for i, obj := range a.Objects {
			if obj == nil || obj.kind() != d.kind {
				return b[:start], fmt.Errorf("%w: object %d is %T under %s", ErrTypeMismatch, i, obj, a.Type)
			}
			ioa := obj.Address()
			if ioa > maxIOA {
				return b[:start], fmt.Errorf("%w: information object address %d does not fit %d octets",
					ErrInvalidValue, ioa, p.IOASize)
			}
			switch {
			case !a.Sequence || i == 0:
				b = append(b, byte(ioa), byte(ioa>>8), byte(ioa>>16))[:len(b)+p.IOASize]
			case ioa != a.Objects[0].Address()+IOA(i):
				return b[:start], fmt.Errorf("%w: object %d has address %d, want %d",
					ErrNotSequential, i, ioa, a.Objects[0].Address()+IOA(i))
			}
			var err error
			if b, err = obj.body(b, d); err != nil {
				return b[:start], fmt.Errorf("%w (object %d, address %d)", err, i, ioa)
			}
			switch d.tag {
			case tagCP24:
				b = appendCP24(b, obj.stamp(), loc)
			case tagCP56:
				b = appendCP56(b, obj.stamp(), loc)
			case tagNone:
			}
		}
	}
	if size := len(b) - start; size > p.maxSize() {
		return b[:start], fmt.Errorf("%w: %d octets, max %d", ErrTooLong, size, p.maxSize())
	}
	return b, nil
}

// Decode parses one ASDU laid out according to p. The result does not alias
// b.
//
// A type identification without an object model is not an error: its
// payload is returned in [ASDU.Raw].
func Decode(b []byte, p Params) (*ASDU, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(b) < p.headerSize() {
		return nil, fmt.Errorf("%w: %d octets, header needs %d", ErrMalformed, len(b), p.headerSize())
	}
	if len(b) > p.maxSize() {
		return nil, fmt.Errorf("%w: %d octets, max %d", ErrTooLong, len(b), p.maxSize())
	}
	a := &ASDU{
		Type:     TypeID(b[0]),
		Sequence: b[1]&0x80 != 0,
		Cause:    Cause(b[2] & 0x3F),
		Negative: b[2]&0x40 != 0,
		Test:     b[2]&0x80 != 0,
	}
	n := int(b[1] & 0x7F)
	i := 3
	if p.CauseSize == 2 {
		a.Originator = b[i]
		i++
	}
	a.CommonAddr = CommonAddr(b[i])
	i++
	if p.CommonAddrSize == 2 {
		a.CommonAddr |= CommonAddr(b[i]) << 8
		i++
	}
	b = b[i:]

	d := registry[a.Type]
	if d == nil {
		a.Raw = append([]byte(nil), b...)
		a.RawCount = n
		return a, nil
	}

	elem := d.size + d.tag.size()
	want := n * (p.IOASize + elem)
	if a.Sequence && n > 0 {
		want = p.IOASize + n*elem
	}
	if len(b) != want {
		return nil, fmt.Errorf("%w: %s with %d objects needs %d payload octets, got %d",
			ErrMalformed, a.Type, n, want, len(b))
	}

	loc := p.location()
	maxIOA := IOA(1)<<(8*p.IOASize) - 1
	a.Objects = make([]InformationObject, 0, n)
	var ioa IOA
	for k := 0; k < n; k++ {
		if !a.Sequence || k == 0 {
			ioa = 0
			for j := p.IOASize - 1; j >= 0; j-- {
				ioa = ioa<<8 | IOA(b[j])
			}
			b = b[p.IOASize:]
			if a.Sequence && ioa+IOA(n-1) > maxIOA {
				return nil, fmt.Errorf("%w: sequence of %d from address %d runs past the address range",
					ErrMalformed, n, ioa)
			}
		} else {
			ioa++
		}
		var ts Timestamp
		switch d.tag {
		case tagCP24:
			ts = parseCP24(b[d.size:], loc)
		case tagCP56:
			ts = parseCP56(b[d.size:], loc)
		case tagNone:
		}
		a.Objects = append(a.Objects, d.dec(ioa, b[:d.size], ts, d))
		b = b[elem:]
	}
	return a, nil
}

// IsBroadcast reports whether ca is the global address under the layout p:
// 0xFFFF for a two-octet common address, 0xFF for a one-octet one.
func (p Params) IsBroadcast(ca CommonAddr) bool {
	return ca == p.broadcast()
}
