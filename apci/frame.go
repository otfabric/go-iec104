// SPDX-License-Identifier: MIT

package apci

import (
	"errors"
	"fmt"
	"io"
)

const (
	// StartByte is the first octet of every APDU.
	StartByte = 0x68

	// ControlLength is the size of the control field in octets.
	ControlLength = 4

	// HeaderLength is the size of the start octet plus the length octet.
	HeaderLength = 2

	// MaxAPDULength is the largest value of the APDU length octet: the
	// control field plus the ASDU.
	MaxAPDULength = 253

	// MaxASDULength is the largest ASDU an I-format APDU can carry.
	MaxASDULength = MaxAPDULength - ControlLength

	// MaxFrameLength is the largest APDU on the wire, including the start
	// and length octets.
	MaxFrameLength = HeaderLength + MaxAPDULength
)

// Framing errors returned by [Parse] and [ReadFrame]. They are wrapped with
// detail; test with errors.Is.
var (
	// ErrInvalidStart reports an APDU that does not begin with [StartByte].
	ErrInvalidStart = errors.New("apci: invalid start byte")

	// ErrInvalidLength reports a length octet outside 4..253, a buffer that
	// does not match its length octet, or an S/U frame carrying a payload.
	ErrInvalidLength = errors.New("apci: invalid APDU length")

	// ErrInvalidControl reports a control field that is not a valid I, S or
	// U format, including a U frame with no or several functions set.
	ErrInvalidControl = errors.New("apci: invalid control field")

	// ErrASDUTooLong reports an ASDU larger than [MaxASDULength].
	ErrASDUTooLong = errors.New("apci: ASDU too long")
)

// Format is the APDU control field format.
type Format uint8

// Control field formats.
const (
	// FormatI is the numbered information transfer format. It carries an ASDU.
	FormatI Format = iota
	// FormatS is the numbered supervisory format: an acknowledgement.
	FormatS
	// FormatU is the unnumbered control format: STARTDT, STOPDT and TESTFR.
	FormatU
)

// String returns "I", "S" or "U".
func (f Format) String() string {
	switch f {
	case FormatI:
		return "I"
	case FormatS:
		return "S"
	case FormatU:
		return "U"
	default:
		return fmt.Sprintf("Format(%d)", uint8(f))
	}
}

// Frame is one decoded APDU.
//
// SendSeq is meaningful for I frames, RecvSeq for I and S frames, Function
// for U frames and ASDU for I frames.
type Frame struct {
	Format   Format
	SendSeq  uint16
	RecvSeq  uint16
	Function UFunction
	ASDU     []byte
}

// NewI returns an I-format frame carrying asdu. The slice is not copied.
func NewI(sendSeq, recvSeq uint16, asdu []byte) Frame {
	return Frame{Format: FormatI, SendSeq: sendSeq & SeqMask, RecvSeq: recvSeq & SeqMask, ASDU: asdu}
}

// NewS returns an S-format frame acknowledging every I frame up to, but not
// including, recvSeq.
func NewS(recvSeq uint16) Frame {
	return Frame{Format: FormatS, RecvSeq: recvSeq & SeqMask}
}

// NewU returns a U-format frame for fn.
func NewU(fn UFunction) Frame {
	return Frame{Format: FormatU, Function: fn}
}

// Len returns the size of the frame on the wire.
func (f Frame) Len() int {
	n := HeaderLength + ControlLength
	if f.Format == FormatI {
		n += len(f.ASDU)
	}
	return n
}

// AppendBinary appends the wire encoding of f to b.
func (f Frame) AppendBinary(b []byte) ([]byte, error) {
	switch f.Format {
	case FormatI:
		if len(f.ASDU) > MaxASDULength {
			return b, fmt.Errorf("%w: %d octets", ErrASDUTooLong, len(f.ASDU))
		}
		if f.SendSeq > SeqMask || f.RecvSeq > SeqMask {
			return b, fmt.Errorf("%w: sequence number out of range", ErrInvalidControl)
		}
		b = append(b, StartByte, byte(ControlLength+len(f.ASDU)),
			byte(f.SendSeq<<1), byte(f.SendSeq>>7),
			byte(f.RecvSeq<<1), byte(f.RecvSeq>>7))
		return append(b, f.ASDU...), nil
	case FormatS:
		if f.RecvSeq > SeqMask {
			return b, fmt.Errorf("%w: sequence number out of range", ErrInvalidControl)
		}
		return append(b, StartByte, ControlLength, 0x01, 0x00,
			byte(f.RecvSeq<<1), byte(f.RecvSeq>>7)), nil
	case FormatU:
		if !f.Function.Valid() {
			return b, fmt.Errorf("%w: U function 0x%02X", ErrInvalidControl, uint8(f.Function))
		}
		return append(b, StartByte, ControlLength, byte(f.Function), 0x00, 0x00, 0x00), nil
	default:
		return b, fmt.Errorf("%w: format %d", ErrInvalidControl, uint8(f.Format))
	}
}

// MarshalBinary returns the wire encoding of f.
func (f Frame) MarshalBinary() ([]byte, error) {
	return f.AppendBinary(make([]byte, 0, f.Len()))
}

// String returns a compact, log-friendly description of the frame.
func (f Frame) String() string {
	switch f.Format {
	case FormatI:
		return fmt.Sprintf("I N(S)=%d N(R)=%d len=%d", f.SendSeq, f.RecvSeq, len(f.ASDU))
	case FormatS:
		return fmt.Sprintf("S N(R)=%d", f.RecvSeq)
	case FormatU:
		return "U " + f.Function.String()
	default:
		return f.Format.String()
	}
}

// Parse decodes exactly one APDU from b, which must hold the whole frame
// including the start and length octets and nothing else. The ASDU of an
// I frame aliases b.
func Parse(b []byte) (Frame, error) {
	if len(b) < HeaderLength+ControlLength {
		return Frame{}, fmt.Errorf("%w: %d octets", ErrInvalidLength, len(b))
	}
	if b[0] != StartByte {
		return Frame{}, fmt.Errorf("%w: 0x%02X", ErrInvalidStart, b[0])
	}
	n := int(b[1])
	if n < ControlLength || n > MaxAPDULength || n != len(b)-HeaderLength {
		return Frame{}, fmt.Errorf("%w: length octet %d, %d octets follow", ErrInvalidLength, n, len(b)-HeaderLength)
	}
	return parseBody(b[HeaderLength:])
}

// parseBody decodes the control field and payload (everything after the
// length octet).
func parseBody(b []byte) (Frame, error) {
	c := b[:ControlLength]
	switch {
	case c[0]&0x01 == 0:
		if c[2]&0x01 != 0 {
			return Frame{}, fmt.Errorf("%w: I frame with odd third octet", ErrInvalidControl)
		}
		return Frame{
			Format:  FormatI,
			SendSeq: uint16(c[0])>>1 | uint16(c[1])<<7,
			RecvSeq: uint16(c[2])>>1 | uint16(c[3])<<7,
			ASDU:    b[ControlLength:],
		}, nil
	case c[0]&0x03 == 0x01:
		if len(b) != ControlLength {
			return Frame{}, fmt.Errorf("%w: S frame with payload", ErrInvalidLength)
		}
		if c[0] != 0x01 || c[1] != 0 || c[2]&0x01 != 0 {
			return Frame{}, fmt.Errorf("%w: malformed S frame", ErrInvalidControl)
		}
		return Frame{Format: FormatS, RecvSeq: uint16(c[2])>>1 | uint16(c[3])<<7}, nil
	default:
		if len(b) != ControlLength {
			return Frame{}, fmt.Errorf("%w: U frame with payload", ErrInvalidLength)
		}
		fn := UFunction(c[0])
		if !fn.Valid() || c[1] != 0 || c[2] != 0 || c[3] != 0 {
			return Frame{}, fmt.Errorf("%w: U frame % X", ErrInvalidControl, c)
		}
		return Frame{Format: FormatU, Function: fn}, nil
	}
}

// ReadFrame reads exactly one APDU from r. It never reads past the end of
// the frame, so r needs no buffering for correctness. The returned ASDU is
// freshly allocated.
//
// A clean end of stream before the first octet yields io.EOF; a stream that
// ends inside a frame yields io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderLength]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if hdr[0] != StartByte {
		return Frame{}, fmt.Errorf("%w: 0x%02X", ErrInvalidStart, hdr[0])
	}
	n := int(hdr[1])
	if n < ControlLength || n > MaxAPDULength {
		return Frame{}, fmt.Errorf("%w: length octet %d", ErrInvalidLength, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return parseBody(body)
}
