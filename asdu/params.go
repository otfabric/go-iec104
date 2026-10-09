// SPDX-License-Identifier: MIT

package asdu

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by the codec. They are wrapped with detail; test with
// errors.Is.
var (
	// ErrInvalidParams reports a [Params] value with field sizes the
	// standard does not allow.
	ErrInvalidParams = errors.New("asdu: invalid parameters")

	// ErrMalformed reports bytes that are not a well-formed ASDU: a
	// truncated header, or a payload whose size does not match the number
	// of objects announced.
	ErrMalformed = errors.New("asdu: malformed ASDU")

	// ErrUnsupportedType reports an attempt to encode typed objects under a
	// type identification this package has no model for.
	ErrUnsupportedType = errors.New("asdu: unsupported type identification")

	// ErrTypeMismatch reports an information object that does not belong to
	// the type identification of its ASDU.
	ErrTypeMismatch = errors.New("asdu: information object does not match type identification")

	// ErrInvalidValue reports a field that cannot be represented on the
	// wire: an address wider than the configured field, a qualifier or
	// value outside its bit range, more than 127 objects.
	ErrInvalidValue = errors.New("asdu: value out of range")

	// ErrNotSequential reports an ASDU with Sequence set whose information
	// object addresses are not consecutive.
	ErrNotSequential = errors.New("asdu: sequence addresses are not consecutive")

	// ErrTooLong reports an encoded ASDU larger than [Params.MaxSize].
	ErrTooLong = errors.New("asdu: ASDU too long")
)

// MaxObjects is the largest number of information objects or elements one
// ASDU can announce.
const MaxObjects = 127

// Params holds the system parameters that fix the ASDU layout. Both stations
// must agree on them.
type Params struct {
	// CauseSize is the size of the cause of transmission in octets: 1, or 2
	// when the originator address is present.
	CauseSize int

	// CommonAddrSize is the size of the common address in octets: 1 or 2.
	CommonAddrSize int

	// IOASize is the size of the information object address in octets: 1,
	// 2 or 3.
	IOASize int

	// MaxSize is the largest encoded ASDU in octets. Zero means 249, the
	// limit of IEC 60870-5-104.
	MaxSize int

	// Location is the time zone of the time tags on the wire, which carry
	// no zone of their own. Nil means UTC.
	Location *time.Location
}

// IEC104 is the fixed ASDU layout of IEC 60870-5-104: a two-octet cause of
// transmission with originator address, a two-octet common address and a
// three-octet information object address, with time tags in UTC.
var IEC104 = Params{CauseSize: 2, CommonAddrSize: 2, IOASize: 3, MaxSize: 249}

// Validate reports whether the field sizes are ones the standard allows.
func (p Params) Validate() error {
	switch {
	case p.CauseSize != 1 && p.CauseSize != 2:
		return fmt.Errorf("%w: cause size %d, want 1 or 2", ErrInvalidParams, p.CauseSize)
	case p.CommonAddrSize != 1 && p.CommonAddrSize != 2:
		return fmt.Errorf("%w: common address size %d, want 1 or 2", ErrInvalidParams, p.CommonAddrSize)
	case p.IOASize < 1 || p.IOASize > 3:
		return fmt.Errorf("%w: information object address size %d, want 1..3", ErrInvalidParams, p.IOASize)
	case p.MaxSize < 0:
		return fmt.Errorf("%w: max size %d", ErrInvalidParams, p.MaxSize)
	}
	return nil
}

// In returns a copy of p whose time tags are interpreted in loc.
func (p Params) In(loc *time.Location) Params {
	p.Location = loc
	return p
}

func (p Params) headerSize() int { return 2 + p.CauseSize + p.CommonAddrSize }

func (p Params) maxSize() int {
	if p.MaxSize == 0 {
		return 249
	}
	return p.MaxSize
}

func (p Params) location() *time.Location {
	if p.Location == nil {
		return time.UTC
	}
	return p.Location
}

// broadcast returns the global common address for the configured field size.
func (p Params) broadcast() CommonAddr {
	if p.CommonAddrSize == 1 {
		return 0xFF
	}
	return Broadcast
}
