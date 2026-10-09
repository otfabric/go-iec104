// SPDX-License-Identifier: MIT

package asdu

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Quality is the set of quality flags of an information element. Which flags
// a type can carry depends on its descriptor (SIQ, DIQ, QDS or QDP); flags a
// type cannot carry are dropped on encode.
type Quality uint8

// Quality flags. A zero Quality means the value is good.
const (
	// QualityOverflow (OV) marks a value beyond its predefined range.
	// Carried by measured values, step positions and bitstrings.
	QualityOverflow Quality = 0x01
	// QualityElapsedInvalid (EI) marks an invalid elapsed time. Carried by
	// protection equipment events only.
	QualityElapsedInvalid Quality = 0x08
	// QualityBlocked (BL) marks a value blocked for transmission.
	QualityBlocked Quality = 0x10
	// QualitySubstituted (SB) marks a value supplied by an operator or an
	// automatic source.
	QualitySubstituted Quality = 0x20
	// QualityNotTopical (NT) marks a value whose most recent update failed.
	QualityNotTopical Quality = 0x40
	// QualityInvalid (IV) marks a value that must not be used.
	QualityInvalid Quality = 0x80

	// QualityGood is the zero value: no flag set.
	QualityGood Quality = 0
)

const (
	maskSIQ Quality = 0xF0 // BL SB NT IV
	maskQDS Quality = 0xF1 // OV BL SB NT IV
	maskQDP Quality = 0xF8 // EI BL SB NT IV
)

// Good reports whether no quality flag is set.
func (q Quality) Good() bool { return q == 0 }

// Has reports whether every flag in f is set.
func (q Quality) Has(f Quality) bool { return q&f == f }

// String returns the set flags by their standard abbreviations, for example
// "NT|IV", or "good".
func (q Quality) String() string {
	if q == 0 {
		return "good"
	}
	var parts []string
	for _, f := range []struct {
		bit  Quality
		name string
	}{
		{QualityOverflow, "OV"}, {QualityElapsedInvalid, "EI"}, {QualityBlocked, "BL"},
		{QualitySubstituted, "SB"}, {QualityNotTopical, "NT"}, {QualityInvalid, "IV"},
	} {
		if q&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	if rest := q &^ 0xF9; rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%02X", uint8(rest)))
	}
	return strings.Join(parts, "|")
}

// DoubleState is the two-bit state of a double-point information (DPI), a
// double command (DCS) or a protection event (ES).
type DoubleState uint8

// Double-point states. A double command may only carry DoubleOff or DoubleOn.
const (
	DoubleIntermediate  DoubleState = 0 // Indeterminate or intermediate state
	DoubleOff           DoubleState = 1 // Determined state OFF
	DoubleOn            DoubleState = 2 // Determined state ON
	DoubleIndeterminate DoubleState = 3 // Indeterminate state
)

// String returns "intermediate", "off", "on" or "indeterminate".
func (s DoubleState) String() string {
	switch s {
	case DoubleIntermediate:
		return "intermediate"
	case DoubleOff:
		return "off"
	case DoubleOn:
		return "on"
	case DoubleIndeterminate:
		return "indeterminate"
	default:
		return fmt.Sprintf("DoubleState(%d)", uint8(s))
	}
}

// StepDirection is the state of a regulating step command (RCS).
type StepDirection uint8

// Regulating step command states.
const (
	StepLower  StepDirection = 1 // Next step lower
	StepHigher StepDirection = 2 // Next step higher
)

// Normalized is a normalized value (NVA): a 16-bit fixed-point number in the
// range -1 <= v < 1 with a resolution of 2^-15.
type Normalized int16

// Float64 returns the value as a floating-point number in [-1, 1).
func (n Normalized) Float64() float64 { return float64(n) / 32768 }

// NormalizedFromFloat converts f to the nearest normalized value, clamping
// it to the representable range [-1, 1 - 2^-15].
func NormalizedFromFloat(f float64) Normalized {
	v := math.Round(f * 32768)
	switch {
	case math.IsNaN(v):
		return 0
	case v > math.MaxInt16:
		return math.MaxInt16
	case v < math.MinInt16:
		return math.MinInt16
	}
	return Normalized(v)
}

// CommandQualifier is the qualifier of a single, double or regulating step
// command (QU, 0..31).
type CommandQualifier uint8

// Standard command qualifiers. Values 4..8 are reserved for the standard and
// 9..31 for private use.
const (
	QualifierNone       CommandQualifier = 0 // No additional definition
	QualifierShortPulse CommandQualifier = 1 // Short pulse duration
	QualifierLongPulse  CommandQualifier = 2 // Long pulse duration
	QualifierPersistent CommandQualifier = 3 // Persistent output
)

// QOI is the qualifier of interrogation.
type QOI uint8

// Qualifiers of interrogation. Groups 1..16 are QOIStation+1 .. +16; see
// [QOIGroup].
const (
	QOIStation QOI = 20 // Station interrogation (global)
	QOIGroup1  QOI = 21 // Interrogation of group 1
	QOIGroup16 QOI = 36 // Interrogation of group 16
)

// QOIGroup returns the qualifier for interrogation group n (1..16).
func QOIGroup(n int) QOI { return QOIStation + QOI(n) }

// Cause returns the cause of transmission the controlled station uses for
// data sent in answer to an interrogation with this qualifier.
func (q QOI) Cause() Cause { return Cause(q) }

// Counter interrogation request qualifiers (RQT).
const (
	CounterGroup1  uint8 = 1 // Request counter group 1; groups 2..4 follow
	CounterGroup4  uint8 = 4 // Request counter group 4
	CounterGeneral uint8 = 5 // General request counter
)

// Counter interrogation freeze qualifiers (FRZ).
const (
	FreezeRead         uint8 = 0 // Read, no freeze or reset
	FreezeWithoutReset uint8 = 1 // Counter freeze without reset
	FreezeWithReset    uint8 = 2 // Counter freeze with reset
	FreezeResetOnly    uint8 = 3 // Counter reset
)

// Causes of initialization (COI).
const (
	InitLocalPowerOn uint8 = 0 // Local power switch on
	InitLocalReset   uint8 = 1 // Local manual reset
	InitRemoteReset  uint8 = 2 // Remote reset
)

// Qualifiers of reset process command (QRP).
const (
	ResetProcessGeneral uint8 = 1 // General reset of process
	ResetPendingEvents  uint8 = 2 // Reset of pending information with time tag
)

// Kinds of parameter of measured value (KPA, the low six bits of QPM).
const (
	ParameterThreshold uint8 = 1 // Threshold value
	ParameterSmoothing uint8 = 2 // Smoothing factor (filter time constant)
	ParameterLowLimit  uint8 = 3 // Low limit for transmission of measured values
	ParameterHighLimit uint8 = 4 // High limit for transmission of measured values

	// ParameterChange (LPC) is set in a QPM when a local parameter changed.
	ParameterChange uint8 = 0x40
	// ParameterNotInOperation (POP) is set in a QPM when the parameter is
	// not in operation.
	ParameterNotInOperation uint8 = 0x80
)

// Timestamp is a time tag: CP56Time2a (a full date and time) or CP24Time2a
// (minute, second and millisecond only), depending on the type
// identification.
//
// The wire format carries no time zone; times are converted to and from
// [Params.Location]. A CP56Time2a year is two digits: 70..99 decode as
// 1970..1999 and 0..69 as 2000..2069.
//
// A CP24Time2a tag decodes onto 0001-01-01 00:mm:ss.mmm: only the minute,
// second and nanosecond of Time are meaningful, and the receiver has to
// supply the hour and date. On encode only those fields are used.
//
// A zero Time under a type identification that requires a CP56Time2a is
// encoded as 2000-01-01 with the invalid flag set. A received CP56Time2a
// with a field out of range, or a date that does not exist, decodes to the
// zero Time with Invalid set.
type Timestamp struct {
	time.Time

	// Invalid is the IV flag: the time is not reliable.
	Invalid bool
	// Substituted is the GEN flag: the time was not taken at the source of
	// the information but added by intermediate equipment.
	Substituted bool
	// SummerTime is the SU flag (CP56Time2a only): the time is daylight
	// saving time.
	SummerTime bool
}

// At returns a valid time tag for t.
func At(t time.Time) Timestamp { return Timestamp{Time: t} }

// Now returns a valid time tag for the current time.
func Now() Timestamp { return Timestamp{Time: time.Now()} }

const (
	sizeCP24 = 3
	sizeCP56 = 7
)

func appendCP24(b []byte, t Timestamp, loc *time.Location) []byte {
	tt := t.In(loc)
	ms := tt.Second()*1000 + tt.Nanosecond()/int(time.Millisecond)
	return append(b, byte(ms), byte(ms>>8), byte(tt.Minute())|timeFlags(t))
}

func timeFlags(t Timestamp) byte {
	var f byte
	if t.Invalid {
		f |= 0x80
	}
	if t.Substituted {
		f |= 0x40
	}
	return f
}

func appendCP56(b []byte, t Timestamp, loc *time.Location) []byte {
	if t.IsZero() {
		t = Timestamp{Time: time.Date(2000, 1, 1, 0, 0, 0, 0, loc), Invalid: true}
	}
	tt := t.In(loc)
	b = appendCP24(b, t, loc)
	hour := byte(tt.Hour())
	if t.SummerTime {
		hour |= 0x80
	}
	dow := byte(tt.Weekday())
	if dow == 0 {
		dow = 7
	}
	return append(b, hour, byte(tt.Day())|dow<<5, byte(tt.Month()), byte(tt.Year()%100))
}

func parseCP24(b []byte, loc *time.Location) Timestamp {
	ms := int(b[0]) | int(b[1])<<8
	minute := int(b[2] & 0x3F)
	return Timestamp{
		Time: time.Date(1, 1, 1, 0, minute, ms/1000,
			ms%1000*int(time.Millisecond), loc),
		// Out-of-range fields are normalized by time.Date and flagged.
		Invalid:     b[2]&0x80 != 0 || ms > 59999 || minute > 59,
		Substituted: b[2]&0x40 != 0,
	}
}

func parseCP56(b []byte, loc *time.Location) Timestamp {
	ms := int(b[0]) | int(b[1])<<8
	minute, hour := int(b[2]&0x3F), int(b[3]&0x1F)
	day, month, year := int(b[4]&0x1F), time.Month(b[5]&0x0F), int(b[6]&0x7F)
	validYear := year <= 99
	if year >= 70 {
		year += 1900
	} else {
		year += 2000
	}
	t := Timestamp{
		Time: time.Date(year, month, day, hour, minute, ms/1000,
			ms%1000*int(time.Millisecond), loc),
		Invalid:     b[2]&0x80 != 0,
		Substituted: b[2]&0x40 != 0,
		SummerTime:  b[3]&0x80 != 0,
	}
	// A field outside its range, or a date that does not exist, is not a
	// time at all: report it as the zero time, flagged invalid.
	if !validYear || ms > 59999 || minute > 59 || hour > 23 || t.Day() != day || t.Month() != month {
		t.Time = time.Time{}
		t.Invalid = true
	}
	return t
}
