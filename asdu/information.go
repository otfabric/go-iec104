// SPDX-License-Identifier: MIT

package asdu

import (
	"encoding/binary"
	"fmt"
	"math"
)

// InformationObject is one information object of an ASDU: an address plus
// the information elements of its type.
//
// The set of implementations is closed: it is the object structs of this
// package, used by value. Use a type switch to consume them:
//
//	for _, obj := range a.Objects {
//		switch o := obj.(type) {
//		case asdu.SinglePoint:
//			...
//		case asdu.MeasuredFloat:
//			...
//		}
//	}
type InformationObject interface {
	// Address returns the information object address.
	Address() IOA

	kind() kind
	stamp() Timestamp
	// body appends the information elements, without address and time tag.
	body(b []byte, d *typeDesc) ([]byte, error)
}

type kind uint8

const (
	kSinglePoint kind = iota + 1
	kDoublePoint
	kStepPosition
	kBitstring
	kNormalized
	kScaled
	kFloat
	kTotal
	kProtEvent
	kProtStart
	kProtOutput
	kPacked
	kSingleCmd
	kDoubleCmd
	kStepCmd
	kSetNormalized
	kSetScaled
	kSetFloat
	kBitstringCmd
	kEndOfInit
	kInterrogation
	kCounterInterrogation
	kRead
	kClockSync
	kTestCmd
	kResetProcess
	kDelay
	kParamNormalized
	kParamScaled
	kParamFloat
	kParamActivation
	kFileReady
	kSectionReady
	kFileCall
	kFileLast
	kFileAck
	kFileSegment
	kFileDirectory
	kFileQuery
)

type timeTag uint8

const (
	tagNone timeTag = iota
	tagCP24
	tagCP56
	tagCP56Pair // two CP56Time2a: a time range
)

func (t timeTag) size() int {
	switch t {
	case tagCP24:
		return sizeCP24
	case tagCP56:
		return sizeCP56
	case tagCP56Pair:
		return 2 * sizeCP56
	default:
		return 0
	}
}

// typeDesc describes how one type identification is laid out.
type typeDesc struct {
	id   TypeID
	name string
	desc string
	kind kind
	size int // information elements, without address and time tag
	tag  timeTag
	dec  func(ioa IOA, b []byte, ts Timestamp, d *typeDesc) InformationObject
	// variable marks a type whose single object ends in a byte string of
	// its own length (F_SG_NA_1); size is then the fixed part.
	variable bool
	// dec2 replaces dec for a type with tagCP56Pair.
	dec2 func(ioa IOA, b []byte, from, to Timestamp) InformationObject
}

var registry [256]*typeDesc

// defaultTypes maps an object kind to the type identification [New] picks
// for it: index 0 without a time tag, index 1 with one.
var defaultTypes = map[kind][2]TypeID{}

func register(id TypeID, name, desc string, k kind, size int, tag timeTag,
	dec func(IOA, []byte, Timestamp, *typeDesc) InformationObject) {
	registry[id] = &typeDesc{id: id, name: name, desc: desc, kind: k, size: size, tag: tag, dec: dec}
	def := defaultTypes[k]
	switch {
	case tag == tagNone && def[0] == 0:
		def[0] = id
	case (tag == tagCP56 || tag == tagCP56Pair) && def[1] == 0:
		def[1] = id
	}
	defaultTypes[k] = def
}

// TypeOf returns the type identification [New] uses for obj: the type
// without time tag when the object's Time is zero, the type with
// CP56Time2a otherwise. Kinds that exist in only one form always map to it.
func TypeOf(obj InformationObject) TypeID {
	def := defaultTypes[obj.kind()]
	if (!obj.stamp().IsZero() && def[1] != 0) || def[0] == 0 {
		return def[1]
	}
	return def[0]
}

func rangeErr(what string, v, lo, hi int) error {
	return fmt.Errorf("%w: %s %d, want %d..%d", ErrInvalidValue, what, v, lo, hi)
}

func bit(v bool, mask byte) byte {
	if v {
		return mask
	}
	return 0
}

// --- Process information in monitor direction ---

// SinglePoint is single-point information (SIQ): M_SP_NA_1, M_SP_TA_1 and
// M_SP_TB_1.
type SinglePoint struct {
	IOA     IOA
	Value   bool
	Quality Quality // BL, SB, NT, IV
	Time    Timestamp
}

// Address returns the information object address.
func (o SinglePoint) Address() IOA { return o.IOA }
func (SinglePoint) kind() kind     { return kSinglePoint }
func (o SinglePoint) stamp() Timestamp {
	return o.Time
}
func (o SinglePoint) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(b, bit(o.Value, 0x01)|byte(o.Quality&maskSIQ)), nil
}

// DoublePoint is double-point information (DIQ): M_DP_NA_1, M_DP_TA_1 and
// M_DP_TB_1.
type DoublePoint struct {
	IOA     IOA
	Value   DoubleState
	Quality Quality // BL, SB, NT, IV
	Time    Timestamp
}

// Address returns the information object address.
func (o DoublePoint) Address() IOA     { return o.IOA }
func (DoublePoint) kind() kind         { return kDoublePoint }
func (o DoublePoint) stamp() Timestamp { return o.Time }
func (o DoublePoint) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Value > 3 {
		return b, rangeErr("double-point state", int(o.Value), 0, 3)
	}
	return append(b, byte(o.Value)|byte(o.Quality&maskSIQ)), nil
}

// StepPosition is step position information (VTI and QDS): M_ST_NA_1,
// M_ST_TA_1 and M_ST_TB_1.
type StepPosition struct {
	IOA       IOA
	Value     int8 // -64..63
	Transient bool // equipment is in a transient state
	Quality   Quality
	Time      Timestamp
}

// Address returns the information object address.
func (o StepPosition) Address() IOA     { return o.IOA }
func (StepPosition) kind() kind         { return kStepPosition }
func (o StepPosition) stamp() Timestamp { return o.Time }
func (o StepPosition) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Value < -64 || o.Value > 63 {
		return b, rangeErr("step position", int(o.Value), -64, 63)
	}
	return append(b, byte(o.Value)&0x7F|bit(o.Transient, 0x80), byte(o.Quality&maskQDS)), nil
}

// Bitstring32 is a bitstring of 32 bit (BSI and QDS): M_BO_NA_1, M_BO_TA_1
// and M_BO_TB_1.
type Bitstring32 struct {
	IOA     IOA
	Value   uint32
	Quality Quality
	Time    Timestamp
}

// Address returns the information object address.
func (o Bitstring32) Address() IOA     { return o.IOA }
func (Bitstring32) kind() kind         { return kBitstring }
func (o Bitstring32) stamp() Timestamp { return o.Time }
func (o Bitstring32) body(b []byte, _ *typeDesc) ([]byte, error) {
	b = binary.LittleEndian.AppendUint32(b, o.Value)
	return append(b, byte(o.Quality&maskQDS)), nil
}

// MeasuredNormalized is a normalized measured value (NVA and QDS):
// M_ME_NA_1, M_ME_TA_1, M_ME_TD_1 and, without quality descriptor,
// M_ME_ND_1.
type MeasuredNormalized struct {
	IOA     IOA
	Value   Normalized
	Quality Quality // not carried by M_ME_ND_1
	Time    Timestamp
}

// Address returns the information object address.
func (o MeasuredNormalized) Address() IOA     { return o.IOA }
func (MeasuredNormalized) kind() kind         { return kNormalized }
func (o MeasuredNormalized) stamp() Timestamp { return o.Time }
func (o MeasuredNormalized) body(b []byte, d *typeDesc) ([]byte, error) {
	b = binary.LittleEndian.AppendUint16(b, uint16(o.Value))
	if d.id == M_ME_ND_1 {
		return b, nil
	}
	return append(b, byte(o.Quality&maskQDS)), nil
}

// MeasuredScaled is a scaled measured value (SVA and QDS): M_ME_NB_1,
// M_ME_TB_1 and M_ME_TE_1.
type MeasuredScaled struct {
	IOA     IOA
	Value   int16
	Quality Quality
	Time    Timestamp
}

// Address returns the information object address.
func (o MeasuredScaled) Address() IOA     { return o.IOA }
func (MeasuredScaled) kind() kind         { return kScaled }
func (o MeasuredScaled) stamp() Timestamp { return o.Time }
func (o MeasuredScaled) body(b []byte, _ *typeDesc) ([]byte, error) {
	b = binary.LittleEndian.AppendUint16(b, uint16(o.Value))
	return append(b, byte(o.Quality&maskQDS)), nil
}

// MeasuredFloat is a short floating point measured value (IEEE 754 and
// QDS): M_ME_NC_1, M_ME_TC_1 and M_ME_TF_1.
type MeasuredFloat struct {
	IOA     IOA
	Value   float32
	Quality Quality
	Time    Timestamp
}

// Address returns the information object address.
func (o MeasuredFloat) Address() IOA     { return o.IOA }
func (MeasuredFloat) kind() kind         { return kFloat }
func (o MeasuredFloat) stamp() Timestamp { return o.Time }
func (o MeasuredFloat) body(b []byte, _ *typeDesc) ([]byte, error) {
	b = binary.LittleEndian.AppendUint32(b, math.Float32bits(o.Value))
	return append(b, byte(o.Quality&maskQDS)), nil
}

// IntegratedTotal is a binary counter reading (BCR): M_IT_NA_1, M_IT_TA_1
// and M_IT_TB_1.
type IntegratedTotal struct {
	IOA      IOA
	Value    int32
	Sequence uint8 // sequence number, 0..31
	Carry    bool  // CY: counter overflowed in the integration period
	Adjusted bool  // CA: counter was adjusted since the last reading
	Invalid  bool  // IV: counter reading is invalid
	Time     Timestamp
}

// Address returns the information object address.
func (o IntegratedTotal) Address() IOA     { return o.IOA }
func (IntegratedTotal) kind() kind         { return kTotal }
func (o IntegratedTotal) stamp() Timestamp { return o.Time }
func (o IntegratedTotal) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Sequence > 31 {
		return b, rangeErr("counter sequence number", int(o.Sequence), 0, 31)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(o.Value))
	return append(b, o.Sequence|bit(o.Carry, 0x20)|bit(o.Adjusted, 0x40)|bit(o.Invalid, 0x80)), nil
}

// ProtectionEvent is an event of protection equipment (SEP and CP16Time2a):
// M_EP_TA_1 and M_EP_TD_1. The type always carries a time tag.
type ProtectionEvent struct {
	IOA     IOA
	State   DoubleState
	Quality Quality // EI, BL, SB, NT, IV
	Elapsed uint16  // relay duration time in milliseconds
	Time    Timestamp
}

// Address returns the information object address.
func (o ProtectionEvent) Address() IOA     { return o.IOA }
func (ProtectionEvent) kind() kind         { return kProtEvent }
func (o ProtectionEvent) stamp() Timestamp { return o.Time }
func (o ProtectionEvent) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.State > 3 {
		return b, rangeErr("event state", int(o.State), 0, 3)
	}
	b = append(b, byte(o.State)|byte(o.Quality&maskQDP))
	return binary.LittleEndian.AppendUint16(b, o.Elapsed), nil
}

// Start events of protection equipment (SPE), the bits of
// [ProtectionStart.Events].
const (
	StartGeneral uint8 = 0x01 // GS: general start of operation
	StartL1      uint8 = 0x02 // SL1: start of operation phase L1
	StartL2      uint8 = 0x04 // SL2: start of operation phase L2
	StartL3      uint8 = 0x08 // SL3: start of operation phase L3
	StartEarth   uint8 = 0x10 // SIE: start of operation IE (earth current)
	StartReverse uint8 = 0x20 // SRD: start of operation in reverse direction
)

// ProtectionStart is packed start events of protection equipment (SPE, QDP
// and CP16Time2a): M_EP_TB_1 and M_EP_TE_1. The type always carries a time
// tag.
type ProtectionStart struct {
	IOA      IOA
	Events   uint8   // Start* bits
	Quality  Quality // EI, BL, SB, NT, IV
	Duration uint16  // relay duration time in milliseconds
	Time     Timestamp
}

// Address returns the information object address.
func (o ProtectionStart) Address() IOA     { return o.IOA }
func (ProtectionStart) kind() kind         { return kProtStart }
func (o ProtectionStart) stamp() Timestamp { return o.Time }
func (o ProtectionStart) body(b []byte, _ *typeDesc) ([]byte, error) {
	b = append(b, o.Events&0x3F, byte(o.Quality&maskQDP))
	return binary.LittleEndian.AppendUint16(b, o.Duration), nil
}

// Output circuit information of protection equipment (OCI), the bits of
// [ProtectionOutput.Circuits].
const (
	OutputGeneral uint8 = 0x01 // GC: general command to output circuit
	OutputL1      uint8 = 0x02 // CL1: command to output circuit phase L1
	OutputL2      uint8 = 0x04 // CL2: command to output circuit phase L2
	OutputL3      uint8 = 0x08 // CL3: command to output circuit phase L3
)

// ProtectionOutput is packed output circuit information of protection
// equipment (OCI, QDP and CP16Time2a): M_EP_TC_1 and M_EP_TF_1. The type
// always carries a time tag.
type ProtectionOutput struct {
	IOA       IOA
	Circuits  uint8   // Output* bits
	Quality   Quality // EI, BL, SB, NT, IV
	Operating uint16  // relay operating time in milliseconds
	Time      Timestamp
}

// Address returns the information object address.
func (o ProtectionOutput) Address() IOA     { return o.IOA }
func (ProtectionOutput) kind() kind         { return kProtOutput }
func (o ProtectionOutput) stamp() Timestamp { return o.Time }
func (o ProtectionOutput) body(b []byte, _ *typeDesc) ([]byte, error) {
	b = append(b, o.Circuits&0x0F, byte(o.Quality&maskQDP))
	return binary.LittleEndian.AppendUint16(b, o.Operating), nil
}

// PackedSinglePoints is packed single-point information with status change
// detection (SCD and QDS): M_PS_NA_1.
type PackedSinglePoints struct {
	IOA     IOA
	Status  uint16 // bit n is the state of point n
	Changed uint16 // bit n is set when point n changed since the last report
	Quality Quality
}

// Address returns the information object address.
func (o PackedSinglePoints) Address() IOA   { return o.IOA }
func (PackedSinglePoints) kind() kind       { return kPacked }
func (PackedSinglePoints) stamp() Timestamp { return Timestamp{} }
func (o PackedSinglePoints) body(b []byte, _ *typeDesc) ([]byte, error) {
	b = binary.LittleEndian.AppendUint16(b, o.Status)
	b = binary.LittleEndian.AppendUint16(b, o.Changed)
	return append(b, byte(o.Quality&maskQDS)), nil
}

// --- Process information in control direction ---

func commandOctet(state uint8, q CommandQualifier, sel bool) (byte, error) {
	if q > 31 {
		return 0, rangeErr("command qualifier", int(q), 0, 31)
	}
	return state | byte(q)<<2 | bit(sel, 0x80), nil
}

// SingleCommand is a single command (SCO): C_SC_NA_1 and C_SC_TA_1.
type SingleCommand struct {
	IOA       IOA
	Value     bool
	Qualifier CommandQualifier
	Select    bool // true selects, false executes
	Time      Timestamp
}

// Address returns the information object address.
func (o SingleCommand) Address() IOA     { return o.IOA }
func (SingleCommand) kind() kind         { return kSingleCmd }
func (o SingleCommand) stamp() Timestamp { return o.Time }
func (o SingleCommand) body(b []byte, _ *typeDesc) ([]byte, error) {
	c, err := commandOctet(bit(o.Value, 0x01), o.Qualifier, o.Select)
	return append(b, c), err
}

// DoubleCommand is a double command (DCO): C_DC_NA_1 and C_DC_TA_1.
type DoubleCommand struct {
	IOA       IOA
	Value     DoubleState // DoubleOff or DoubleOn
	Qualifier CommandQualifier
	Select    bool // true selects, false executes
	Time      Timestamp
}

// Address returns the information object address.
func (o DoubleCommand) Address() IOA     { return o.IOA }
func (DoubleCommand) kind() kind         { return kDoubleCmd }
func (o DoubleCommand) stamp() Timestamp { return o.Time }
func (o DoubleCommand) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Value > 3 {
		return b, rangeErr("double command state", int(o.Value), 0, 3)
	}
	c, err := commandOctet(byte(o.Value), o.Qualifier, o.Select)
	return append(b, c), err
}

// StepCommand is a regulating step command (RCO): C_RC_NA_1 and C_RC_TA_1.
type StepCommand struct {
	IOA       IOA
	Value     StepDirection // StepLower or StepHigher
	Qualifier CommandQualifier
	Select    bool // true selects, false executes
	Time      Timestamp
}

// Address returns the information object address.
func (o StepCommand) Address() IOA     { return o.IOA }
func (StepCommand) kind() kind         { return kStepCmd }
func (o StepCommand) stamp() Timestamp { return o.Time }
func (o StepCommand) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Value > 3 {
		return b, rangeErr("step command state", int(o.Value), 0, 3)
	}
	c, err := commandOctet(byte(o.Value), o.Qualifier, o.Select)
	return append(b, c), err
}

func setpointOctet(ql uint8, sel bool) (byte, error) {
	if ql > 127 {
		return 0, rangeErr("set-point qualifier", int(ql), 0, 127)
	}
	return ql | bit(sel, 0x80), nil
}

// SetpointNormalized is a normalized set-point command (NVA and QOS):
// C_SE_NA_1 and C_SE_TA_1.
type SetpointNormalized struct {
	IOA       IOA
	Value     Normalized
	Qualifier uint8 // QL, 0..127
	Select    bool  // true selects, false executes
	Time      Timestamp
}

// Address returns the information object address.
func (o SetpointNormalized) Address() IOA     { return o.IOA }
func (SetpointNormalized) kind() kind         { return kSetNormalized }
func (o SetpointNormalized) stamp() Timestamp { return o.Time }
func (o SetpointNormalized) body(b []byte, _ *typeDesc) ([]byte, error) {
	q, err := setpointOctet(o.Qualifier, o.Select)
	return append(binary.LittleEndian.AppendUint16(b, uint16(o.Value)), q), err
}

// SetpointScaled is a scaled set-point command (SVA and QOS): C_SE_NB_1 and
// C_SE_TB_1.
type SetpointScaled struct {
	IOA       IOA
	Value     int16
	Qualifier uint8 // QL, 0..127
	Select    bool  // true selects, false executes
	Time      Timestamp
}

// Address returns the information object address.
func (o SetpointScaled) Address() IOA     { return o.IOA }
func (SetpointScaled) kind() kind         { return kSetScaled }
func (o SetpointScaled) stamp() Timestamp { return o.Time }
func (o SetpointScaled) body(b []byte, _ *typeDesc) ([]byte, error) {
	q, err := setpointOctet(o.Qualifier, o.Select)
	return append(binary.LittleEndian.AppendUint16(b, uint16(o.Value)), q), err
}

// SetpointFloat is a short floating point set-point command (IEEE 754 and
// QOS): C_SE_NC_1 and C_SE_TC_1.
type SetpointFloat struct {
	IOA       IOA
	Value     float32
	Qualifier uint8 // QL, 0..127
	Select    bool  // true selects, false executes
	Time      Timestamp
}

// Address returns the information object address.
func (o SetpointFloat) Address() IOA     { return o.IOA }
func (SetpointFloat) kind() kind         { return kSetFloat }
func (o SetpointFloat) stamp() Timestamp { return o.Time }
func (o SetpointFloat) body(b []byte, _ *typeDesc) ([]byte, error) {
	q, err := setpointOctet(o.Qualifier, o.Select)
	return append(binary.LittleEndian.AppendUint32(b, math.Float32bits(o.Value)), q), err
}

// BitstringCommand is a bitstring of 32 bit command (BSI): C_BO_NA_1 and
// C_BO_TA_1.
type BitstringCommand struct {
	IOA   IOA
	Value uint32
	Time  Timestamp
}

// Address returns the information object address.
func (o BitstringCommand) Address() IOA     { return o.IOA }
func (BitstringCommand) kind() kind         { return kBitstringCmd }
func (o BitstringCommand) stamp() Timestamp { return o.Time }
func (o BitstringCommand) body(b []byte, _ *typeDesc) ([]byte, error) {
	return binary.LittleEndian.AppendUint32(b, o.Value), nil
}

// --- System information ---

// EndOfInitialization reports that a station finished initializing (COI):
// M_EI_NA_1. Its address is always zero.
type EndOfInitialization struct {
	IOA         IOA
	Cause       uint8 // Init* cause of initialization, 0..127
	LocalChange bool  // initialization after a change of local parameters
}

// Address returns the information object address.
func (o EndOfInitialization) Address() IOA   { return o.IOA }
func (EndOfInitialization) kind() kind       { return kEndOfInit }
func (EndOfInitialization) stamp() Timestamp { return Timestamp{} }
func (o EndOfInitialization) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Cause > 127 {
		return b, rangeErr("cause of initialization", int(o.Cause), 0, 127)
	}
	return append(b, o.Cause|bit(o.LocalChange, 0x80)), nil
}

// Interrogation is an interrogation command (QOI): C_IC_NA_1. Its address
// is always zero.
type Interrogation struct {
	IOA       IOA
	Qualifier QOI
}

// Address returns the information object address.
func (o Interrogation) Address() IOA   { return o.IOA }
func (Interrogation) kind() kind       { return kInterrogation }
func (Interrogation) stamp() Timestamp { return Timestamp{} }
func (o Interrogation) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(b, byte(o.Qualifier)), nil
}

// CounterInterrogation is a counter interrogation command (QCC): C_CI_NA_1.
// Its address is always zero.
type CounterInterrogation struct {
	IOA     IOA
	Request uint8 // RQT: Counter* request, 0..63
	Freeze  uint8 // FRZ: Freeze* qualifier, 0..3
}

// Address returns the information object address.
func (o CounterInterrogation) Address() IOA   { return o.IOA }
func (CounterInterrogation) kind() kind       { return kCounterInterrogation }
func (CounterInterrogation) stamp() Timestamp { return Timestamp{} }
func (o CounterInterrogation) body(b []byte, _ *typeDesc) ([]byte, error) {
	if o.Request > 63 {
		return b, rangeErr("counter request", int(o.Request), 0, 63)
	}
	if o.Freeze > 3 {
		return b, rangeErr("counter freeze", int(o.Freeze), 0, 3)
	}
	return append(b, o.Request|o.Freeze<<6), nil
}

// Cause returns the cause of transmission the controlled station uses for
// counters sent in answer to this request.
func (o CounterInterrogation) Cause() Cause {
	if o.Request >= CounterGroup1 && o.Request <= CounterGroup4 {
		return CauseCounterGeneral + Cause(o.Request)
	}
	return CauseCounterGeneral
}

// Read is a read command: C_RD_NA_1. It has no information elements; the
// address names the object to read.
type Read struct {
	IOA IOA
}

// Address returns the information object address.
func (o Read) Address() IOA                             { return o.IOA }
func (Read) kind() kind                                 { return kRead }
func (Read) stamp() Timestamp                           { return Timestamp{} }
func (Read) body(b []byte, _ *typeDesc) ([]byte, error) { return b, nil }

// ClockSync is a clock synchronization command (CP56Time2a): C_CS_NA_1. Its
// address is always zero.
type ClockSync struct {
	IOA  IOA
	Time Timestamp
}

// Address returns the information object address.
func (o ClockSync) Address() IOA                             { return o.IOA }
func (ClockSync) kind() kind                                 { return kClockSync }
func (o ClockSync) stamp() Timestamp                         { return o.Time }
func (ClockSync) body(b []byte, _ *typeDesc) ([]byte, error) { return b, nil }

// TestPattern is the fixed test bit pattern (FBP) of C_TS_NA_1.
const TestPattern uint16 = 0x55AA

// TestCommand is a test command: C_TS_NA_1, where Counter is the fixed test
// pattern [TestPattern], and C_TS_TA_1, where it is the test sequence
// counter (TSC) and a CP56Time2a follows. IEC 60870-5-104 uses C_TS_TA_1
// only. Its address is always zero.
type TestCommand struct {
	IOA     IOA
	Counter uint16
	Time    Timestamp
}

// Address returns the information object address.
func (o TestCommand) Address() IOA     { return o.IOA }
func (TestCommand) kind() kind         { return kTestCmd }
func (o TestCommand) stamp() Timestamp { return o.Time }
func (o TestCommand) body(b []byte, _ *typeDesc) ([]byte, error) {
	return binary.LittleEndian.AppendUint16(b, o.Counter), nil
}

// ResetProcess is a reset process command (QRP): C_RP_NA_1. Its address is
// always zero.
type ResetProcess struct {
	IOA       IOA
	Qualifier uint8 // ResetProcessGeneral or ResetPendingEvents
}

// Address returns the information object address.
func (o ResetProcess) Address() IOA   { return o.IOA }
func (ResetProcess) kind() kind       { return kResetProcess }
func (ResetProcess) stamp() Timestamp { return Timestamp{} }
func (o ResetProcess) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(b, o.Qualifier), nil
}

// DelayAcquisition is a delay acquisition command (CP16Time2a): C_CD_NA_1.
// It is not used by IEC 60870-5-104. Its address is always zero.
type DelayAcquisition struct {
	IOA   IOA
	Delay uint16 // milliseconds
}

// Address returns the information object address.
func (o DelayAcquisition) Address() IOA   { return o.IOA }
func (DelayAcquisition) kind() kind       { return kDelay }
func (DelayAcquisition) stamp() Timestamp { return Timestamp{} }
func (o DelayAcquisition) body(b []byte, _ *typeDesc) ([]byte, error) {
	return binary.LittleEndian.AppendUint16(b, o.Delay), nil
}

// --- Parameters ---

// ParameterNormalized is a parameter of a normalized measured value (NVA
// and QPM): P_ME_NA_1.
type ParameterNormalized struct {
	IOA       IOA
	Value     Normalized
	Qualifier uint8 // QPM: Parameter* kind and flags
}

// Address returns the information object address.
func (o ParameterNormalized) Address() IOA   { return o.IOA }
func (ParameterNormalized) kind() kind       { return kParamNormalized }
func (ParameterNormalized) stamp() Timestamp { return Timestamp{} }
func (o ParameterNormalized) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint16(b, uint16(o.Value)), o.Qualifier), nil
}

// ParameterScaled is a parameter of a scaled measured value (SVA and QPM):
// P_ME_NB_1.
type ParameterScaled struct {
	IOA       IOA
	Value     int16
	Qualifier uint8 // QPM: Parameter* kind and flags
}

// Address returns the information object address.
func (o ParameterScaled) Address() IOA   { return o.IOA }
func (ParameterScaled) kind() kind       { return kParamScaled }
func (ParameterScaled) stamp() Timestamp { return Timestamp{} }
func (o ParameterScaled) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint16(b, uint16(o.Value)), o.Qualifier), nil
}

// ParameterFloat is a parameter of a short floating point measured value
// (IEEE 754 and QPM): P_ME_NC_1.
type ParameterFloat struct {
	IOA       IOA
	Value     float32
	Qualifier uint8 // QPM: Parameter* kind and flags
}

// Address returns the information object address.
func (o ParameterFloat) Address() IOA   { return o.IOA }
func (ParameterFloat) kind() kind       { return kParamFloat }
func (ParameterFloat) stamp() Timestamp { return Timestamp{} }
func (o ParameterFloat) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint32(b, math.Float32bits(o.Value)), o.Qualifier), nil
}

// Qualifiers of parameter activation (QPA).
const (
	ActivateLoadedParameters uint8 = 1 // Act/deact of previously loaded parameters
	ActivateObjectParameter  uint8 = 2 // Act/deact of the parameter of the addressed object
	ActivateCyclic           uint8 = 3 // Act/deact of persistent cyclic or periodic transmission
)

// ParameterActivation is a parameter activation (QPA): P_AC_NA_1.
type ParameterActivation struct {
	IOA       IOA
	Qualifier uint8 // Activate* qualifier
}

// Address returns the information object address.
func (o ParameterActivation) Address() IOA   { return o.IOA }
func (ParameterActivation) kind() kind       { return kParamActivation }
func (ParameterActivation) stamp() Timestamp { return Timestamp{} }
func (o ParameterActivation) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(b, o.Qualifier), nil
}

// --- File transfer ---

// File transfer qualifiers. Each is the low nibble of its octet; the high
// nibble carries an error or a private qualifier.
const (
	// Select and call qualifier (SCQ) of [FileCall].
	FileSelect        uint8 = 1 // Select file
	FileRequest       uint8 = 2 // Request file
	FileDeactivate    uint8 = 3 // Deactivate file
	FileDelete        uint8 = 4 // Delete file
	SectionSelect     uint8 = 5 // Select section
	SectionRequest    uint8 = 6 // Request section
	SectionDeactivate uint8 = 7 // Deactivate section

	// Last section or segment qualifier (LSQ) of [FileLastSegment].
	LastFileNoDeactivation    uint8 = 1 // File transfer without deactivation
	LastFileDeactivation      uint8 = 2 // File transfer with deactivation
	LastSectionNoDeactivation uint8 = 3 // Section transfer without deactivation
	LastSectionDeactivation   uint8 = 4 // Section transfer with deactivation

	// Acknowledge file or section qualifier (AFQ) of [FileAck].
	AckFilePositive    uint8 = 1 // Positive acknowledge of file transfer
	AckFileNegative    uint8 = 2 // Negative acknowledge of file transfer
	AckSectionPositive uint8 = 3 // Positive acknowledge of section transfer
	AckSectionNegative uint8 = 4 // Negative acknowledge of section transfer

	// FileNegative is the bit of a file ready qualifier (FRQ) or section
	// ready qualifier (SRQ) that refuses the select, request, deactivate or
	// delete, or reports the section as not ready.
	FileNegative uint8 = 0x80

	// Status of file (SOF) flags of [FileDirectoryEntry]; the low five
	// bits are a status value.
	FileLastOfDirectory uint8 = 0x20 // LFD: last file of the directory
	FileIsDirectory     uint8 = 0x40 // FOR: the name is a subdirectory
	FileActive          uint8 = 0x80 // FA: the file is being transferred
)

// MaxFileLength is the largest length of a file or section (LOF): 24 bits.
const MaxFileLength = 1<<24 - 1

func appendFileLength(b []byte, n uint32) ([]byte, error) {
	if n > MaxFileLength {
		return b, rangeErr("length of file or section", int(n), 0, MaxFileLength)
	}
	return append(b, byte(n), byte(n>>8), byte(n>>16)), nil
}

func fileLength(b []byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 }

// FileReady announces a file, or refuses a file request (NOF, LOF and FRQ):
// F_FR_NA_1.
type FileReady struct {
	IOA       IOA
	Name      uint16 // NOF: name of file
	Length    uint32 // LOF: length in octets, up to MaxFileLength
	Qualifier uint8  // FRQ; FileNegative when the request is refused
}

// Address returns the information object address.
func (o FileReady) Address() IOA   { return o.IOA }
func (FileReady) kind() kind       { return kFileReady }
func (FileReady) stamp() Timestamp { return Timestamp{} }
func (o FileReady) body(b []byte, _ *typeDesc) ([]byte, error) {
	b, err := appendFileLength(binary.LittleEndian.AppendUint16(b, o.Name), o.Length)
	return append(b, o.Qualifier), err
}

// SectionReady announces a section of a file (NOF, NOS, LOF and SRQ):
// F_SR_NA_1.
type SectionReady struct {
	IOA       IOA
	Name      uint16 // NOF: name of file
	Section   uint8  // NOS: name of section
	Length    uint32 // LOF: length of the section in octets
	Qualifier uint8  // SRQ; FileNegative when the section is not ready
}

// Address returns the information object address.
func (o SectionReady) Address() IOA   { return o.IOA }
func (SectionReady) kind() kind       { return kSectionReady }
func (SectionReady) stamp() Timestamp { return Timestamp{} }
func (o SectionReady) body(b []byte, _ *typeDesc) ([]byte, error) {
	b, err := appendFileLength(append(binary.LittleEndian.AppendUint16(b, o.Name), o.Section), o.Length)
	return append(b, o.Qualifier), err
}

// FileCall calls a directory, or selects, requests, deactivates or deletes
// a file or a section (NOF, NOS and SCQ): F_SC_NA_1.
type FileCall struct {
	IOA       IOA
	Name      uint16 // NOF: name of file
	Section   uint8  // NOS: name of section
	Qualifier uint8  // SCQ: FileSelect, FileRequest, ...
}

// Address returns the information object address.
func (o FileCall) Address() IOA   { return o.IOA }
func (FileCall) kind() kind       { return kFileCall }
func (FileCall) stamp() Timestamp { return Timestamp{} }
func (o FileCall) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint16(b, o.Name), o.Section, o.Qualifier), nil
}

// FileLastSegment ends a section or a file and carries its checksum (NOF,
// NOS, LSQ and CHS): F_LS_NA_1.
type FileLastSegment struct {
	IOA       IOA
	Name      uint16 // NOF: name of file
	Section   uint8  // NOS: name of section
	Qualifier uint8  // LSQ: LastFile..., LastSection...
	Checksum  uint8  // CHS: sum modulo 256 of the octets of the section or file
}

// Address returns the information object address.
func (o FileLastSegment) Address() IOA   { return o.IOA }
func (FileLastSegment) kind() kind       { return kFileLast }
func (FileLastSegment) stamp() Timestamp { return Timestamp{} }
func (o FileLastSegment) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint16(b, o.Name), o.Section, o.Qualifier, o.Checksum), nil
}

// FileAck acknowledges a file or a section (NOF, NOS and AFQ): F_AF_NA_1.
type FileAck struct {
	IOA       IOA
	Name      uint16 // NOF: name of file
	Section   uint8  // NOS: name of section
	Qualifier uint8  // AFQ: AckFilePositive, ...
}

// Address returns the information object address.
func (o FileAck) Address() IOA   { return o.IOA }
func (FileAck) kind() kind       { return kFileAck }
func (FileAck) stamp() Timestamp { return Timestamp{} }
func (o FileAck) body(b []byte, _ *typeDesc) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint16(b, o.Name), o.Section, o.Qualifier), nil
}

// MaxSegmentLength is the largest segment an IEC 60870-5-104 ASDU can
// carry: 249 octets less the data unit identifier, the address and the
// segment header.
const MaxSegmentLength = 249 - 6 - 3 - 4

// FileSegment carries one segment of a section (NOF, NOS, LOS and the
// segment): F_SG_NA_1. An ASDU holds exactly one segment. Because Data is a
// slice, a FileSegment cannot be compared with ==.
type FileSegment struct {
	IOA     IOA
	Name    uint16 // NOF: name of file
	Section uint8  // NOS: name of section
	Data    []byte // the segment, up to 255 octets (LOS) and the ASDU size
}

// Address returns the information object address.
func (o FileSegment) Address() IOA   { return o.IOA }
func (FileSegment) kind() kind       { return kFileSegment }
func (FileSegment) stamp() Timestamp { return Timestamp{} }
func (o FileSegment) body(b []byte, _ *typeDesc) ([]byte, error) {
	if len(o.Data) > 255 {
		return b, rangeErr("length of segment", len(o.Data), 0, 255)
	}
	b = append(binary.LittleEndian.AppendUint16(b, o.Name), o.Section, byte(len(o.Data)))
	return append(b, o.Data...), nil
}

// FileDirectoryEntry is one entry of a directory (NOF, LOF, SOF and
// CP56Time2a): F_DR_TA_1. A directory is sent as a sequence (SQ = 1): the
// address of each entry is the address of its file.
type FileDirectoryEntry struct {
	IOA    IOA
	Name   uint16    // NOF: name of file or subdirectory
	Length uint32    // LOF: length in octets
	Status uint8     // SOF: status and the File... flags
	Time   Timestamp // creation time
}

// Address returns the information object address.
func (o FileDirectoryEntry) Address() IOA     { return o.IOA }
func (FileDirectoryEntry) kind() kind         { return kFileDirectory }
func (o FileDirectoryEntry) stamp() Timestamp { return o.Time }
func (o FileDirectoryEntry) body(b []byte, _ *typeDesc) ([]byte, error) {
	b, err := appendFileLength(binary.LittleEndian.AppendUint16(b, o.Name), o.Length)
	return append(b, o.Status), err
}

// FileQueryLog requests an archive file for a time range (NOF and two
// CP56Time2a): F_SC_NB_1.
type FileQueryLog struct {
	IOA   IOA
	Name  uint16 // NOF: name of file
	Start Timestamp
	Stop  Timestamp
}

// Address returns the information object address.
func (o FileQueryLog) Address() IOA   { return o.IOA }
func (FileQueryLog) kind() kind       { return kFileQuery }
func (FileQueryLog) stamp() Timestamp { return Timestamp{} }
func (o FileQueryLog) body(b []byte, _ *typeDesc) ([]byte, error) {
	return binary.LittleEndian.AppendUint16(b, o.Name), nil
}

// --- Decoders and registry ---

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// vti decodes the 7-bit two's complement step position value.
func vti(b byte) int8 { return int8(b<<1) >> 1 }

func init() {
	type dec = func(IOA, []byte, Timestamp, *typeDesc) InformationObject

	variants := func(k kind, size int, d dec, desc string, ids ...struct {
		id   TypeID
		name string
		tag  timeTag
	}) {
		for _, v := range ids {
			full := desc
			switch v.tag {
			case tagCP24:
				full += " with CP24Time2a"
			case tagCP56:
				full += " with CP56Time2a"
			case tagNone, tagCP56Pair:
			}
			register(v.id, v.name, full, k, size, v.tag, d)
		}
	}
	type v = struct {
		id   TypeID
		name string
		tag  timeTag
	}

	variants(kSinglePoint, 1, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return SinglePoint{IOA: a, Value: b[0]&0x01 != 0, Quality: Quality(b[0]) & maskSIQ, Time: ts}
	}, "Single-point information",
		v{M_SP_NA_1, "M_SP_NA_1", tagNone}, v{M_SP_TA_1, "M_SP_TA_1", tagCP24}, v{M_SP_TB_1, "M_SP_TB_1", tagCP56})

	variants(kDoublePoint, 1, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return DoublePoint{IOA: a, Value: DoubleState(b[0] & 0x03), Quality: Quality(b[0]) & maskSIQ, Time: ts}
	}, "Double-point information",
		v{M_DP_NA_1, "M_DP_NA_1", tagNone}, v{M_DP_TA_1, "M_DP_TA_1", tagCP24}, v{M_DP_TB_1, "M_DP_TB_1", tagCP56})

	variants(kStepPosition, 2, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return StepPosition{IOA: a, Value: vti(b[0]), Transient: b[0]&0x80 != 0, Quality: Quality(b[1]) & maskQDS, Time: ts}
	}, "Step position information",
		v{M_ST_NA_1, "M_ST_NA_1", tagNone}, v{M_ST_TA_1, "M_ST_TA_1", tagCP24}, v{M_ST_TB_1, "M_ST_TB_1", tagCP56})

	variants(kBitstring, 5, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return Bitstring32{IOA: a, Value: u32(b), Quality: Quality(b[4]) & maskQDS, Time: ts}
	}, "Bitstring of 32 bit",
		v{M_BO_NA_1, "M_BO_NA_1", tagNone}, v{M_BO_TA_1, "M_BO_TA_1", tagCP24}, v{M_BO_TB_1, "M_BO_TB_1", tagCP56})

	decNormalized := func(a IOA, b []byte, ts Timestamp, d *typeDesc) InformationObject {
		o := MeasuredNormalized{IOA: a, Value: Normalized(u16(b)), Time: ts}
		if d.id != M_ME_ND_1 {
			o.Quality = Quality(b[2]) & maskQDS
		}
		return o
	}
	variants(kNormalized, 3, decNormalized, "Measured value, normalized",
		v{M_ME_NA_1, "M_ME_NA_1", tagNone}, v{M_ME_TA_1, "M_ME_TA_1", tagCP24}, v{M_ME_TD_1, "M_ME_TD_1", tagCP56})
	register(M_ME_ND_1, "M_ME_ND_1", "Measured value, normalized without quality descriptor",
		kNormalized, 2, tagNone, decNormalized)

	variants(kScaled, 3, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return MeasuredScaled{IOA: a, Value: int16(u16(b)), Quality: Quality(b[2]) & maskQDS, Time: ts}
	}, "Measured value, scaled",
		v{M_ME_NB_1, "M_ME_NB_1", tagNone}, v{M_ME_TB_1, "M_ME_TB_1", tagCP24}, v{M_ME_TE_1, "M_ME_TE_1", tagCP56})

	variants(kFloat, 5, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return MeasuredFloat{IOA: a, Value: math.Float32frombits(u32(b)), Quality: Quality(b[4]) & maskQDS, Time: ts}
	}, "Measured value, short floating point",
		v{M_ME_NC_1, "M_ME_NC_1", tagNone}, v{M_ME_TC_1, "M_ME_TC_1", tagCP24}, v{M_ME_TF_1, "M_ME_TF_1", tagCP56})

	variants(kTotal, 5, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return IntegratedTotal{IOA: a, Value: int32(u32(b)), Sequence: b[4] & 0x1F,
			Carry: b[4]&0x20 != 0, Adjusted: b[4]&0x40 != 0, Invalid: b[4]&0x80 != 0, Time: ts}
	}, "Integrated totals",
		v{M_IT_NA_1, "M_IT_NA_1", tagNone}, v{M_IT_TA_1, "M_IT_TA_1", tagCP24}, v{M_IT_TB_1, "M_IT_TB_1", tagCP56})

	variants(kProtEvent, 3, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return ProtectionEvent{IOA: a, State: DoubleState(b[0] & 0x03), Quality: Quality(b[0]) & maskQDP,
			Elapsed: u16(b[1:]), Time: ts}
	}, "Event of protection equipment",
		v{M_EP_TA_1, "M_EP_TA_1", tagCP24}, v{M_EP_TD_1, "M_EP_TD_1", tagCP56})

	variants(kProtStart, 4, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return ProtectionStart{IOA: a, Events: b[0] & 0x3F, Quality: Quality(b[1]) & maskQDP,
			Duration: u16(b[2:]), Time: ts}
	}, "Packed start events of protection equipment",
		v{M_EP_TB_1, "M_EP_TB_1", tagCP24}, v{M_EP_TE_1, "M_EP_TE_1", tagCP56})

	variants(kProtOutput, 4, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return ProtectionOutput{IOA: a, Circuits: b[0] & 0x0F, Quality: Quality(b[1]) & maskQDP,
			Operating: u16(b[2:]), Time: ts}
	}, "Packed output circuit information of protection equipment",
		v{M_EP_TC_1, "M_EP_TC_1", tagCP24}, v{M_EP_TF_1, "M_EP_TF_1", tagCP56})

	register(M_PS_NA_1, "M_PS_NA_1", "Packed single-point information with status change detection",
		kPacked, 5, tagNone, func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return PackedSinglePoints{IOA: a, Status: u16(b), Changed: u16(b[2:]), Quality: Quality(b[4]) & maskQDS}
		})

	variants(kSingleCmd, 1, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return SingleCommand{IOA: a, Value: b[0]&0x01 != 0, Qualifier: CommandQualifier(b[0] >> 2 & 0x1F),
			Select: b[0]&0x80 != 0, Time: ts}
	}, "Single command", v{C_SC_NA_1, "C_SC_NA_1", tagNone}, v{C_SC_TA_1, "C_SC_TA_1", tagCP56})

	variants(kDoubleCmd, 1, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return DoubleCommand{IOA: a, Value: DoubleState(b[0] & 0x03), Qualifier: CommandQualifier(b[0] >> 2 & 0x1F),
			Select: b[0]&0x80 != 0, Time: ts}
	}, "Double command", v{C_DC_NA_1, "C_DC_NA_1", tagNone}, v{C_DC_TA_1, "C_DC_TA_1", tagCP56})

	variants(kStepCmd, 1, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return StepCommand{IOA: a, Value: StepDirection(b[0] & 0x03), Qualifier: CommandQualifier(b[0] >> 2 & 0x1F),
			Select: b[0]&0x80 != 0, Time: ts}
	}, "Regulating step command", v{C_RC_NA_1, "C_RC_NA_1", tagNone}, v{C_RC_TA_1, "C_RC_TA_1", tagCP56})

	variants(kSetNormalized, 3, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return SetpointNormalized{IOA: a, Value: Normalized(u16(b)), Qualifier: b[2] & 0x7F, Select: b[2]&0x80 != 0, Time: ts}
	}, "Set-point command, normalized", v{C_SE_NA_1, "C_SE_NA_1", tagNone}, v{C_SE_TA_1, "C_SE_TA_1", tagCP56})

	variants(kSetScaled, 3, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return SetpointScaled{IOA: a, Value: int16(u16(b)), Qualifier: b[2] & 0x7F, Select: b[2]&0x80 != 0, Time: ts}
	}, "Set-point command, scaled", v{C_SE_NB_1, "C_SE_NB_1", tagNone}, v{C_SE_TB_1, "C_SE_TB_1", tagCP56})

	variants(kSetFloat, 5, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return SetpointFloat{IOA: a, Value: math.Float32frombits(u32(b)), Qualifier: b[4] & 0x7F, Select: b[4]&0x80 != 0, Time: ts}
	}, "Set-point command, short floating point", v{C_SE_NC_1, "C_SE_NC_1", tagNone}, v{C_SE_TC_1, "C_SE_TC_1", tagCP56})

	variants(kBitstringCmd, 4, func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return BitstringCommand{IOA: a, Value: u32(b), Time: ts}
	}, "Bitstring of 32 bit command", v{C_BO_NA_1, "C_BO_NA_1", tagNone}, v{C_BO_TA_1, "C_BO_TA_1", tagCP56})

	register(M_EI_NA_1, "M_EI_NA_1", "End of initialization", kEndOfInit, 1, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return EndOfInitialization{IOA: a, Cause: b[0] & 0x7F, LocalChange: b[0]&0x80 != 0}
		})
	register(C_IC_NA_1, "C_IC_NA_1", "Interrogation command", kInterrogation, 1, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return Interrogation{IOA: a, Qualifier: QOI(b[0])}
		})
	register(C_CI_NA_1, "C_CI_NA_1", "Counter interrogation command", kCounterInterrogation, 1, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return CounterInterrogation{IOA: a, Request: b[0] & 0x3F, Freeze: b[0] >> 6}
		})
	register(C_RD_NA_1, "C_RD_NA_1", "Read command", kRead, 0, tagNone,
		func(a IOA, _ []byte, _ Timestamp, _ *typeDesc) InformationObject { return Read{IOA: a} })
	register(C_CS_NA_1, "C_CS_NA_1", "Clock synchronization command", kClockSync, 0, tagCP56,
		func(a IOA, _ []byte, ts Timestamp, _ *typeDesc) InformationObject { return ClockSync{IOA: a, Time: ts} })
	decTest := func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
		return TestCommand{IOA: a, Counter: u16(b), Time: ts}
	}
	register(C_TS_NA_1, "C_TS_NA_1", "Test command", kTestCmd, 2, tagNone, decTest)
	register(C_TS_TA_1, "C_TS_TA_1", "Test command with CP56Time2a", kTestCmd, 2, tagCP56, decTest)
	register(C_RP_NA_1, "C_RP_NA_1", "Reset process command", kResetProcess, 1, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return ResetProcess{IOA: a, Qualifier: b[0]}
		})
	register(C_CD_NA_1, "C_CD_NA_1", "Delay acquisition command", kDelay, 2, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return DelayAcquisition{IOA: a, Delay: u16(b)}
		})
	register(P_ME_NA_1, "P_ME_NA_1", "Parameter of measured value, normalized", kParamNormalized, 3, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return ParameterNormalized{IOA: a, Value: Normalized(u16(b)), Qualifier: b[2]}
		})
	register(P_ME_NB_1, "P_ME_NB_1", "Parameter of measured value, scaled", kParamScaled, 3, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return ParameterScaled{IOA: a, Value: int16(u16(b)), Qualifier: b[2]}
		})
	register(P_ME_NC_1, "P_ME_NC_1", "Parameter of measured value, short floating point", kParamFloat, 5, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return ParameterFloat{IOA: a, Value: math.Float32frombits(u32(b)), Qualifier: b[4]}
		})
	register(P_AC_NA_1, "P_AC_NA_1", "Parameter activation", kParamActivation, 1, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return ParameterActivation{IOA: a, Qualifier: b[0]}
		})

	register(F_FR_NA_1, "F_FR_NA_1", "File ready", kFileReady, 6, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return FileReady{IOA: a, Name: u16(b), Length: fileLength(b[2:]), Qualifier: b[5]}
		})
	register(F_SR_NA_1, "F_SR_NA_1", "Section ready", kSectionReady, 7, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return SectionReady{IOA: a, Name: u16(b), Section: b[2], Length: fileLength(b[3:]), Qualifier: b[6]}
		})
	register(F_SC_NA_1, "F_SC_NA_1", "Call directory, select file, call file, call section", kFileCall, 4, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return FileCall{IOA: a, Name: u16(b), Section: b[2], Qualifier: b[3]}
		})
	register(F_LS_NA_1, "F_LS_NA_1", "Last section, last segment", kFileLast, 5, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return FileLastSegment{IOA: a, Name: u16(b), Section: b[2], Qualifier: b[3], Checksum: b[4]}
		})
	register(F_AF_NA_1, "F_AF_NA_1", "Ack file, ack section", kFileAck, 4, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return FileAck{IOA: a, Name: u16(b), Section: b[2], Qualifier: b[3]}
		})
	// The fixed part of a segment: name of file, name of section, length.
	register(F_SG_NA_1, "F_SG_NA_1", "Segment", kFileSegment, 4, tagNone,
		func(a IOA, b []byte, _ Timestamp, _ *typeDesc) InformationObject {
			return FileSegment{IOA: a, Name: u16(b), Section: b[2], Data: append([]byte(nil), b[4:]...)}
		})
	registry[F_SG_NA_1].variable = true
	register(F_DR_TA_1, "F_DR_TA_1", "Directory", kFileDirectory, 6, tagCP56,
		func(a IOA, b []byte, ts Timestamp, _ *typeDesc) InformationObject {
			return FileDirectoryEntry{IOA: a, Name: u16(b), Length: fileLength(b[2:]), Status: b[5], Time: ts}
		})
	register(F_SC_NB_1, "F_SC_NB_1", "Query log, request archive file", kFileQuery, 2, tagCP56Pair, nil)
	registry[F_SC_NB_1].dec2 = func(a IOA, b []byte, from, to Timestamp) InformationObject {
		return FileQueryLog{IOA: a, Name: u16(b), Start: from, Stop: to}
	}
}
