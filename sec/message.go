// SPDX-License-Identifier: MIT

package sec

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-iec104/asdu"
)

// A security ASDU is a data unit identifier with a variable structure
// qualifier of 1 and no information object address, followed by the
// message fields. Multi-octet integers are least significant octet first.
// On the wire an ASDU segmentation control octet (ASC) follows the data unit
// identifier of every segment (see [Segment]); the whole message as handled
// here, and as covered by the MACs, leaves it out.

// Header is the data unit identifier of a security ASDU.
type Header struct {
	Type       asdu.TypeID
	Cause      asdu.Cause
	Negative   bool
	Test       bool
	Originator uint8
	CommonAddr asdu.CommonAddr
}

func headerLen(p asdu.Params) int { return 2 + p.CauseSize + p.CommonAddrSize }

func checkParams(p asdu.Params) error {
	if p.CauseSize != 1 && p.CauseSize != 2 || p.CommonAddrSize != 1 && p.CommonAddrSize != 2 {
		return fmt.Errorf("%w: cause size %d, common address size %d", ErrConfig, p.CauseSize, p.CommonAddrSize)
	}
	return nil
}

func (h Header) append(b []byte, p asdu.Params) []byte {
	cot := byte(h.Cause) & 0x3f
	if h.Negative {
		cot |= 0x40
	}
	if h.Test {
		cot |= 0x80
	}
	b = append(b, byte(h.Type), 1, cot)
	if p.CauseSize == 2 {
		b = append(b, h.Originator)
	}
	b = append(b, byte(h.CommonAddr))
	if p.CommonAddrSize == 2 {
		b = append(b, byte(h.CommonAddr>>8))
	}
	return b
}

// parseHeader reads the data unit identifier of any ASDU; vsq is the
// variable structure qualifier.
func parseHeader(b []byte, p asdu.Params) (h Header, vsq byte, err error) {
	if len(b) < headerLen(p) {
		return h, 0, fmt.Errorf("%w: %d octets", ErrMessage, len(b))
	}
	h = Header{Type: asdu.TypeID(b[0]), Cause: asdu.Cause(b[2] & 0x3f), Negative: b[2]&0x40 != 0, Test: b[2]&0x80 != 0}
	i := 3
	if p.CauseSize == 2 {
		h.Originator = b[i]
		i++
	}
	h.CommonAddr = asdu.CommonAddr(b[i])
	if p.CommonAddrSize == 2 {
		h.CommonAddr |= asdu.CommonAddr(b[i+1]) << 8
	}
	return h, b[1], nil
}

// Message is a security message: one of the types below.
type Message interface {
	// Type is the type identification of the message.
	Type() asdu.TypeID
	// appendBody appends the fields after the data unit identifier; the
	// MAC only when mac is true.
	appendBody(b []byte, mac bool) ([]byte, error)
}

// AssociationRequest is S_AQ_NA_1, sent by the controlling station to start
// the Station Association. AIS is 0.
type AssociationRequest struct {
	AIM, AIS    uint16
	Protocol    ProtocolInfo
	Certificate []byte // DER, at most 65535 octets
}

// AssociationResponse is S_AP_NA_1, the controlled station's answer.
type AssociationResponse struct {
	AIM, AIS    uint16
	Certificate []byte // DER
	Random      []byte // challenge data, 4 to 64 octets
}

// UpdateKeyChangeRequest is S_UH_NA_1: the controlling station's algorithm
// choice and random data, authenticated with the new update keys.
type UpdateKeyChangeRequest struct {
	AIM, AIS uint16
	KeyWrap  uint8 // KWA, see [KeyWrapAES256]
	MAC      uint8 // MAL, see [MACAlgorithm]
	Random   []byte
	Tag      []byte // the MAC value
}

// UpdateKeyChangeResponse is S_UP_NA_1: the controlled station's proof that
// it derived the same update keys.
type UpdateKeyChangeResponse struct {
	AIM, AIS uint16
	Tag      []byte
}

// SessionInitiationRequest is S_SI_NA_1: a controlled station whose session
// keys became invalid asks for new ones.
type SessionInitiationRequest struct {
	AIM, AIS uint16
	Random   []byte // 4 to 64 octets
	Tag      []byte
}

// SessionRequest is S_SQ_NA_1, which starts the Session Key Change.
type SessionRequest struct {
	AIM, AIS uint16
	Protocol ProtocolInfo
	Random   []byte
}

// SessionResponse is S_SP_NA_1, the controlled station's answer.
type SessionResponse struct {
	AIM, AIS uint16
	Random   []byte // 4 to 64 octets
	Tag      []byte
}

// SessionKeyChangeRequest is S_KH_NA_1: the new session keys, wrapped with
// the encryption update key, and the data protection algorithm.
type SessionKeyChangeRequest struct {
	AIM, AIS       uint16
	DataProtection uint8 // DPA, see [DataProtection]
	Wrapped        []byte
	Tag            []byte
}

// SessionKeyChangeResponse is S_KP_NA_1, which confirms the new session keys.
type SessionKeyChangeResponse struct {
	AIM, AIS uint16
	Tag      []byte
}

// SecureData is S_SD_NA_1, which carries one application ASDU. Payload is
// everything after the sequence number: with a MAC the length of the ASDU
// (two octets), the ASDU and the MAC; with AES-256-GCM the ciphertext of the
// same length and ASDU, followed by the tag.
type SecureData struct {
	AIM, AIS uint16
	Sequence uint32 // DSQ
	Payload  []byte
}

// Type implements [Message].
func (AssociationRequest) Type() asdu.TypeID { return asdu.S_AQ_NA_1 }

// Type implements [Message].
func (AssociationResponse) Type() asdu.TypeID { return asdu.S_AP_NA_1 }

// Type implements [Message].
func (UpdateKeyChangeRequest) Type() asdu.TypeID { return asdu.S_UH_NA_1 }

// Type implements [Message].
func (UpdateKeyChangeResponse) Type() asdu.TypeID { return asdu.S_UP_NA_1 }

// Type implements [Message].
func (SessionInitiationRequest) Type() asdu.TypeID { return asdu.S_SI_NA_1 }

// Type implements [Message].
func (SessionRequest) Type() asdu.TypeID { return asdu.S_SQ_NA_1 }

// Type implements [Message].
func (SessionResponse) Type() asdu.TypeID { return asdu.S_SP_NA_1 }

// Type implements [Message].
func (SessionKeyChangeRequest) Type() asdu.TypeID { return asdu.S_KH_NA_1 }

// Type implements [Message].
func (SessionKeyChangeResponse) Type() asdu.TypeID { return asdu.S_KP_NA_1 }

// Type implements [Message].
func (SecureData) Type() asdu.TypeID { return asdu.S_SD_NA_1 }

func appendIDs(b []byte, aim, ais uint16) []byte {
	return binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(b, aim), ais)
}

// appendLen appends the length of v in size octets.
func appendLen(b, v []byte, size int, what string) ([]byte, error) {
	if len(v) >= 1<<(8*size) {
		return nil, fmt.Errorf("%w: %s of %d octets", ErrMessage, what, len(v))
	}
	if size == 1 {
		return append(b, byte(len(v))), nil
	}
	return binary.LittleEndian.AppendUint16(b, uint16(len(v))), nil
}

func appendTag(b, tag []byte, mac bool) []byte {
	if mac {
		return append(b, tag...)
	}
	return b
}

func checkRandom(r []byte, what string) error {
	if len(r) < 4 || len(r) > 64 {
		return fmt.Errorf("%w: %s random data of %d octets, want 4 to 64", ErrMessage, what, len(r))
	}
	return nil
}

func (m AssociationRequest) appendBody(b []byte, _ bool) ([]byte, error) {
	pri, err := m.Protocol.encode(false)
	if err != nil {
		return nil, err
	}
	b = append(appendIDs(b, m.AIM, m.AIS), pri[:]...)
	if b, err = appendLen(b, m.Certificate, 2, "certificate"); err != nil {
		return nil, err
	}
	return append(b, m.Certificate...), nil
}

func (m AssociationResponse) appendBody(b []byte, _ bool) ([]byte, error) {
	b, err := appendLen(appendIDs(b, m.AIM, m.AIS), m.Certificate, 2, "certificate")
	if err != nil {
		return nil, err
	}
	if b, err = appendLen(b, m.Random, 1, "random data"); err != nil {
		return nil, err
	}
	return append(append(b, m.Certificate...), m.Random...), nil
}

func (m UpdateKeyChangeRequest) appendBody(b []byte, mac bool) ([]byte, error) {
	b, err := appendLen(append(appendIDs(b, m.AIM, m.AIS), m.KeyWrap, m.MAC), m.Random, 1, "random data")
	if err != nil {
		return nil, err
	}
	return appendTag(append(b, m.Random...), m.Tag, mac), nil
}

func (m UpdateKeyChangeResponse) appendBody(b []byte, mac bool) ([]byte, error) {
	return appendTag(appendIDs(b, m.AIM, m.AIS), m.Tag, mac), nil
}

func (m SessionInitiationRequest) appendBody(b []byte, mac bool) ([]byte, error) {
	if m.AIM == 0 || m.AIS == 0 {
		return nil, fmt.Errorf("%w: session initiation request with association ID 0", ErrMessage)
	}
	if err := checkRandom(m.Random, "session initiation request"); err != nil {
		return nil, err
	}
	b = append(appendIDs(b, m.AIM, m.AIS), byte(len(m.Random)))
	return appendTag(append(b, m.Random...), m.Tag, mac), nil
}

func (m SessionRequest) appendBody(b []byte, _ bool) ([]byte, error) {
	pri, err := m.Protocol.encode(true)
	if err != nil {
		return nil, err
	}
	b, err = appendLen(append(appendIDs(b, m.AIM, m.AIS), pri[:]...), m.Random, 1, "random data")
	if err != nil {
		return nil, err
	}
	return append(b, m.Random...), nil
}

func (m SessionResponse) appendBody(b []byte, mac bool) ([]byte, error) {
	b, err := appendLen(appendIDs(b, m.AIM, m.AIS), m.Random, 1, "random data")
	if err != nil {
		return nil, err
	}
	return appendTag(append(b, m.Random...), m.Tag, mac), nil
}

func (m SessionKeyChangeRequest) appendBody(b []byte, mac bool) ([]byte, error) {
	b, err := appendLen(append(appendIDs(b, m.AIM, m.AIS), m.DataProtection), m.Wrapped, 2, "wrapped key data")
	if err != nil {
		return nil, err
	}
	return appendTag(append(b, m.Wrapped...), m.Tag, mac), nil
}

func (m SessionKeyChangeResponse) appendBody(b []byte, mac bool) ([]byte, error) {
	return appendTag(appendIDs(b, m.AIM, m.AIS), m.Tag, mac), nil
}

func (m SecureData) appendBody(b []byte, _ bool) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint32(appendIDs(b, m.AIM, m.AIS), m.Sequence), m.Payload...), nil
}

// Encode returns the whole security ASDU: h, whose Type is taken from m, and
// the fields of m. It has no segmentation control octet; see [Segment].
func Encode(h Header, p asdu.Params, m Message) ([]byte, error) { return encode(h, p, m, true) }

// encode is Encode, without the trailing MAC when mac is false: the part of a
// message its own MAC covers.
func encode(h Header, p asdu.Params, m Message, mac bool) ([]byte, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	h.Type = m.Type()
	return m.appendBody(h.append(make([]byte, 0, 64), p), mac)
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.LittleEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *reader) rest() []byte {
	v := r.b
	r.b = nil
	return v
}

// Decode parses a whole security ASDU (no segmentation control octet) that
// travels in direction d. The type must be a security type with the cause
// of transmission permitted for it in that direction. A MAC is returned as
// the trailing octets; its length is checked when it is verified.
func Decode(b []byte, p asdu.Params, d Direction) (Header, Message, error) {
	if err := checkParams(p); err != nil {
		return Header{}, nil, err
	}
	h, vsq, err := parseHeader(b, p)
	if err != nil {
		return h, nil, err
	}
	cause, ok := PermittedCause(h.Type, d)
	switch {
	case !h.Type.IsSecurity():
		return h, nil, fmt.Errorf("%w: type %d is not a security type", ErrMessage, h.Type)
	case vsq != 1:
		return h, nil, fmt.Errorf("%w: %s with variable structure qualifier %#02x", ErrMessage, h.Type, vsq)
	case !ok || h.Cause != cause:
		return h, nil, fmt.Errorf("%w: %s with cause %d in %s direction", ErrMessage, h.Type, h.Cause, d)
	}
	r := &reader{b: b[headerLen(p):]}
	var m Message
	switch h.Type {
	case asdu.S_AQ_NA_1:
		v := AssociationRequest{AIM: r.u16(), AIS: r.u16()}
		if pri := r.take(2); pri != nil {
			v.Protocol = decodeProtocolInfo(pri, false)
		}
		v.Certificate = r.take(int(r.u16()))
		m = v
	case asdu.S_AP_NA_1:
		v := AssociationResponse{AIM: r.u16(), AIS: r.u16()}
		cdl := int(r.u16())
		cgl := int(r.u8())
		v.Certificate, v.Random = r.take(cdl), r.take(cgl)
		m = v
	case asdu.S_UH_NA_1:
		v := UpdateKeyChangeRequest{AIM: r.u16(), AIS: r.u16(), KeyWrap: r.u8(), MAC: r.u8()}
		v.Random = r.take(int(r.u8()))
		v.Tag = r.rest()
		m = v
	case asdu.S_UP_NA_1:
		m = UpdateKeyChangeResponse{AIM: r.u16(), AIS: r.u16(), Tag: r.rest()}
	case asdu.S_SI_NA_1:
		v := SessionInitiationRequest{AIM: r.u16(), AIS: r.u16()}
		v.Random = r.take(int(r.u8()))
		v.Tag = r.rest()
		if !r.bad {
			if err := checkRandom(v.Random, "session initiation request"); err != nil {
				return h, nil, err
			}
			if v.AIM == 0 || v.AIS == 0 {
				return h, nil, fmt.Errorf("%w: session initiation request with association ID 0", ErrMessage)
			}
		}
		m = v
	case asdu.S_SQ_NA_1:
		v := SessionRequest{AIM: r.u16(), AIS: r.u16()}
		if pri := r.take(2); pri != nil {
			v.Protocol = decodeProtocolInfo(pri, true)
		}
		v.Random = r.take(int(r.u8()))
		m = v
	case asdu.S_SP_NA_1:
		v := SessionResponse{AIM: r.u16(), AIS: r.u16()}
		v.Random = r.take(int(r.u8()))
		v.Tag = r.rest()
		m = v
	case asdu.S_KH_NA_1:
		v := SessionKeyChangeRequest{AIM: r.u16(), AIS: r.u16(), DataProtection: r.u8()}
		v.Wrapped = r.take(int(r.u16()))
		v.Tag = r.rest()
		m = v
	case asdu.S_KP_NA_1:
		m = SessionKeyChangeResponse{AIM: r.u16(), AIS: r.u16(), Tag: r.rest()}
	case asdu.S_SD_NA_1:
		m = SecureData{AIM: r.u16(), AIS: r.u16(), Sequence: r.u32(), Payload: r.rest()}
	default:
		// Not reached: PermittedCause knows only the types above.
		return h, nil, fmt.Errorf("%w: type %d", ErrMessage, h.Type)
	}
	if r.bad {
		return h, nil, fmt.Errorf("%w: %s too short", ErrMessage, h.Type)
	}
	if len(r.b) != 0 {
		return h, nil, fmt.Errorf("%w: %s with %d trailing octets", ErrMessage, h.Type, len(r.b))
	}
	return h, m, nil
}
