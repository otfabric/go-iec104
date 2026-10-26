// SPDX-License-Identifier: MIT

package sec

import (
	"fmt"

	"github.com/otfabric/go-iec104/asdu"
)

// Direction is the direction an ASDU travels in.
type Direction uint8

const (
	// Control is the control direction: from the controlling station (the
	// client) to the controlled station (the server).
	Control Direction = iota
	// Monitor is the monitor direction: from the controlled station to the
	// controlling station.
	Monitor
)

// String names the direction.
func (d Direction) String() string {
	if d == Control {
		return "control"
	}
	return "monitor"
}

// Role is the station role of an [Endpoint].
type Role uint8

const (
	// Controlling is the controlling station, the client. It starts the
	// Station Association and the Session Key Change.
	Controlling Role = iota
	// Controlled is the controlled station, the server.
	Controlled
)

// String names the role.
func (r Role) String() string {
	if r == Controlling {
		return "controlling"
	}
	return "controlled"
}

func (r Role) sends() Direction {
	if r == Controlling {
		return Control
	}
	return Monitor
}

func (r Role) receives() Direction {
	if r == Controlling {
		return Monitor
	}
	return Control
}

// typeInfo is the cause of transmission a security type may carry in each
// direction (0: not permitted in that direction).
type typeInfo struct {
	control, monitor asdu.Cause
}

var typeInfos = map[asdu.TypeID]typeInfo{
	asdu.S_AQ_NA_1: {control: asdu.CauseAssociation},
	asdu.S_AP_NA_1: {monitor: asdu.CauseAssociation},
	asdu.S_UH_NA_1: {control: asdu.CauseAssociation},
	asdu.S_UP_NA_1: {monitor: asdu.CauseAssociation},
	asdu.S_SI_NA_1: {monitor: asdu.CauseSessionKey},
	asdu.S_SQ_NA_1: {control: asdu.CauseSessionKey},
	asdu.S_SP_NA_1: {monitor: asdu.CauseSessionKey},
	asdu.S_KH_NA_1: {control: asdu.CauseSessionKey},
	asdu.S_KP_NA_1: {monitor: asdu.CauseSessionKey},
	asdu.S_SD_NA_1: {control: asdu.CauseDataProtection, monitor: asdu.CauseDataProtection},
}

// PermittedCause returns the cause of transmission a security message of
// type t carries in direction d, and false when t is not a security type or
// does not travel in that direction.
func PermittedCause(t asdu.TypeID, d Direction) (asdu.Cause, bool) {
	ti, ok := typeInfos[t]
	if !ok {
		return 0, false
	}
	c := ti.control
	if d == Monitor {
		c = ti.monitor
	}
	return c, c != 0
}

// ProtocolInfo is the protocol information (PRI) of the Association Request
// and the Session Request: a version, major and minor, of 0 to 15 each.
type ProtocolInfo struct {
	Major, Minor uint8
	// Broadcast is the BK flag of a Session Request: the change is for the
	// broadcast session key of IEC 60870-5-101. It is never set over
	// IEC 60870-5-104.
	Broadcast bool
	// Reserved holds the other bits of the second octet as received.
	Reserved uint8
}

// Version1 is the protocol version 1.0 that conforming devices send.
var Version1 = ProtocolInfo{Major: 1}

func (p ProtocolInfo) encode(session bool) ([2]byte, error) {
	if p.Major > 15 || p.Minor > 15 {
		return [2]byte{}, fmt.Errorf("%w: protocol version %d.%d", ErrMessage, p.Major, p.Minor)
	}
	b := [2]byte{p.Major<<4 | p.Minor, p.Reserved}
	if session {
		b[1] &^= 1
		if p.Broadcast {
			b[1] |= 1
		}
	}
	return b, nil
}

func decodeProtocolInfo(b []byte, session bool) ProtocolInfo {
	p := ProtocolInfo{Major: b[0] >> 4, Minor: b[0] & 0x0f, Reserved: b[1]}
	if session {
		p.Broadcast = b[1]&1 != 0
		p.Reserved &^= 1
	}
	return p
}

func (p ProtocolInfo) isVersion1() bool {
	return p.Major == Version1.Major && p.Minor == Version1.Minor
}
