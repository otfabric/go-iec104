// SPDX-License-Identifier: MIT

package asdu

import "fmt"

// TypeID is the ASDU type identification. The constants use the mnemonics of
// IEC 60870-5-101 so they can be matched against the standard, device
// interoperability lists and protocol analysers.
type TypeID uint8

// Process information in monitor direction.
const (
	M_SP_NA_1 TypeID = 1  // Single-point information
	M_SP_TA_1 TypeID = 2  // Single-point information with CP24Time2a
	M_DP_NA_1 TypeID = 3  // Double-point information
	M_DP_TA_1 TypeID = 4  // Double-point information with CP24Time2a
	M_ST_NA_1 TypeID = 5  // Step position information
	M_ST_TA_1 TypeID = 6  // Step position information with CP24Time2a
	M_BO_NA_1 TypeID = 7  // Bitstring of 32 bit
	M_BO_TA_1 TypeID = 8  // Bitstring of 32 bit with CP24Time2a
	M_ME_NA_1 TypeID = 9  // Measured value, normalized
	M_ME_TA_1 TypeID = 10 // Measured value, normalized with CP24Time2a
	M_ME_NB_1 TypeID = 11 // Measured value, scaled
	M_ME_TB_1 TypeID = 12 // Measured value, scaled with CP24Time2a
	M_ME_NC_1 TypeID = 13 // Measured value, short floating point
	M_ME_TC_1 TypeID = 14 // Measured value, short floating point with CP24Time2a
	M_IT_NA_1 TypeID = 15 // Integrated totals
	M_IT_TA_1 TypeID = 16 // Integrated totals with CP24Time2a
	M_EP_TA_1 TypeID = 17 // Event of protection equipment with CP24Time2a
	M_EP_TB_1 TypeID = 18 // Packed start events of protection equipment with CP24Time2a
	M_EP_TC_1 TypeID = 19 // Packed output circuit information with CP24Time2a
	M_PS_NA_1 TypeID = 20 // Packed single-point information with status change detection
	M_ME_ND_1 TypeID = 21 // Measured value, normalized without quality descriptor
	M_SP_TB_1 TypeID = 30 // Single-point information with CP56Time2a
	M_DP_TB_1 TypeID = 31 // Double-point information with CP56Time2a
	M_ST_TB_1 TypeID = 32 // Step position information with CP56Time2a
	M_BO_TB_1 TypeID = 33 // Bitstring of 32 bit with CP56Time2a
	M_ME_TD_1 TypeID = 34 // Measured value, normalized with CP56Time2a
	M_ME_TE_1 TypeID = 35 // Measured value, scaled with CP56Time2a
	M_ME_TF_1 TypeID = 36 // Measured value, short floating point with CP56Time2a
	M_IT_TB_1 TypeID = 37 // Integrated totals with CP56Time2a
	M_EP_TD_1 TypeID = 38 // Event of protection equipment with CP56Time2a
	M_EP_TE_1 TypeID = 39 // Packed start events of protection equipment with CP56Time2a
	M_EP_TF_1 TypeID = 40 // Packed output circuit information with CP56Time2a
)

// Process information in control direction.
const (
	C_SC_NA_1 TypeID = 45 // Single command
	C_DC_NA_1 TypeID = 46 // Double command
	C_RC_NA_1 TypeID = 47 // Regulating step command
	C_SE_NA_1 TypeID = 48 // Set-point command, normalized
	C_SE_NB_1 TypeID = 49 // Set-point command, scaled
	C_SE_NC_1 TypeID = 50 // Set-point command, short floating point
	C_BO_NA_1 TypeID = 51 // Bitstring of 32 bit command
	C_SC_TA_1 TypeID = 58 // Single command with CP56Time2a
	C_DC_TA_1 TypeID = 59 // Double command with CP56Time2a
	C_RC_TA_1 TypeID = 60 // Regulating step command with CP56Time2a
	C_SE_TA_1 TypeID = 61 // Set-point command, normalized with CP56Time2a
	C_SE_TB_1 TypeID = 62 // Set-point command, scaled with CP56Time2a
	C_SE_TC_1 TypeID = 63 // Set-point command, short floating point with CP56Time2a
	C_BO_TA_1 TypeID = 64 // Bitstring of 32 bit command with CP56Time2a
)

// System information in monitor direction.
const (
	M_EI_NA_1 TypeID = 70 // End of initialization
)

// System information in control direction.
const (
	C_IC_NA_1 TypeID = 100 // Interrogation command
	C_CI_NA_1 TypeID = 101 // Counter interrogation command
	C_RD_NA_1 TypeID = 102 // Read command
	C_CS_NA_1 TypeID = 103 // Clock synchronization command
	C_TS_NA_1 TypeID = 104 // Test command (IEC 60870-5-101 only)
	C_RP_NA_1 TypeID = 105 // Reset process command
	C_CD_NA_1 TypeID = 106 // Delay acquisition command (IEC 60870-5-101 only)
	C_TS_TA_1 TypeID = 107 // Test command with CP56Time2a
)

// Parameters in control direction.
const (
	P_ME_NA_1 TypeID = 110 // Parameter of measured value, normalized
	P_ME_NB_1 TypeID = 111 // Parameter of measured value, scaled
	P_ME_NC_1 TypeID = 112 // Parameter of measured value, short floating point
	P_AC_NA_1 TypeID = 113 // Parameter activation
)

// File transfer. These types have no object model in this package: they
// decode into [ASDU.Raw].
const (
	F_FR_NA_1 TypeID = 120 // File ready
	F_SR_NA_1 TypeID = 121 // Section ready
	F_SC_NA_1 TypeID = 122 // Call directory, select file, call file, call section
	F_LS_NA_1 TypeID = 123 // Last section, last segment
	F_AF_NA_1 TypeID = 124 // Ack file, ack section
	F_SG_NA_1 TypeID = 125 // Segment
	F_DR_TA_1 TypeID = 126 // Directory
	F_SC_NB_1 TypeID = 127 // Query log, request archive file
)

// rawNames names the type identifications that are defined by the standard
// but carried as raw payload.
var rawNames = map[TypeID][2]string{
	F_FR_NA_1: {"F_FR_NA_1", "File ready"},
	F_SR_NA_1: {"F_SR_NA_1", "Section ready"},
	F_SC_NA_1: {"F_SC_NA_1", "Call directory, select file, call file, call section"},
	F_LS_NA_1: {"F_LS_NA_1", "Last section, last segment"},
	F_AF_NA_1: {"F_AF_NA_1", "Ack file, ack section"},
	F_SG_NA_1: {"F_SG_NA_1", "Segment"},
	F_DR_TA_1: {"F_DR_TA_1", "Directory"},
	F_SC_NB_1: {"F_SC_NB_1", "Query log, request archive file"},
}

// String returns the standard mnemonic, for example "M_ME_NC_1", or
// "TypeID(n)" for a type this package does not know.
func (t TypeID) String() string {
	if d := registry[t]; d != nil {
		return d.name
	}
	if n, ok := rawNames[t]; ok {
		return n[0]
	}
	return fmt.Sprintf("TypeID(%d)", uint8(t))
}

// Description returns the name the standard gives the type, for example
// "Measured value, short floating point". It is empty for an unknown type.
func (t TypeID) Description() string {
	if d := registry[t]; d != nil {
		return d.desc
	}
	return rawNames[t][1]
}

// Supported reports whether this package can decode the type into typed
// information objects. Other types travel as [ASDU.Raw].
func (t TypeID) Supported() bool {
	return registry[t] != nil
}

// HasTimeTag reports whether objects of the type carry a time tag.
func (t TypeID) HasTimeTag() bool {
	d := registry[t]
	return d != nil && d.tag != tagNone
}

// InControlDirection reports whether the type is sent by the controlling
// station: process commands (45..69), system commands (100..109) and
// parameters (110..119). The controlled station mirrors these types back as
// confirmations.
func (t TypeID) InControlDirection() bool {
	return (t >= 45 && t <= 69) || (t >= 100 && t <= 119)
}

// IsProcessCommand reports whether the type is a process command: single,
// double and regulating step commands, set points and bitstring commands.
func (t TypeID) IsProcessCommand() bool {
	return t >= 45 && t <= 69
}

// IsPrivate reports whether the type is in the range the standard reserves
// for private use (128..255).
func (t TypeID) IsPrivate() bool {
	return t >= 128
}

// Cause is the 6-bit cause of transmission.
type Cause uint8

// Causes of transmission.
const (
	CausePeriodic            Cause = 1  // Periodic, cyclic
	CauseBackground          Cause = 2  // Background scan
	CauseSpontaneous         Cause = 3  // Spontaneous
	CauseInitialized         Cause = 4  // Initialized
	CauseRequest             Cause = 5  // Request or requested
	CauseActivation          Cause = 6  // Activation
	CauseActivationCon       Cause = 7  // Activation confirmation
	CauseDeactivation        Cause = 8  // Deactivation
	CauseDeactivationCon     Cause = 9  // Deactivation confirmation
	CauseActivationTerm      Cause = 10 // Activation termination
	CauseReturnRemote        Cause = 11 // Return information caused by a remote command
	CauseReturnLocal         Cause = 12 // Return information caused by a local command
	CauseFileTransfer        Cause = 13 // File transfer
	CauseInterrogatedStation Cause = 20 // Interrogated by station interrogation
	CauseInterrogatedGroup1  Cause = 21 // Interrogated by group 1 interrogation; groups 2..16 follow
	CauseInterrogatedGroup16 Cause = 36 // Interrogated by group 16 interrogation
	CauseCounterGeneral      Cause = 37 // Requested by general counter request
	CauseCounterGroup1       Cause = 38 // Requested by group 1 counter request; groups 2..4 follow
	CauseCounterGroup4       Cause = 41 // Requested by group 4 counter request
	CauseUnknownType         Cause = 44 // Unknown type identification
	CauseUnknownCause        Cause = 45 // Unknown cause of transmission
	CauseUnknownCommonAddr   Cause = 46 // Unknown common address of ASDU
	CauseUnknownIOA          Cause = 47 // Unknown information object address
)

var causeNames = map[Cause]string{
	CausePeriodic:            "periodic",
	CauseBackground:          "background",
	CauseSpontaneous:         "spontaneous",
	CauseInitialized:         "initialized",
	CauseRequest:             "request",
	CauseActivation:          "activation",
	CauseActivationCon:       "activation-con",
	CauseDeactivation:        "deactivation",
	CauseDeactivationCon:     "deactivation-con",
	CauseActivationTerm:      "activation-term",
	CauseReturnRemote:        "return-remote",
	CauseReturnLocal:         "return-local",
	CauseFileTransfer:        "file-transfer",
	CauseInterrogatedStation: "interrogated-station",
	CauseCounterGeneral:      "counter-general",
	CauseUnknownType:         "unknown-type",
	CauseUnknownCause:        "unknown-cause",
	CauseUnknownCommonAddr:   "unknown-common-address",
	CauseUnknownIOA:          "unknown-ioa",
}

// String returns a short lower-case name, for example "spontaneous".
func (c Cause) String() string {
	if s, ok := causeNames[c]; ok {
		return s
	}
	switch {
	case c >= CauseInterrogatedGroup1 && c <= CauseInterrogatedGroup16:
		return fmt.Sprintf("interrogated-group-%d", c-CauseInterrogatedStation)
	case c >= CauseCounterGroup1 && c <= CauseCounterGroup4:
		return fmt.Sprintf("counter-group-%d", c-CauseCounterGeneral)
	}
	return fmt.Sprintf("Cause(%d)", uint8(c))
}

// IsUnknown reports whether c is one of the four negative "unknown ..."
// causes (44..47) a station uses to reject an ASDU it cannot process.
func (c Cause) IsUnknown() bool {
	return c >= CauseUnknownType && c <= CauseUnknownIOA
}

// IOA is an information object address. IEC 60870-5-104 uses three octets.
type IOA uint32

// CommonAddr is the common address of ASDU: the station address.
type CommonAddr uint16

// Broadcast is the global common address for a two-octet common address
// field: every station of the connection is addressed.
const Broadcast CommonAddr = 0xFFFF
