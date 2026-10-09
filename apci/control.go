// SPDX-License-Identifier: MIT

package apci

import "fmt"

// UFunction is the function of a U-format frame, expressed as the first
// control octet (function bit plus the two format bits).
type UFunction uint8

// U-format functions. Exactly one is set in a valid U frame.
const (
	// StartDTAct asks the controlled station to start data transfer.
	StartDTAct UFunction = 0x07
	// StartDTCon confirms StartDTAct.
	StartDTCon UFunction = 0x0B
	// StopDTAct asks the controlled station to stop data transfer.
	StopDTAct UFunction = 0x13
	// StopDTCon confirms StopDTAct.
	StopDTCon UFunction = 0x23
	// TestFRAct is the link test request.
	TestFRAct UFunction = 0x43
	// TestFRCon confirms TestFRAct.
	TestFRCon UFunction = 0x83
)

// Valid reports whether fn is one of the six defined U functions.
func (fn UFunction) Valid() bool {
	switch fn {
	case StartDTAct, StartDTCon, StopDTAct, StopDTCon, TestFRAct, TestFRCon:
		return true
	default:
		return false
	}
}

// IsAct reports whether fn is an activation (request) rather than a
// confirmation.
func (fn UFunction) IsAct() bool {
	return fn == StartDTAct || fn == StopDTAct || fn == TestFRAct
}

// Confirmation returns the confirmation that answers the activation fn. It
// returns 0 when fn is not an activation.
func (fn UFunction) Confirmation() UFunction {
	switch fn {
	case StartDTAct:
		return StartDTCon
	case StopDTAct:
		return StopDTCon
	case TestFRAct:
		return TestFRCon
	default:
		return 0
	}
}

// String returns the standard mnemonic, for example "STARTDT act".
func (fn UFunction) String() string {
	switch fn {
	case StartDTAct:
		return "STARTDT act"
	case StartDTCon:
		return "STARTDT con"
	case StopDTAct:
		return "STOPDT act"
	case StopDTCon:
		return "STOPDT con"
	case TestFRAct:
		return "TESTFR act"
	case TestFRCon:
		return "TESTFR con"
	default:
		return fmt.Sprintf("UFunction(0x%02X)", uint8(fn))
	}
}
