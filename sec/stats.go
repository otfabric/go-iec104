// SPDX-License-Identifier: MIT

package sec

import "fmt"

// Stat is one of the security statistics of IEC TS 60870-5-7 (the counters
// of IEC 62351-5), in the order of its table.
type Stat uint8

// The statistics.
const (
	StatSuccessfulAssociations Stat = iota
	StatAssociationFailures
	StatSuccessfulSessionKeyChanges
	StatSessionKeyChangeFailures
	StatKeyInvalidationsTime
	StatKeyInvalidationsCount
	StatProtocolInformationErrors
	StatKeyAuthAlgorithmFailures
	StatKeyWrapAlgorithmFailures
	StatDataProtectionAlgorithmFailures
	StatKeyAuthenticationErrors
	StatDataAuthenticationErrors
	StatUnexpectedMessages
	StatMaxReplyTimeouts
	StatRemoteAuthorizationFailures
	StatOperationAuthorizationFailures
	StatRemoteCertificateFailures
	StatRemoteCertificateExpirations
	StatRemoteCertificateRevocations
	StatLocalCertificateExpirations
	StatLocalCertificateRevocations
	StatKeyInvalidationsRemoteRevocation
	StatKeyInvalidationsLocalRevocation
	StatSuccessfulDataAuthentications
	StatReplyTimeouts
	StatRequestTimeouts
	StatMessagesSent
	StatMessagesReceived
	StatDiscardedMessages
	NumStats
)

// statInfo is a statistic's name and, for those that have one, the security
// event of IEC 62351-5 announced when it is incremented.
var statInfo = [NumStats]struct {
	name, event string
	severity    Severity
}{
	{"Successful Station Associations", "STAS_PROC_SUCC", Notice},
	{"Station Association Failures", "STAS_PROC_FAIL", Alarm},
	{"Successful Session Key Changes", "SKEY_PROC_SUCC", Notice},
	{"Session Key Change Failures", "SKEY_PROC_FAIL", Alarm},
	{"Session Key Invalidations due to Max Session Key Usage Time expired", "SKEY_INV_USETOUT", Alarm},
	{"Session Key Invalidations due to Max Session Key Usage Count reached", "SKEY_INV_USECNT", Alarm},
	{"Protocol Information Errors", "PROT_INFO_ERR", Alarm},
	{"Key Authentication Algorithm Support Failures", "KEY_AUTNALG_SUP", Alarm},
	{"Key Wrap Algorithm Support Failures", "KEY_WRAPALG_SUP", Alarm},
	{"Data Protection Algorithm Support Failures", "DATA_PROTALG_SUP", Alarm},
	{"Key Authentication Errors", "KEY_AUTN_ERR", Alarm},
	{"Data Authentication Errors", "DATA_AUTN_ERR", Warning},
	{"Unexpected Messages", "UNXP_MSG_ERR", Warning},
	{"Max Reply Timeouts", "MAX_REPLY_TOUT", Warning},
	{"Remote Station's Authorization Failures", "NODE_NOT_AUTR", Alarm},
	{"Operation Authorization Failures", "OPER_NOT_AUTR", Warning},
	{"Remote Station's Certificate Validity Check Failures", "REM_CERT_NOTVALID", Alarm},
	{"Remote Station's Certificate Expirations", "REM_CERT_EXPIRED", Warning},
	{"Remote Station's Certificate Revocations", "REM_CERT_REVOKED", Alarm},
	{"Local Station's Certificate Expirations", "LOC_CERT_EXPIRED", Warning},
	{"Local Station's Certificate Revocations", "LOC_CERT_REVOKED", Alarm},
	{"Cryptographic Keys Invalidations due to Remote Station's Certificate Revocation", "KEYS_INV_REMCERTREV", Alarm},
	{"Cryptographic Keys Invalidations due to Local Station's Certificate Revocation", "KEYS_INV_LOCCERTREV", Alarm},
	{"Successful Data Authentications", "", 0},
	{"Reply Timeouts", "", 0},
	{"Request Timeouts", "", 0},
	{"Total Messages Sent", "", 0},
	{"Total Messages Received", "", 0},
	{"Discarded Messages", "", 0},
}

// String is the statistic's name.
func (s Stat) String() string {
	if s < NumStats {
		return statInfo[s].name
	}
	return fmt.Sprintf("stat(%d)", uint8(s))
}

// Event returns the mnemonic and severity of the security event of
// IEC 62351-5 that the statistic announces, and false when it has none.
func (s Stat) Event() (string, Severity, bool) {
	if s >= NumStats || statInfo[s].event == "" {
		return "", 0, false
	}
	return statInfo[s].event, statInfo[s].severity, true
}

// Severity is the severity of a security event.
type Severity uint8

// Severities of the security events.
const (
	Notice Severity = iota + 1
	Warning
	Alarm
)

// String names the severity.
func (s Severity) String() string {
	switch s {
	case Notice:
		return "notice"
	case Warning:
		return "warning"
	case Alarm:
		return "alarm"
	}
	return "none"
}

// Statistics are the counters of one association. The counters wrap after
// 2^32-1.
type Statistics [NumStats]uint32

// Event is a security event: a statistic was incremented. Err, when not nil,
// says why (a refused certificate, a MAC that did not verify). An event that
// is no statistic, a failure to save the association, has Stat NumStats.
type Event struct {
	Stat     Stat
	Mnemonic string // for example "KEY_AUTN_ERR"; empty for plain counters
	Severity Severity
	Count    uint32 // the statistic after the increment
	Err      error
}
