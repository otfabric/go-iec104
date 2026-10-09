# Interoperability: otfabric/go-iec104

What the library implements, following the structure of the
interoperability list in IEC 60870-5-104 clause 9. Use it to compare against
the interoperability list of the device or control centre on the other side.

Legend: **yes** implemented and tested · **raw** carried as undecoded payload
(`ASDU.Raw`) · **no** not implemented · **app** the library carries it, the
behaviour is the application's.

## System and network

| Item | Support |
|------|---------|
| Controlling station (master) | yes, `client` |
| Controlled station (slave) | yes, `server` |
| Combined station (both directions on one connection) | no; run a client and a server side by side |
| Transport | TCP, IPv4 and IPv6 |
| Port | 2404 by default, any |
| TLS (IEC 62351-3) | yes, standard `crypto/tls`, default port 19998 |
| IEC 62351-5 application-layer authentication | no |
| Redundant connections (redundancy groups) | app; see [Redundancy](#redundancy) |

## Application layer framing

Fixed by IEC 60870-5-104 and the defaults of `asdu.IEC104`:

| Field | Size |
|-------|------|
| Cause of transmission | 2 octets (with originator address) |
| Common address of ASDU | 2 octets |
| Information object address | 3 octets |
| Maximum APDU length | 253 octets (ASDU up to 249) |
| Time tags | CP56Time2a, UTC by default (`asdu.Params.In` for another zone) |

Other field sizes (1-octet cause, 1-octet common address, 1- or 2-octet
object address) are supported by the codec for IEC 60870-5-101 use and for
non-conformant devices (`WithASDUParams`).

Both SQ = 0 (addressed objects) and SQ = 1 (sequence of elements) are
decoded for every type. Encoding uses SQ = 1 only when `ASDU.Sequence` is set.

## APCI

| Item | Support |
|------|---------|
| I, S and U formats | yes |
| STARTDT, STOPDT, TESTFR | yes, both roles |
| `k`: maximum unacknowledged I frames sent | yes, 1..32767, default 12 |
| `w`: latest acknowledgement after I frames received | yes, 1..`k`, default 8 |
| `t0`: connection establishment | yes, default 30s (client) |
| `t1`: send or test APDU timeout | yes, default 15s |
| `t2`: acknowledgement timeout, `t2 < t1` | yes, default 10s |
| `t3`: idle test timeout | yes, default 20s, 0 disables |
| Sequence number validation | yes; a violation closes the connection |

The parameters are not negotiated: configure both sides alike. See
[ARCHITECTURE.md](ARCHITECTURE.md#conformance-decisions) for the behaviour in
each exceptional situation.

## Type identifications

### Process information in monitor direction

| Type | ID | Description | Support | Go type |
|------|----|-------------|---------|---------|
| `M_SP_NA_1` | 1 | Single-point information | yes | `SinglePoint` |
| `M_SP_TA_1` | 2 | … with CP24Time2a ¹ | yes | `SinglePoint` |
| `M_DP_NA_1` | 3 | Double-point information | yes | `DoublePoint` |
| `M_DP_TA_1` | 4 | … with CP24Time2a ¹ | yes | `DoublePoint` |
| `M_ST_NA_1` | 5 | Step position information | yes | `StepPosition` |
| `M_ST_TA_1` | 6 | … with CP24Time2a ¹ | yes | `StepPosition` |
| `M_BO_NA_1` | 7 | Bitstring of 32 bit | yes | `Bitstring32` |
| `M_BO_TA_1` | 8 | … with CP24Time2a ¹ | yes | `Bitstring32` |
| `M_ME_NA_1` | 9 | Measured value, normalized | yes | `MeasuredNormalized` |
| `M_ME_TA_1` | 10 | … with CP24Time2a ¹ | yes | `MeasuredNormalized` |
| `M_ME_NB_1` | 11 | Measured value, scaled | yes | `MeasuredScaled` |
| `M_ME_TB_1` | 12 | … with CP24Time2a ¹ | yes | `MeasuredScaled` |
| `M_ME_NC_1` | 13 | Measured value, short floating point | yes | `MeasuredFloat` |
| `M_ME_TC_1` | 14 | … with CP24Time2a ¹ | yes | `MeasuredFloat` |
| `M_IT_NA_1` | 15 | Integrated totals | yes | `IntegratedTotal` |
| `M_IT_TA_1` | 16 | … with CP24Time2a ¹ | yes | `IntegratedTotal` |
| `M_EP_TA_1` | 17 | Event of protection equipment with CP24Time2a ¹ | yes | `ProtectionEvent` |
| `M_EP_TB_1` | 18 | Packed start events of protection equipment with CP24Time2a ¹ | yes | `ProtectionStart` |
| `M_EP_TC_1` | 19 | Packed output circuit information with CP24Time2a ¹ | yes | `ProtectionOutput` |
| `M_PS_NA_1` | 20 | Packed single-point information with status change detection | yes | `PackedSinglePoints` |
| `M_ME_ND_1` | 21 | Measured value, normalized without quality descriptor | yes | `MeasuredNormalized` |
| `M_SP_TB_1` | 30 | Single-point information with CP56Time2a | yes | `SinglePoint` |
| `M_DP_TB_1` | 31 | Double-point information with CP56Time2a | yes | `DoublePoint` |
| `M_ST_TB_1` | 32 | Step position information with CP56Time2a | yes | `StepPosition` |
| `M_BO_TB_1` | 33 | Bitstring of 32 bit with CP56Time2a | yes | `Bitstring32` |
| `M_ME_TD_1` | 34 | Measured value, normalized with CP56Time2a | yes | `MeasuredNormalized` |
| `M_ME_TE_1` | 35 | Measured value, scaled with CP56Time2a | yes | `MeasuredScaled` |
| `M_ME_TF_1` | 36 | Measured value, short floating point with CP56Time2a | yes | `MeasuredFloat` |
| `M_IT_TB_1` | 37 | Integrated totals with CP56Time2a | yes | `IntegratedTotal` |
| `M_EP_TD_1` | 38 | Event of protection equipment with CP56Time2a | yes | `ProtectionEvent` |
| `M_EP_TE_1` | 39 | Packed start events of protection equipment with CP56Time2a | yes | `ProtectionStart` |
| `M_EP_TF_1` | 40 | Packed output circuit information with CP56Time2a | yes | `ProtectionOutput` |

¹ Defined by IEC 60870-5-101 and not part of the IEC 60870-5-104 subset.
Supported by the codec so that the `asdu` package is complete for
IEC 60870-5-101 and tolerant of devices that send them over TCP. `asdu.New`
never selects these types; set `ASDU.Type` explicitly.

### Process information in control direction

| Type | ID | Description | Support | Go type |
|------|----|-------------|---------|---------|
| `C_SC_NA_1` | 45 | Single command | yes | `SingleCommand` |
| `C_DC_NA_1` | 46 | Double command | yes | `DoubleCommand` |
| `C_RC_NA_1` | 47 | Regulating step command | yes | `StepCommand` |
| `C_SE_NA_1` | 48 | Set-point command, normalized | yes | `SetpointNormalized` |
| `C_SE_NB_1` | 49 | Set-point command, scaled | yes | `SetpointScaled` |
| `C_SE_NC_1` | 50 | Set-point command, short floating point | yes | `SetpointFloat` |
| `C_BO_NA_1` | 51 | Bitstring of 32 bit | yes | `BitstringCommand` |
| `C_SC_TA_1` | 58 | Single command with CP56Time2a | yes | `SingleCommand` |
| `C_DC_TA_1` | 59 | Double command with CP56Time2a | yes | `DoubleCommand` |
| `C_RC_TA_1` | 60 | Regulating step command with CP56Time2a | yes | `StepCommand` |
| `C_SE_TA_1` | 61 | Set-point command, normalized with CP56Time2a | yes | `SetpointNormalized` |
| `C_SE_TB_1` | 62 | Set-point command, scaled with CP56Time2a | yes | `SetpointScaled` |
| `C_SE_TC_1` | 63 | Set-point command, short floating point with CP56Time2a | yes | `SetpointFloat` |
| `C_BO_TA_1` | 64 | Bitstring of 32 bit with CP56Time2a | yes | `BitstringCommand` |

### System information

| Type | ID | Description | Support | Go type |
|------|----|-------------|---------|---------|
| `M_EI_NA_1` | 70 | End of initialization | yes | `EndOfInitialization` |
| `C_IC_NA_1` | 100 | Interrogation command | yes | `Interrogation` |
| `C_CI_NA_1` | 101 | Counter interrogation command | yes | `CounterInterrogation` |
| `C_RD_NA_1` | 102 | Read command | yes | `Read` |
| `C_CS_NA_1` | 103 | Clock synchronization command | yes | `ClockSync` |
| `C_TS_NA_1` | 104 | Test command ¹ | yes | `TestCommand` |
| `C_RP_NA_1` | 105 | Reset process command | yes | `ResetProcess` |
| `C_CD_NA_1` | 106 | Delay acquisition command ¹ | yes | `DelayAcquisition` |
| `C_TS_TA_1` | 107 | Test command with CP56Time2a | yes | `TestCommand` |

### Parameters in control direction

| Type | ID | Description | Support | Go type |
|------|----|-------------|---------|---------|
| `P_ME_NA_1` | 110 | Parameter of measured value, normalized | yes | `ParameterNormalized` |
| `P_ME_NB_1` | 111 | Parameter of measured value, scaled | yes | `ParameterScaled` |
| `P_ME_NC_1` | 112 | Parameter of measured value, short floating point | yes | `ParameterFloat` |
| `P_AC_NA_1` | 113 | Parameter activation | yes | `ParameterActivation` |

### File transfer

| Type | ID | Description | Support |
|------|----|-------------|---------|
| `F_FR_NA_1` | 120 | File ready | raw |
| `F_SR_NA_1` | 121 | Section ready | raw |
| `F_SC_NA_1` | 122 | Call directory, select file, call file, call section | raw |
| `F_LS_NA_1` | 123 | Last section, last segment | raw |
| `F_AF_NA_1` | 124 | Ack file, ack section | raw |
| `F_SG_NA_1` | 125 | Segment | raw |
| `F_DR_TA_1` | 126 | Directory | raw |
| `F_SC_NB_1` | 127 | Query log, request archive file | raw |

### Private range

Types 128..255 are **raw** in both directions.

## Causes of transmission

All causes 1..13, 20..41 and 44..47 are defined (`asdu.Cause…`) and carried
unchanged. The originator address is supported (`client.WithOriginator`).
The test bit and the P/N bit are exposed as `ASDU.Test` and `ASDU.Negative`.

## Basic application functions

| Function | Client | Server |
|----------|--------|--------|
| Station initialization (`M_EI_NA_1`) | received via `Handler` | app: send with `Session.Send` |
| Cyclic, background, spontaneous transmission | received via `Handler` | app: `Session.Send`, `Server.Broadcast` |
| Station interrogation, global and groups 1..16 | `Interrogate` | app, via `Mux` |
| Counter interrogation, general and groups 1..4, freeze/reset qualifiers | `CounterInterrogate` | app, via `Mux` |
| Read procedure | `Read` | app, via `Mux` |
| Clock synchronization | `ClockSync` | app, via `Mux` |
| Command transmission, direct | `Command` | app, via `Mux` |
| Command transmission, select and execute | `Command` with `Select`, then without | app: the handler keeps the select state |
| Command deactivation | `Deactivate` | app, via `Mux` |
| Commands with time tag | set `Time` on the command | app: the handler checks the age |
| Test procedure (`C_TS_TA_1`) | `TestCommand` | app, via `Mux` |
| Reset process | `ResetProcess` | app, via `Mux` |
| Parameter loading and activation | `Send` | app, via `Mux` |
| File transfer | `Send` with raw payload | app, raw payload |
| Rejecting unknown type / cause / common address | reported as `NegativeError` | yes: `Mux` and `WithCommonAddrs` |
| Rejecting unknown information object address | reported as `NegativeError` | app: `Session.Reject(req, asdu.CauseUnknownIOA)` |

"app, via `Mux`" means the library routes the request to the handler
registered for the type and provides `Confirm`, `Negative`, `Terminate` and
`Reject` for the answers; what the station does is the handler's code.

## Redundancy

The standard lets a controlled station serve several connections of one
redundancy group, of which exactly one is started.

- **Server**: accepts any number of connections; each has its own
  STARTDT/STOPDT state (`Session.Started`). `Server.Broadcast` sends to
  started sessions only. The library does not group sessions or enforce
  "one started connection per group"; it sends to every started one.
- **Client**: one `Client` is one connection. For a standby connection use
  `WithAutoStart(false)` and call `StartDT` on switchover.

## Known deviations

- A server confirms STOPDT immediately after acknowledging what it received;
  it does not wait for its own outstanding I frames to be acknowledged
  first. They remain supervised by `t1`.
- The client's activation confirmation wait does not extend to the
  activation termination of a command; the termination reaches the `Handler`.
- A received ASDU that cannot be decoded is dropped without a negative
  answer.

## Verification status

The library is tested against itself and against hand-written frames taken
from the standard. It has **not yet** been run against third-party
implementations or certified test equipment. Interoperability reports are
welcome.
