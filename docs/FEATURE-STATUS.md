# Feature status

What go-iec104 implements and what evidence backs it. Status: go-iec104 v0.0.5, qualified against [iec104-interop v0.3.1](https://github.com/otfabric/iec104-interop/releases/tag/v0.3.1). The type identifications and causes, clause by clause, are in [INTEROPERABILITY.md](../INTEROPERABILITY.md); what is out of scope is in [LIMITATIONS.md](../LIMITATIONS.md).

None of this is a conformance claim: nothing is certified, and nothing has been run against certified test equipment or field devices.

## 1. Versions

| go-iec104 | Go | iec104-interop | Supported |
|---|---|---|---|
| **v0.0.5** | 1.23 or later (CI: 1.23 to 1.26) | v0.3.1 | **yes** |
| < v0.0.5 | 1.23 or later | older | no |

Security fixes go into the latest version only ([SECURITY.md](../SECURITY.md)).

## 2. Platforms

The library is pure Go with no dependencies outside the standard library.

| Platform | Tested | Notes |
|---|---|---|
| Linux amd64 | the full test suite, the interop suite and `interop/cbsigma` in CI | |
| Linux arm64, Linux arm, macOS arm64, Windows amd64 | `make cross`, build only, not in CI | tests are not run there by CI |

HMAC-SHA3-256 is present only when built with Go 1.24 or later (`sec/algorithms_sha3.go`).

## 3. Feature support

✅ supported · ◐ partly (see the notes) · ⚙ codec only (encode and decode, no procedure) · — not implemented.

**E2E**: a go-iec104 client and server exercise it in `e2e/`, named by test. **Independent**: software that is not go-iec104 exchanged it with go-iec104 in the `interop` suite, against the images pinned by digest. "All four" means lib60870-C v2.4.1, OpenMUC j60870 1.8.0, wendy512/iec104 v1.0.4 on go-iecp5 v1.2.6 and cB-Sigma/iec60870 v0.3.0.

### Link and connection

| Feature | Status | E2E | Independent |
|---|---|---|---|
| I, S and U frames, sequence numbers | ✅ | `TestWireMatrix`, `TestSequenceNumberWrap` | all four |
| STARTDT, STOPDT | ✅ | `TestDataTransfer`, `TestStartStopStaysInStep` | all four |
| `k`, `w` windows | ✅ | `TestNarrowParameters` | all four, at `k = w = 1` |
| `t3` idle test | ✅ | `TestIdleConnection` | all four, both directions |
| `t1` closes a silent link | ✅ | `TestSilentLink` | none |
| Client reconnect | ✅ | `TestReconnect` | all four, after a station restart |
| Client retries of read-only requests | ✅ | `TestRetry` | none |
| Concurrent sessions | ✅ | `TestConcurrentSessions` | all four |
| TLS (IEC 62351-3) | ✅ | the `tls` variant of the station scenarios, `TestMutualTLS` | none |

### Application functions

| Feature | Status | E2E | Independent |
|---|---|---|---|
| Station interrogation | ✅ | `TestInterrogation` | all four |
| Counter interrogation | ✅ | `TestInterrogation` | all four |
| Read | ✅ | `TestRead` | lib60870-C, wendy512, cB-Sigma; j60870 closes the connection (known bug) |
| Clock synchronization, test command | ✅ | `TestSystemCommands` | all four |
| Commands, direct and select-before-operate, deactivation | ✅ | `TestCommands`, `TestSelectBeforeOperate` | all four |
| Commands with time tag | ✅ | `TestCommands` | lib60870-C, j60870, cB-Sigma; go-iecp5 drops them |
| Refusals (unknown type, cause, common address, object) | ✅ | `TestRefusals` | all four |
| Types outside the reference fixture (protection events, packed single points, bitstring commands, parameters, reset process, delay acquisition, end of initialization) | ✅ | `TestWireMatrix` | none: this repository's tests only |
| Other field sizes, IEC 60870-5-101 widths | ✅ | `TestWireMatrixOtherParameters` | none |
| Private types 128..255, raw payload | ✅ | `TestWireMatrix` | none |

### File transfer

| Feature | Status | E2E | Independent |
|---|---|---|---|
| Download, `Client.GetFile` | ✅ | `TestFileTransfer` | lib60870-C, cB-Sigma |
| Download, `server.FileServer` | ✅ | `TestFileTransfer` | lib60870-C, j60870, cB-Sigma |
| Upload, directory | ✅ | `TestFileUploadAndDirectory` | none: no pinned image offers them |
| File deletion, query log | ⚙ | none | none |

### Redundancy and events

| Feature | Status | E2E | Independent |
|---|---|---|---|
| Client redundancy group, failover, switchover | ✅ | `TestRedundancyGroup`, `TestSwitchoverStaysInStep` | one group across two reference stacks |
| Server redundancy groups | ✅ | `TestServerRedundancyGroups` | none |
| Event queue with acknowledged delivery, in memory | ✅ | `TestEventQueue`, `TestEventQueueOverflow` | reference clients (`TestServerEventQueue`) |
| Combined station on one connection | — | | |

### Application-layer security (IEC 62351-5:2023 with IEC TS 60870-5-7:2025)

| Feature | Status | E2E | Independent |
|---|---|---|---|
| Station Association, Session Key Change, Secure Data, both roles | ✅ | the `secure` and `secure-gcm-tls` variants of the station scenarios | cB-Sigma only, container and in process |
| Role-based access control | ✅ | `TestSecurityRoles` | cB-Sigma only |
| Several controlling stations, refused station | ✅ | `TestSecurityStations`, `TestSecurityRefusedStation` | cB-Sigma only, for a refused AIM |
| Broadcast session key, IEC 62351-8 tokens, certificate revocation lists, secp256k1, X448, brainpool | — | | |

The security was derived from cB-Sigma/iec60870, not from the IEC documents, so that one implementation is not a test of it against the standard ([SECURITY.md](../SECURITY.md#application-layer-security-iec-62351-5)).

### Observability

| Feature | Status | E2E | Independent |
|---|---|---|---|
| Structured logging, metrics hooks, state callbacks | ✅ | `TestStatesLogsAndMetrics` | n/a |

## 4. Interop results

Peer versions, digests and per-direction results are in [INTEROPERABILITY.md](../INTEROPERABILITY.md#verification-status). The Interop workflow runs on every push and pull request.

## 5. Not verified

- Certified test equipment, field devices and any conformance test.
- TLS against any other implementation.
- `t1` and `t2` behaviour against another implementation.
- File upload and the directory against another implementation.
- IEC 62351-5 against anything other than cB-Sigma/iec60870.
- Any platform other than Linux amd64, in CI.
