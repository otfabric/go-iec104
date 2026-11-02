# Limitations

What go-iec104 does not do, or does only partly. The interoperability list, clause by clause, is in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## Scope not implemented

- **IEC 60870-5-101** serial links: not in this module. The `asdu` package takes the 101 field sizes so that a separate module can build on it.
- **File deletion and the query log**: their types are in the codec, with no procedure.
- **IEC 62351-5**: no broadcast key, no IEC 62351-8 tokens, no secp256k1, X448 or brainpool. See [SECURITY.md](SECURITY.md#application-layer-security-iec-62351-5).
- **Event queue**: in memory. It survives an absent control centre, not a restart of the station.

## Verification

- Independently verified against lib60870-C, OpenMUC j60870, wendy512/iec104 and cB-Sigma/iec60870, at the versions and with the results in [INTEROPERABILITY.md](INTEROPERABILITY.md#verification-status).
- IEC 62351-5 was derived from cB-Sigma/iec60870, not from the IEC documents, and is verified against that one implementation only.
- File upload, the file directory, TLS, interrogation groups, a quality on bitstrings and server redundancy against another implementation: the `interop` suite has the tests, for every reference that declares each feature (container contract 1.3). The pinned images (iec104-interop v0.3.1) predate that contract, so there these tests skip and the features rest on this repository's own tests. The tests pass against candidate builds of iec104-interop; the pins follow its release. See [INTEROPERABILITY.md](INTEROPERABILITY.md#verification-status).
- Not verified against certified test equipment or field devices.
- Certification: none.

## Known deviations

- **The `default` redundancy group is not one in the sense of clause 10.** Without `WithRedundancyGroups`, every client is an independent session that can be started next to the others: a STARTDT closes nothing, the one that is not active still gets answers, and when the active one stops the queue moves to another started one. A group named with `WithRedundancyGroups` has one started connection: a takeover closes the other.

- The client's activation confirmation wait does not extend to the activation termination of a command; the termination reaches the `Handler`.
- A received ASDU that cannot be decoded is dropped without a negative answer.
