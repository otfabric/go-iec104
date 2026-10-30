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
- File upload and the file directory are verified by this repository's own tests only: the interop images do not offer them.
- Not verified against certified test equipment or field devices.
- Certification: none.

## Known deviations

- The client's activation confirmation wait does not extend to the activation termination of a command; the termination reaches the `Handler`.
- A received ASDU that cannot be decoded is dropped without a negative answer.
