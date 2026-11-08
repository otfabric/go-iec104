# Recorded IEC 60870-5-104 traffic

Network captures between IEC 60870-5-104 implementations that are not
go-iec104, recorded by others and committed byte-identical. go-iec104's
tests reassemble every TCP conversation, decode every APDU and encode it
again, check both sides' sequence numbers and acknowledgements, compare the
decoded fields with Wireshark and with CERT.LV's Zeek analyzer, replay the
recorded controlled stations against the client and the recorded
controlling stations against the server. This is evidence from recorded
software, not from devices: **none of the recordings we found could be
shown to come from a physical device** (see "Evidence" below). It is not a
test against a live system and not a conformance claim.

## Sources and terms

| Directory | Source | Revision | Terms |
|---|---|---|---|
| `certlv/` | [cert-lv/spicy-iec104](https://github.com/cert-lv/spicy-iec104/tree/e758272584b063a4789899db19be7d56a4f665c3/testing/Traces) `testing/Traces`, `testing/Baseline` | commit `e758272584b063a4789899db19be7d56a4f665c3` | Repository under the BSD 3-Clause licence (COPYING); no statement for the traces themselves |
| `uowm/` | [Zenodo record 7108614](https://zenodo.org/records/7108614), IEC 60870-5-104 Intrusion Detection Dataset, University of Western Macedonia | record revision 6 (published 2022-09-23) | CC-BY-4.0; cite P. Radoglou-Grammatikis et al., IEEE TII 18(3), 2022, doi:10.1109/TII.2021.3093905 |
| `wireshark/` | [Wireshark](https://gitlab.com/wireshark/wireshark/-/blob/f7e10bdd477b2f8f4995aa45c8155a0768f433ab/test/captures/iec104_coverage.pcap.gz) `test/captures/iec104_coverage.pcap.gz` | commit `f7e10bdd477b2f8f4995aa45c8155a0768f433ab` | Repository GPL-2.0-or-later; no statement for the capture |

The files are byte-identical to their sources, checked by
[SHA256SUMS](SHA256SUMS) (`make captures-verify`, also a CI job). The
`uowm/` files are members of the dataset's 7z archives, extracted unchanged:

| Archive | Size | SHA256 |
|---|---:|---|
| `20200425_UOWM_IEC104_Dataset_m_sp_na_1_DoS.7z` | 69,419,855 | `c9185a67aeb8aa2c479510559a4fcebbfd75c4e9bbcd3636f8090e33e786eaf8` |
| `20200426_UOWM_IEC104_Dataset_c_ci_na_1.7z` | 71,204,475 | `2b77e81754652fc24cc7181fb4a2e37e0fc00e22f2edb9d5077ab72101945711` |
| `20200427_UOWM_IEC104_Dataset_c_se_na_1.7z` | 81,958,663 | `ba6ff264a698fc142c4ccbf86384529516d6256a43d86cc4af5f94ddc247b043` |
| `20200428_UOWM_IEC104_Dataset_c_sc_na_1.7z` | 82,660,522 | `942c0d6a1fcb1bfc0cd928d6c2d8ffd3a66e7f562c23cbe615b413d0cb33ed56` |
| `20200605_UOWM_IEC104_Dataset_c_rd_na_1.7z` | 104,566,361 | `43a4b132c1d61a590923391673e66be067e70a9f777fd6b52cdf4d5a1442610a` |
| `20200606_UOWM_IEC104_Dataset_c_rp_na_1.7z` | 107,022,556 | `61a5b19b851c66b21c7a65b4d5a1f397e5acac8b40367ee8e0967bab2db2bfc1` |
| `20200608_UOWM_IEC104_Dataset_mitm_drop.7z` | 102,319,063 | `f916019dcfe27281dc26fd4befff30e2d5568acc0484c4c76b123959489cd8b1` |

Of each archive one `*_iec104_only.pcap` is committed (the dataset's own
filter to the IEC 104 frames: no SYN, no segments without payload). The
other five archives of the record, the CSV flow statistics and the full
recordings are not. Four full recordings (29 to 75 MB, all IEC 104 and the
rest of the testbed's traffic) are listed in [CACHED](CACHED):
`make captures-fetch` downloads them from CERT.LV's copies (byte-identical
to the archive members) into the git-ignored `cache/`, and
`make captures-extended` runs the replay suites over them too. One of them
holds the MITM drop attack, of which the dataset has no filtered file.

`certlv/zeek/<capture>/` holds the logs CERT.LV's test suite expects from
its Zeek analyzer for the four `certlv/` traces, unchanged.

## Names

`<client>_<device>_<operation>.<ext>`, lower case, words joined by hyphens;
the extension keeps the original format. Original names and URLs are in
[manifest.json](manifest.json).

| Part | Values |
|---|---|
| client | `qtester104` (QTester104 v2.1), `qtester104-attacker` (the station's view of QTester104 and an attacker on connections of their own), `attacker`, `unknown` (not stated by the source), `synthetic` |
| device | `iec-testserver` (IEC TestServer on Windows 7 virtual machines), `unknown`, `synthetic` |
| operation | the dataset's attack name, or what the capture holds |

## Evidence

Levels: A verified physical-device traffic, B credibly documented
physical-device traffic, C independent recorded traffic with unknown
hardware origin, D simulated or software testbed, E generated.

| File | Original name | Level | Basis |
|---|---|:-:|---|
| `certlv/unknown_unknown_interrogation-commands.pcap` | `first/iec104.pcap` (a copy of automayt/ICS-pcap `IEC 60870/iec104/iec104.pcap`) | C | Recorded on Ethernet in 2013. The station's MAC prefix 00:16:D1 is registered to ZAT a.s., the client's 00:22:15 to ASUSTek; no software or device model is stated anywhere |
| `certlv/unknown_unknown_file-read.pcapng` | `fifth/read.pcapng` | D | Loopback interface: two programs on one host, not named |
| `certlv/unknown_unknown_file-write.pcapng` | `fifth/write.pcapng` | D | Loopback interface |
| `certlv/unknown_unknown_errors.pcapng` | `sixth/errors.pcapng` | D | Loopback interface |
| `uowm/*` | `<date>_UOWM_IEC104_Dataset_<attack>_{iecserver1,qtester}_iec104_only.pcap` | D | Software testbed |
| `wireshark/synthetic_synthetic_iec104-coverage.pcap.gz` | `iec104_coverage.pcap.gz` | E | Generated for the dissector tests |

The UOWM ReadMe describes five virtual RTUs (IEC TestServer) and "two real
RTU devices", but identifies the real ones neither by address nor by make or
model. In the recordings all seven controlled stations (192.168.1.13, .19,
.21, .22, .24, .25 and .26) have MAC addresses in VirtualBox's range
08:00:27, answer with the same data and show the same faults (below); the
station of the committed files is named `vm2_RTU-PC` in the full
recording's NetBIOS traffic. None can be shown to be a physical device, so
the dataset is level D, not B.

## What the recordings show

Counts per file are in [manifest.json](manifest.json). Across the 12
committed captures: 681 conversations, 77,299 APDUs (43,122 I, 11,219 S,
22,957 U), all reassembled and all decoded except 740 ASDUs whose length
does not match their type identification (739 recorded, 1 synthetic) and 1
U frame with two functions (synthetic). Every decoded APDU of the recorded
implementations (levels C and D) encodes back byte for byte; of the
synthetic capture 132 do not, and differ only in reserved bits and days of
week that do not match the date.

Recorded behaviour of other implementations that go-iec104's tests pin
(`client/capture_test.go`, `server/capture_test.go`):

- **IEC TestServer** (UOWM): on a new connection its first I frame
  acknowledges a frame the controlling station never sent (N(R)=1 left over
  from the previous connection); it sends I frames after confirming STOPDT;
  it confirms STOPDT with I frames outstanding; it answers requests of one
  connection on every connection; its negative confirmations of C_RP_NA_1
  lack the qualifier octet; it mirrors single commands with another
  qualifier (SCO 0x28 answered with 0x08); it confirms counter
  interrogations without terminating them; it keeps a connection whose
  peer never answers its TESTFR act.
- **The UOWM attacker** (Metasploit iec104 module or OpenMUC j60870; the
  dataset does not say which per file): C_RD_NA_1 with cause activation and
  an extra octet, C_SE_NA_1 two octets short, counter interrogations with
  qualifier 20, TESTFR act left unanswered.
- **The CERT.LV loopback programs**: a day of week 0 (unused) in CP56Time2a;
  the call of a whole file with section number 1 and the last section of a
  file numbered with the last section's number (lib60870-C sends 0 and the
  number after the last section); file segments of 233 octets; parameters
  of measured values in answer to an interrogation.

## Not in the recordings

TLS (IEC 62351-3) and IEC 62351-5 application-layer security in real
traffic (the synthetic capture has security ASDUs with placeholder data
only), redundancy groups and switchover, file directories, deletion, the
query log, commands with time tag outside the synthetic capture,
select-before-operate, deactivation, test command C_TS_TA_1, CP24Time2a in
recorded traffic, k or w above 15 in recorded traffic, and any traffic of
a physical device.
