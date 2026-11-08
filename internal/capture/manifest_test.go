// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

// testdata/captures/manifest.json describes every committed capture: where
// it comes from, what is known about the systems in it, its evidence level
// and what go-iec104 derives from it. TestManifest checks the files and the
// counts against it; IEC104_CAPTURE_GENERATE=1 (make captures-manifest)
// writes it again from the sources below and the code.

// source is where a set of captures comes from.
type source struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Revision string `json:"revision"`
	Terms    string `json:"terms"`
	Notes    string `json:"notes"`
}

// entry is one committed capture.
type entry struct {
	Path         string   `json:"path"`
	Source       string   `json:"source"`
	OriginalName string   `json:"original_name"`
	URL          string   `json:"url"`
	Size         int      `json:"size"`
	SHA256       string   `json:"sha256"`
	Format       string   `json:"format"`
	Recorded     string   `json:"recorded"`
	Evidence     string   `json:"evidence"`
	Basis        string   `json:"evidence_basis"`
	Systems      []string `json:"systems"`
	Operations   string   `json:"operations"`
	Privacy      string   `json:"privacy"`
	Missing      string   `json:"missing_for_verification"`
	Counts       counts   `json:"counts"`
}

// counts is what go-iec104 derives from a capture.
type counts struct {
	Conversations int `json:"conversations"`
	FromZero      int `json:"conversations_from_start"`
	APDUs         int `json:"apdus"`
	I             int `json:"i_frames"`
	S             int `json:"s_frames"`
	U             int `json:"u_frames"`
	APCIErrors    int `json:"apci_errors"`
	ASDUErrors    int `json:"asdu_errors"`
	Exact         int `json:"reencoded_exactly"`
	Retransmitted int `json:"tcp_retransmitted"`
	OutOfOrder    int `json:"tcp_out_of_order"`
	Gaps          int `json:"tcp_gaps"`
	Split         int `json:"apdus_split_over_segments"`
	Shared        int `json:"segments_with_several_apdus"`
	Skipped       int `json:"octets_skipped"`
	SeqErrors     int `json:"sequence_errors"`
	StoppedI      int `json:"i_frames_while_stopped"`
	Types         int `json:"type_identifications"`
}

type manifest struct {
	Description string   `json:"description"`
	Levels      any      `json:"evidence_levels"`
	Sources     []source `json:"sources"`
	Files       []entry  `json:"files"`
}

const (
	srcCERTLV  = "cert-lv/spicy-iec104"
	srcUOWM    = "zenodo-7108614"
	srcWireshk = "wireshark"
)

var manifestSources = []source{
	{ID: srcCERTLV, URL: "https://github.com/cert-lv/spicy-iec104/tree/e758272584b063a4789899db19be7d56a4f665c3/testing/Traces",
		Revision: "e758272584b063a4789899db19be7d56a4f665c3",
		Terms:    "The repository is under the BSD 3-Clause licence (COPYING, Copyright 2023 Georgios Michail Makrakis, 2024 CERT.LV); the traces have no statement of their own.",
		Notes: "Test traces of CERT.LV's Spicy/Zeek IEC 104 analyzer. first/iec104.pcap is a copy of https://github.com/automayt/ICS-pcap/blob/master/IEC%2060870/iec104/iec104.pcap (testing/Traces/first/README); fifth/ and sixth/ were added in 2025 (commits 344fe86, b06d12f) without a statement of how they were made. " +
			"second/, third/ and fourth/ are byte-identical copies of files of the Zenodo record and are fetched by make captures-fetch, not committed. testing/Baseline holds Zeek's logs of the traces."},
	{ID: srcUOWM, URL: "https://zenodo.org/records/7108614",
		Revision: "record 7108614, revision 6 (published 2022-09-23, updated 2024-07-16)",
		Terms:    "CC-BY-4.0 (record metadata). Cite: P. Radoglou-Grammatikis et al., IEEE Transactions on Industrial Informatics 18(3), 2022, doi:10.1109/TII.2021.3093905.",
		Notes: "IEC 60870-5-104 Intrusion Detection Dataset, University of Western Macedonia. Each 7z archive holds, per entity, the whole traffic and an *_iec104_only.pcap filtered to the IEC 104 frames (no SYN, no ACK-only segments). " +
			"The ReadMe names five virtual RTUs (IEC TestServer on Windows 7), two real RTU devices, QTester104 v2.1 as HMI and three Kali Linux attackers (Metasploit iec104 module, OpenMUC j60870). " +
			"The ReadMe identifies the real RTUs neither by address nor by make or model. In the recordings all seven controlled stations (192.168.1.13, .19, .21, .22, .24, .25, .26) have MAC addresses of the VirtualBox range 08:00:27 and behave identically; none can be shown to be a physical device."},
	{ID: srcWireshk, URL: "https://gitlab.com/wireshark/wireshark/-/blob/f7e10bdd477b2f8f4995aa45c8155a0768f433ab/test/captures/iec104_coverage.pcap.gz",
		Revision: "f7e10bdd477b2f8f4995aa45c8155a0768f433ab",
		Terms:    "The Wireshark repository is GPL-2.0-or-later; the capture has no statement of its own.",
		Notes:    "A synthetic capture written for the dissector tests (commit message: generated, not taken from a network)."},
}

var manifestFiles = []entry{
	{Path: "certlv/unknown_unknown_interrogation-commands.pcap", Source: srcCERTLV, OriginalName: "testing/Traces/first/iec104.pcap",
		Evidence: "C", Basis: "Recorded on a network (Ethernet, 2013-07-04); the station's MAC prefix 00:16:D1 is registered to ZAT a.s., the client's 00:22:15 to ASUSTek; neither the software nor a device model is stated anywhere.",
		Systems:    []string{"controlling station 10.20.102.1 (unknown software)", "controlled station 10.20.100.108, common address 10 (unknown device)"},
		Operations: "TESTFR, STARTDT, two station interrogations (one answered by end of initialization first), single, double, regulating step, bitstring and set point commands (normalized, scaled, float) with confirmations, terminations and the spontaneous returns, with and without CP56Time2a",
		Privacy:    "private addresses only", Missing: "the controlled station's make, model and firmware"},
	{Path: "certlv/unknown_unknown_file-read.pcapng", Source: srcCERTLV, OriginalName: "testing/Traces/fifth/read.pcapng",
		Evidence: "D", Basis: "Recorded on the loopback interface (127.0.0.1 both ends, 2025-11-14): two programs on one host; which implementations is not stated.",
		Systems:    []string{"controlling station (unknown software)", "controlled station, common address 1 (unknown software)"},
		Operations: "STARTDT, clock synchronization and interrogations to the broadcast address, counter interrogation, three file downloads (11, 11 and 24568 octets, sections of 5000) with section and file acknowledgements, crossed TESTFR",
		Privacy:    "loopback only", Missing: "which implementations made it"},
	{Path: "certlv/unknown_unknown_file-write.pcapng", Source: srcCERTLV, OriginalName: "testing/Traces/fifth/write.pcapng",
		Evidence: "D", Basis: "Recorded on the loopback interface (2025-11-14): two programs on one host; which implementations is not stated.",
		Systems:    []string{"controlling station (unknown software)", "controlled station, common address 1 (unknown software)"},
		Operations: "STARTDT, end of initialization, clock synchronization, interrogations, three file uploads to the station (11, 11 and 24568 octets), crossed TESTFR",
		Privacy:    "loopback only", Missing: "which implementations made it"},
	{Path: "certlv/unknown_unknown_errors.pcapng", Source: srcCERTLV, OriginalName: "testing/Traces/sixth/errors.pcapng",
		Evidence: "D", Basis: "Recorded on the loopback interface (2025-12-25): two programs on one host; which implementations is not stated.",
		Systems:    []string{"controlling station (unknown software)", "controlled station, common address 1 (unknown software)"},
		Operations: "End of initialization, clock synchronization, an interrogation answered with parameters of measured values (P_ME_NA_1..P_ME_NC_1, cause 20), reads and parameter activations refused with \"unknown information object address\", one parameter confirmed",
		Privacy:    "loopback only", Missing: "which implementations made it"},
	{Path: "uowm/qtester104_iec-testserver_c-ci-na-1.pcap", Source: srcUOWM,
		OriginalName: "20200426_UOWM_IEC104_Dataset_c_ci_na_1.7z: 20200426_UOWM_IEC104_Dataset_c_ci_na_1/20200426_UOWM_IEC104_Dataset_c_ci_na_1_qtester/20200426_UOWM_IEC104_Dataset_c_ci_na_1_qtester_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe): QTester104 against IEC TestServer on VirtualBox VMs (MAC prefix 08:00:27).",
		Systems:    []string{"QTester104 v2.1 on Windows 7, 192.168.1.20", "IEC TestServer on Windows 7, seven stations (VirtualBox)"},
		Operations: "seven conversations of about 3.5 hours: station interrogations, TESTFR both ways, spontaneous single points, integrated totals the station reports periodically",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "uowm/qtester104-attacker_iec-testserver_c-ci-na-1.pcap", Source: srcUOWM,
		OriginalName: "20200426_UOWM_IEC104_Dataset_c_ci_na_1.7z: .../20200426_UOWM_IEC104_Dataset_c_ci_na_1_iecserver1/20200426_UOWM_IEC104_Dataset_c_ci_na_1_iecserver1_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe); station 192.168.1.21 is a VirtualBox VM (08:00:27:e8:42:e6, NetBIOS name vm2_RTU-PC in the full recording).",
		Systems:    []string{"IEC TestServer, 192.168.1.21", "QTester104, 192.168.1.20", "attacker1, Kali Linux, 192.168.1.28 (Metasploit iec104 module)"},
		Operations: "the station's view: QTester104's interrogations and the attacker's unauthorized counter interrogations (C_CI_NA_1 with qualifier 20), each on a connection of its own",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "uowm/qtester104-attacker_iec-testserver_c-se-na-1.pcap", Source: srcUOWM,
		OriginalName: "20200427_UOWM_IEC104_Dataset_c_se_na_1.7z: .../20200427_UOWM_IEC104_Dataset_c_se_na_1_iecserver1_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe); VirtualBox VMs.",
		Systems:    []string{"IEC TestServer, 192.168.1.21", "QTester104, 192.168.1.20", "attacker1, 192.168.1.28"},
		Operations: "the attacker's set point commands (C_SE_NA_1, some of them two octets short of the type's length), the station's confirmations, QTester104's interrogations",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "uowm/qtester104-attacker_iec-testserver_c-sc-na-1.pcap", Source: srcUOWM,
		OriginalName: "20200428_UOWM_IEC104_Dataset_c_sc_na_1.7z: .../20200428_UOWM_IEC104_Dataset_c_sc_na_1_iecserver1_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe); VirtualBox VMs.",
		Systems:    []string{"IEC TestServer, 192.168.1.21", "QTester104, 192.168.1.20", "attacker1, 192.168.1.28"},
		Operations: "the attacker's single commands (C_SC_NA_1), confirmations and terminations, QTester104's interrogations",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "uowm/qtester104-attacker_iec-testserver_c-rd-na-1.pcap", Source: srcUOWM,
		OriginalName: "20200605_UOWM_IEC104_Dataset_c_rd_na_1.7z: .../20200605_UOWM_IEC104_Dataset_c_rd_na_1_iecserver1_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe); VirtualBox VMs.",
		Systems:    []string{"IEC TestServer, 192.168.1.21", "QTester104, 192.168.1.20", "attacker1, 192.168.1.28"},
		Operations: "the attacker's read commands (C_RD_NA_1 with cause activation and one octet too many), the station's negative confirmations, QTester104's interrogations",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "uowm/qtester104-attacker_iec-testserver_c-rp-na-1.pcap", Source: srcUOWM,
		OriginalName: "20200606_UOWM_IEC104_Dataset_c_rp_na_1.7z: .../20200606_UOWM_IEC104_Dataset_c_rp_na_1_iecserver1_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe); VirtualBox VMs.",
		Systems:    []string{"IEC TestServer, 192.168.1.21", "QTester104, 192.168.1.20", "attacker1, 192.168.1.28"},
		Operations: "the attacker's reset process commands (C_RP_NA_1), the station's negative confirmations without the qualifier octet, sent on every connection",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "uowm/qtester104-attacker_iec-testserver_m-sp-na-1-dos.pcap", Source: srcUOWM,
		OriginalName: "20200425_UOWM_IEC104_Dataset_m_sp_na_1_DoS.7z: .../20200425_UOWM_IEC104_Dataset_m_sp_na_1_DoS_iecserver1_iec104_only.pcap",
		Evidence:     "D", Basis: "Software testbed (ReadMe); VirtualBox VMs.",
		Systems:    []string{"IEC TestServer, 192.168.1.21", "QTester104, 192.168.1.20"},
		Operations: "32,697 spontaneous single points from the station to QTester104 in three hours, interrogations",
		Privacy:    "private testbed addresses only", Missing: "-"},
	{Path: "wireshark/synthetic_synthetic_iec104-coverage.pcap.gz", Source: srcWireshk, OriginalName: "test/captures/iec104_coverage.pcap.gz",
		Evidence: "E", Basis: "Generated for Wireshark's dissector tests, not taken from a network (commit message).",
		Systems:    []string{"none: generated"},
		Operations: "every defined type identification with one, two and sequence-numbered objects, all causes, U/S/I frames, APDUs sharing a segment and split over two, noise before a start octet, IEC 60870-5-7 security ASDUs with placeholder data, IEC 101/103 frames on other ports",
		Privacy:    "placeholder data", Missing: "it is not traffic of any implementation"},
}

const manifestPath = "../../testdata/captures/manifest.json"

// derive computes the counts of one capture.
func derive(t *testing.T, path string) counts {
	t.Helper()
	convs, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c counts
	types := map[asdu.TypeID]bool{}
	for _, cv := range convs {
		a := Analyze(cv, asdu.IEC104)
		c.Conversations++
		if a.FromZero {
			c.FromZero++
		}
		c.APDUs += len(cv.APDUs)
		c.I, c.S, c.U = c.I+a.I, c.S+a.S, c.U+a.U
		c.Retransmitted += cv.Retransmitted
		c.OutOfOrder += cv.OutOfOrder
		c.Gaps += cv.Gaps
		c.Split += cv.Split
		c.Shared += cv.Shared
		c.Skipped += cv.Skipped
		c.StoppedI += len(a.StoppedI)
		for _, s := range a.Seq {
			c.SeqErrors += len(s.SendErrors) + len(s.RecvErrors)
		}
		for _, d := range a.Decoded {
			switch {
			case d.APCIErr != nil:
				c.APCIErrors++
			case d.ASDUErr != nil:
				c.ASDUErrors++
			case d.Exact():
				c.Exact++
			}
			if d.ASDU != nil {
				types[d.ASDU.Type] = true
			}
		}
	}
	c.Types = len(types)
	return c
}

func buildManifest(t *testing.T) manifest {
	t.Helper()
	m := manifest{
		Description: "Recorded IEC 60870-5-104 traffic go-iec104 is tested against (testdata/captures/README.md). Files are byte-identical to their sources.",
		Levels: map[string]string{
			"A": "verified physical-device traffic",
			"B": "credibly documented physical-device traffic",
			"C": "independent recorded traffic, hardware origin unknown",
			"D": "simulated or software testbed",
			"E": "standards-derived examples or generated fixtures",
		},
		Sources: manifestSources,
	}
	for _, e := range manifestFiles {
		p := filepath.Join("..", "..", "testdata", "captures", filepath.FromSlash(e.Path))
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		e.Size, e.SHA256 = len(b), hex.EncodeToString(sum[:])
		for _, s := range manifestSources {
			if s.ID == e.Source && e.URL == "" {
				e.URL = s.URL
			}
		}
		switch {
		case strings.HasSuffix(e.Path, ".pcapng"):
			e.Format = "pcapng, BSD loopback (link type 0), IPv4, TCP 2404"
		case strings.HasSuffix(e.Path, ".pcap.gz"):
			e.Format = "pcap (gzip), Ethernet, IPv4, TCP 2404"
		default:
			e.Format = "pcap, Ethernet, IPv4, TCP 2404"
		}
		e.Recorded = recordedSpan(t, b)
		e.Counts = derive(t, p)
		m.Files = append(m.Files, e)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m
}

// recordedSpan returns the first and last time stamp of a capture.
func recordedSpan(t *testing.T, b []byte) string {
	t.Helper()
	b, err := gunzip(b)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := packets(b)
	if err != nil || len(ps) == 0 {
		t.Fatal(err)
	}
	return ps[0].time.Format("2006-01-02 15:04:05Z07:00") + " .. " + ps[len(ps)-1].time.Format("2006-01-02 15:04:05Z07:00")
}

func TestManifest(t *testing.T) {
	m := buildManifest(t)
	got, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("IEC104_CAPTURE_GENERATE") != "" {
		if err := os.WriteFile(manifestPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("testdata/captures/manifest.json is not what the captures and the code give: run make captures-manifest and review the difference")
	}
	if len(committed(t)) != len(manifestFiles) {
		t.Errorf("%d captures committed, %d in the manifest", len(committed(t)), len(manifestFiles))
	}
}

// TestGenerateFuzzSeeds writes fuzz seeds for apci.FuzzParse and
// asdu.FuzzDecode from the recorded (not generated) captures: one APDU, and one ASDU, of
// every distinct shape (format, type identification, cause and P/N and T
// bits, decodes or not). It runs with IEC104_CAPTURE_GENERATE=1.
func TestGenerateFuzzSeeds(t *testing.T) {
	if os.Getenv("IEC104_CAPTURE_GENERATE") == "" {
		t.Skip("set IEC104_CAPTURE_GENERATE=1 to rewrite the fuzz seeds taken from the captures")
	}
	write := func(dir string, b []byte) {
		sum := sha256.Sum256(b)
		name := filepath.Join(dir, "capture-"+hex.EncodeToString(sum[:8]))
		body := "go test fuzz v1\n[]byte(" + strconvQuote(b) + ")\n"
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	apciDir := filepath.Join("..", "..", "apci", "testdata", "fuzz", "FuzzParse")
	asduDir := filepath.Join("..", "..", "asdu", "testdata", "fuzz", "FuzzDecode")
	seen := map[string]bool{}
	for _, f := range committed(t) {
		if strings.Contains(f, "synthetic") {
			continue // generated: the codec tests cover its shapes
		}
		convs, err := ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range convs {
			for _, d := range Analyze(c, asdu.IEC104).Decoded {
				key := []byte{byte(d.Frame.Format)}
				if d.APCIErr != nil {
					key = append(key, 0xff)
				}
				if len(d.Frame.ASDU) >= 3 {
					key = append(key, d.Frame.ASDU[0], d.Frame.ASDU[2])
				}
				if d.ASDUErr != nil {
					key = append(key, 0xee)
				}
				if seen[string(key)] {
					continue
				}
				seen[string(key)] = true
				write(apciDir, d.Data)
				if d.APCIErr == nil && d.Frame.Format == 0 {
					write(asduDir, d.Frame.ASDU)
				}
			}
		}
	}
}

// strconvQuote quotes b the way the fuzz corpus files do.
func strconvQuote(b []byte) string { return strconv.Quote(string(b)) }
