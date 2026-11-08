// SPDX-License-Identifier: MIT

package capture

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

// CERT.LV's Spicy analyzer for Zeek as a second independent decoder.
// testdata/captures/certlv/zeek/<capture>/ holds, unchanged, the logs its
// test suite expects for the four CERT.LV traces (testing/Baseline of
// cert-lv/spicy-iec104 at the pinned revision). TestOracleZeek compares
// what go-iec104 decodes with the telemetry, interrogation, command, clock
// synchronization, parameter and read logs.

var zeekCaptures = map[string]string{
	"interrogation-commands": "certlv/unknown_unknown_interrogation-commands.pcap",
	"file-read":              "certlv/unknown_unknown_file-read.pcapng",
	"file-write":             "certlv/unknown_unknown_file-write.pcapng",
	"errors":                 "certlv/unknown_unknown_errors.pcapng",
}

// zeekLog returns the rows of a Zeek log as maps by field name; a missing
// log has no rows.
func zeekLog(t *testing.T, dir, name string) []map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var fields []string
	var rows []map[string]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#fields\t") {
			fields = strings.Split(line, "\t")[1:]
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != len(fields) {
			t.Fatalf("%s/%s: %d columns, %d fields", dir, name, len(cols), len(fields))
		}
		row := map[string]string{}
		for i, c := range cols {
			row[fields[i]] = c
		}
		rows = append(rows, row)
	}
	return rows
}

// zeekCause maps the analyzer's names of the causes of transmission.
var zeekCause = map[string]asdu.Cause{
	"Per/Cyc": asdu.CausePeriodic, "Back": asdu.CauseBackground, "Spont": asdu.CauseSpontaneous,
	"Init": asdu.CauseInitialized, "Req": asdu.CauseRequest, "Act": asdu.CauseActivation,
	"ActCon": asdu.CauseActivationCon, "Deact": asdu.CauseDeactivation, "DeactCon": asdu.CauseDeactivationCon,
	"ActTerm": asdu.CauseActivationTerm, "Inrogen": asdu.CauseInterrogatedStation, "UnkObjAddr": asdu.CauseUnknownIOA,
}

func zbool(v bool) string {
	if v {
		return "T"
	}
	return "F"
}

// zeekValue renders the value of an object as the analyzer logs it.
func zeekValue(o asdu.InformationObject) string {
	switch o := o.(type) {
	case asdu.SinglePoint:
		return zbool(o.Value)
	case asdu.DoublePoint:
		return strconv.Itoa(int(o.Value))
	case asdu.StepPosition:
		return strconv.Itoa(int(o.Value))
	case asdu.Bitstring32:
		return octets(o.Value)
	case asdu.MeasuredNormalized:
		return strconv.Itoa(int(o.Value))
	case asdu.MeasuredScaled:
		return strconv.Itoa(int(o.Value))
	case asdu.MeasuredFloat:
		return strconv.FormatFloat(float64(o.Value), 'f', -1, 32)
	case asdu.ParameterNormalized:
		return strconv.Itoa(int(o.Value))
	case asdu.ParameterScaled:
		return strconv.Itoa(int(o.Value))
	case asdu.ParameterFloat:
		return strconv.FormatFloat(float64(o.Value), 'f', -1, 32)
	case asdu.SingleCommand:
		return zbool(o.Value)
	case asdu.DoubleCommand:
		return strconv.Itoa(int(o.Value))
	case asdu.StepCommand:
		return strconv.Itoa(int(o.Value))
	case asdu.BitstringCommand:
		return octets(o.Value)
	case asdu.SetpointNormalized:
		return strconv.Itoa(int(o.Value))
	case asdu.SetpointScaled:
		return strconv.Itoa(int(o.Value))
	case asdu.SetpointFloat:
		return strconv.FormatFloat(float64(o.Value), 'f', -1, 32)
	}
	return "?"
}

// octets renders a 32-bit bitstring as its four octets in transmission
// order, as Zeek and Wireshark print it. go-iec104 holds it as a
// little-endian integer, as lib60870-C v2.4.1 does (BitString32_encode):
// the octets are the same.
func octets(v uint32) string {
	return fmt.Sprintf("0x%02x%02x%02x%02x", byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// sameZeek compares a logged value with go-iec104's; floats numerically.
func sameZeek(want, got string) bool {
	if want == got {
		return true
	}
	w, err1 := strconv.ParseFloat(want, 64)
	g, err2 := strconv.ParseFloat(got, 64)
	return err1 == nil && err2 == nil && math.Abs(w-g) <= 1e-6*math.Max(1, math.Abs(w))
}

// zeekTime renders a CP56Time2a as the analyzer logs it.
func zeekTime(ts asdu.Timestamp) string {
	return fmt.Sprintf("y=%02d mon=%02d day=%02d h=%02d min=%02d sec=%02d msec=%d iv=%s",
		ts.Year()%100, int(ts.Month()), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(),
		ts.Nanosecond()/1e6, zbool(ts.Invalid))
}

func timeOf(o asdu.InformationObject) (asdu.Timestamp, bool) {
	switch o := o.(type) {
	case asdu.SinglePoint:
		return o.Time, !o.Time.IsZero()
	case asdu.DoublePoint:
		return o.Time, !o.Time.IsZero()
	case asdu.StepPosition:
		return o.Time, !o.Time.IsZero()
	case asdu.Bitstring32:
		return o.Time, !o.Time.IsZero()
	case asdu.MeasuredNormalized:
		return o.Time, !o.Time.IsZero()
	case asdu.MeasuredScaled:
		return o.Time, !o.Time.IsZero()
	case asdu.MeasuredFloat:
		return o.Time, !o.Time.IsZero()
	case asdu.ClockSync:
		return o.Time, true
	}
	return asdu.Timestamp{}, false
}

func TestOracleZeek(t *testing.T) {
	for dir, capture := range zeekCaptures {
		t.Run(dir, func(t *testing.T) {
			logs := filepath.Join("..", "..", "testdata", "captures", "certlv", "zeek", dir)
			convs, err := ReadFile(filepath.Join("..", "..", "testdata", "captures", filepath.FromSlash(capture)))
			if err != nil {
				t.Fatal(err)
			}
			var station, requests []*asdu.ASDU
			for _, c := range convs {
				for _, d := range Analyze(c, asdu.IEC104).Decoded {
					switch {
					case d.ASDU == nil:
					case d.FromClient:
						requests = append(requests, d.ASDU)
					default:
						station = append(station, d.ASDU)
					}
				}
			}
			compared := 0
			check := func(log string, i int, field, want, got string) {
				compared++
				if !sameZeek(want, got) {
					t.Errorf("%s row %d %s: Zeek %q, go-iec104 %q", log, i, field, want, got)
				}
			}

			// Telemetry: the station's monitor-direction objects, and the
			// parameters it reports in answer to an interrogation.
			var tele []struct {
				a *asdu.ASDU
				o asdu.InformationObject
			}
			for _, a := range station {
				if a.Type.InControlDirection() && (a.Type < asdu.P_ME_NA_1 || a.Type > asdu.P_ME_NC_1 || a.Cause != asdu.CauseInterrogatedStation) {
					continue
				}
				if a.Type == asdu.M_EI_NA_1 || a.Type.IsFileTransfer() {
					continue
				}
				for _, o := range a.Objects {
					tele = append(tele, struct {
						a *asdu.ASDU
						o asdu.InformationObject
					}{a, o})
				}
			}
			rows := zeekLog(t, logs, "iec104_telemetry.log")
			if len(rows) != len(tele) {
				t.Fatalf("telemetry: Zeek %d rows, go-iec104 %d objects", len(rows), len(tele))
			}
			for i, r := range rows {
				x := tele[i]
				check("telemetry", i, "asdu_type", r["asdu_type"], x.a.Type.String())
				check("telemetry", i, "cot", strconv.Itoa(int(zeekCause[r["cot"]])), strconv.Itoa(int(x.a.Cause)))
				check("telemetry", i, "ca", r["ca"], strconv.Itoa(int(x.a.CommonAddr)))
				check("telemetry", i, "ioa", r["ioa"], strconv.Itoa(int(x.o.Address())))
				if !strings.HasPrefix(r["asdu_type"], "P_ME") {
					check("telemetry", i, "value", r["value"], zeekValue(x.o))
				}
				if ts, ok := timeOf(x.o); ok {
					check("telemetry", i, "cp56", r["cp56"], zeekTime(ts))
				}
			}

			// Interrogations and counter interrogations.
			var query []*asdu.ASDU
			for _, a := range requests {
				if a.Type == asdu.C_IC_NA_1 || a.Type == asdu.C_CI_NA_1 {
					query = append(query, a)
				}
			}
			rows = zeekLog(t, logs, "iec104_query.log")
			if len(rows) > len(query) {
				t.Fatalf("query: Zeek %d rows, go-iec104 %d requests", len(rows), len(query))
			}
			for i, r := range rows {
				// The analyzer logs one row per completed procedure; a
				// request repeated before its confirmation is one.
				a := query[len(query)-len(rows)+i]
				check("query", i, "asdu_type", r["asdu_type"], a.Type.String())
				switch o := a.First().(type) {
				case asdu.Interrogation:
					check("query", i, "qoi", r["qoi"], strconv.Itoa(int(o.Qualifier)))
				case asdu.CounterInterrogation:
					check("query", i, "qcc_rqt", r["qcc_rqt"], strconv.Itoa(int(o.Request)))
				}
			}

			// Commands.
			var cmds []*asdu.ASDU
			for _, a := range requests {
				if a.Type.IsProcessCommand() && a.Cause == asdu.CauseActivation {
					cmds = append(cmds, a)
				}
			}
			rows = zeekLog(t, logs, "iec104_write.log")
			if len(rows) != 0 && len(rows) != len(cmds) {
				t.Fatalf("write: Zeek %d rows, go-iec104 %d commands", len(rows), len(cmds))
			}
			for i, r := range rows {
				a := cmds[i]
				check("write", i, "asdu_type", r["asdu_type"], a.Type.String())
				check("write", i, "ca", r["ca"], strconv.Itoa(int(a.CommonAddr)))
				check("write", i, "ioa", r["ioa"], strconv.Itoa(int(a.First().Address())))
				check("write", i, "value", r["value"], zeekValue(a.First()))
			}

			// Clock synchronization.
			for i, r := range zeekLog(t, logs, "iec104_ctrl.log") {
				for _, a := range requests {
					if a.Type == asdu.C_CS_NA_1 {
						ts, _ := timeOf(a.First())
						check("ctrl", i, "time_sync", r["time_sync"], zeekTime(ts))
						ca := strconv.Itoa(int(a.CommonAddr))
						if r["status"] == "ok_broadcast" && a.CommonAddr == asdu.Broadcast {
							// The analyzer logs the address of the
							// station that confirmed a broadcast.
							ca = r["ca"]
						}
						check("ctrl", i, "ca", r["ca"], ca)
					}
				}
			}

			// Parameter activations the analyzer logs (the refused ones).
			var params []*asdu.ASDU
			for _, a := range requests {
				if a.Type >= asdu.P_ME_NA_1 && a.Type <= asdu.P_ME_NC_1 {
					params = append(params, a)
				}
			}
			for i, r := range zeekLog(t, logs, "iec104_param.log") {
				found := false
				for _, a := range params {
					if a.Type.String() == r["asdu_type"] && zeekValue(a.First()) == r["value"] && strconv.Itoa(int(a.First().Address())) == r["ioa"] {
						found = true
					}
				}
				compared++
				if !found {
					t.Errorf("param row %d: %s ioa %s value %s not among go-iec104's requests", i, r["asdu_type"], r["ioa"], r["value"])
				}
			}

			// Reads and their refusals.
			var reads []*asdu.ASDU
			for _, c := range [][]*asdu.ASDU{requests, station} {
				for _, a := range c {
					if a.Type == asdu.C_RD_NA_1 {
						reads = append(reads, a)
					}
				}
			}
			for i, r := range zeekLog(t, logs, "iec104_read.log") {
				found := false
				for _, a := range reads {
					if zeekCause[r["cot"]] == a.Cause && strconv.Itoa(int(a.First().Address())) == r["ioa"] && strconv.Itoa(int(a.CommonAddr)) == r["ca"] {
						found = true
					}
				}
				compared++
				if !found {
					t.Errorf("read row %d: cot %s ioa %s not among go-iec104's", i, r["cot"], r["ioa"])
				}
			}
			t.Logf("%d values compared with Zeek's logs", compared)
		})
	}
}
