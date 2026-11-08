// SPDX-License-Identifier: MIT

package capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

// Wireshark as an independent decoder. make captures-oracle runs tshark over
// every committed capture and keeps, per frame, the fields below in
// <capture>.tshark.tsv.gz next to it; TestOracleTshark compares what
// go-iec104 decodes from the same frames with them, field by field. The
// files record the tshark version they were made with.

// oracleFields are the tshark fields kept, in column order after
// frame.number. Each column holds one value per APDU, ASDU or information
// object of the frame, comma-separated.
var oracleFields = []string{
	"iec60870_104.type", "iec60870_104.tx", "iec60870_104.rx", "iec60870_104.utype",
	"iec60870_asdu.typeid", "iec60870_asdu.numix", "iec60870_asdu.sq", "iec60870_asdu.causetx",
	"iec60870_asdu.nega", "iec60870_asdu.test", "iec60870_asdu.oa", "iec60870_asdu.addr",
	"iec60870_asdu.ioa",
	"iec60870_asdu.siq.spi", "iec60870_asdu.diq.dpi",
	"iec60870_asdu.normval", "iec60870_asdu.scalval", "iec60870_asdu.float", "iec60870_asdu.bcr.count",
	"iec60870_asdu.cp56time.ms", "iec60870_asdu.cp56time.min", "iec60870_asdu.cp56time.hour",
	"iec60870_asdu.cp56time.day", "iec60870_asdu.cp56time.dow", "iec60870_asdu.cp56time.month",
	"iec60870_asdu.cp56time.year", "iec60870_asdu.cp56time.iv", "iec60870_asdu.cp56time.su",
	"iec60870_asdu.qoi",
}

// oracleFile is the oracle of a capture.
func oracleFile(capture string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(capture, ".gz"), filepath.Ext(strings.TrimSuffix(capture, ".gz")))
	return base + ".tshark.tsv.gz"
}

// TestGenerateOracle writes the oracle files. It needs tshark and runs only
// with IEC104_CAPTURE_ORACLE=1 (make captures-oracle).
func TestGenerateOracle(t *testing.T) {
	if os.Getenv("IEC104_CAPTURE_ORACLE") == "" {
		t.Skip("set IEC104_CAPTURE_ORACLE=1 to regenerate the tshark oracle (needs tshark)")
	}
	version, err := exec.Command("tshark", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(version), "\n")
	for _, f := range committed(t) {
		args := []string{"-r", f, "-n", "-Y", "tcp.port == 2404 && iec60870_104", "-T", "fields",
			"-E", "occurrence=a", "-E", "aggregator=,", "-E", "separator=/t", "-e", "frame.number"}
		for _, fl := range oracleFields {
			args = append(args, "-e", fl)
		}
		out, err := exec.Command("tshark", args...).Output()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := fmt.Fprintf(zw, "# %s\n# frame.number\t%s\n", strings.TrimSpace(first), strings.Join(oracleFields, "\t")); err != nil {
			t.Fatal(err)
		}
		_, _ = zw.Write(out)
		_ = zw.Close()
		if err := os.WriteFile(oracleFile(f), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// committed returns the committed captures.
func committed(t testing.TB) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{"*.pcap", "*.pcapng", "*.pcap.gz"} {
		m, err := filepath.Glob(filepath.Join("..", "..", "testdata", "captures", "*", pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no captures in testdata/captures")
	}
	return files
}

// oracleRow is one frame of the oracle: one value list per field.
type oracleRow map[string][]string

func readOracle(t *testing.T, path string) (version string, rows map[int]oracleRow) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	rows = map[int]oracleRow{}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "# ") {
			if version == "" {
				version = line[2:]
			}
			continue
		}
		cols := strings.Split(line, "\t")
		frame, err := strconv.Atoi(cols[0])
		if err != nil || len(cols) != len(oracleFields)+1 {
			t.Fatalf("%s: malformed line %q", path, line)
		}
		row := oracleRow{}
		for i, f := range oracleFields {
			if cols[i+1] != "" {
				row[f] = strings.Split(cols[i+1], ",")
			}
		}
		rows[frame] = row
	}
	return version, rows
}

// ourRow is what go-iec104 decodes from the APDUs a frame completes, in the
// form of the oracle columns.
func ourRow(ds []Decoded) oracleRow {
	row := oracleRow{}
	add := func(f, v string) { row[f] = append(row[f], v) }
	b := func(v bool) string {
		if v {
			return "True"
		}
		return "False"
	}
	for _, d := range ds {
		if d.APCIErr != nil {
			continue
		}
		f := d.Frame
		switch f.Format {
		case apci.FormatI:
			add("iec60870_104.type", "0x00000000")
			add("iec60870_104.tx", strconv.Itoa(int(f.SendSeq)))
			add("iec60870_104.rx", strconv.Itoa(int(f.RecvSeq)))
		case apci.FormatS:
			add("iec60870_104.type", "0x00000001")
			add("iec60870_104.rx", strconv.Itoa(int(f.RecvSeq)))
		case apci.FormatU:
			add("iec60870_104.type", "0x00000003")
			add("iec60870_104.utype", fmt.Sprintf("0x%08x", uint8(f.Function)>>2))
		}
		x := d.ASDU
		if x == nil {
			continue
		}
		add("iec60870_asdu.typeid", strconv.Itoa(int(x.Type)))
		add("iec60870_asdu.numix", strconv.Itoa(x.Len()))
		add("iec60870_asdu.sq", b(x.Sequence))
		add("iec60870_asdu.causetx", strconv.Itoa(int(x.Cause)))
		add("iec60870_asdu.nega", b(x.Negative))
		add("iec60870_asdu.test", b(x.Test))
		add("iec60870_asdu.oa", strconv.Itoa(int(x.Originator)))
		add("iec60870_asdu.addr", strconv.Itoa(int(x.CommonAddr)))
		for _, o := range x.Objects {
			add("iec60870_asdu.ioa", strconv.Itoa(int(o.Address())))
			objectFields(o, add, b)
		}
	}
	return row
}

// objectFields adds the oracle columns of one information object.
func objectFields(o asdu.InformationObject, add func(f, v string), b func(bool) string) {
	v := reflect.ValueOf(o)
	switch o := o.(type) {
	case asdu.SinglePoint:
		add("iec60870_asdu.siq.spi", b(o.Value))
	case asdu.DoublePoint:
		add("iec60870_asdu.diq.dpi", strconv.Itoa(int(o.Value)))
	case asdu.MeasuredNormalized:
		add("iec60870_asdu.normval", strconv.FormatFloat(o.Value.Float64(), 'g', -1, 64))
	case asdu.SetpointNormalized:
		add("iec60870_asdu.normval", strconv.FormatFloat(o.Value.Float64(), 'g', -1, 64))
	case asdu.ParameterNormalized:
		add("iec60870_asdu.normval", strconv.FormatFloat(o.Value.Float64(), 'g', -1, 64))
	case asdu.ParameterScaled:
		add("iec60870_asdu.scalval", strconv.Itoa(int(o.Value)))
	case asdu.ParameterFloat:
		add("iec60870_asdu.float", strconv.FormatFloat(float64(o.Value), 'g', -1, 32))
	case asdu.MeasuredScaled:
		add("iec60870_asdu.scalval", strconv.Itoa(int(o.Value)))
	case asdu.SetpointScaled:
		add("iec60870_asdu.scalval", strconv.Itoa(int(o.Value)))
	case asdu.MeasuredFloat:
		add("iec60870_asdu.float", strconv.FormatFloat(float64(o.Value), 'g', -1, 32))
	case asdu.SetpointFloat:
		add("iec60870_asdu.float", strconv.FormatFloat(float64(o.Value), 'g', -1, 32))
	case asdu.IntegratedTotal:
		add("iec60870_asdu.bcr.count", strconv.Itoa(int(o.Value)))
	case asdu.Interrogation:
		add("iec60870_asdu.qoi", strconv.Itoa(int(o.Qualifier)))
	}
	tf := v.FieldByName("Time")
	if !tf.IsValid() {
		return
	}
	ts, ok := tf.Interface().(asdu.Timestamp)
	if !ok {
		return
	}
	if !hasCP56(o) {
		return
	}
	cp := asdu.New(asdu.CauseSpontaneous, 1, asdu.ClockSync{Time: ts})
	raw, err := cp.Encode(asdu.IEC104)
	if err != nil {
		return
	}
	t := raw[len(raw)-7:]
	add("iec60870_asdu.cp56time.ms", strconv.Itoa(int(t[0])|int(t[1])<<8))
	add("iec60870_asdu.cp56time.min", strconv.Itoa(int(t[2]&0x3f)))
	add("iec60870_asdu.cp56time.hour", strconv.Itoa(int(t[3]&0x1f)))
	add("iec60870_asdu.cp56time.day", strconv.Itoa(int(t[4]&0x1f)))
	add("iec60870_asdu.cp56time.dow", strconv.Itoa(int(t[4]>>5)))
	add("iec60870_asdu.cp56time.month", strconv.Itoa(int(t[5]&0x0f)))
	add("iec60870_asdu.cp56time.year", strconv.Itoa(int(t[6]&0x7f)))
	add("iec60870_asdu.cp56time.iv", b(t[2]&0x80 != 0))
	add("iec60870_asdu.cp56time.su", b(t[3]&0x80 != 0))
}

// hasCP56 reports whether o is of a type that carries a CP56Time2a.
func hasCP56(o asdu.InformationObject) bool {
	t := asdu.TypeOf(o)
	if _, ok := o.(asdu.ClockSync); ok {
		return true
	}
	return t.HasTimeTag() && !strings.Contains(t.Description(), "CP24Time2a")
}

// sameValue compares one oracle value with go-iec104's: numbers
// numerically (tshark prints floats with its own precision), all else as
// text.
func sameValue(field, want, got string) bool {
	if want == got {
		return true
	}
	if field == "iec60870_asdu.normval" || field == "iec60870_asdu.float" {
		w, err1 := strconv.ParseFloat(want, 64)
		g, err2 := strconv.ParseFloat(got, 64)
		return err1 == nil && err2 == nil && math.Abs(w-g) <= 1e-6*math.Max(1, math.Abs(w))
	}
	return false
}

// oracleDiff is a difference between tshark and go-iec104 in one frame.
type oracleDiff struct {
	Frame        int
	Field        string
	Tshark, Ours string
	Class        string
}

// Classes of differences between Wireshark and go-iec104.
const (
	classPortReuse = "Wireshark does not dissect a connection that reuses the ports of an earlier one when the recording left out the SYN (it takes the segments for retransmissions); go-iec104 starts a new connection at the jump in sequence numbers"
	classMalformed = "an ASDU whose length does not match its type identification: go-iec104 refuses it whole (asdu.ErrMalformed); Wireshark shows its header"
	classInvalidU  = "a U frame with more than one function bit: go-iec104 refuses it (apci.ErrInvalidControl); Wireshark lists both functions"
	classRawType   = "Wireshark 4.6.9 shows the information objects of this type identification as raw data; go-iec104 decodes them"
	classSecurity  = "IEC 62351-5 ASDUs (type identifications 81..87): the asdu package carries them as raw payload for package sec; Wireshark decodes the ASDU some of them wrap"
	classRaw       = "a type identification go-iec104 has no object model for (reserved types, S_IT_TC_1 = 41 of IEC 60870-5-7): carried as raw payload (asdu.ASDU.Raw); Wireshark decodes or guesses its objects"
	classWeekday   = "a day of week that does not match the date (the synthetic capture sets it freely): go-iec104 keeps whether the field is used (Timestamp.NoWeekday) and derives the day from the date"
	classOther     = "unclassified"
)

// compareOracle compares every frame of a capture with the oracle.
func compareOracle(t *testing.T, file string) (frames, values int, diffs []oracleDiff) {
	t.Helper()
	_, rows := readOracle(t, oracleFile(file))
	convs, err := ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	byFrame := map[int][]Decoded{}
	for _, c := range convs {
		for _, d := range Analyze(c, asdu.IEC104).Decoded {
			byFrame[d.APDU.Frame] = append(byFrame[d.APDU.Frame], d)
		}
	}
	defer func() {
		for i := range diffs {
			diffs[i].Class = classify(diffs[i], byFrame[diffs[i].Frame])
		}
	}()
	seen := map[int]bool{}
	for f := range rows {
		seen[f] = true
	}
	for f := range byFrame {
		seen[f] = true
	}
	for f := range seen {
		want, got := rows[f], ourRow(byFrame[f])
		if want == nil {
			diffs = append(diffs, oracleDiff{Frame: f, Field: "frame", Tshark: "not dissected", Ours: fmt.Sprint(len(byFrame[f]), " APDUs")})
			continue
		}
		frames++
		for _, field := range oracleFields {
			w, g := want[field], got[field]
			if len(w) != len(g) {
				diffs = append(diffs, oracleDiff{Frame: f, Field: field, Tshark: strings.Join(w, ","), Ours: strings.Join(g, ",")})
				continue
			}
			for i := range w {
				values++
				if !sameValue(field, w[i], g[i]) {
					diffs = append(diffs, oracleDiff{Frame: f, Field: field, Tshark: w[i], Ours: g[i]})
				}
			}
		}
	}
	return frames, values, diffs
}

// classify names the class of a difference from what go-iec104 decoded
// in the frame.
func classify(d oracleDiff, ds []Decoded) string {
	if d.Field == "frame" {
		return classPortReuse
	}
	for _, x := range ds {
		switch {
		case x.APCIErr != nil:
			return classInvalidU
		case x.ASDUErr != nil:
			return classMalformed
		case x.ASDU != nil && x.ASDU.Type.IsSecurity():
			return classSecurity
		case x.ASDU != nil && len(x.ASDU.Objects) == 0 && x.ASDU.Raw != nil:
			return classRaw
		}
	}
	if d.Field == "iec60870_asdu.cp56time.dow" && d.Tshark != "0" {
		return classWeekday
	}
	for _, x := range ds {
		if x.ASDU != nil && len(x.ASDU.Objects) > 0 && !strings.HasPrefix(d.Field, "iec60870_104.") &&
			(d.Tshark == "" || strings.Count(d.Tshark, ",") < strings.Count(d.Ours, ",")) {
			return classRawType
		}
	}
	return classOther
}

// oracleExpected pins, per capture, the frames compared with Wireshark,
// the values compared in them and the differences by class. Every
// difference is classified; a new one fails the test.
var oracleExpected = map[string]struct {
	frames, values int
	diffs          map[string]int
}{
	"certlv/unknown_unknown_errors.pcapng":                       {49, 423, nil},
	"certlv/unknown_unknown_file-read.pcapng":                    {198, 2038, nil},
	"certlv/unknown_unknown_file-write.pcapng":                   {197, 2016, nil},
	"certlv/unknown_unknown_interrogation-commands.pcap":         {64, 1905, nil},
	"uowm/qtester104-attacker_iec-testserver_c-ci-na-1.pcap":     {3442, 17575, nil},
	"uowm/qtester104-attacker_iec-testserver_c-rd-na-1.pcap":     {5014, 23140, map[string]int{classMalformed: 1773, classPortReuse: 3}},
	"uowm/qtester104-attacker_iec-testserver_c-rp-na-1.pcap":     {5191, 21635, map[string]int{classMalformed: 3798, classPortReuse: 12}},
	"uowm/qtester104-attacker_iec-testserver_c-sc-na-1.pcap":     {3763, 18921, nil},
	"uowm/qtester104-attacker_iec-testserver_c-se-na-1.pcap":     {3795, 17543, map[string]int{classMalformed: 1062, classPortReuse: 2}},
	"uowm/qtester104-attacker_iec-testserver_m-sp-na-1-dos.pcap": {26601, 436137, nil},
	"uowm/qtester104_iec-testserver_c-ci-na-1.pcap":              {16726, 75654, nil},
	"wireshark/synthetic_synthetic_iec104-coverage.pcap.gz": {262, 4220, map[string]int{
		classInvalidU: 2, classMalformed: 9, classRaw: 47, classRawType: 394, classSecurity: 20, classWeekday: 137}},
}

func TestOracleTshark(t *testing.T) {
	files := committed(t)
	if len(files) != len(oracleExpected) {
		t.Errorf("%d committed captures, %d in oracleExpected", len(files), len(oracleExpected))
	}
	for _, f := range files {
		name := strings.TrimPrefix(filepath.ToSlash(f), "../../testdata/captures/")
		t.Run(name, func(t *testing.T) {
			version, _ := readOracle(t, oracleFile(f))
			frames, values, diffs := compareOracle(t, f)
			want, ok := oracleExpected[name]
			if !ok {
				t.Fatalf("no oracleExpected entry")
			}
			got := map[string]int{}
			for _, d := range diffs {
				got[d.Class]++
				if d.Class == classOther {
					t.Errorf("frame %d %s: Wireshark %q, go-iec104 %q", d.Frame, d.Field, d.Tshark, d.Ours)
				}
			}
			if frames != want.frames || values != want.values {
				t.Errorf("%d frames, %d values compared; want %d and %d", frames, values, want.frames, want.values)
			}
			for c, n := range got {
				if want.diffs[c] != n {
					t.Errorf("%d differences, want %d: %s", n, want.diffs[c], c)
				}
			}
			for c, n := range want.diffs {
				if got[c] == 0 {
					t.Errorf("0 differences, want %d: %s", n, c)
				}
			}
			t.Logf("%s: %d frames, %d values, %d classified differences", version, frames, values, len(diffs))
		})
	}
}
