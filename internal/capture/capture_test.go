// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

// seg is one TCP segment of a synthetic capture.
type seg struct {
	toServer bool
	flags    byte // TCP flags; 0x18 (PSH, ACK) when zero
	seq      uint32
	payload  []byte
	cport    uint16 // client port, 50000 when zero
}

const (
	synFlag = 0x02
	finFlag = 0x01
	rstFlag = 0x04
	ackFlag = 0x10
)

// ipTCP returns an IPv4 packet with one TCP segment between 10.0.0.1 (the
// client) and 10.0.0.2:2404.
func ipTCP(s seg) []byte {
	cport := s.cport
	if cport == 0 {
		cport = 50000
	}
	src, dst := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	sport, dport := cport, uint16(Port)
	if !s.toServer {
		src, dst, sport, dport = dst, src, dport, sport
	}
	flags := s.flags
	if flags == 0 {
		flags = 0x18
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], s.seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	tcp = append(tcp, s.payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = protoTCP
	copy(ip[12:], src)
	copy(ip[16:], dst)
	return append(ip, tcp...)
}

func ether(ip []byte) []byte {
	return append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00}, ip...)
}

// pcapFile builds a little-endian microsecond pcap with the given link type.
func pcapFile(link uint32, frames ...[]byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], 65535)
	binary.LittleEndian.PutUint32(b[20:], link)
	for i, f := range frames {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(h[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(h[12:], uint32(len(f)))
		b = append(append(b, h...), f...)
	}
	return b
}

func ethPcap(segs ...seg) []byte {
	frames := make([][]byte, len(segs))
	for i, s := range segs {
		frames[i] = ether(ipTCP(s))
	}
	return pcapFile(linkEthernet, frames...)
}

func u(fn apci.UFunction) []byte { b, _ := apci.NewU(fn).MarshalBinary(); return b }

func iframe(ns, nr uint16, a *asdu.ASDU) []byte {
	raw, err := a.Encode(asdu.IEC104)
	if err != nil {
		panic(err)
	}
	b, _ := apci.NewI(ns, nr, raw).MarshalBinary()
	return b
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var (
	startAct = u(apci.StartDTAct)
	startCon = u(apci.StartDTCon)
	gi       = iframe(0, 0, asdu.New(asdu.CauseActivation, 1, asdu.Interrogation{Qualifier: asdu.QOIStation}))
	giCon    = iframe(0, 1, asdu.New(asdu.CauseActivationCon, 1, asdu.Interrogation{Qualifier: asdu.QOIStation}))
	point    = iframe(1, 1, asdu.New(asdu.CauseInterrogatedStation, 1, asdu.SinglePoint{IOA: 100, Value: true}))
	giTerm   = iframe(2, 1, asdu.New(asdu.CauseActivationTerm, 1, asdu.Interrogation{Qualifier: asdu.QOIStation}))
)

// conversation returns the frames of a short interrogation with SYN, from
// client ISN 1000 and server ISN 5000.
func conversation() []seg {
	return []seg{
		{toServer: true, flags: synFlag, seq: 1000},
		{flags: synFlag | ackFlag, seq: 5000},
		{toServer: true, seq: 1001, payload: startAct},
		{seq: 5001, payload: startCon},
		{toServer: true, seq: 1007, payload: gi},
		{seq: 5007, payload: cat(giCon, point, giTerm)},
		{toServer: true, flags: finFlag | ackFlag, seq: 1007 + uint32(len(gi))},
	}
}

func readOne(t *testing.T, b []byte) Conversation {
	t.Helper()
	cs, err := Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("%d conversations, want 1", len(cs))
	}
	return cs[0]
}

func wantAPDUs(t *testing.T, c Conversation, want ...[]byte) {
	t.Helper()
	if len(c.APDUs) != len(want) {
		t.Fatalf("%d APDUs, want %d: %v", len(c.APDUs), len(want), c)
	}
	for i, w := range want {
		if !bytes.Equal(c.APDUs[i].Data, w) {
			t.Errorf("APDU %d = % x, want % x", i, c.APDUs[i].Data, w)
		}
	}
}

func TestReadConversation(t *testing.T) {
	c := readOne(t, ethPcap(conversation()...))
	if !c.Opened || !c.Closed || c.Reset || c.Client != "10.0.0.1:50000" || c.Server != "10.0.0.2:2404" {
		t.Errorf("conversation %+v", c)
	}
	wantAPDUs(t, c, startAct, startCon, gi, giCon, point, giTerm)
	if c.Shared != 1 || c.Split != 0 {
		t.Errorf("shared %d split %d, want 1 and 0", c.Shared, c.Split)
	}
	if !c.APDUs[0].FromClient || c.APDUs[1].FromClient || c.APDUs[5].Frame != 6 || c.APDUs[5].First != 6 {
		t.Errorf("APDU sides or frames wrong: %+v", c.APDUs)
	}
	if want := time.Unix(1700000005, 0).UTC(); !c.APDUs[5].Time.Equal(want) {
		t.Errorf("time %v, want %v", c.APDUs[5].Time, want)
	}
	a := Analyze(c, asdu.IEC104)
	if !a.FromZero || a.I != 4 || a.U != 2 || a.S != 0 {
		t.Errorf("analysis I=%d U=%d S=%d fromZero=%v", a.I, a.U, a.S, a.FromZero)
	}
	for _, d := range a.Decoded {
		if !d.Exact() {
			t.Errorf("frame %d not re-encoded exactly", d.APDU.Frame)
		}
	}
	p := a.ASDU[asdu.C_IC_NA_1]
	if p == nil || p.Requests != 1 || p.Confirmed != 1 || p.Terminated != 1 || p.Unanswered != 0 {
		t.Errorf("interrogation %+v", p)
	}
	if up := a.UFn["STARTDT"]; up == nil || up.Requests != 1 || up.Confirmed != 1 {
		t.Errorf("STARTDT %+v", up)
	}
	if a.Seq[Controlled].MaxUnacked != 3 || a.Seq[Controlling].MaxUnconfirmed != 3 || a.Unsolicited != 0 {
		t.Errorf("windows %+v, unsolicited %d", a.Seq, a.Unsolicited)
	}
}

func TestReadReassembly(t *testing.T) {
	segs := conversation()
	resp := segs[5].payload
	// The answer split in three segments that arrive out of order, one of
	// them twice, the request retransmitted.
	cut1, cut2 := 3, len(giCon)+4
	a := seg{seq: 5007, payload: resp[:cut1]}
	b := seg{seq: 5007 + uint32(cut1), payload: resp[cut1:cut2]}
	c := seg{seq: 5007 + uint32(cut2), payload: resp[cut2:]}
	frames := append(append([]seg{}, segs[:5]...), segs[4], c, a, b, a, segs[6])
	conv := readOne(t, ethPcap(frames...))
	wantAPDUs(t, conv, startAct, startCon, gi, giCon, point, giTerm)
	if conv.Retransmitted != 2 || conv.OutOfOrder != 2 || conv.Split != 2 || conv.Conflicts != 0 {
		t.Errorf("counters: %v", conv)
	}
	// giCon comes in a (frame 8) and b (frame 9); point in b and c (frame
	// 7), complete with b; giTerm in c.
	if conv.APDUs[3].First != 8 || conv.APDUs[3].Frame != 9 || conv.APDUs[4].First != 7 || conv.APDUs[4].Frame != 9 || conv.APDUs[5].Frame != 7 {
		t.Errorf("frames: %+v", conv.APDUs[3:])
	}
}

func TestReadConflict(t *testing.T) {
	segs := conversation()
	bad := append([]byte(nil), segs[5].payload...)
	bad[len(bad)-1] ^= 0xff
	frames := append(append([]seg{}, segs...), seg{seq: 5007, payload: bad})
	conv := readOne(t, ethPcap(frames...))
	if conv.Conflicts != 1 || conv.Retransmitted != 1 {
		t.Errorf("counters: %v", conv)
	}
	wantAPDUs(t, conv, startAct, startCon, gi, giCon, point, giTerm)
}

func TestReadGapAndNoise(t *testing.T) {
	segs := conversation()
	resp := segs[5].payload
	// The capture lost the octets of giCon's second half: giCon is dropped,
	// framing resumes at point. Noise before a start octet is skipped.
	half := len(giCon) / 2
	frames := append(append([]seg{}, segs[:5]...),
		seg{seq: 5007, payload: resp[:half]},
		seg{seq: 5007 + uint32(len(giCon)), payload: resp[len(giCon):]},
		seg{seq: 5007 + uint32(len(resp)), payload: cat([]byte{1, 2, 3}, u(apci.TestFRAct))},
		seg{seq: 5007 + uint32(len(resp)) + 9, payload: []byte{0x68}},
	)
	conv := readOne(t, ethPcap(frames...))
	wantAPDUs(t, conv, startAct, startCon, gi, point, giTerm, u(apci.TestFRAct))
	if conv.Gaps != 1 || conv.Dropped != 2 || conv.Skipped != half+3+1 {
		t.Errorf("counters: %v (half %d)", conv, half)
	}
}

func TestReadWithoutSYN(t *testing.T) {
	// A recording that kept only the payload: the lowest sequence number
	// starts the stream, even when its segment comes second.
	frames := []seg{
		{toServer: true, seq: 1007, payload: gi},
		{toServer: true, seq: 1001, payload: startAct},
		{seq: 5001, payload: startCon},
	}
	conv := readOne(t, ethPcap(frames...))
	if conv.Opened || conv.OutOfOrder != 1 {
		t.Errorf("counters: %v", conv)
	}
	wantAPDUs(t, conv, startAct, gi, startCon)
	// It begins with STARTDT act: checked from zero.
	if a := Analyze(conv, asdu.IEC104); !a.FromZero {
		t.Error("not from zero although it begins with STARTDT act")
	}
	// Without it the counters are taken from the first frames.
	conv = readOne(t, ethPcap(frames[0], frames[2]))
	if a := Analyze(conv, asdu.IEC104); a.FromZero || a.Seq[Controlling].Start != 0 || len(a.Seq[Controlling].SendErrors) != 0 {
		t.Errorf("analysis %+v", a.Seq)
	}
}

func TestReadPortReuse(t *testing.T) {
	// Two connections on the same ports: a SYN starts the second; without
	// SYN, so does a sequence number far from the first connection's.
	first := conversation()
	second := []seg{
		{toServer: true, flags: synFlag, seq: 900000000},
		{toServer: true, seq: 900000001, payload: startAct},
	}
	cs, err := Read(ethPcap(append(first, second...)...))
	if err != nil || len(cs) != 2 || len(cs[1].APDUs) != 1 || !cs[1].Opened {
		t.Fatalf("with SYN: %v %v", cs, err)
	}
	third := []seg{{toServer: true, seq: 2000000000, payload: startAct}}
	cs, err = Read(ethPcap(append(first[2:6], third...)...))
	if err != nil || len(cs) != 2 || len(cs[0].APDUs) != 6 || len(cs[1].APDUs) != 1 {
		t.Fatalf("without SYN: %v %v", cs, err)
	}
	// A reset ends the first.
	reset := append(append([]seg{}, first[:6]...), seg{flags: rstFlag | ackFlag, seq: 5007 + uint32(len(first[5].payload))})
	if c := readOne(t, ethPcap(reset...)); !c.Reset {
		t.Errorf("reset not seen: %v", c)
	}
}

func TestReadFormats(t *testing.T) {
	segs := conversation()
	ips := make([][]byte, len(segs))
	for i, s := range segs {
		ips[i] = ipTCP(s)
	}
	frames := func(prefix func([]byte) []byte) [][]byte {
		out := make([][]byte, len(ips))
		for i, ip := range ips {
			out[i] = prefix(ip)
		}
		return out
	}
	loop := func(ip []byte) []byte { return append([]byte{2, 0, 0, 0}, ip...) }
	sll := func(ip []byte) []byte { return append(append(make([]byte, 14), 0x08, 0x00), ip...) }
	vlan := func(ip []byte) []byte {
		return append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0, 5, 0x08, 0x00}, ip...)
	}
	raw := func(ip []byte) []byte { return ip }
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(ethPcap(segs...))
	_ = w.Close()
	for name, file := range map[string][]byte{
		"null":   pcapFile(linkNull, frames(loop)...),
		"sll":    pcapFile(linkSLL, frames(sll)...),
		"vlan":   pcapFile(linkEthernet, frames(vlan)...),
		"raw":    pcapFile(linkRaw, frames(raw)...),
		"gzip":   gz.Bytes(),
		"pcapng": pcapng(frames(func(ip []byte) []byte { return ether(ip) })),
		"bigend": bigEndian(ethPcap(segs...)),
	} {
		c := readOne(t, file)
		if len(c.APDUs) != 6 {
			t.Errorf("%s: %v", name, c)
		}
	}
}

// pcapng builds a little-endian pcapng file with nanosecond time stamps.
func pcapng(frames [][]byte) []byte {
	block := func(typ uint32, body []byte) []byte {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		n := uint32(12 + len(body))
		b := binary.LittleEndian.AppendUint32(nil, typ)
		b = binary.LittleEndian.AppendUint32(b, n)
		b = append(b, body...)
		return binary.LittleEndian.AppendUint32(b, n)
	}
	shb := binary.LittleEndian.AppendUint32(nil, 0x1a2b3c4d)
	shb = append(shb, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	idb := []byte{1, 0, 0, 0, 0, 0, 1, 0}
	idb = append(idb, 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0) // if_tsresol 9, end of options
	out := append(block(0x0a0d0d0a, shb), block(1, idb)...)
	for i, f := range frames {
		ts := uint64(1700000000+i) * 1e9
		body := binary.LittleEndian.AppendUint32(nil, 0)
		body = binary.LittleEndian.AppendUint32(body, uint32(ts>>32))
		body = binary.LittleEndian.AppendUint32(body, uint32(ts))
		body = binary.LittleEndian.AppendUint32(body, uint32(len(f)))
		body = binary.LittleEndian.AppendUint32(body, uint32(len(f)))
		out = append(out, block(6, append(body, f...))...)
	}
	return out
}

// bigEndian rewrites a little-endian microsecond pcap as big-endian.
func bigEndian(le []byte) []byte {
	b := append([]byte(nil), le...)
	swap := func(off, n int) {
		for i, j := off, off+n-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
	}
	swap(0, 4)
	swap(4, 2)
	swap(6, 2)
	for _, off := range []int{8, 12, 16, 20} {
		swap(off, 4)
	}
	for off := 24; off < len(b); {
		n := int(binary.LittleEndian.Uint32(b[off+8:]))
		for _, f := range []int{0, 4, 8, 12} {
			swap(off+f, 4)
		}
		off += 16 + n
	}
	return b
}

func TestReadErrors(t *testing.T) {
	good := ethPcap(conversation()...)
	for name, b := range map[string][]byte{
		"empty":        nil,
		"magic":        []byte("not a capture"),
		"short header": good[:20],
		"cut record":   good[:len(good)-3],
		"bad gzip":     {0x1f, 0x8b, 0, 0},
		"pcapng block": {0x0a, 0x0d, 0x0d, 0x0a, 8, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a},
	} {
		if _, err := Read(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v, want ErrFormat", name, err)
		}
	}
	if _, err := Read(pcapFile(147, []byte{1, 2, 3})); err == nil {
		t.Error("unsupported link type accepted")
	}
	if _, err := ReadFile("testdata/does-not-exist.pcap"); err == nil {
		t.Error("missing file accepted")
	}
}

func TestAnalyzeSequenceErrors(t *testing.T) {
	// The station acknowledges a frame the client never sent, then skips
	// a send sequence number.
	bad := iframe(0, 1, asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1}))
	skip := iframe(2, 0, asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 1}))
	frames := []seg{
		{toServer: true, flags: synFlag, seq: 1000},
		{flags: synFlag | ackFlag, seq: 5000},
		{toServer: true, seq: 1001, payload: startAct},
		{seq: 5001, payload: cat(startCon, bad, skip)},
		{toServer: true, seq: 1007, payload: u(apci.TestFRAct)},
		{seq: 5007 + uint32(len(bad)+len(skip)), payload: iframe(3, 0, asdu.New(asdu.CauseActivationCon, 1, asdu.Interrogation{}))},
	}
	a := Analyze(readOne(t, ethPcap(frames...)), asdu.IEC104)
	if len(a.Seq[Controlled].RecvErrors) != 1 || len(a.Seq[Controlled].SendErrors) != 1 {
		t.Errorf("errors %+v", a.Seq[Controlled])
	}
	if a.UFn["TESTFR"].Requests != 1 || a.UFn["TESTFR"].Confirmed != 0 {
		t.Errorf("TESTFR %+v", a.UFn["TESTFR"])
	}
	if len(a.StoppedI) != 0 || a.Unsolicited != 2 {
		t.Errorf("stopped %v unsolicited %d", a.StoppedI, a.Unsolicited)
	}
	if got := a.TypeList(); len(got) != 2 || got[0] != asdu.M_SP_NA_1 {
		t.Errorf("types %v", got)
	}
}
