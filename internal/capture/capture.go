// SPDX-License-Identifier: MIT

// Package capture reads recorded IEC 60870-5-104 traffic for tests: classic
// pcap and pcapng files, gzip-compressed or not, with Ethernet, BSD
// loopback, Linux cooked or raw IPv4 frames. It reassembles each TCP
// direction deterministically and splits the byte stream into APDUs.
//
// Reassembly orders the segments of a direction by sequence number, from
// the SYN when the capture holds it and from the lowest sequence number
// otherwise. A segment whose bytes were all delivered already (a
// retransmission) is dropped; a segment that overlaps delivered bytes
// contributes only its new bytes, and differing overlapping bytes are
// counted as conflicts. Segments that arrive out of order are put back in
// order. A sequence gap (bytes missing from the capture) ends a run of
// contiguous bytes: an APDU cut by it is counted as dropped, and framing
// resumes at the next start octet after it.
//
// The APDU framing is the one of IEC 60870-5-104 clause 5: start octet
// 0x68, a length octet of 4..253 and that many octets. Octets that are not
// a start octet where an APDU should begin are skipped and counted, never
// interpreted. A segment may carry several APDUs and an APDU may span
// several segments; each APDU records the frames its first and last octet
// came in.
//
// It is test infrastructure for the captures in testdata/captures and is not
// part of the public API. It reads files from this repository, but it
// still checks every length it reads.
package capture

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Port is the IEC 60870-5-104 port.
const Port = 2404

// APDU is one APDU of a conversation, start and length octets included.
type APDU struct {
	FromClient bool      // sent by the side that is not on the server port
	First      int       // 1-based number of the frame that carried the first octet
	Frame      int       // 1-based number of the frame that carried the last octet
	Time       time.Time // time of Frame
	Data       []byte
}

// Conversation is one TCP connection to the server port.
type Conversation struct {
	Client, Server string // "ip:port"
	// SYN, FIN and RST seen in either direction.
	Opened, Closed, Reset bool
	// Retransmitted counts segments whose bytes were all delivered already;
	// OutOfOrder segments that arrived after a segment with a higher
	// sequence number; Conflicts overlapping bytes that differ from the
	// ones delivered first.
	Retransmitted, OutOfOrder, Conflicts int
	// Gaps counts sequence gaps in both directions; Dropped the APDUs cut by
	// a gap or by the end of the capture; Skipped the octets outside any
	// APDU (noise before a start octet, or the rest of an APDU cut by a
	// gap).
	Gaps, Dropped, Skipped int
	// Split counts APDUs that span more than one segment; Shared the
	// segments that carry more than one APDU.
	Split, Shared int
	// APDUs of both directions. Each direction is in sequence order; the
	// two are merged by completing frame.
	APDUs []APDU
}

// ErrFormat reports a file that is neither pcap nor pcapng, or is cut short.
var ErrFormat = errors.New("capture: unsupported or malformed capture file")

// Link-layer header types (LINKTYPE_*).
const (
	linkNull     = 0
	linkEthernet = 1
	linkRaw      = 101
	linkLoop     = 108
	linkSLL      = 113
	linkIPv4     = 228
)

const (
	etherIPv4 = 0x0800
	etherVLAN = 0x8100
	protoTCP  = 6
)

// ReadFile reads a capture file and returns its conversations on [Port].
func ReadFile(path string) ([]Conversation, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	return Read(b)
}

// Read parses a capture held in memory and returns its conversations on
// [Port].
func Read(b []byte) ([]Conversation, error) { return ReadPort(b, Port) }

// ReadPort parses a capture held in memory and returns the conversations
// whose server listens on port, ordered by the frame that opened them.
func ReadPort(b []byte, port uint16) ([]Conversation, error) {
	b, err := gunzip(b)
	if err != nil {
		return nil, err
	}
	frames, err := packets(b)
	if err != nil {
		return nil, err
	}
	a := &assembler{port: port, current: map[connKey]*conn{}}
	for i, f := range frames {
		if err := a.frame(i+1, f); err != nil {
			return nil, fmt.Errorf("frame %d: %w", i+1, err)
		}
	}
	return a.conversations(), nil
}

// maxGunzip bounds the size of a decompressed capture.
const maxGunzip = 256 << 20

func gunzip(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxGunzip+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if len(out) > maxGunzip {
		return nil, fmt.Errorf("%w: more than %d octets decompressed", ErrFormat, maxGunzip)
	}
	return out, nil
}

// packet is one link-layer frame.
type packet struct {
	link uint32
	time time.Time
	data []byte
}

// packets returns the frames of a pcap or pcapng file.
func packets(b []byte) ([]packet, error) {
	if len(b) < 4 {
		return nil, ErrFormat
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		return pcapPackets(b, binary.LittleEndian, time.Microsecond)
	case 0xa1b23c4d:
		return pcapPackets(b, binary.LittleEndian, time.Nanosecond)
	case 0xd4c3b2a1:
		return pcapPackets(b, binary.BigEndian, time.Microsecond)
	case 0x4d3cb2a1:
		return pcapPackets(b, binary.BigEndian, time.Nanosecond)
	case 0x0a0d0d0a:
		return pcapngPackets(b)
	}
	return nil, ErrFormat
}

func pcapPackets(b []byte, bo binary.ByteOrder, unit time.Duration) ([]packet, error) {
	if len(b) < 24 {
		return nil, ErrFormat
	}
	link := bo.Uint32(b[20:24]) & 0x0fffffff
	var out []packet
	for off := 24; off < len(b); {
		if len(b)-off < 16 {
			return nil, ErrFormat
		}
		sec, frac := int64(bo.Uint32(b[off:])), int64(bo.Uint32(b[off+4:]))
		n := int(bo.Uint32(b[off+8 : off+12]))
		off += 16
		if n > len(b)-off {
			return nil, ErrFormat
		}
		ts := time.Unix(sec, frac*int64(unit)).UTC()
		out = append(out, packet{link: link, time: ts, data: b[off : off+n]})
		off += n
	}
	return out, nil
}

// iface is a pcapng interface: its link type and time stamp unit.
type iface struct {
	link uint32
	unit time.Duration
}

func pcapngPackets(b []byte) ([]packet, error) {
	var (
		bo    binary.ByteOrder = binary.LittleEndian
		ifcs  []iface
		out   []packet
		block int
	)
	for off := 0; off < len(b); off += block {
		if len(b)-off < 12 {
			return nil, ErrFormat
		}
		typ := bo.Uint32(b[off:])
		if typ == 0x0a0d0d0a { // section header: byte order from its magic
			switch binary.LittleEndian.Uint32(b[off+8:]) {
			case 0x1a2b3c4d:
				bo = binary.LittleEndian
			case 0x4d3c2b1a:
				bo = binary.BigEndian
			default:
				return nil, ErrFormat
			}
			ifcs = ifcs[:0]
		}
		block = int(bo.Uint32(b[off+4:]))
		if block < 12 || block%4 != 0 || block > len(b)-off {
			return nil, ErrFormat
		}
		body := b[off+8 : off+block-4]
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				return nil, ErrFormat
			}
			ifcs = append(ifcs, iface{link: uint32(bo.Uint16(body)), unit: tsresol(body[8:], bo)})
		case 6: // enhanced packet
			if len(body) < 20 {
				return nil, ErrFormat
			}
			ifc := int(bo.Uint32(body))
			capLen := int(bo.Uint32(body[12:]))
			if ifc >= len(ifcs) || capLen > len(body)-20 {
				return nil, ErrFormat
			}
			ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
			out = append(out, packet{link: ifcs[ifc].link, time: stamp(ts, ifcs[ifc].unit), data: body[20 : 20+capLen]})
		case 3: // simple packet, interface 0, no time stamp
			if len(body) < 4 || len(ifcs) == 0 {
				return nil, ErrFormat
			}
			capLen := min(int(bo.Uint32(body)), len(body)-4)
			out = append(out, packet{link: ifcs[0].link, data: body[4 : 4+capLen]})
		}
	}
	return out, nil
}

// tsresol returns the time stamp unit from the options of an interface
// description block: microseconds unless if_tsresol says otherwise.
func tsresol(opts []byte, bo binary.ByteOrder) time.Duration {
	for len(opts) >= 4 {
		code, n := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || n > len(opts)-4 {
			break
		}
		if code == 9 && n == 1 {
			r := opts[4]
			if r&0x80 == 0 && r <= 9 {
				u := time.Second
				for range r {
					u /= 10
				}
				return u
			}
		}
		opts = opts[4+(n+3)&^3:]
	}
	return time.Microsecond
}

func stamp(ts uint64, unit time.Duration) time.Time {
	per := uint64(time.Second / unit)
	sec, frac := ts/per, ts%per
	if sec > 1<<40 {
		return time.Time{}
	}
	return time.Unix(int64(sec), int64(frac)*int64(unit)).UTC()
}

// segment is the TCP payload of one frame.
type segment struct {
	frame   int
	time    time.Time
	seq     uint32
	end     uint32 // seq plus the payload length
	payload []byte
}

// flow is one direction of a TCP connection.
type flow struct {
	syn  bool
	isn  uint32
	segs []segment
}

type connKey struct{ client, server string }

type conn struct {
	key                   connKey
	firstFrame            int
	up, down              flow // client to server, server to client
	opened, closed, reset bool
}

type assembler struct {
	port    uint16
	current map[connKey]*conn
	all     []*conn
}

// frame takes one link-layer frame; frames that are not IPv4/TCP to or from
// the server port are ignored.
func (a *assembler) frame(num int, p packet) error {
	d, ok, err := ipv4(p)
	if err != nil || !ok {
		return err
	}
	ihl := int(d[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[2:4]))
	if ihl < 20 || total < ihl || d[9] != protoTCP {
		return nil
	}
	if total > len(d) {
		return fmt.Errorf("IPv4 packet of %d octets truncated to %d", total, len(d))
	}
	if binary.BigEndian.Uint16(d[6:8])&0x3fff != 0 {
		return errors.New("fragmented IPv4 is not supported")
	}
	src := fmt.Sprintf("%d.%d.%d.%d", d[12], d[13], d[14], d[15])
	dst := fmt.Sprintf("%d.%d.%d.%d", d[16], d[17], d[18], d[19])
	t := d[ihl:total]
	if len(t) < 20 {
		return nil
	}
	sport, dport := binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
	thl := int(t[12]>>4) * 4
	if thl < 20 || thl > len(t) {
		return nil
	}
	var key connKey
	var toServer bool
	switch {
	case dport == a.port:
		key, toServer = connKey{fmt.Sprintf("%s:%d", src, sport), fmt.Sprintf("%s:%d", dst, dport)}, true
	case sport == a.port:
		key = connKey{fmt.Sprintf("%s:%d", dst, dport), fmt.Sprintf("%s:%d", src, sport)}
	default:
		return nil
	}
	flags := t[13]
	syn, ack := flags&0x02 != 0, flags&0x10 != 0
	seq := binary.BigEndian.Uint32(t[4:8])
	c := a.current[key]
	// A SYN from the client on a connection that already carried data or
	// ended starts a new connection on the same ports. So does, in a
	// recording that left the SYN out, a segment whose sequence number is
	// far from where its direction stands: a new initial sequence number.
	if c == nil || (syn && !ack && toServer && (len(c.up.segs)+len(c.down.segs) > 0 || c.closed || c.reset)) ||
		(!syn && c.jump(toServer, seq)) {
		c = &conn{key: key, firstFrame: num}
		a.current[key] = c
		a.all = append(a.all, c)
	}
	f := &c.down
	if toServer {
		f = &c.up
	}
	switch {
	case syn:
		c.opened = true
		f.syn, f.isn = true, seq
	case flags&0x04 != 0:
		c.reset = true
	case flags&0x01 != 0:
		c.closed = true
	}
	if payload := t[thl:]; len(payload) > 0 && !syn {
		// The payload length in sequence space, from the 16-bit IP total
		// length and the two header lengths.
		end := seq + uint32(binary.BigEndian.Uint16(d[2:4])) - uint32(d[0]&0x0f)*4 - uint32(t[12]>>4)*4
		f.segs = append(f.segs, segment{frame: num, time: p.time, seq: seq, end: end, payload: payload})
	}
	return nil
}

// maxJump is the largest distance in sequence space between a segment and
// the end of the last segment of its direction that is taken for the same
// connection. Initial sequence numbers are random over 2^32.
const maxJump = 1 << 24

// jump reports whether seq lies too far from the direction's last segment
// to belong to the same connection.
func (c *conn) jump(toServer bool, seq uint32) bool {
	f := &c.down
	if toServer {
		f = &c.up
	}
	if len(f.segs) == 0 {
		return false
	}
	d := seqDiff(seq, f.segs[len(f.segs)-1].end)
	return d > maxJump || d < -maxJump
}

// ipv4 returns the IPv4 packet of a frame, or false for a frame that holds
// none.
func ipv4(p packet) ([]byte, bool, error) {
	d := p.data
	switch p.link {
	case linkEthernet:
		if len(d) < 14 {
			return nil, false, nil
		}
		etherType := binary.BigEndian.Uint16(d[12:14])
		d = d[14:]
		for etherType == etherVLAN {
			if len(d) < 4 {
				return nil, false, nil
			}
			etherType = binary.BigEndian.Uint16(d[2:4])
			d = d[4:]
		}
		if etherType != etherIPv4 {
			return nil, false, nil
		}
	case linkNull, linkLoop:
		// Address family in host (null) or network (loop) byte order; 2 is
		// AF_INET everywhere.
		if len(d) < 4 || (binary.LittleEndian.Uint32(d) != 2 && binary.BigEndian.Uint32(d) != 2) {
			return nil, false, nil
		}
		d = d[4:]
	case linkSLL:
		if len(d) < 16 || binary.BigEndian.Uint16(d[14:16]) != etherIPv4 {
			return nil, false, nil
		}
		d = d[16:]
	case linkRaw, linkIPv4:
	default:
		return nil, false, fmt.Errorf("link type %d is not supported", p.link)
	}
	if len(d) < 20 || d[0]>>4 != 4 {
		return nil, false, nil
	}
	return d, true, nil
}

// seqDiff is a - b in TCP sequence space (RFC 1982 serial arithmetic):
// negative when a lies before b.
func seqDiff(a, b uint32) int64 {
	d := int64(a - b)
	if d >= 1<<31 {
		d -= 1 << 32
	}
	return d
}

// mark is the frame that delivered the octets of a run from off onwards.
type mark struct {
	off   int
	frame int
	time  time.Time
}

// run is a stretch of contiguous reassembled octets of one direction.
type run struct {
	data  []byte
	marks []mark // ascending off; marks[0].off == 0
	gap   bool   // the octets that follow the run are missing
}

// span returns the marks of the earliest and the latest frame that
// delivered octets from to end (exclusive).
func (r *run) span(from, end int) (first, last mark) {
	i := sort.Search(len(r.marks), func(i int) bool { return r.marks[i].off > from }) - 1
	first, last = r.marks[i], r.marks[i]
	for i++; i < len(r.marks) && r.marks[i].off < end; i++ {
		m := r.marks[i]
		if m.frame < first.frame {
			first = m
		}
		if m.frame > last.frame {
			last = m
		}
	}
	return first, last
}

// streamStats are the reassembly counters of one direction.
type streamStats struct {
	retransmitted, outOfOrder, conflicts, gaps int
}

// stream reassembles a flow in sequence order into runs of contiguous
// octets.
func (f *flow) stream() ([]run, streamStats) {
	var st streamStats
	if len(f.segs) == 0 {
		return nil, st
	}
	var base uint32
	if f.syn {
		base = f.isn + 1
	} else {
		base = f.segs[0].seq
		for _, s := range f.segs[1:] {
			if seqDiff(s.seq, base) < 0 {
				base = s.seq
			}
		}
	}
	// Arrival order: a segment that starts before the end of one that
	// arrived earlier, without being a retransmission of it, arrived out of
	// order.
	var high int64
	for i, s := range f.segs {
		start := seqDiff(s.seq, base)
		if i > 0 && start < high && !f.repeated(i) {
			st.outOfOrder++
		}
		high = max(high, start+int64(len(s.payload)))
	}
	segs := append([]segment(nil), f.segs...)
	sort.SliceStable(segs, func(i, j int) bool { return seqDiff(segs[i].seq, base) < seqDiff(segs[j].seq, base) })
	out := []run{{}}
	var next int64 // offset from base of the next octet expected
	for _, s := range segs {
		start := seqDiff(s.seq, base)
		end := start + int64(len(s.payload))
		cur := &out[len(out)-1]
		if end <= next {
			st.retransmitted++
			st.conflicts += conflicts(cur, start, next, s.payload)
			continue
		}
		p := s.payload
		switch {
		case start > next && len(cur.data) > 0: // octets missing from the capture
			st.gaps++
			cur.gap = true
			out = append(out, run{})
			cur = &out[len(out)-1]
		case start < next:
			st.conflicts += conflicts(cur, start, next, p[:next-start])
			p = p[next-start:]
		}
		cur.marks = append(cur.marks, mark{off: len(cur.data), frame: s.frame, time: s.time})
		cur.data = append(cur.data, p...)
		next = end
	}
	return out, st
}

// repeated reports whether segment i starts where a segment that arrived
// before it started: a retransmission rather than a late segment.
func (f *flow) repeated(i int) bool {
	for _, e := range f.segs[:i] {
		if e.seq == f.segs[i].seq {
			return true
		}
	}
	return false
}

// conflicts counts the octets of p, which starts at stream offset start,
// that differ from the octets of r already delivered up to next. Only the
// part of p inside the current run is compared.
func conflicts(r *run, start, next int64, p []byte) int {
	runStart := next - int64(len(r.data))
	n := 0
	for i, c := range p {
		off := start + int64(i) - runStart
		if off >= 0 && off < int64(len(r.data)) && off < next-runStart && r.data[off] != c {
			n++
		}
	}
	return n
}

// apdus splits a run into APDUs.
func apdus(r run, fromClient bool) (out []APDU, dropped, skipped, split int, shared map[int]int) {
	shared = map[int]int{}
	d := r.data
	for off := 0; off < len(d); {
		if d[off] != 0x68 {
			skipped++
			off++
			continue
		}
		if len(d)-off < 2 || int(d[off+1])+2 > len(d)-off {
			// Cut by a gap or by the end of the capture.
			dropped++
			skipped += len(d) - off
			break
		}
		n := int(d[off+1]) + 2
		if n < 6 {
			skipped++
			off++
			continue
		}
		// The octets may have come in several frames, out of order: the
		// APDU is complete with the latest of them.
		first, last := r.span(off, off+n)
		if first.frame != last.frame {
			split++
		}
		shared[last.frame]++
		out = append(out, APDU{
			FromClient: fromClient, First: first.frame, Frame: last.frame, Time: last.time,
			Data: append([]byte(nil), d[off:off+n]...),
		})
		off += n
	}
	return out, dropped, skipped, split, shared
}

func (a *assembler) conversations() []Conversation {
	sort.SliceStable(a.all, func(i, j int) bool { return a.all[i].firstFrame < a.all[j].firstFrame })
	out := make([]Conversation, 0, len(a.all))
	for _, c := range a.all {
		cv := Conversation{Client: c.key.client, Server: c.key.server, Opened: c.opened, Closed: c.closed, Reset: c.reset}
		var sides [2][]APDU
		for k, dir := range []struct {
			f          *flow
			fromClient bool
		}{{&c.up, true}, {&c.down, false}} {
			runs, st := dir.f.stream()
			cv.Retransmitted += st.retransmitted
			cv.OutOfOrder += st.outOfOrder
			cv.Conflicts += st.conflicts
			cv.Gaps += st.gaps
			for _, r := range runs {
				p, dropped, skipped, split, shared := apdus(r, dir.fromClient)
				sides[k] = append(sides[k], p...)
				cv.Dropped += dropped
				cv.Skipped += skipped
				cv.Split += split
				for _, n := range shared {
					if n > 1 {
						cv.Shared++
					}
				}
			}
		}
		cv.APDUs = merge(sides[0], sides[1])
		if len(cv.APDUs) > 0 || cv.Opened {
			out = append(out, cv)
		}
	}
	return out
}

// merge merges the APDUs of the two directions by completing frame,
// keeping each direction in sequence order.
func merge(up, down []APDU) []APDU {
	out := make([]APDU, 0, len(up)+len(down))
	for len(up) > 0 && len(down) > 0 {
		if up[0].Frame <= down[0].Frame {
			out, up = append(out, up[0]), up[1:]
		} else {
			out, down = append(out, down[0]), down[1:]
		}
	}
	return append(append(out, up...), down...)
}

// String describes the conversation for test logs.
func (c Conversation) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s -> %s: %d APDUs", c.Client, c.Server, len(c.APDUs))
	for _, kv := range []struct {
		k string
		v int
	}{{"retransmitted", c.Retransmitted}, {"out-of-order", c.OutOfOrder}, {"conflicts", c.Conflicts},
		{"gaps", c.Gaps}, {"dropped", c.Dropped}, {"skipped", c.Skipped}, {"split", c.Split}, {"shared", c.Shared}} {
		if kv.v != 0 {
			fmt.Fprintf(&sb, ", %s %d", kv.k, kv.v)
		}
	}
	return sb.String()
}
