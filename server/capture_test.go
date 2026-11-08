// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/capture"
)

// The recorded traffic in testdata/captures, played against the server: a
// scripted controlling station sends the recorded requests (ASDU octets as
// recorded, sequence numbers rebuilt from the live link, capture.Peer), and
// the server answers through its API the way the recorded station did. The
// application part, what to answer, is taken from the recording: a handler
// replies to each request with the Session methods the recorded answer
// corresponds to, and sends the recorded data with Session.Send. What the
// library does by itself (STARTDT, STOPDT and TESTFR confirmations,
// acknowledgements, the refusals of Mux, the whole file transfer of
// FileServer) is the server's own. Every answer is compared with the
// recorded one.

func captureFiles(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "testdata", "captures", "*", "*.pcap*"))
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("IEC104_CAPTURE_EXTENDED") != "" {
		more, _ := filepath.Glob(filepath.Join("..", "testdata", "captures", "cache", "*", "*.pcap*"))
		files = append(files, more...)
	}
	if len(files) == 0 {
		t.Fatal("no captures in testdata/captures")
	}
	sort.Strings(files)
	return files
}

// Classified differences between the recorded station and the server.
const (
	diffBroadcastCA      = "a request to the broadcast address is answered with the station's own common address: the handler's choice, made here as the recording did"
	diffCallNOS          = "FileServer calls the whole file with section number 0, the value lib60870-C v2.4.1 sends (file_server.c, sendCallFile); the recorded station sent 1"
	diffLastNOS          = "FileServer numbers the last section of the file (F_LS_NA_1, LSQ 1) after the last section, as lib60870-C v2.4.1 (file_server.c, sendLastSection); the recorded station sent the last section's number"
	diffForeignMirror    = "the recorded station sent a confirmation or termination of a request made on another connection (it answers on every connection): sent with Session.Send, as only the application can"
	diffMalformedAnswer  = "the recorded station sent an ASDU whose length does not match its type (C_RP_NA_1 negative confirmations without the qualifier octet): go-iec104 encodes no such ASDU, so it is left out"
	diffAckBeforeStop    = "the server confirms STOPDT once its I frames are acknowledged (IEC 60870-5-104 ed. 2, 5.3); the recorded station confirmed with frames outstanding, so the scripted controlling station acknowledges them first"
	diffMirrorQualifier  = "the recorded station mirrored single commands with another qualifier (SCO 0x28 answered with 0x08); Session.Confirm and Session.Terminate mirror the command as received"
	diffMalformedRequest = "a request whose length does not match its type (the attacker's C_RD_NA_1 with an extra octet, C_SE_NA_1 two octets short): the server drops it without an answer and serves on (LIMITATIONS.md); the recorded station answered some of them with a negative confirmation"
	diffSegments         = "FileServer sends segments of up to 236 octets (the most an ASDU of 249 octets holds); the recorded station cut them at 233: the section content is compared instead"
)

// recordedStation is the application part of a recorded station.
type recordedStation struct {
	mu       sync.Mutex
	session  *Session
	requests map[reqKey][]*asdu.ASDU // received, by type and address
	stored   map[uint16][]byte       // files the controlling station sent
	cond     *sync.Cond
}

type reqKey struct {
	t   asdu.TypeID
	ioa asdu.IOA
}

func newRecordedStation() *recordedStation {
	st := &recordedStation{requests: map[reqKey][]*asdu.ASDU{}, stored: map[uint16][]byte{}}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (st *recordedStation) HandleASDU(s *Session, a *asdu.ASDU) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.session = s
	var ioa asdu.IOA
	if o := a.First(); o != nil {
		ioa = o.Address()
	}
	k := reqKey{a.Type, ioa}
	st.requests[k] = append(st.requests[k], a)
	st.cond.Broadcast()
}

// request waits for the n-th request (from 1) of the type and address the
// recorded mirror m answers.
func (st *recordedStation) request(m *asdu.ASDU, n int) (*Session, *asdu.ASDU, bool) {
	var ioa asdu.IOA
	if o := m.First(); o != nil {
		ioa = o.Address()
	}
	k := reqKey{m.Type, ioa}
	deadline := time.Now().Add(5 * time.Second)
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(st.requests[k]) < n {
		if time.Now().After(deadline) {
			return nil, nil, false
		}
		st.mu.Unlock()
		time.Sleep(time.Millisecond)
		st.mu.Lock()
	}
	return st.session, st.requests[k][n-1], true
}

// sess returns the session of the conversation: the one that delivered a
// request, or before any the only one of srv.
func (st *recordedStation) sess(srv *Server) *Session {
	deadline := time.Now().Add(5 * time.Second)
	for {
		st.mu.Lock()
		s := st.session
		st.mu.Unlock()
		if s == nil {
			if all := srv.Sessions(); len(all) == 1 && all[0].Started() {
				s = all[0]
			}
		}
		if s != nil || time.Now().After(deadline) {
			return s
		}
		time.Sleep(time.Millisecond)
	}
}

// AcceptFile, StoreFile: the FileSink of the recorded station takes every file.
func (st *recordedStation) AcceptFile(*Session, asdu.CommonAddr, asdu.IOA, uint16, int) bool {
	return true
}

func (st *recordedStation) StoreFile(_ *Session, _ asdu.CommonAddr, _ asdu.IOA, name uint16, f File) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	var b []byte
	for _, s := range f.Sections {
		b = append(b, s...)
	}
	st.stored[name] = b
	return nil
}

// recordedFiles returns the files the recorded station sent, in the
// sections it announced.
func recordedFiles(a *capture.Analysis) map[uint16]File {
	files := map[uint16]File{}
	var cur []byte
	for _, d := range a.Decoded {
		if d.FromClient || d.ASDU == nil {
			continue
		}
		switch o := d.ASDU.First().(type) {
		case asdu.SectionReady:
			cur = nil
		case asdu.FileSegment:
			cur = append(cur, o.Data...)
		case asdu.FileLastSegment:
			if o.Qualifier == asdu.LastSectionNoDeactivation {
				f := files[o.Name]
				f.Sections = append(f.Sections, cur)
				files[o.Name] = f
			}
		}
	}
	return files
}

// uploaded returns the content of the files the recorded controlling
// station sent.
func uploaded(a *capture.Analysis) map[uint16][]byte {
	out := map[uint16][]byte{}
	for _, d := range a.Decoded {
		if !d.FromClient || d.ASDU == nil {
			continue
		}
		if o, ok := d.ASDU.First().(asdu.FileSegment); ok {
			out[o.Name] = append(out[o.Name], o.Data...)
		}
	}
	return out
}

// serverReplay is the outcome of one conversation.
type serverReplay struct {
	result capture.Result
	diffs  map[string]int
	errs   []string
	files  int // files transferred and compared
}

func replayServer(t *testing.T, a *capture.Analysis, checkMalformed bool) serverReplay {
	t.Helper()
	st := newRecordedStation()
	mux := NewMux()
	files := recordedFiles(a)
	fs := NewFileServer(FileSourceFunc(func(_ *Session, _ asdu.CommonAddr, _ asdu.IOA, name uint16) (File, bool) {
		f, ok := files[name]
		return f, ok
	}))
	fs.Sink = st
	mux.Handle(fs, FileTypes...)
	// A type the recorded station refused as unknown has no handler: Mux
	// refuses it. Every other type goes to the recorded station.
	refused := map[asdu.TypeID]bool{}
	types := map[asdu.TypeID]bool{}
	for _, d := range a.Decoded {
		if d.ASDU == nil {
			continue
		}
		if d.FromClient {
			types[d.ASDU.Type] = true
		} else if d.ASDU.Cause == asdu.CauseUnknownType {
			refused[d.ASDU.Type] = true
		}
	}
	for typ := range types {
		if !refused[typ] && !typ.IsFileTransfer() {
			mux.Handle(st, typ)
		}
	}
	srv, err := New(mux, WithParams(apci.Params{K: max(12, a.Seq[capture.Controlled].MaxUnacked), W: 8,
		T1: 15 * time.Second, T2: 100 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	out := serverReplay{diffs: map[string]int{}}
	var mu sync.Mutex
	fail := func(format string, args ...any) {
		mu.Lock()
		out.errs = append(out.errs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	// The answers go out one after the other, from one goroutine: Send
	// blocks while the window is full, which the peer opens as it reads.
	actions := make(chan func(), 1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for f := range actions {
			f()
		}
	}()
	defer wg.Wait()
	defer close(actions)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	segWant, segGot := map[[2]int][]byte{}, map[[2]int][]byte{}
	p := &capture.Peer{Conn: conn, Side: capture.Controlling, AckBeforeStop: true,
		// The station's idle test (t3) is timing: the server's is off, and
		// the recorded test frames of the station and their answers are
		// left out. So are the station's ASDUs go-iec104 cannot decode: no
		// API sends them (TestCaptureServerReplay counts them).
		Skip: func(i int, d capture.Decoded) bool {
			if !d.FromClient && d.Frame.Format == apci.FormatI && d.ASDU == nil {
				mu.Lock()
				out.diffs[diffMalformedAnswer]++
				mu.Unlock()
				return true
			}
			if d.Frame.Format != apci.FormatU {
				return false
			}
			return !d.FromClient && d.Frame.Function == apci.TestFRAct || d.FromClient && d.Frame.Function == apci.TestFRCon
		},
		Trigger: func(i int, d capture.Decoded) bool {
			if d.Frame.Format != apci.FormatI || d.ASDU == nil {
				return false // confirmations and test frames: the server's own
			}
			x := d.ASDU
			if x.Type.IsFileTransfer() || x.Cause == asdu.CauseUnknownType && refused[x.Type] {
				return false // FileServer, Mux
			}
			mirror := x.Type.InControlDirection() && (x.Cause == asdu.CauseActivationCon || x.Cause == asdu.CauseDeactivationCon ||
				x.Cause == asdu.CauseActivationTerm || x.Negative || x.Cause.IsUnknown())
			n := 0
			if mirror {
				// The mirror answers the latest request of its type and
				// address before it in the recording.
				for _, e := range a.Decoded[:i] {
					if e.FromClient && e.ASDU != nil && e.ASDU.Type == x.Type && e.ASDU.First() != nil &&
						x.First() != nil && e.ASDU.First().Address() == x.First().Address() {
						n++
					}
				}
				if n == 0 {
					// No request on this connection: the recorded station
					// mirrored one another connection made. Only the
					// application can do that, with Send.
					mirror = false
					mu.Lock()
					out.diffs[diffForeignMirror]++
					mu.Unlock()
				}
			}
			if mirror {
				actions <- func() {
					s, req, ok := st.request(x, n)
					if !ok {
						fail("frame %d: the server did not pass on the request %s answers", d.APDU.Frame, x)
						return
					}
					req = req.Reply(req.Cause, req.Negative)
					if req.CommonAddr != x.CommonAddr {
						req.CommonAddr = x.CommonAddr
						mu.Lock()
						out.diffs[diffBroadcastCA]++
						mu.Unlock()
					}
					if err := s.Reply(req, x.Cause, x.Negative); err != nil {
						fail("frame %d: Reply: %v", d.APDU.Frame, err)
					}
				}
				return true
			}
			actions <- func() {
				s := st.sess(srv)
				if s == nil {
					fail("frame %d: no session to send %s on", d.APDU.Frame, x)
					return
				}
				if err := s.Send(ctx, x); err != nil {
					fail("frame %d: Send: %v", d.APDU.Frame, err)
				}
			}
			return true
		},
		Same: func(i int, want, got []byte) string {
			if bytes.Equal(want, got) {
				return ""
			}
			w, err1 := asdu.Decode(want, asdu.IEC104)
			g, err2 := asdu.Decode(got, asdu.IEC104)
			if err1 == nil && err2 == nil && w.Type == g.Type {
				switch wo := w.First().(type) {
				case asdu.FileSegment:
					gs := g.First().(asdu.FileSegment)
					segWant[[2]int{int(wo.Name), int(wo.Section)}] = append(segWant[[2]int{int(wo.Name), int(wo.Section)}], wo.Data...)
					segGot[[2]int{int(gs.Name), int(gs.Section)}] = append(segGot[[2]int{int(gs.Name), int(gs.Section)}], gs.Data...)
					out.diffs[diffSegments]++
					return ""
				case asdu.SingleCommand:
					gc := g.First().(asdu.SingleCommand)
					if wo.IOA == gc.IOA && wo.Value == gc.Value && wo.Qualifier != gc.Qualifier && w.Cause == g.Cause {
						out.diffs[diffMirrorQualifier]++
						return ""
					}
				case asdu.FileCall:
					gc := g.First().(asdu.FileCall)
					if wo.Qualifier == asdu.FileRequest && gc.Section == 0 && gc.Name == wo.Name && gc.Qualifier == wo.Qualifier {
						out.diffs[diffCallNOS]++
						return ""
					}
				case asdu.FileLastSegment:
					gl := g.First().(asdu.FileLastSegment)
					if wo.Qualifier == asdu.LastFileNoDeactivation && gl.Section == wo.Section+1 &&
						gl.Name == wo.Name && gl.Qualifier == wo.Qualifier && gl.Checksum == wo.Checksum {
						out.diffs[diffLastNOS]++
						return ""
					}
				}
			}
			return fmt.Sprintf("answer differs:\n  recorded % x (%v)\n  sent     % x (%v)", want, w, got, g)
		}}

	end, malformed := len(a.Decoded), -1
	for i, d := range a.Decoded {
		if d.FromClient && d.APCIErr == nil && d.Frame.Format == apci.FormatI && d.ASDU == nil {
			end, malformed = i, i // a request go-iec104 cannot decode: checked below
			break
		}
	}
	for _, i := range a.StoppedI {
		if i < end {
			end = i
			break
		}
	}
	out.result = p.Run(a, 0, end)
	if out.result.Err == nil {
		_ = p.Flush()
	}
	if n := len(out.result.Notes); n > 0 {
		out.diffs[diffAckBeforeStop] += n
	}
	if checkMalformed && malformed >= 0 && malformed == end && out.result.Err == nil {
		// The server drops a request it cannot decode, without an answer
		// (LIMITATIONS.md), acknowledges it and goes on serving the
		// connection. The recorded station answered with a negative
		// confirmation.
		if r := p.Run(a, malformed, malformed+1); r.Err != nil {
			fail("sending the malformed request: %v", r.Err)
		}
		for _, f := range p.Drain(100 * time.Millisecond) {
			if f.Format == apci.FormatI {
				fail("frame %d: the server answered a request it cannot decode: %s", a.Decoded[malformed].APDU.Frame, f)
			}
		}
		if err := p.Test(); err != nil {
			fail("frame %d: the server stopped serving after a request it cannot decode: %v", a.Decoded[malformed].APDU.Frame, err)
		} else {
			out.diffs[diffMalformedRequest]++
		}
	}
	for k, w := range segWant {
		if !bytes.Equal(w, segGot[k]) {
			fail("file %d section %d: the server sent other content than recorded", k[0], k[1])
		}
	}
	want := uploaded(a)
	st.mu.Lock()
	for name, b := range want {
		if !bytes.Equal(st.stored[name], b) {
			fail("file %d: the server stored %d octets, the recording sent %d", name, len(st.stored[name]), len(b))
		} else {
			out.files++
		}
	}
	st.mu.Unlock()
	out.files += len(files)
	return out
}

// replayableByServer reports why a conversation cannot be replayed against
// the server, or "" when it can.
func replayableByServer(a *capture.Analysis) string {
	switch {
	case !a.FromZero:
		return "recorded without its start: the sequence numbers are unknown"
	case len(a.Seq[capture.Controlling].SendErrors)+len(a.Seq[capture.Controlled].SendErrors) > 0:
		return "the recording breaks the send sequence"
	}
	return ""
}

func TestCaptureServerReplay(t *testing.T) {
	for _, file := range captureFiles(t) {
		name := strings.TrimPrefix(filepath.ToSlash(file), "../testdata/captures/")
		t.Run(name, func(t *testing.T) {
			convs, err := capture.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var played, skipped, compared, exact, files, checked int
			diffs := map[string]int{}
			for _, c := range convs {
				a := capture.Analyze(c, asdu.IEC104)
				if why := replayableByServer(a); why != "" {
					skipped++
					continue
				}
				// The attacker's malformed requests are all alike: the
				// first ten conversations of a capture check them.
				r := replayServer(t, a, checked < 10)
				if r.diffs[diffMalformedRequest] > 0 {
					checked++
				}
				played++
				compared += r.result.Compared
				exact += r.result.Exact
				files += r.files
				for k, n := range r.diffs {
					diffs[k] += n
				}
				for _, m := range r.result.Mismatches {
					t.Errorf("%s: %s", c.Client, m)
				}
				if r.result.Err != nil {
					t.Errorf("%s: replay stopped: %v", c.Client, r.result.Err)
				}
				for _, e := range r.errs {
					t.Errorf("%s: %s", c.Client, e)
				}
			}
			t.Logf("%d conversations replayed, %d skipped; %d answers compared, %d exact; %d files", played, skipped, compared, exact, files)
			for k, n := range diffs {
				t.Logf("classified difference, %d answers: %s", n, k)
			}
		})
	}
}
