// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/capture"
)

// The recorded traffic in testdata/captures: every conversation is played
// against the client. A scripted controlled station sends the recorded
// station's frames (ASDU octets as recorded, sequence numbers rebuilt from
// the live link, capture.Peer) and the client is made to send the recorded
// controlling station's requests through its API. Every request it sends
// is compared with the recorded one, and every ASDU it delivers to the
// Handler with the recorded one.

// captureFiles lists the committed captures, and with IEC104_CAPTURE_EXTENDED
// set the ones make captures-fetch downloads as well.
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

// replayable reports why a conversation cannot be replayed against the
// client, or "" when it can.
func replayable(a *capture.Analysis) string {
	switch {
	case !a.FromZero:
		return "recorded without its start: the sequence numbers are unknown"
	case len(a.Seq[capture.Controlled].RecvErrors) > 0:
		return "the recorded station acknowledges frames it never received: " + a.Seq[capture.Controlled].RecvErrors[0]
	case len(a.Seq[capture.Controlling].SendErrors)+len(a.Seq[capture.Controlled].SendErrors) > 0:
		return "the recording breaks the send sequence"
	}
	return ""
}

type delivered struct {
	mu sync.Mutex
	a  []*asdu.ASDU
}

func (d *delivered) HandleASDU(a *asdu.ASDU) {
	d.mu.Lock()
	d.a = append(d.a, a)
	d.mu.Unlock()
}

func (d *delivered) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.a)
}

// clientReplay is the outcome of one conversation.
type clientReplay struct {
	result   capture.Result
	expected int // decodable station ASDUs
	got      []*asdu.ASDU
	unsent   int // recorded requests the client cannot send
	// closedStopped: the client closed the connection on a station I frame
	// sent while data transfer was stopped, as the recording ends with.
	closedStopped bool
	errs          []string
}

// replayClient plays conversation a against a go-iec104 client through Send
// and the link procedures.
func replayClient(t *testing.T, a *capture.Analysis) clientReplay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	params := apci.Params{K: max(12, a.Seq[capture.Controlling].MaxUnacked), W: 8,
		T0: 5 * time.Second, T1: 15 * time.Second, T2: 100 * time.Millisecond}
	h := &delivered{}
	c, err := New(ln.Addr().String(), WithParams(params), WithAutoStart(false), WithHandler(h),
		WithRequestTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	defer func() { _ = conn.Close() }()

	var out clientReplay
	var mu sync.Mutex
	fail := func(format string, args ...any) {
		mu.Lock()
		out.errs = append(out.errs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	var wg, uwg sync.WaitGroup // all calls; the link procedures
	defer wg.Wait()
	// The end of the replay: the index of the first request the client
	// cannot send, which ends it.
	end := len(a.Decoded)
	for i, d := range a.Decoded {
		if d.FromClient && d.APCIErr == nil && d.Frame.Format == apci.FormatI && d.ASDU == nil {
			end = i
			out.unsent++
			break
		}
	}
	// A station I frame sent while data transfer is stopped ends the
	// replay: the client closes the connection on it.
	stoppedAt := -1
	for _, i := range a.StoppedI {
		if !a.Decoded[i].FromClient && i < end {
			stoppedAt, end = i, i
			break
		}
	}
	p := &capture.Peer{Conn: conn, Side: capture.Controlled, Trigger: func(i int, d capture.Decoded) bool {
		run := func(what string, f func() error) {
			// A call starts once the link procedure before it, whose
			// confirmation the peer has sent, is complete.
			uwg.Wait()
			wg.Add(1)
			u := d.Frame.Format == apci.FormatU && a.Confirmed(i)
			if u {
				uwg.Add(1)
			}
			go func() {
				defer wg.Done()
				if u {
					defer uwg.Done()
				}
				if err := f(); err != nil {
					fail("frame %d: %s: %v", d.APDU.Frame, what, err)
				}
			}()
		}
		// A link procedure the recorded station never confirmed ends in
		// t1 for the client as well: its error is expected.
		unconfirmed := func(f func() error) func() error {
			if a.Confirmed(i) {
				return f
			}
			return func() error {
				if f() == nil {
					return fmt.Errorf("confirmed, although the recorded station never confirmed it")
				}
				return nil
			}
		}
		switch {
		case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StartDTAct:
			run("StartDT", unconfirmed(func() error { return c.StartDT(ctx) }))
		case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StopDTAct:
			run("StopDT", unconfirmed(func() error { return c.StopDT(ctx) }))
		case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.TestFRAct:
			run("TestLink", unconfirmed(func() error { return c.TestLink(ctx) }))
		case d.Frame.Format == apci.FormatI:
			req := d.ASDU
			run("Send", func() error { return c.Send(ctx, req) })
		default:
			return false // a TESTFR con: the client answers by itself
		}
		return true
	}}
	out.result = p.Run(a, 0, end)
	if out.result.Err == nil {
		_ = p.Flush()
	}
	if stoppedAt >= 0 && out.result.Err == nil {
		wg.Wait()
		if r := p.Run(a, stoppedAt, stoppedAt+1); r.Err != nil {
			fail("sending the I frame of a stopped station: %v", r.Err)
		} else if err := p.Closed(5 * time.Second); err != nil {
			fail("frame %d: an I frame while data transfer is stopped: the client did not close the connection: %v",
				a.Decoded[stoppedAt].APDU.Frame, err)
		} else {
			out.closedStopped = true
		}
	}
	stop := end
	if out.result.Stopped >= 0 {
		stop = min(stop, out.result.Stopped)
	}
	for _, d := range a.Decoded[:stop] {
		if !d.FromClient && d.ASDU != nil {
			out.expected++
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.len() < out.expected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	h.mu.Lock()
	out.got = append([]*asdu.ASDU(nil), h.a...)
	h.mu.Unlock()
	return out
}

func TestCaptureClientReplay(t *testing.T) {
	for _, file := range captureFiles(t) {
		name := strings.TrimPrefix(filepath.ToSlash(file), "../testdata/captures/")
		t.Run(name, func(t *testing.T) {
			convs, err := capture.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var played, skipped, compared, exact, delivered int
			for _, c := range convs {
				a := capture.Analyze(c, asdu.IEC104)
				if why := replayable(a); why != "" {
					skipped++
					t.Logf("%s: not replayed: %s", c.Client, why)
					continue
				}
				r := replayClient(t, a)
				played++
				compared += r.result.Compared
				exact += r.result.Exact
				for _, m := range r.result.Mismatches {
					t.Errorf("%s: %s", c.Client, m)
				}
				if r.result.Err != nil {
					t.Errorf("%s: replay stopped: %v", c.Client, r.result.Err)
				}
				for _, e := range r.errs {
					t.Errorf("%s: %s", c.Client, e)
				}
				// Every station ASDU the client decodes reaches the Handler,
				// as recorded.
				var want []*asdu.ASDU
				for _, d := range a.Decoded {
					if !d.FromClient && d.ASDU != nil {
						want = append(want, d.ASDU)
					}
				}
				want = want[:min(len(want), r.expected)]
				if len(r.got) != len(want) {
					t.Errorf("%s: Handler got %d ASDUs, recorded %d", c.Client, len(r.got), len(want))
				}
				for i := range min(len(r.got), len(want)) {
					g, _ := r.got[i].Encode(asdu.IEC104)
					w, _ := want[i].Encode(asdu.IEC104)
					if string(g) != string(w) {
						t.Errorf("%s: delivered ASDU %d is %s, recorded %s", c.Client, i, r.got[i], want[i])
					}
				}
				delivered += len(r.got)
			}
			t.Logf("%d conversations replayed, %d skipped; %d requests compared, %d exact; %d ASDUs delivered",
				played, skipped, compared, exact, delivered)
		})
	}
}

// procedure is a request of the recording that the client sends through
// the API call that makes it, and what the recording says it returns.
type procedure struct {
	index int    // the request in Analysis.Decoded
	name  string // the API call
	call  func(ctx context.Context, c *Client) (any, error)
	check func(got any, err error) string // "" when the result matches
	auto  []int                           // later requests the call sends by itself
	end   int                             // the recorded answer that concludes it
}

// mirrorOf returns the index of the station's confirmation or refusal of
// request i, or -1.
func mirrorOf(a *capture.Analysis, i int) int {
	req := a.Decoded[i].ASDU
	for j := i + 1; j < len(a.Decoded); j++ {
		d := a.Decoded[j]
		if d.ASDU == nil {
			continue
		}
		if d.FromClient {
			if d.ASDU.Type == req.Type && d.ASDU.First().Address() == req.First().Address() {
				return -1 // asked again before it was answered
			}
			continue
		}
		x := d.ASDU
		if x.Type != req.Type || x.First() == nil || x.First().Address() != req.First().Address() {
			continue
		}
		if x.Cause == asdu.CauseActivationCon || x.Cause == asdu.CauseDeactivationCon || x.Negative || x.Cause.IsUnknown() {
			return j
		}
	}
	return -1
}

func negative(want *asdu.ASDU, err error) string {
	var ne *iec104.NegativeError
	switch {
	case want.Negative || want.Cause.IsUnknown():
		if !errors.As(err, &ne) {
			return fmt.Sprintf("recorded refusal %s, got %v", want, err)
		}
	case err != nil:
		return fmt.Sprintf("recorded confirmation %s, got %v", want, err)
	}
	return ""
}

// procedures maps the recorded requests to API calls.
func procedures(a *capture.Analysis) []procedure {
	var out []procedure
	auto := map[int]bool{}
	for i, d := range a.Decoded {
		if !d.FromClient || d.ASDU == nil || auto[i] {
			continue
		}
		req := d.ASDU
		ca := req.CommonAddr
		switch o := req.First().(type) {
		case asdu.Interrogation, asdu.CounterInterrogation, asdu.ClockSync, asdu.Read:
			m := mirrorOf(a, i)
			if m < 0 || req.Cause != asdu.CauseActivation && req.Cause != asdu.CauseRequest {
				continue
			}
			want := a.Decoded[m].ASDU
			p := procedure{index: i, end: m}
			switch o := o.(type) {
			case asdu.Interrogation:
				data, term := collected(a, m, req.Type, o.Qualifier.Cause())
				p.name, p.end = "Interrogate", concludedAt(a, m, term)
				p.call = func(ctx context.Context, c *Client) (any, error) { return c.Interrogate(ctx, ca, o.Qualifier) }
				p.check = collectCheck(want, data, term)
			case asdu.CounterInterrogation:
				data, term := collected(a, m, req.Type, o.Cause())
				p.name, p.end = "CounterInterrogate", concludedAt(a, m, term)
				p.call = func(ctx context.Context, c *Client) (any, error) {
					return c.CounterInterrogate(ctx, ca, o.Request, o.Freeze)
				}
				p.check = collectCheck(want, data, term)
			case asdu.ClockSync:
				p.name = "ClockSync"
				p.call = func(ctx context.Context, c *Client) (any, error) { return nil, c.ClockSync(ctx, ca, o.Time.Time) }
				p.check = func(_ any, err error) string { return negative(want, err) }
			case asdu.Read:
				p.name = "Read"
				p.call = func(ctx context.Context, c *Client) (any, error) { return c.Read(ctx, ca, o.IOA) }
				p.check = func(got any, err error) string { return negative(want, err) }
			}
			out = append(out, p)
		case asdu.FileCall:
			if o.Qualifier != asdu.FileSelect {
				continue
			}
			data, steps, ok := download(a, i, o)
			if !ok {
				continue
			}
			for _, s := range steps {
				auto[s] = true
			}
			out = append(out, procedure{index: i, name: "GetFile", auto: steps, end: steps[len(steps)-1],
				call: func(ctx context.Context, c *Client) (any, error) { return c.GetFile(ctx, ca, o.IOA, o.Name) },
				check: func(got any, err error) string {
					if err != nil {
						return err.Error()
					}
					if !bytes.Equal(got.([]byte), data) {
						return fmt.Sprintf("file of %d octets, recorded %d", len(got.([]byte)), len(data))
					}
					return ""
				}})
		case asdu.FileReady:
			sections, steps, last, ok := upload(a, i, o)
			if !ok {
				continue
			}
			for _, s := range steps {
				auto[s] = true
			}
			out = append(out, procedure{index: i, name: "PutFile", auto: steps, end: last,
				call: func(ctx context.Context, c *Client) (any, error) {
					return nil, c.PutFile(ctx, ca, o.IOA, o.Name, sections...)
				},
				check: func(_ any, err error) string {
					if err != nil {
						return err.Error()
					}
					return ""
				}})
		default:
			if !req.Type.IsProcessCommand() {
				continue
			}
			m := mirrorOf(a, i)
			if m < 0 || req.Cause != asdu.CauseActivation {
				continue
			}
			want := a.Decoded[m].ASDU
			obj := req.First()
			out = append(out, procedure{index: i, name: "Command", end: m,
				call:  func(ctx context.Context, c *Client) (any, error) { return nil, c.Command(ctx, ca, obj) },
				check: func(_ any, err error) string { return negative(want, err) }})
		}
	}
	return out
}

// collected returns the station's ASDUs with the given cause between the
// confirmation at index m and the termination of typ, and the index of the
// termination, or -1 when the recording has none.
func collected(a *capture.Analysis, m int, typ asdu.TypeID, cause asdu.Cause) ([]*asdu.ASDU, int) {
	var out []*asdu.ASDU
	for j := m + 1; j < len(a.Decoded); j++ {
		d := a.Decoded[j]
		if d.FromClient || d.ASDU == nil {
			continue
		}
		if d.ASDU.Type == typ && d.ASDU.Cause == asdu.CauseActivationTerm {
			return out, j
		}
		if d.ASDU.Cause == cause {
			out = append(out, d.ASDU)
		}
	}
	return out, -1
}

// concludedAt is the index at which a collecting request is over: its
// termination, or never when the recording has none.
func concludedAt(a *capture.Analysis, m, term int) int {
	if term < 0 {
		return len(a.Decoded)
	}
	return max(m, term)
}

// collectCheck checks the result of an interrogation. Without a recorded
// termination the call cannot complete: it ends with an error when data
// transfer stops or the connection closes.
func collectCheck(want *asdu.ASDU, data []*asdu.ASDU, term int) func(any, error) string {
	return func(got any, err error) string {
		if s := negative(want, err); want.Negative || want.Cause.IsUnknown() {
			return s
		}
		if term < 0 {
			if err == nil {
				return "completed although the station never terminated it"
			}
			return ""
		}
		if err != nil {
			return err.Error()
		}
		return sameASDUs(got.([]*asdu.ASDU), data)
	}
}

// download returns the recorded content of the file the select at index i
// fetches and the indexes of the further requests of the transfer, up to
// the acknowledgement of the file.
func download(a *capture.Analysis, i int, sel asdu.FileCall) ([]byte, []int, bool) {
	var data []byte
	var steps []int
	for j := i + 1; j < len(a.Decoded); j++ {
		d := a.Decoded[j]
		if d.ASDU == nil {
			continue
		}
		switch o := d.ASDU.First().(type) {
		case asdu.FileSegment:
			if !d.FromClient && o.Name == sel.Name {
				data = append(data, o.Data...)
			}
		case asdu.FileCall:
			if d.FromClient && o.Name == sel.Name {
				steps = append(steps, j)
			}
		case asdu.FileAck:
			if d.FromClient && o.Name == sel.Name {
				steps = append(steps, j)
				if o.Qualifier == asdu.AckFilePositive {
					return data, steps, true
				}
			}
		}
	}
	return nil, nil, false
}

// upload returns the sections of the file announced at index i and the
// indexes of the further requests of the transfer.
func upload(a *capture.Analysis, i int, ready asdu.FileReady) ([][]byte, []int, int, bool) {
	var sections [][]byte
	var steps []int
	for j := i + 1; j < len(a.Decoded); j++ {
		d := a.Decoded[j]
		if d.ASDU == nil || !d.FromClient {
			if d.ASDU != nil {
				if o, ok := d.ASDU.First().(asdu.FileAck); ok && o.Name == ready.Name && o.Qualifier == asdu.AckFilePositive {
					return sections, steps, j, true
				}
			}
			continue
		}
		switch o := d.ASDU.First().(type) {
		case asdu.SectionReady:
			if o.Name == ready.Name {
				sections = append(sections, nil)
				steps = append(steps, j)
			}
		case asdu.FileSegment:
			if o.Name == ready.Name && len(sections) > 0 {
				sections[len(sections)-1] = append(sections[len(sections)-1], o.Data...)
				steps = append(steps, j)
			}
		case asdu.FileLastSegment:
			if o.Name == ready.Name {
				steps = append(steps, j)
			}
		}
	}
	return nil, nil, 0, false
}

func sameASDUs(got, want []*asdu.ASDU) string {
	if len(got) != len(want) {
		return fmt.Sprintf("%d ASDUs, recorded %d", len(got), len(want))
	}
	for i := range got {
		g, _ := got[i].Encode(asdu.IEC104)
		w, _ := want[i].Encode(asdu.IEC104)
		if !bytes.Equal(g, w) {
			return fmt.Sprintf("ASDU %d is %s, recorded %s", i, got[i], want[i])
		}
	}
	return ""
}

// Classified variations between a recorded request and the one the client
// sends through the API: both are valid, the choice is the sender's.
const (
	varWeekday   = "ClockSync states the day of the week; the recorded controlling station sent 0 (unused)"
	varCallNOS   = "the call of the whole file carries section number 0, the value lib60870-C v2.4.1 puts in its call of a file (file_server.c, sendCallFile); the recorded controlling station sent 1"
	varLastNOS   = "the last section of the file (F_LS_NA_1, LSQ 1) carries the number after the last section, as lib60870-C v2.4.1 numbers it (file_server.c, sendLastSection); the recorded controlling station sent the last section's number"
	varSegments  = "segments of up to 236 octets (the most an ASDU of 249 octets holds); the recorded controlling station cut them at 233: the section content is compared instead"
	varUnchecked = "unclassified"
)

// requestVariations compares recorded requests with the ones the client
// sent, classifies the differences and keeps the content of file segments
// to compare per section.
type requestVariations struct {
	counts    map[string]int
	want, got map[[2]int][]byte // segment data by name of file and section
}

func newRequestVariations() *requestVariations {
	return &requestVariations{counts: map[string]int{}, want: map[[2]int][]byte{}, got: map[[2]int][]byte{}}
}

func (v *requestVariations) same(want, got []byte) string {
	w, err1 := asdu.Decode(want, asdu.IEC104)
	g, err2 := asdu.Decode(got, asdu.IEC104)
	if err1 == nil && err2 == nil && w.Type == asdu.F_SG_NA_1 && g.Type == asdu.F_SG_NA_1 {
		ws, gs := w.First().(asdu.FileSegment), g.First().(asdu.FileSegment)
		v.want[[2]int{int(ws.Name), int(ws.Section)}] = append(v.want[[2]int{int(ws.Name), int(ws.Section)}], ws.Data...)
		v.got[[2]int{int(gs.Name), int(gs.Section)}] = append(v.got[[2]int{int(gs.Name), int(gs.Section)}], gs.Data...)
		if !bytes.Equal(want, got) {
			v.counts[varSegments]++
		}
		return ""
	}
	if bytes.Equal(want, got) {
		return ""
	}
	if err1 == nil && err2 == nil && w.Type == g.Type {
		switch wo := w.First().(type) {
		case asdu.ClockSync:
			gt := g.First().(asdu.ClockSync).Time
			if wo.Time.NoWeekday && !gt.NoWeekday && wo.Time.Equal(gt.Time) {
				v.counts[varWeekday]++
				return ""
			}
		case asdu.FileCall:
			gc := g.First().(asdu.FileCall)
			if wo.Qualifier == asdu.FileRequest && gc.Section == 0 && wo.Name == gc.Name && wo.Qualifier == gc.Qualifier {
				v.counts[varCallNOS]++
				return ""
			}
		case asdu.FileLastSegment:
			gl := g.First().(asdu.FileLastSegment)
			if wo.Qualifier == asdu.LastFileNoDeactivation && gl.Section == wo.Section+1 &&
				wo.Name == gl.Name && wo.Qualifier == gl.Qualifier && wo.Checksum == gl.Checksum {
				v.counts[varLastNOS]++
				return ""
			}
		}
	}
	v.counts[varUnchecked]++
	return fmt.Sprintf("request differs:\n  recorded % x (%v)\n  sent     % x (%v)", want, w, got, g)
}

// sections reports the sections whose content differs.
func (v *requestVariations) sections() []string {
	var out []string
	for k, w := range v.want {
		if !bytes.Equal(w, v.got[k]) {
			out = append(out, fmt.Sprintf("file %d section %d: sent %d octets that differ from the %d recorded", k[0], k[1], len(v.got[k]), len(w)))
		}
	}
	return out
}

func TestCaptureClientProcedures(t *testing.T) {
	for _, file := range captureFiles(t) {
		name := strings.TrimPrefix(filepath.ToSlash(file), "../testdata/captures/")
		t.Run(name, func(t *testing.T) {
			convs, err := capture.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			calls, variations := map[string]int{}, map[string]int{}
			for _, c := range convs {
				a := capture.Analyze(c, asdu.IEC104)
				if replayable(a) != "" {
					continue
				}
				procs := procedures(a)
				if len(procs) == 0 {
					continue
				}
				vars := newRequestVariations()
				for _, e := range replayProcedures(t, a, procs, vars) {
					t.Errorf("%s: %s", c.Client, e)
				}
				for _, p := range procs {
					calls[p.name]++
				}
				for k, n := range vars.counts {
					variations[k] += n
				}
			}
			t.Logf("API calls replayed: %v", calls)
			for k, n := range variations {
				t.Logf("classified variation, %d requests: %s", n, k)
			}
		})
	}
}

func replayProcedures(t *testing.T, a *capture.Analysis, procs []procedure, vars *requestVariations) []string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	params := apci.Params{K: max(12, a.Seq[capture.Controlling].MaxUnacked), W: 8,
		T0: 5 * time.Second, T1: 15 * time.Second, T2: 100 * time.Millisecond}
	c, err := New(ln.Addr().String(), WithParams(params), WithAutoStart(false), WithRequestTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	defer func() { _ = conn.Close() }()

	var mu sync.Mutex
	var errs []string
	fail := func(format string, args ...any) {
		mu.Lock()
		errs = append(errs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	byIndex := map[int]procedure{}
	done := map[int]chan struct{}{} // by procedure index
	auto := map[int]bool{}
	for _, p := range procs {
		byIndex[p.index] = p
		for _, s := range p.auto {
			auto[s] = true
		}
	}
	end := len(a.Decoded)
	for i, d := range a.Decoded {
		if d.FromClient && d.APCIErr == nil && d.Frame.Format == apci.FormatI && d.ASDU == nil {
			end = i
			break
		}
	}
	for _, i := range a.StoppedI {
		if !a.Decoded[i].FromClient && i < end {
			end = i
			break
		}
	}
	var wg, uwg sync.WaitGroup
	defer wg.Wait()
	p := &capture.Peer{Conn: conn, Side: capture.Controlled,
		Same: func(i int, want, got []byte) string { return vars.same(want, got) },
		Trigger: func(i int, d capture.Decoded) bool {
			if auto[i] || d.Frame.Format == apci.FormatU && d.Frame.Function != apci.StartDTAct &&
				d.Frame.Function != apci.StopDTAct && d.Frame.Function != apci.TestFRAct {
				return false // sent by the client by itself
			}
			uwg.Wait()
			// A call goes out once the calls the recording concluded
			// before it have returned: the client refuses a request while
			// the same one is pending.
			for _, pr := range procs {
				if ch := done[pr.index]; ch != nil && pr.end < i {
					select {
					case <-ch:
					case <-time.After(5 * time.Second):
					}
				}
			}
			start := func(what string, u bool, f func() error) {
				wg.Add(1)
				if u {
					uwg.Add(1)
				}
				go func() {
					defer wg.Done()
					if u {
						defer uwg.Done()
					}
					if err := f(); err != nil {
						fail("frame %d: %s: %v", d.APDU.Frame, what, err)
					}
				}()
			}
			unconfirmed := func(f func() error) func() error {
				if a.Confirmed(i) {
					return f
				}
				return func() error {
					if f() == nil {
						return fmt.Errorf("confirmed, although the recorded station never confirmed it")
					}
					return nil
				}
			}
			switch {
			case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StartDTAct:
				start("StartDT", a.Confirmed(i), unconfirmed(func() error { return c.StartDT(ctx) }))
			case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StopDTAct:
				start("StopDT", a.Confirmed(i), unconfirmed(func() error { return c.StopDT(ctx) }))
			case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.TestFRAct:
				start("TestLink", a.Confirmed(i), unconfirmed(func() error { return c.TestLink(ctx) }))
			case d.Frame.Format == apci.FormatI:
				if pr, ok := byIndex[i]; ok {
					wg.Add(1)
					ch := make(chan struct{})
					done[i] = ch
					go func() {
						defer wg.Done()
						defer close(ch)
						got, err := pr.call(ctx, c)
						if s := pr.check(got, err); s != "" {
							fail("frame %d: %s: %s", d.APDU.Frame, pr.name, s)
						}
					}()
					return true
				}
				req := d.ASDU
				start("Send", false, func() error { return c.Send(ctx, req) })
			default:
				return false
			}
			return true
		}}
	r := p.Run(a, 0, end)
	if r.Err == nil {
		_ = p.Flush()
	} else {
		fail("replay stopped: %v", r.Err)
	}
	for _, m := range r.Mismatches {
		fail("%s", m)
	}
	wg.Wait()
	for _, e := range vars.sections() {
		fail("%s", e)
	}
	return errs
}

// TestCaptureClientStaleAck plays the IEC TestServer of the UOWM dataset as
// recorded, control fields included, on the connections where its first I
// frame acknowledges a frame the client never sent (N(R)=1 before any
// request: its receive counter is left over from an earlier connection).
// The client closes the connection, as its link does for every N(R) that
// acknowledges more than was sent.
func TestCaptureClientStaleAck(t *testing.T) {
	cases := 0
	for _, file := range captureFiles(t) {
		convs, err := capture.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range convs {
			a := capture.Analyze(c, asdu.IEC104)
			errs := a.Seq[capture.Controlled].RecvErrors
			if !a.FromZero || len(errs) == 0 || cases >= 20 {
				continue
			}
			// The first frame of the station that acknowledges too much.
			bad := -1
			for i, d := range a.Decoded {
				if !d.FromClient && d.APCIErr == nil && d.Frame.Format != apci.FormatU && strings.HasPrefix(errs[0], fmt.Sprintf("frame %d:", d.APDU.Frame)) {
					bad = i
					break
				}
			}
			if bad < 0 {
				t.Fatalf("%s %s: no frame for %q", file, c.Client, errs[0])
			}
			cases++
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			cl, err := New(ln.Addr().String(), WithAutoStart(false), WithParams(apci.Params{K: 12, W: 8, T2: 100 * time.Millisecond}))
			if err != nil {
				t.Fatal(err)
			}
			accepted := make(chan net.Conn, 1)
			go func() {
				if conn, err := ln.Accept(); err == nil {
					accepted <- conn
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := cl.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			conn := <-accepted
			var wg sync.WaitGroup
			p := &capture.Peer{Conn: conn, Side: capture.Controlled, Trigger: func(i int, d capture.Decoded) bool {
				if d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StartDTAct {
					wg.Add(1)
					go func() { defer wg.Done(); _ = cl.StartDT(ctx) }()
					return true
				}
				return false
			}}
			if r := p.Run(a, 0, bad); r.Err != nil {
				t.Fatalf("%s: %v", c.Client, r.Err)
			}
			wg.Wait()
			// The recorded octets, N(R) included.
			if _, err := conn.Write(a.Decoded[bad].Data); err != nil {
				t.Fatal(err)
			}
			if err := p.Closed(5 * time.Second); err != nil {
				t.Errorf("%s frame %d: the client did not close on %s: %v", c.Client, a.Decoded[bad].APDU.Frame, errs[0], err)
			}
			cancel()
			_ = cl.Close()
			_ = conn.Close()
			_ = ln.Close()
		}
	}
	if cases == 0 {
		t.Fatal("no recorded conversation with an N(R) past the frames sent")
	}
	t.Logf("%d recorded conversations: the client closes on the station's stale N(R)", cases)
}
