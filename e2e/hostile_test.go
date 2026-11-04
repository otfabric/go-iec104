// SPDX-License-Identifier: MIT

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/station"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// The hostile tests put a peer that does not follow the protocol on the
// other end of a real connection, speaking raw APDUs built with the public
// apci and asdu encoders. Whatever it sends, the go-iec104 side must end
// the connection or answer as the protocol says within a bound, must not
// take anything else down with it, and must leave nothing behind.
//
// The codecs are fuzzed in apci, asdu and sec, and the protocol machine is
// driven by scripted peers in internal/link; these tests are about the
// server and the client as a whole, timers and handlers included.

// hostileParams are the timers of the side under attack: short, so that a
// peer that stops talking is noticed quickly.
func hostileParams() apci.Params {
	return apci.Params{K: 12, W: 8, T0: time.Second, T1: 400 * time.Millisecond, T2: 100 * time.Millisecond,
		T3: 200 * time.Millisecond}
}

// closeBound is how long a protocol violation may take to end the
// connection; idleBound how long a peer that says nothing may hold it: t3
// until the test frame, t1 until it is not confirmed, and slack for a busy
// machine running the race detector.
const (
	closeBound = 2 * time.Second
	idleBound  = 3 * time.Second
)

// rawPeer is one end of a connection that speaks raw APDUs. It keeps the
// sequence numbers so that it can also behave, when a case wants it to.
// Writes may come from several goroutines; reads from one.
type rawPeer struct {
	t    testing.TB
	conn net.Conn

	mu     sync.Mutex
	vs, vr uint16
}

func dialRaw(t testing.TB, addr string) *rawPeer {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &rawPeer{t: t, conn: conn}
}

// write sends raw octets and reports whether they were all written.
func (p *rawPeer) write(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := p.conn.Write(b)
	return err
}

func (p *rawPeer) mustWrite(b []byte) {
	p.t.Helper()
	if err := p.write(b); err != nil {
		p.t.Fatalf("raw write: %v", err)
	}
}

func frameBytes(t testing.TB, f apci.Frame) []byte {
	t.Helper()
	b, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal %s: %v", f, err)
	}
	return b
}

func (p *rawPeer) sendU(fn apci.UFunction) error {
	return p.write(frameBytes(p.t, apci.NewU(fn)))
}

// sendRawASDU sends raw as the next I frame, with correct sequence numbers.
func (p *rawPeer) sendRawASDU(raw []byte) error {
	p.mu.Lock()
	f := apci.NewI(p.vs, p.vr, raw)
	p.vs = apci.SeqNext(p.vs)
	p.mu.Unlock()
	return p.write(frameBytes(p.t, f))
}

func (p *rawPeer) sendASDU(a *asdu.ASDU) error {
	p.t.Helper()
	raw, err := a.Encode(asdu.IEC104)
	if err != nil {
		p.t.Fatalf("encode %s: %v", a, err)
	}
	return p.sendRawASDU(raw)
}

func (p *rawPeer) mustSendASDU(a *asdu.ASDU) {
	p.t.Helper()
	if err := p.sendASDU(a); err != nil {
		p.t.Fatalf("send %s: %v", a, err)
	}
}

// readFrame reads one APDU, waiting at most d.
func (p *rawPeer) readFrame(d time.Duration) (apci.Frame, error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(d))
	return apci.ReadFrame(p.conn)
}

// next returns the next ASDU the other side sends, behaving meanwhile: it
// acknowledges every I frame at once, confirms test frames and, as a
// station, STARTDT. Other frames are passed to onFrame, when not nil.
func (p *rawPeer) next(d time.Duration, onFrame func(apci.Frame)) (*asdu.ASDU, error) {
	deadline := time.Now().Add(d)
	for {
		f, err := p.readFrame(time.Until(deadline))
		if err != nil {
			return nil, err
		}
		switch {
		case f.Format == apci.FormatI:
			p.mu.Lock()
			if f.SendSeq != p.vr {
				p.mu.Unlock()
				return nil, fmt.Errorf("I frame N(S)=%d, want %d", f.SendSeq, p.vr)
			}
			p.vr = apci.SeqNext(p.vr)
			vr := p.vr
			p.mu.Unlock()
			if err := p.write(frameBytes(p.t, apci.NewS(vr))); err != nil {
				return nil, err
			}
			return asdu.Decode(f.ASDU, asdu.IEC104)
		case f.Format == apci.FormatU && f.Function == apci.TestFRAct:
			if err := p.sendU(apci.TestFRCon); err != nil {
				return nil, err
			}
		case f.Format == apci.FormatU && f.Function == apci.StartDTAct:
			if err := p.sendU(apci.StartDTCon); err != nil {
				return nil, err
			}
		default:
			if onFrame != nil {
				onFrame(f)
			}
		}
	}
}

// expect returns the next ASDU that satisfies match, skipping others.
func (p *rawPeer) expect(what string, match func(*asdu.ASDU) bool) *asdu.ASDU {
	p.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, err := p.next(time.Until(deadline), nil)
		if err != nil {
			p.t.Fatalf("waiting for %s: %v", what, err)
		}
		if match(a) {
			return a
		}
	}
}

// expectU waits for the U frame fn, answering test frames on the way.
func (p *rawPeer) expectU(fn apci.UFunction) {
	p.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := p.readFrame(time.Until(deadline))
		if err != nil {
			p.t.Fatalf("waiting for U %s: %v", fn, err)
		}
		switch {
		case f.Format == apci.FormatU && f.Function == fn:
			return
		case f.Format == apci.FormatU && f.Function == apci.TestFRAct:
			if err := p.sendU(apci.TestFRCon); err != nil {
				p.t.Fatalf("TESTFR con: %v", err)
			}
		case f.Format == apci.FormatI:
			p.t.Fatalf("waiting for U %s: got %s", fn, f)
		}
	}
}

// expectS waits for an acknowledgement of everything sent so far, answering
// test frames on the way.
func (p *rawPeer) expectS() {
	p.t.Helper()
	p.mu.Lock()
	want := p.vs
	p.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := p.readFrame(time.Until(deadline))
		if err != nil {
			p.t.Fatalf("waiting for S N(R)=%d: %v", want, err)
		}
		switch {
		case f.Format == apci.FormatS && f.RecvSeq == want:
			return
		case f.Format == apci.FormatU && f.Function == apci.TestFRAct:
			if err := p.sendU(apci.TestFRCon); err != nil {
				p.t.Fatalf("TESTFR con: %v", err)
			}
		case f.Format == apci.FormatI:
			p.t.Fatalf("waiting for S N(R)=%d: got %s", want, f)
		}
	}
}

// startDT starts data transfer as a controlling station.
func (p *rawPeer) startDT() {
	p.t.Helper()
	if err := p.sendU(apci.StartDTAct); err != nil {
		p.t.Fatalf("STARTDT act: %v", err)
	}
	p.expectU(apci.StartDTCon)
}

// expectClosed waits until the other side has closed the connection,
// discarding whatever it sends meanwhile, and fails after bound.
func (p *rawPeer) expectClosed(bound time.Duration) time.Duration {
	p.t.Helper()
	begin := time.Now()
	_ = p.conn.SetReadDeadline(begin.Add(bound))
	_, err := io.Copy(io.Discard, p.conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		p.t.Fatalf("connection still open after %s", bound)
	}
	return time.Since(begin)
}

// interrogate runs a station interrogation over the raw connection and
// returns the number of data ASDUs; it proves the session is still served.
func (p *rawPeer) interrogate(ca asdu.CommonAddr) int {
	p.t.Helper()
	p.mustSendASDU(asdu.New(asdu.CauseActivation, ca, asdu.Interrogation{Qualifier: asdu.QOIStation}))
	data, confirmed := 0, false
	for {
		a := p.expect("the interrogation", func(*asdu.ASDU) bool { return true })
		switch {
		case a.Type != asdu.C_IC_NA_1:
			data++
		case a.Negative:
			p.t.Fatalf("interrogation refused: %s", a)
		case a.Cause == asdu.CauseActivationCon:
			confirmed = true
		case a.Cause == asdu.CauseActivationTerm:
			if !confirmed || data == 0 {
				p.t.Fatalf("interrogation ended after confirmation %v and %d data ASDUs", confirmed, data)
			}
			return data
		}
	}
}

// expectReply waits for the station's mirror of a request of type typ with
// cause, and checks its P/N bit.
func (p *rawPeer) expectReply(typ asdu.TypeID, cause asdu.Cause, negative bool) *asdu.ASDU {
	p.t.Helper()
	a := p.expect(fmt.Sprintf("%s with cause %s", typ, cause), func(a *asdu.ASDU) bool { return a.Type == typ })
	if a.Cause != cause || a.Negative != negative {
		p.t.Fatalf("reply %s, want cause %s negative %v", a, cause, negative)
	}
	return a
}

// goroutines returns a function that fails t when goroutines started since
// the call are still running a while after everything was closed, the
// pattern of the chaos test.
func goroutines(t testing.TB) func() {
	baseline := runtime.NumGoroutine()
	return func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > baseline+2 {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Errorf("%d goroutines before, %d after everything was closed:\n%s", baseline, n, buf)
		}
	}
}

// legitimateInterrogation proves the station still serves: a go-iec104
// client connects and interrogates it.
func legitimateInterrogation(t testing.TB, st *station.Station, fx *station.Fixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, st.Loopback(), client.WithParams(testutil.Params()), client.WithRequestTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("a legitimate client cannot connect after the attack: %v", err)
	}
	defer func() { _ = c.Close() }()
	data, err := c.Interrogate(ctx, fx.Station.CommonAddr, asdu.QOIStation)
	if err != nil {
		t.Fatalf("a legitimate client cannot interrogate after the attack: %v", err)
	}
	if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
		t.Fatalf("interrogation after the attack:\n got  %v\n want %v", got, want)
	}
}

// Outcomes of a hostile case against the server.
const (
	closes  = iota // the server ends the connection
	answers        // the server answers as the protocol says and keeps serving
)

type hostileCase struct {
	name    string
	outcome int
	bound   time.Duration // for closes; closeBound when zero
	// attack runs against a fresh connection to the station, whose common
	// address is ca.
	attack func(t *testing.T, p *rawPeer, ca asdu.CommonAddr)
}

// rawASDU is an ASDU written octet by octet in the IEC 60870-5-104 layout:
// type, VSQ, cause (2), common address (2), then the objects.
func rawASDU(typ, vsq byte, cause asdu.Cause, ca asdu.CommonAddr, objects ...byte) []byte {
	return append([]byte{typ, vsq, byte(cause), 0, byte(ca), byte(ca >> 8)}, objects...)
}

func hostileServerCases() []hostileCase {
	interrogation := func(ca asdu.CommonAddr) *asdu.ASDU {
		return asdu.New(asdu.CauseActivation, ca, asdu.Interrogation{Qualifier: asdu.QOIStation})
	}
	write := func(t *testing.T, p *rawPeer, b []byte) {
		t.Helper()
		p.mustWrite(b)
	}
	fileCall := func(ca asdu.CommonAddr, o asdu.InformationObject) *asdu.ASDU {
		return asdu.New(asdu.CauseFileTransfer, ca, o)
	}
	return []hostileCase{
		// Framing. The APDU starts with 68H and a length octet of 4..253
		// (IEC 60870-5-104, clause 5, frame formats); anything else is not an APDU, and the
		// stream cannot be resynchronised.
		{"garbage", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte("GET / HTTP/1.1\r\nHost: station\r\n\r\n"))
		}},
		{"wrong start byte after STARTDT", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			p.startDT()
			write(t, p, []byte{0x69, 0x04, 0x43, 0, 0, 0})
		}},
		{"length octet 254", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, append([]byte{0x68, 254}, make([]byte, 254)...))
		}},
		{"length octet 255", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, append([]byte{0x68, 255}, make([]byte, 255)...))
		}},
		{"length octet 3", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte{0x68, 0x03, 0x07, 0, 0})
		}},
		{"length octet 0", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte{0x68, 0x00, 0x68, 0x04, 0x07, 0, 0, 0})
		}},
		{"S frame with payload", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			p.startDT()
			write(t, p, []byte{0x68, 0x05, 0x01, 0, 0, 0, 0xAA})
		}},
		{"U frame with payload", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte{0x68, 0x05, 0x43, 0, 0, 0, 0xAA})
		}},

		// Peers that stop talking in the middle of a frame, or never start:
		// the reader waits for the rest, so only the idle test (t3, then t1
		// for its confirmation) can end them.
		{"truncated frame then silence", closes, idleBound, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			p.startDT()
			write(t, p, []byte{0x68, 0x0E, 0x00, 0x00})
		}},
		{"connect and say nothing", closes, idleBound, func(*testing.T, *rawPeer, asdu.CommonAddr) {}},
		{"one octet at a time", closes, idleBound, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			// Slowloris: a frame trickles in an octet at a time, never
			// completed in time; the octets must not count as activity.
			raw, err := interrogation(ca).Encode(asdu.IEC104)
			if err != nil {
				t.Fatal(err)
			}
			frame := frameBytes(t, apci.NewI(0, 0, raw))
			go func() {
				for i := 0; ; i = (i + 1) % len(frame) {
					if p.write(frame[i:i+1]) != nil {
						return
					}
					time.Sleep(hostileParams().T3 / 2)
				}
			}()
		}},

		// The control field.
		{"U frame with several functions", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte{0x68, 0x04, 0x04 | 0x40 | 0x03, 0, 0, 0})
		}},
		{"U frame with every function", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte{0x68, 0x04, 0xFF, 0, 0, 0})
		}},
		{"U frame with nonzero octets 2 to 4", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, []byte{0x68, 0x04, 0x43, 0x01, 0, 0})
		}},
		{"I frame with odd third octet", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			p.startDT()
			write(t, p, []byte{0x68, 0x0E, 0x00, 0x00, 0x01, 0x00, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20})
		}},

		// Sequence numbers and the state of data transfer.
		{"I frame before STARTDT", closes, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			_ = p.sendASDU(interrogation(ca))
		}},
		{"I frame after STOPDT", closes, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			if err := p.sendU(apci.StopDTAct); err != nil {
				t.Fatal(err)
			}
			p.expectU(apci.StopDTCon)
			_ = p.sendASDU(interrogation(ca))
		}},
		{"I frame with wrong N(S)", closes, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			raw, _ := interrogation(ca).Encode(asdu.IEC104)
			write(t, p, frameBytes(t, apci.NewI(5, 0, raw)))
		}},
		{"I frame replayed", closes, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			raw, _ := interrogation(ca).Encode(asdu.IEC104)
			frame := frameBytes(t, apci.NewI(0, 0, raw))
			write(t, p, append(append([]byte(nil), frame...), frame...))
		}},
		{"I frame acknowledging frames never sent", closes, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			raw, _ := interrogation(ca).Encode(asdu.IEC104)
			write(t, p, frameBytes(t, apci.NewI(0, 9, raw)))
		}},
		{"S frame acknowledging frames never sent", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			p.startDT()
			write(t, p, frameBytes(t, apci.NewS(5)))
		}},
		{"S frame acknowledging 32767 frames", closes, 0, func(t *testing.T, p *rawPeer, _ asdu.CommonAddr) {
			write(t, p, frameBytes(t, apci.NewS(apci.SeqMask)))
		}},

		// Unsolicited confirmations are not a violation: they are ignored.
		{"unsolicited confirmations", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			for _, fn := range []apci.UFunction{apci.StartDTCon, apci.StopDTCon, apci.TestFRCon} {
				if err := p.sendU(fn); err != nil {
					t.Fatal(err)
				}
			}
			p.startDT()
			p.interrogate(ca)
		}},
		{"STARTDT act repeated", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			for range 50 {
				p.startDT()
			}
			p.interrogate(ca)
		}},

		// Test frames: every one is confirmed, however many there are.
		{"TESTFR flood", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			const n = 5000
			act := frameBytes(t, apci.NewU(apci.TestFRAct))
			done := make(chan error, 1)
			go func() { done <- p.write(bytes.Repeat(act, n)) }()
			for got := 0; got < n; {
				f, err := p.readFrame(5 * time.Second)
				if err != nil {
					t.Fatalf("after %d of %d TESTFR con: %v", got, n, err)
				}
				if f.Format == apci.FormatU && f.Function == apci.TestFRCon {
					got++
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			p.startDT()
			p.interrogate(ca)
		}},
		// ASDUs the station cannot decode are dropped, and acknowledged
		// like any other: the APCI stays in step.
		{"VSQ announces 127 objects, carries one", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			if err := p.sendRawASDU(rawASDU(byte(asdu.C_IC_NA_1), 0x7F, asdu.CauseActivation, ca, 0, 0, 0, 20)); err != nil {
				t.Fatal(err)
			}
			p.expectS()
			p.interrogate(ca)
		}},
		{"VSQ sequence of 127, APDU of 253 octets", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			objs := bytes.Repeat([]byte{0xA5}, apci.MaxASDULength-6)
			if err := p.sendRawASDU(rawASDU(byte(asdu.C_SC_NA_1), 0xFF, asdu.CauseActivation, ca, objs...)); err != nil {
				t.Fatal(err)
			}
			p.expectS()
			p.interrogate(ca)
		}},
		// ASDUs that announce no object at all decode; the services of the
		// library refuse them, and the connection goes on.
		{"VSQ of zero objects", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			for _, typ := range server.FileTypes {
				if err := p.sendRawASDU(rawASDU(byte(typ), 0x00, asdu.CauseFileTransfer, ca)); err != nil {
					t.Fatal(err)
				}
				if typ == asdu.F_SG_NA_1 {
					// Of variable length, it must carry exactly one object:
					// undecodable, dropped.
					p.expectS()
					continue
				}
				p.expectReply(typ, asdu.CauseUnknownType, true)
			}
			if err := p.sendRawASDU(rawASDU(byte(asdu.F_SC_NA_1), 0x00, asdu.CauseRequest, ca)); err != nil {
				t.Fatal(err)
			}
			// The Mux refuses an ASDU without objects before any handler sees it.
			p.expectReply(asdu.F_SC_NA_1, asdu.CauseUnknownType, true)
			if err := p.sendRawASDU(rawASDU(byte(asdu.M_SP_NA_1), 0x00, asdu.CauseActivation, ca)); err != nil {
				t.Fatal(err)
			}
			p.expectReply(asdu.M_SP_NA_1, asdu.CauseUnknownType, true)
			// Commands and interrogations without an object never reach the
			// station's handlers, which index the first object.
			for _, typ := range []asdu.TypeID{asdu.C_SC_NA_1, asdu.C_IC_NA_1, asdu.C_CI_NA_1, asdu.C_CS_NA_1, asdu.C_RD_NA_1} {
				cause := asdu.CauseActivation
				if typ == asdu.C_RD_NA_1 {
					cause = asdu.CauseRequest
				}
				if err := p.sendRawASDU(rawASDU(byte(typ), 0x00, cause, ca)); err != nil {
					t.Fatal(err)
				}
				p.expectReply(typ, asdu.CauseUnknownType, true)
			}
			p.interrogate(ca)
		}},
		{"ASDU shorter than its header", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			if err := p.sendRawASDU([]byte{byte(asdu.C_IC_NA_1)}); err != nil {
				t.Fatal(err)
			}
			p.expectS()
			p.interrogate(ca)
		}},
		// A type the station does not serve is mirrored with cause 44,
		// "unknown type identification", negative.
		{"unknown type identification", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			for _, typ := range []byte{0, 22, 99, 200, 255} {
				if err := p.sendRawASDU(rawASDU(typ, 1, asdu.CauseActivation, ca, 1, 0, 0, 0xEE)); err != nil {
					t.Fatal(err)
				}
				p.expectReply(asdu.TypeID(typ), asdu.CauseUnknownType, true)
			}
			p.interrogate(ca)
		}},

		// File transfer with what does not exist, or out of turn: mirrored
		// with cause 47, "unknown information object address", negative.
		{"select a file that does not exist", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 0xFFFFFF, Name: 0xFFFF, Qualifier: asdu.FileSelect}))
			p.expectReply(asdu.F_SC_NA_1, asdu.CauseUnknownIOA, true)
			p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 30000, Name: 2, Qualifier: asdu.FileSelect}))
			p.expectReply(asdu.F_SC_NA_1, asdu.CauseUnknownIOA, true)
			p.interrogate(ca)
		}},
		{"request a file never selected", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 30000, Name: 1, Qualifier: asdu.FileRequest}))
			p.expectReply(asdu.F_SC_NA_1, asdu.CauseUnknownIOA, true)
			p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 30000, Name: 1, Section: 1, Qualifier: asdu.SectionRequest}))
			p.expectReply(asdu.F_SC_NA_1, asdu.CauseUnknownIOA, true)
			p.interrogate(ca)
		}},
		{"absurd section numbers", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 30001, Name: 1, Qualifier: asdu.FileSelect}))
			p.expect("file ready", func(a *asdu.ASDU) bool { return a.Type == asdu.F_FR_NA_1 })
			p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 30001, Name: 1, Qualifier: asdu.FileRequest}))
			p.expect("section ready", func(a *asdu.ASDU) bool { return a.Type == asdu.F_SR_NA_1 })
			for _, nos := range []uint8{0, 2, 3, 200, 255} {
				p.mustSendASDU(fileCall(ca, asdu.FileCall{IOA: 30001, Name: 1, Section: nos, Qualifier: asdu.SectionRequest}))
				p.expectReply(asdu.F_SC_NA_1, asdu.CauseUnknownIOA, true)
				p.mustSendASDU(fileCall(ca, asdu.FileAck{IOA: 30001, Name: 1, Section: nos, Qualifier: asdu.AckSectionPositive}))
				p.expectReply(asdu.F_AF_NA_1, asdu.CauseUnknownIOA, true)
			}
			p.interrogate(ca)
		}},
		{"upload out of turn", answers, 0, func(t *testing.T, p *rawPeer, ca asdu.CommonAddr) {
			p.startDT()
			const ioa = station.FirstUploadIOA + 7
			// Segments and last segments of a file that was never announced.
			p.mustSendASDU(fileCall(ca, asdu.FileSegment{IOA: ioa, Name: 1, Section: 1, Data: []byte{1, 2, 3}}))
			p.expectReply(asdu.F_SG_NA_1, asdu.CauseUnknownIOA, true)
			p.mustSendASDU(fileCall(ca, asdu.FileLastSegment{IOA: ioa, Name: 1, Section: 1,
				Qualifier: asdu.LastFileNoDeactivation}))
			p.expectReply(asdu.F_LS_NA_1, asdu.CauseUnknownIOA, true)
			// A file of the largest length, then sections out of order or
			// longer than the file.
			p.mustSendASDU(fileCall(ca, asdu.FileReady{IOA: ioa, Name: 1, Length: asdu.MaxFileLength}))
			p.expect("the call of the file", func(a *asdu.ASDU) bool { return a.Type == asdu.F_SC_NA_1 && !a.Negative })
			for _, sr := range []asdu.SectionReady{
				{IOA: ioa, Name: 1, Section: 7, Length: 10},
				{IOA: ioa, Name: 1, Section: 0, Length: 10},
				{IOA: ioa, Name: 2, Section: 1, Length: 10},
			} {
				p.mustSendASDU(fileCall(ca, sr))
				p.expectReply(asdu.F_SR_NA_1, asdu.CauseUnknownIOA, true)
			}
			p.interrogate(ca)
		}},
	}
}

// Every hostile controlling station, one connection each: the server ends
// the connection or answers as the protocol says, stays up for a
// legitimate client, and leaves no goroutine behind.
func TestHostileControllingStation(t *testing.T) {
	for _, tc := range hostileServerCases() {
		t.Run(tc.name, func(t *testing.T) {
			leaks := goroutines(t)
			fx := station.Baseline(t)
			st := station.Start(t, fx, server.WithParams(hostileParams()))
			ca := fx.Station.CommonAddr

			p := dialRaw(t, st.Loopback())
			testutil.Eventually(t, "the session", func() bool { return len(st.Server.Sessions()) == 1 })
			tc.attack(t, p, ca)
			switch tc.outcome {
			case closes:
				bound := tc.bound
				if bound == 0 {
					bound = closeBound
				}
				took := p.expectClosed(bound)
				t.Logf("closed after %s", took.Round(time.Millisecond))
				testutil.Eventually(t, "the session to end", func() bool { return len(st.Server.Sessions()) == 0 })
			case answers:
				// Still served: the case has interrogated over it already.
				if n := len(st.Server.Sessions()); n != 1 {
					t.Fatalf("%d sessions, want the attacker's", n)
				}
				_ = p.conn.Close()
			}

			legitimateInterrogation(t, st, fx)
			if err := st.Server.Close(); err != nil {
				t.Errorf("server Close: %v", err)
			}
			_ = p.conn.Close()
			leaks()
		})
	}
}

// A peer that floods test frames and never reads the confirmations: the
// server's write blocks, t1 bounds it, and the connection ends. Others are
// still served. The connection is an in-memory pipe, which buffers
// nothing: over TCP the kernel's buffers would absorb megabytes first.
func TestHostileTestFrameFloodNeverRead(t *testing.T) {
	leaks := goroutines(t)
	srv, err := server.New(nil, server.WithParams(hostileParams()))
	if err != nil {
		t.Fatal(err)
	}
	ln := newPipeListener()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	conn, err := ln.DialContext(context.Background(), "pipe", "station")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	act := bytes.Repeat(frameBytes(t, apci.NewU(apci.TestFRAct)), 64)
	flooding := make(chan struct{})
	go func() {
		defer close(flooding)
		for {
			if _, err := conn.Write(act); err != nil {
				return
			}
		}
	}()
	testutil.Eventually(t, "the session", func() bool { return len(srv.Sessions()) == 1 })
	begin := time.Now()
	for len(srv.Sessions()) != 0 {
		if time.Since(begin) > idleBound {
			t.Fatalf("session still open after %s", idleBound)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("closed after %s", time.Since(begin).Round(time.Millisecond))
	<-flooding

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "station:2404", client.WithParams(testutil.Params()), client.WithDialer(ln))
	if err != nil {
		t.Fatalf("a legitimate client cannot connect after the attack: %v", err)
	}
	if err := c.TestLink(ctx); err != nil {
		t.Fatalf("a legitimate client cannot test the link after the attack: %v", err)
	}
	_ = c.Close()
	if err := srv.Close(); err != nil {
		t.Errorf("server Close: %v", err)
	}
	if err := <-served; !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("Serve: %v", err)
	}
	leaks()
}

// A file announced at the largest length, and sections announced at the
// largest length, cost the station memory only for what arrives: a peer
// that announces and sends nothing must not make the station reserve the
// announced octets.
func TestHostileUploadAnnouncementsReserveNothing(t *testing.T) {
	leaks := goroutines(t)
	fx := station.Baseline(t)
	st := station.Start(t, fx, server.WithParams(hostileParams()))
	ca := fx.Station.CommonAddr
	p := dialRaw(t, st.Loopback())
	p.startDT()

	heap := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	before := heap()
	const files = 8 // 8 x 16 MiB announced
	for i := range asdu.IOA(files) {
		ioa := station.FirstUploadIOA + 100 + i
		p.mustSendASDU(asdu.New(asdu.CauseFileTransfer, ca, asdu.FileReady{IOA: ioa, Name: 1, Length: asdu.MaxFileLength}))
		p.expect("the call of the file", func(a *asdu.ASDU) bool { return a.Type == asdu.F_SC_NA_1 && !a.Negative })
		p.mustSendASDU(asdu.New(asdu.CauseFileTransfer, ca,
			asdu.SectionReady{IOA: ioa, Name: 1, Section: 1, Length: asdu.MaxFileLength}))
		p.expect("the call of the section", func(a *asdu.ASDU) bool { return a.Type == asdu.F_SC_NA_1 && !a.Negative })
	}
	after := heap()
	const limit = 16 << 20
	if grew := int64(after) - int64(before); grew > limit {
		t.Errorf("the heap grew by %d MiB for %d announced files that sent no data, want less than %d MiB",
			grew>>20, files, limit>>20)
	}

	_ = p.conn.Close()
	legitimateInterrogation(t, st, fx)
	if err := st.Server.Close(); err != nil {
		t.Errorf("server Close: %v", err)
	}
	leaks()
}

// --- hostile controlled station against the client ---

// rogueStation accepts connections and runs serve on each, once STARTDT is
// confirmed. serve gets every ASDU the client sends; the peer answers test
// frames and acknowledges I frames by itself.
type rogueStation struct {
	ln   net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	peer []*rawPeer
}

func startRogue(t *testing.T, serve func(p *rawPeer, a *asdu.ASDU)) *rogueStation {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &rogueStation{ln: ln}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			p := &rawPeer{t: t, conn: conn}
			r.mu.Lock()
			r.peer = append(r.peer, p)
			r.mu.Unlock()
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer func() { _ = conn.Close() }()
				for {
					a, err := p.next(time.Minute, nil)
					if err != nil {
						return
					}
					serve(p, a)
				}
			}()
		}
	}()
	t.Cleanup(r.close)
	return r
}

func (r *rogueStation) addr() string { return r.ln.Addr().String() }

func (r *rogueStation) close() {
	_ = r.ln.Close()
	r.mu.Lock()
	for _, p := range r.peer {
		_ = p.conn.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func dialRogue(t *testing.T, r *rogueStation, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	all := append([]client.Option{client.WithParams(hostileParams()), client.WithRequestTimeout(time.Second)}, opts...)
	c, err := client.Dial(ctx, r.addr(), all...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// within runs call and fails t when it does not return within bound.
func within(t *testing.T, bound time.Duration, what string, call func() error) error {
	t.Helper()
	done := make(chan error, 1)
	begin := time.Now()
	go func() { done <- call() }()
	select {
	case err := <-done:
		t.Logf("%s returned after %s: %v", what, time.Since(begin).Round(time.Millisecond), err)
		return err
	case <-time.After(bound):
		t.Fatalf("%s did not return within %s", what, bound)
		return nil
	}
}

// usable checks that the client still talks to the station.
func usable(t *testing.T, c *client.Client) {
	t.Helper()
	if err := within(t, closeBound, "TestLink", func() error { return c.TestLink(context.Background()) }); err != nil {
		t.Fatalf("client unusable after the attack: %v", err)
	}
}

// fileScript is a controlled station that serves one file the way a
// hostile station would: ready answers the selection, request the call of
// the file, section the call of section nos and after the positive
// acknowledgement of section nos.
type fileScript struct {
	ready   asdu.FileReady
	request []asdu.InformationObject
	section func(nos uint8) []asdu.InformationObject
	after   func(nos uint8) []asdu.InformationObject
	acks    chan asdu.FileAck
}

func (s *fileScript) serve(p *rawPeer, a *asdu.ASDU) {
	send := func(objs []asdu.InformationObject) {
		for _, o := range objs {
			if p.sendASDU(asdu.New(asdu.CauseFileTransfer, a.CommonAddr, o)) != nil {
				return
			}
		}
	}
	switch o := a.First().(type) {
	case asdu.FileCall:
		switch o.Qualifier {
		case asdu.FileSelect:
			send([]asdu.InformationObject{s.ready})
		case asdu.FileRequest:
			send(s.request)
		case asdu.SectionRequest:
			if s.section != nil {
				send(s.section(o.Section))
			}
		}
	case asdu.FileAck:
		select {
		case s.acks <- o:
		default:
		}
		if o.Qualifier == asdu.AckSectionPositive && s.after != nil {
			send(s.after(o.Section))
		}
	}
}

// Hostile file transfers: GetFile fails with ErrProtocol, acknowledges
// negatively where there is something to acknowledge, and the client stays
// usable.
func TestHostileStationFileTransfer(t *testing.T) {
	const ioa, name = 30000, 1
	type objs = []asdu.InformationObject
	seg := func(nos uint8, data []byte) asdu.FileSegment {
		return asdu.FileSegment{IOA: ioa, Name: name, Section: nos, Data: data}
	}
	lastSection := func(nos, sum uint8) asdu.FileLastSegment {
		return asdu.FileLastSegment{IOA: ioa, Name: name, Section: nos, Qualifier: asdu.LastSectionNoDeactivation, Checksum: sum}
	}
	lastFile := func(nos, sum uint8) asdu.FileLastSegment {
		return asdu.FileLastSegment{IOA: ioa, Name: name, Section: nos, Qualifier: asdu.LastFileNoDeactivation, Checksum: sum}
	}
	sr := func(nos uint8, n uint32) asdu.SectionReady {
		return asdu.SectionReady{IOA: ioa, Name: name, Section: nos, Length: n}
	}
	sum := func(b []byte) (s uint8) {
		for _, v := range b {
			s += v
		}
		return s
	}
	payload := bytes.Repeat([]byte{0x5A}, 200)
	fixed := func(o ...asdu.InformationObject) func(uint8) objs { return func(uint8) objs { return o } }

	tests := []struct {
		name    string
		length  uint32
		request objs
		section func(nos uint8) objs
		after   func(nos uint8) objs
		// wantAck is the qualifier of the acknowledgement the client must
		// send before it fails; 0 when it fails before acknowledging.
		wantAck uint8
	}{
		{"largest file, section longer than announced", asdu.MaxFileLength, objs{sr(1, 100)},
			fixed(seg(1, payload), seg(1, payload), seg(1, payload), lastSection(1, 3*sum(payload))),
			nil, asdu.AckSectionNegative},
		{"more data than the file", 10, objs{sr(1, 10)},
			fixed(seg(1, payload), lastSection(1, sum(payload))), nil, 0},
		{"wrong section checksum", 200, objs{sr(1, 200)},
			fixed(seg(1, payload), lastSection(1, sum(payload)+1)), nil, asdu.AckSectionNegative},
		{"wrong file checksum", 200, objs{sr(1, 200)},
			fixed(seg(1, payload), lastSection(1, sum(payload))), fixed(lastFile(2, sum(payload)+1)), asdu.AckFileNegative},
		{"file shorter than announced", 400, objs{sr(1, 200)},
			fixed(seg(1, payload), lastSection(1, sum(payload))), fixed(lastFile(2, sum(payload))), asdu.AckFileNegative},
		{"segment instead of section ready", 200, objs{seg(1, payload)}, nil, nil, 0},
		{"last segment of the file inside a section", 200, objs{sr(1, 200)},
			fixed(seg(1, payload), lastFile(1, sum(payload))), nil, 0},
		// Section 1 is called and acknowledged; the station sent section 9.
		{"segments of another section", 200, objs{sr(1, 200)},
			fixed(seg(9, payload), lastSection(9, sum(payload))), fixed(lastFile(2, sum(payload))), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := goroutines(t)
			script := &fileScript{ready: asdu.FileReady{IOA: ioa, Name: name, Length: tt.length},
				request: tt.request, section: tt.section, after: tt.after, acks: make(chan asdu.FileAck, 4)}
			rogue := startRogue(t, script.serve)
			c := dialRogue(t, rogue)

			var data []byte
			err := within(t, closeBound, "GetFile", func() (err error) {
				data, err = c.GetFile(context.Background(), 1, ioa, name)
				return err
			})
			if !errors.Is(err, iec104.ErrProtocol) {
				t.Errorf("GetFile = %d octets, %v; want ErrProtocol", len(data), err)
			}
			if tt.wantAck != 0 {
				var last *asdu.FileAck
			acks:
				for {
					select {
					case ack := <-script.acks:
						last = &ack
						if ack.Qualifier == tt.wantAck {
							break acks
						}
					case <-time.After(closeBound):
						t.Errorf("last acknowledgement %+v, want qualifier %d", last, tt.wantAck)
						break acks
					}
				}
			}
			usable(t, c)
			_ = c.Close()
			rogue.close()
			leaks()
		})
	}
}

// A station that announces section after section, each empty and each
// acknowledged, never ends the file: the caller's context bounds it.
func TestHostileStationEndlessSections(t *testing.T) {
	leaks := goroutines(t)
	const ioa, name = 30000, 1
	ready := func(nos uint8) []asdu.InformationObject {
		return []asdu.InformationObject{asdu.SectionReady{IOA: ioa, Name: name, Section: nos%250 + 1}}
	}
	script := &fileScript{
		ready:   asdu.FileReady{IOA: ioa, Name: name, Length: asdu.MaxFileLength},
		request: ready(0),
		section: func(nos uint8) []asdu.InformationObject {
			return []asdu.InformationObject{
				asdu.FileLastSegment{IOA: ioa, Name: name, Section: nos, Qualifier: asdu.LastSectionNoDeactivation},
			}
		},
		after: ready,
		acks:  make(chan asdu.FileAck, 1),
	}
	rogue := startRogue(t, script.serve)
	c := dialRogue(t, rogue)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := within(t, closeBound, "GetFile", func() error {
		_, err := c.GetFile(ctx, 1, ioa, name)
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetFile: %v, want the context's deadline", err)
	}
	usable(t, c)
	_ = c.Close()
	rogue.close()
	leaks()
}

// A station that confirms an interrogation again and again, and never
// terminates it: the request timeout ends the call, and the client stays
// usable.
func TestHostileStationEndlessConfirmations(t *testing.T) {
	leaks := goroutines(t)
	stop := make(chan struct{})
	var streams sync.WaitGroup
	rogue := startRogue(t, func(p *rawPeer, a *asdu.ASDU) {
		if a.Type != asdu.C_IC_NA_1 {
			return
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			con := a.Reply(asdu.CauseActivationCon, false)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if p.sendASDU(con) != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
	})
	c := dialRogue(t, rogue, client.WithRequestTimeout(300*time.Millisecond))
	err := within(t, closeBound, "Interrogate", func() error {
		_, err := c.Interrogate(context.Background(), 1, asdu.QOIStation)
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Interrogate: %v, want the request timeout", err)
	}
	usable(t, c)
	close(stop)
	streams.Wait()
	_ = c.Close()
	rogue.close()
	leaks()
}

// A station that breaks the APCI while a request waits: the request fails
// within a bound, the client reports the connection lost and closes
// cleanly.
func TestHostileStationBreaksAPCI(t *testing.T) {
	tests := []struct {
		name   string
		answer func(p *rawPeer, a *asdu.ASDU)
	}{
		{"I frame with wrong N(S)", func(p *rawPeer, a *asdu.ASDU) {
			raw, _ := a.Reply(asdu.CauseActivationCon, false).Encode(asdu.IEC104)
			_ = p.write(frameBytes(p.t, apci.NewI(7, 1, raw)))
		}},
		{"I frame acknowledging frames never sent", func(p *rawPeer, a *asdu.ASDU) {
			raw, _ := a.Reply(asdu.CauseActivationCon, false).Encode(asdu.IEC104)
			_ = p.write(frameBytes(p.t, apci.NewI(0, 9, raw)))
		}},
		{"S frame acknowledging frames never sent", func(p *rawPeer, _ *asdu.ASDU) {
			_ = p.write(frameBytes(p.t, apci.NewS(100)))
		}},
		{"garbage", func(p *rawPeer, _ *asdu.ASDU) {
			_ = p.write([]byte{0x68, 0xFF, 0xFF, 0xFF})
		}},
		{"U frame with several functions", func(p *rawPeer, _ *asdu.ASDU) {
			_ = p.write([]byte{0x68, 0x04, 0x0B | 0x80, 0, 0, 0})
		}},
		{"truncated frame then silence", func(p *rawPeer, _ *asdu.ASDU) {
			_ = p.write([]byte{0x68, 0x0E, 0x00})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := goroutines(t)
			rogue := startRogue(t, func(p *rawPeer, a *asdu.ASDU) {
				if a.Type == asdu.C_IC_NA_1 {
					tt.answer(p, a)
				}
			})
			states := make(chan iec104.State, 16)
			c := dialRogue(t, rogue, client.WithStateHandler(func(s iec104.State, _ error) {
				select {
				case states <- s:
				default:
				}
			}))
			// The request timeout is longer than t1: what ends the call is
			// the connection, not the timeout.
			err := within(t, idleBound, "Interrogate", func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 2*idleBound)
				defer cancel()
				_, err := c.Interrogate(ctx, 1, asdu.QOIStation)
				return err
			})
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Interrogate: %v, want the connection to fail", err)
			}
			testutil.Eventually(t, "the client to be disconnected", func() bool {
				return c.State() == iec104.StateDisconnected
			})
			if err := c.TestLink(context.Background()); !errors.Is(err, iec104.ErrNotConnected) {
				t.Errorf("TestLink after the connection failed: %v, want ErrNotConnected", err)
			}
			if err := within(t, closeBound, "Close", c.Close); err != nil {
				t.Errorf("Close: %v", err)
			}
			rogue.close()
			leaks()
		})
	}
}

// A station that sends what only a controlling station sends, or confirms
// what was never asked: ignored, and the client keeps working.
func TestHostileStationUnsolicitedControl(t *testing.T) {
	leaks := goroutines(t)
	rogue := startRogue(t, func(p *rawPeer, a *asdu.ASDU) {
		if a.Type != asdu.C_IC_NA_1 {
			return
		}
		for _, fn := range []apci.UFunction{apci.StartDTCon, apci.StopDTCon, apci.TestFRCon, apci.StartDTAct, apci.StopDTAct} {
			for range 20 {
				_ = p.sendU(fn)
			}
		}
		_ = p.sendASDU(a.Reply(asdu.CauseActivationCon, false))
		_ = p.sendASDU(asdu.New(asdu.CauseInterrogatedStation, a.CommonAddr, asdu.SinglePoint{IOA: 1, Value: true}))
		_ = p.sendASDU(a.Reply(asdu.CauseActivationTerm, false))
	})
	c := dialRogue(t, rogue)
	var data []*asdu.ASDU
	err := within(t, closeBound, "Interrogate", func() (err error) {
		data, err = c.Interrogate(context.Background(), 1, asdu.QOIStation)
		return err
	})
	if err != nil || len(data) != 1 {
		t.Fatalf("Interrogate = %d ASDUs, %v; want 1, nil", len(data), err)
	}
	usable(t, c)
	_ = c.Close()
	rogue.close()
	leaks()
}
