// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/otfabric/go-iec104/apci"
)

// Peer plays one side of a recorded conversation over a live connection to
// the go-iec104 implementation of the other side.
//
// Comparison rules: the control fields are dynamic. The peer rebuilds N(S)
// and N(R) of the frames it sends from the live link and sends the
// recorded ASDU octets unchanged. Of the frames it receives it compares
// the format, the U function and the ASDU octets; N(S) must count up from
// zero and N(R) may not acknowledge frames the peer has not sent. S frames
// are dynamic too: the peer sends one where the recording has one and
// whenever W of the received I frames are unacknowledged; the frames of
// the implementation are read whenever they come.
type Peer struct {
	Conn net.Conn
	// Side is the side the peer plays.
	Side Station
	// W is the most I frames the peer receives before it acknowledges them;
	// zero means 8.
	W int
	// Timeout bounds every wait for the implementation; zero means 5s.
	Timeout time.Duration
	// Trigger is called before the peer waits for APDU i of the recording,
	// which the implementation sends. It makes the implementation send it
	// (a request through its API, a confirmation from a handler). It
	// returns false when the implementation sends the APDU by itself.
	Trigger func(i int, d Decoded) bool
	// AckBeforeStop makes the peer acknowledge every I frame received before
	// it sends STOPDT act, as a controlling station must for the controlled
	// station to confirm (IEC 60870-5-104 ed. 2, 5.3), also where the
	// recording does not. Result.Notes counts each time it was needed.
	AckBeforeStop bool
	// Skip, when not nil, leaves out APDU i of the recording: neither sent
	// nor awaited.
	Skip func(i int, d Decoded) bool
	// Same compares a recorded ASDU (want) with the one the implementation
	// sent (got); nil means byte equality. It returns "" when they agree
	// and otherwise a classified description.
	Same func(i int, want, got []byte) string

	sent, recv uint16 // I frames sent and received
	acked      uint16 // N(R) the peer last sent
	theirAck   uint16 // N(R) the implementation last sent
	pending    []apci.Frame
	frames     chan readResult // filled by the reading goroutine
	extraCon   int             // TESTFR con the recorded other side never sent
}

// Mismatch is a difference between the recording and the implementation.
type Mismatch struct {
	Index int    // index of the APDU in Analysis.Decoded
	Frame int    // its frame number in the capture
	What  string // classified description
}

func (m Mismatch) String() string {
	return fmt.Sprintf("frame %d (APDU %d): %s", m.Frame, m.Index, m.What)
}

// Result is the outcome of a replay.
type Result struct {
	// Played counts the APDUs of the recording the peer sent or received.
	Played int
	// Compared counts the received I frames compared with the recording;
	// Exact those equal to it.
	Compared, Exact int
	Mismatches      []Mismatch
	// Notes are differences the implementation is right about: what the
	// recorded other side did not do and the protocol requires.
	Notes []Mismatch
	// Err is the error that ended the replay early, or nil.
	Err error
	// Stopped is the index of the APDU at which it ended, or -1.
	Stopped int
}

type readResult struct {
	frame apci.Frame
	err   error
}

// errSequence reports a sequence number of the implementation that does not
// fit the frames exchanged.
var errSequence = errors.New("sequence number")

// ErrTimeout reports an implementation that did not send what the
// recording holds in time.
var ErrTimeout = errors.New("capture: timed out waiting for the implementation")

// Run plays the APDUs of a from index from up to (not including) to.
func (p *Peer) Run(a *Analysis, from, to int) Result {
	r := Result{Stopped: -1}
	if p.W == 0 {
		p.W = 8
	}
	if p.Timeout == 0 {
		p.Timeout = 5 * time.Second
	}
	for i := from; i < to && i < len(a.Decoded); i++ {
		d := a.Decoded[i]
		if d.APCIErr != nil || p.Skip != nil && p.Skip(i, d) {
			continue
		}
		mine := d.side() == p.Side
		if mine {
			if d.Frame.Format == apci.FormatU && d.Frame.Function == apci.TestFRAct && !answered(a, i) {
				p.extraCon++
				r.Notes = append(r.Notes, Mismatch{Index: i, Frame: d.APDU.Frame,
					What: "the recorded other side did not answer this TESTFR act; the implementation does"})
			}
			if p.AckBeforeStop && d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StopDTAct && p.acked != p.recv {
				r.Notes = append(r.Notes, Mismatch{Index: i, Frame: d.APDU.Frame,
					What: "acknowledged the outstanding I frames before STOPDT act, which the recorded controlling station did not"})
				if err := p.Flush(); err != nil {
					r.Err, r.Stopped = err, i
					return r
				}
			}
			if err := p.send(d); err != nil {
				r.Err, r.Stopped = err, i
				return r
			}
			r.Played++
			continue
		}
		if d.Frame.Format == apci.FormatS {
			continue // dynamic: the implementation acknowledges when it wants
		}
		if p.Trigger != nil {
			p.Trigger(i, d)
		}
		f, err := p.expect(d.Frame)
		if err != nil {
			r.Err, r.Stopped = fmt.Errorf("frame %d: %w", d.APDU.Frame, err), i
			return r
		}
		r.Played++
		if d.Frame.Format != apci.FormatI {
			continue
		}
		r.Compared++
		what := ""
		if p.Same != nil {
			what = p.Same(i, d.Frame.ASDU, f.ASDU)
		} else if !bytes.Equal(d.Frame.ASDU, f.ASDU) {
			what = fmt.Sprintf("ASDU differs:\n  recorded % x\n  sent     % x", d.Frame.ASDU, f.ASDU)
		}
		if what == "" {
			r.Exact++
		} else {
			r.Mismatches = append(r.Mismatches, Mismatch{Index: i, Frame: d.APDU.Frame, What: what})
		}
	}
	return r
}

// Flush acknowledges every I frame received.
func (p *Peer) Flush() error {
	if p.acked == p.recv {
		return nil
	}
	return p.write(apci.NewS(p.recv))
}

// Drain reads what the implementation sends for d and acknowledges it,
// until the connection is idle for d.
func (p *Peer) Drain(d time.Duration) []apci.Frame {
	var out []apci.Frame
	for {
		f, err := p.read(d)
		if err != nil {
			return out
		}
		out = append(out, f)
	}
}

// Test sends TESTFR act and waits for the confirmation: the implementation
// still serves the connection.
func (p *Peer) Test() error {
	if err := p.write(apci.NewU(apci.TestFRAct)); err != nil {
		return err
	}
	_, err := p.expect(apci.NewU(apci.TestFRCon))
	return err
}

// Closed waits up to d for the implementation to close the connection and
// returns ErrTimeout if it does not.
func (p *Peer) Closed(d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		_, err := p.read(time.Until(deadline))
		switch {
		case errors.Is(err, ErrTimeout):
			return err
		case err != nil && !errors.Is(err, errSequence):
			return nil
		case time.Now().After(deadline):
			return ErrTimeout
		}
	}
}

func (p *Peer) send(d Decoded) error {
	switch d.Frame.Format {
	case apci.FormatI:
		f := apci.NewI(p.sent, p.recv, d.Frame.ASDU)
		p.sent = (p.sent + 1) & apci.SeqMask
		return p.write(f)
	case apci.FormatS:
		if p.acked == p.recv {
			return nil
		}
		return p.write(apci.NewS(p.recv))
	default:
		return p.write(d.Frame)
	}
}

func (p *Peer) write(f apci.Frame) error {
	if f.Format != apci.FormatU {
		p.acked = f.RecvSeq
	}
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	if err := p.Conn.SetWriteDeadline(time.Now().Add(p.Timeout)); err != nil {
		return err
	}
	_, err = p.Conn.Write(b)
	return err
}

// expect reads frames until one of the kind of want arrives. S frames are
// taken whenever they come; an I frame that comes while a U frame is
// awaited, or the other way round, is kept for later.
func (p *Peer) expect(want apci.Frame) (apci.Frame, error) {
	for i, f := range p.pending {
		if match(want, f) {
			p.pending = append(p.pending[:i], p.pending[i+1:]...)
			return f, nil
		}
	}
	deadline := time.Now().Add(p.Timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return apci.Frame{}, fmt.Errorf("%w: want %s", ErrTimeout, want)
		}
		f, err := p.read(left)
		if err != nil {
			return apci.Frame{}, fmt.Errorf("want %s: %w", want, err)
		}
		if f.Format == apci.FormatS {
			continue
		}
		if f.Format == apci.FormatU && f.Function == apci.TestFRCon && p.extraCon > 0 && !match(want, f) {
			p.extraCon--
			continue
		}
		if match(want, f) {
			return f, nil
		}
		if f.Format == apci.FormatU && f.Function == apci.TestFRAct {
			// The implementation tests the link on its own: answer it.
			if err := p.write(apci.NewU(apci.TestFRCon)); err != nil {
				return apci.Frame{}, err
			}
			continue
		}
		if f.Format != want.Format && f.Format != apci.FormatS && want.Format != apci.FormatS {
			// An I frame and a U frame that crossed: the order the
			// recording has them in is timing, not protocol.
			p.pending = append(p.pending, f)
			continue
		}
		return apci.Frame{}, fmt.Errorf("got %s, want %s", f, want)
	}
}

// answered reports whether the TESTFR act at index i of the recording is
// confirmed before the next TESTFR act of the same side.
func answered(a *Analysis, i int) bool { return a.Confirmed(i) }

func match(want, got apci.Frame) bool {
	if want.Format != got.Format {
		return false
	}
	return want.Format != apci.FormatU || want.Function == got.Function
}

// read reads one frame and checks its sequence numbers.
func (p *Peer) read(d time.Duration) (apci.Frame, error) {
	// One goroutine reads whole frames: a wait that ends never leaves
	// half a frame read.
	if p.frames == nil {
		p.frames = make(chan readResult, 64)
		go func(conn net.Conn, out chan<- readResult) {
			for {
				f, err := apci.ReadFrame(conn)
				out <- readResult{f, err}
				if err != nil {
					close(out)
					return
				}
			}
		}(p.Conn, p.frames)
	}
	var f apci.Frame
	select {
	case r, ok := <-p.frames:
		if !ok {
			return apci.Frame{}, net.ErrClosed
		}
		if r.err != nil {
			return apci.Frame{}, r.err
		}
		f = r.frame
	case <-time.After(d):
		return apci.Frame{}, ErrTimeout
	}
	switch f.Format {
	case apci.FormatI:
		if f.SendSeq != p.recv {
			return f, fmt.Errorf("%w: N(S)=%d, want %d", errSequence, f.SendSeq, p.recv)
		}
		p.recv = (p.recv + 1) & apci.SeqMask
		if err := p.ackOf(f.RecvSeq); err != nil {
			return f, err
		}
		if seqDist(p.acked, p.recv) >= p.W {
			if err := p.write(apci.NewS(p.recv)); err != nil {
				return f, err
			}
		}
	case apci.FormatS:
		if err := p.ackOf(f.RecvSeq); err != nil {
			return f, err
		}
	case apci.FormatU:
	}
	return f, nil
}

func (p *Peer) ackOf(nr uint16) error {
	if seqDist(p.theirAck, nr) > seqDist(p.theirAck, p.sent) {
		return fmt.Errorf("%w: N(R)=%d acknowledges past the %d I frames sent", errSequence, nr, p.sent)
	}
	p.theirAck = nr
	return nil
}
