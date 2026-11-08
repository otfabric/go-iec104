// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

// Decoded is one APDU of a conversation decoded by go-iec104.
type Decoded struct {
	APDU
	Frame apci.Frame
	ASDU  *asdu.ASDU // I frames whose ASDU decodes
	// APCIErr and ASDUErr are the decode errors, if any.
	APCIErr, ASDUErr error
	// Reencoded is the encoding go-iec104 produces from Frame and ASDU; it
	// is nil when either did not decode.
	Reencoded []byte
}

// Station is one side of a conversation.
type Station int

// The two sides.
const (
	Controlling Station = iota // the client, not on the server port
	Controlled                 // the server
)

func (s Station) String() string {
	if s == Controlling {
		return "controlling"
	}
	return "controlled"
}

// Seq is the sequence-number and acknowledgement record of one side.
type Seq struct {
	// IFrames counts the I frames the side sent; SFrames its S frames.
	IFrames, SFrames int
	// SendErrors are the I frames whose N(S) was not the one expected;
	// RecvErrors the I or S frames whose N(R) acknowledged frames the side
	// had not received, or went backwards.
	SendErrors, RecvErrors []string
	// MaxUnacked is the most I frames the side had sent and the other had
	// not acknowledged (the k the side used). MaxUnconfirmed is the most I
	// frames the side received before acknowledging them (the w it used).
	MaxUnacked, MaxUnconfirmed int
	// Start is the N(S) of the first I frame seen: 0 for a conversation
	// recorded from its STARTDT.
	Start   uint16
	started bool
}

// Procedure counts request/answer pairs of one kind.
type Procedure struct {
	Requests, Confirmed, Negative, Terminated, Unanswered int
}

// Analysis is what go-iec104 derives from one conversation.
type Analysis struct {
	Conversation
	Decoded []Decoded
	// Count of frames by format, of ASDUs by type and by cause.
	I, S, U int
	Types   map[asdu.TypeID]int
	Causes  map[asdu.Cause]int
	// Sequence records of the controlling and the controlled side.
	Seq [2]Seq
	// U frame procedures by function name ("STARTDT", "STOPDT", "TESTFR"),
	// and ASDU procedures by request type.
	UFn  map[string]*Procedure
	ASDU map[asdu.TypeID]*Procedure
	// StoppedI lists the indexes in Decoded of the I frames a side sent
	// while data transfer was stopped: before the first STARTDT con of a
	// conversation recorded from its start, or after a STOPDT con.
	StoppedI []int
	// FromZero reports that the sequence numbers were checked from zero.
	FromZero bool
	// Unsolicited counts the ASDUs with a cause that answers no request:
	// periodic, background, spontaneous, initialized.
	Unsolicited int
}

// Analyze decodes every APDU of c under p and checks the sequence numbers
// and procedures of both sides.
func Analyze(c Conversation, p asdu.Params) *Analysis {
	a := &Analysis{
		Conversation: c,
		Types:        map[asdu.TypeID]int{},
		Causes:       map[asdu.Cause]int{},
		UFn:          map[string]*Procedure{},
		ASDU:         map[asdu.TypeID]*Procedure{},
	}
	for _, x := range c.APDUs {
		a.Decoded = append(a.Decoded, decode(x, p))
	}
	a.sequence()
	a.procedures()
	a.transferState()
	return a
}

func decode(x APDU, p asdu.Params) Decoded {
	d := Decoded{APDU: x}
	d.Frame, d.APCIErr = apci.Parse(x.Data)
	if d.APCIErr != nil {
		return d
	}
	if d.Frame.Format != apci.FormatI {
		d.Reencoded, _ = d.Frame.MarshalBinary()
		return d
	}
	d.ASDU, d.ASDUErr = asdu.Decode(d.Frame.ASDU, p)
	if d.ASDUErr != nil {
		return d
	}
	body, err := d.ASDU.Encode(p)
	if err != nil {
		d.ASDUErr = fmt.Errorf("re-encode: %w", err)
		return d
	}
	f := d.Frame
	f.ASDU = body
	d.Reencoded, _ = f.MarshalBinary()
	return d
}

// Exact reports whether the re-encoding equals the recorded octets.
func (d Decoded) Exact() bool { return d.Reencoded != nil && bytes.Equal(d.Reencoded, d.Data) }

func (d Decoded) side() Station {
	if d.FromClient {
		return Controlling
	}
	return Controlled
}

// seqDist is the distance from a to b modulo 2^15.
func seqDist(a, b uint16) int { return int((b - a) & apci.SeqMask) }

// sequence replays both sides' send and receive counters. next[s] is the
// N(S) side s sends next, acked[s] the last N(R) side s sent: of the
// other side's frames, those up to acked[s] are confirmed. A conversation
// recorded from its SYN starts at zero, and so does one whose first APDU
// is the controlling station's STARTDT act (the recordings that left the
// SYN out keep only APDUs; in those that hold it, every connection begins
// with STARTDT act). Any other takes each counter from the first frame
// that shows it.
func (a *Analysis) sequence() {
	var next, acked [2]uint16
	var knownNext, knownAcked [2]bool
	if a.Opened || a.startsWithStartDT() {
		a.FromZero = true
		knownNext, knownAcked = [2]bool{true, true}, [2]bool{true, true}
	}
	recvNR := func(s Station, nr uint16, frame int) {
		o := 1 - s
		if !knownNext[o] {
			next[o], knownNext[o] = nr, true
		}
		if !knownAcked[s] {
			acked[s], knownAcked[s] = nr, true
		}
		if seqDist(acked[s], nr) > seqDist(acked[s], next[o]) {
			a.Seq[s].RecvErrors = append(a.Seq[s].RecvErrors,
				fmt.Sprintf("frame %d: N(R)=%d, last %d, the other side sent up to %d", frame, nr, acked[s], next[o]))
			return
		}
		acked[s] = nr
	}
	for _, d := range a.Decoded {
		if d.APCIErr != nil {
			continue
		}
		s := d.side()
		o := 1 - s
		st := &a.Seq[s]
		switch d.Frame.Format {
		case apci.FormatI:
			a.I++
			st.IFrames++
			if !st.started {
				st.started, st.Start = true, d.Frame.SendSeq
			}
			if !knownNext[s] {
				next[s], knownNext[s] = d.Frame.SendSeq, true
			}
			if d.Frame.SendSeq != next[s] {
				st.SendErrors = append(st.SendErrors, fmt.Sprintf("frame %d: N(S)=%d, want %d", d.APDU.Frame, d.Frame.SendSeq, next[s]))
				next[s] = d.Frame.SendSeq
			}
			next[s] = (next[s] + 1) & apci.SeqMask
			recvNR(s, d.Frame.RecvSeq, d.APDU.Frame)
			if knownAcked[o] {
				st.MaxUnacked = max(st.MaxUnacked, seqDist(acked[o], next[s]))
				a.Seq[o].MaxUnconfirmed = max(a.Seq[o].MaxUnconfirmed, seqDist(acked[o], next[s]))
			}
		case apci.FormatS:
			a.S++
			st.SFrames++
			recvNR(s, d.Frame.RecvSeq, d.APDU.Frame)
		case apci.FormatU:
			a.U++
		}
	}
}

// Confirmed reports whether the U act at index i of Decoded is confirmed by
// the other side before the same side sends that act again.
func (a *Analysis) Confirmed(i int) bool {
	d := a.Decoded[i]
	if d.APCIErr != nil || d.Frame.Format != apci.FormatU || !isAct(d.Frame.Function) {
		return false
	}
	side, act := d.side(), d.Frame.Function
	for _, e := range a.Decoded[i+1:] {
		if e.APCIErr != nil || e.Frame.Format != apci.FormatU {
			continue
		}
		switch {
		case e.side() != side && actOf(e.Frame.Function) == act && !isAct(e.Frame.Function):
			return true
		case e.side() == side && e.Frame.Function == act:
			return false
		}
	}
	return false
}

// transferState finds the I frames sent while data transfer was stopped.
func (a *Analysis) transferState() {
	started := !a.FromZero // unknown: assume started
	for i, d := range a.Decoded {
		if d.APCIErr != nil {
			continue
		}
		switch {
		case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StartDTCon:
			started = true
		case d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StopDTCon:
			started = false
		case d.Frame.Format == apci.FormatI && !started:
			a.StoppedI = append(a.StoppedI, i)
		}
	}
}

func (a *Analysis) startsWithStartDT() bool {
	if len(a.Decoded) == 0 {
		return false
	}
	d := a.Decoded[0]
	return d.APCIErr == nil && d.FromClient && d.Frame.Format == apci.FormatU && d.Frame.Function == apci.StartDTAct
}

// procedures correlates U functions and control-direction requests with
// their confirmations and terminations.
func (a *Analysis) procedures() {
	type key struct {
		t   asdu.TypeID
		ca  asdu.CommonAddr
		ioa asdu.IOA
	}
	pendingU := map[apci.UFunction]bool{}
	pending := map[key]int{} // open requests
	terminated := map[key]bool{}
	for _, d := range a.Decoded {
		if d.APCIErr != nil {
			continue
		}
		if d.Frame.Format == apci.FormatU {
			fn := d.Frame.Function
			name := uName(fn)
			if a.UFn[name] == nil {
				a.UFn[name] = &Procedure{}
			}
			if isAct(fn) {
				a.UFn[name].Requests++
				pendingU[fn] = true
			} else if pendingU[actOf(fn)] {
				a.UFn[name].Confirmed++
				pendingU[actOf(fn)] = false
			}
			continue
		}
		if d.ASDU == nil {
			continue
		}
		x := d.ASDU
		a.Types[x.Type]++
		a.Causes[x.Cause]++
		var ioa asdu.IOA
		if f := x.First(); f != nil {
			ioa = f.Address()
		}
		k := key{x.Type, x.CommonAddr, ioa}
		p := a.ASDU[x.Type]
		switch {
		case d.FromClient && (x.Cause == asdu.CauseActivation || x.Cause == asdu.CauseDeactivation || x.Cause == asdu.CauseRequest):
			if p == nil {
				p = &Procedure{}
				a.ASDU[x.Type] = p
			}
			p.Requests++
			pending[k]++
			delete(terminated, k)
		case !d.FromClient && p != nil:
			// Answers may carry the station's own common address to a
			// broadcast request.
			if pending[k] == 0 {
				for pk, n := range pending {
					if n > 0 && pk.t == k.t && pk.ioa == k.ioa {
						k = pk
						break
					}
				}
			}
			switch {
			case x.Cause == asdu.CauseActivationTerm:
				if !terminated[k] {
					p.Terminated++
					terminated[k] = true
				}
			case x.Negative || x.Cause.IsUnknown():
				if pending[k] > 0 {
					pending[k]--
				}
				p.Negative++
			case x.Cause == asdu.CauseActivationCon || x.Cause == asdu.CauseDeactivationCon || x.Cause == asdu.CauseRequest:
				if pending[k] > 0 {
					pending[k]--
					p.Confirmed++
				}
			default:
				a.unsolicited(x)
			}
		case !d.FromClient:
			a.unsolicited(x)
		}
	}
	for k, n := range pending {
		if p := a.ASDU[k.t]; p != nil {
			p.Unanswered += n
		}
	}
}

// unsolicited counts a monitor-direction ASDU no request asked for.
func (a *Analysis) unsolicited(x *asdu.ASDU) {
	if x.Cause >= asdu.CausePeriodic && x.Cause <= asdu.CauseInitialized {
		a.Unsolicited++
	}
}

func uName(fn apci.UFunction) string {
	switch fn {
	case apci.StartDTAct, apci.StartDTCon:
		return "STARTDT"
	case apci.StopDTAct, apci.StopDTCon:
		return "STOPDT"
	default:
		return "TESTFR"
	}
}

func isAct(fn apci.UFunction) bool {
	return fn == apci.StartDTAct || fn == apci.StopDTAct || fn == apci.TestFRAct
}

func actOf(fn apci.UFunction) apci.UFunction {
	switch fn {
	case apci.StartDTCon:
		return apci.StartDTAct
	case apci.StopDTCon:
		return apci.StopDTAct
	default:
		return apci.TestFRAct
	}
}

// Timing is the spread of one timer-relevant interval in a conversation.
type Timing struct {
	Count    int
	Min, Max time.Duration
}

// TypeList returns the ASDU types of the analysis in ascending order.
func (a *Analysis) TypeList() []asdu.TypeID {
	out := make([]asdu.TypeID, 0, len(a.Types))
	for t := range a.Types {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
