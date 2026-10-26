// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/asdu"
)

// appData is a single command, C_SC_NA_1, to protect.
var appData = []byte{45, 1, 6, 0, 0x34, 0x12, 1, 0, 0, 0x81}

// station is one end of a test association.
type station struct {
	e      *Endpoint
	events []Event
	data   [][]byte
	errs   []error
}

func (s *station) count(st Stat) uint32 { return s.e.Statistics()[st] }

func (s *station) lastErr() error {
	if len(s.errs) == 0 {
		return nil
	}
	return s.errs[len(s.errs)-1]
}

func (s *station) hasEvent(mnemonic string) bool {
	for _, e := range s.events {
		if e.Mnemonic == mnemonic {
			return true
		}
	}
	return false
}

type frame struct {
	from *station
	b    []byte
}

// pair is a controlling station a and a controlled station b on one
// connection, with a clock of their own.
type pair struct {
	t    *testing.T
	now  time.Time
	a, b *station
	q    []frame
	// drop, when set, loses the frames it reports.
	drop func(from *station, b []byte) bool
}

var (
	idA = mustIdentity(IdentityOptions{})
	idB = mustIdentity(IdentityOptions{})
)

func mustIdentity(o IdentityOptions) *Identity {
	id, err := NewIdentity(o)
	if err != nil {
		panic(err)
	}
	return id
}

// configs returns the default configuration of both stations.
func configs() (a, b Config) {
	s := Settings{ReplyTimeout: time.Second, RequestTimeout: 3 * time.Second}
	a = Config{Role: Controlling, AssociationID: 7, Identity: idA, Trust: idB.Pin(), Settings: s, CommonAddr: 0x1234}
	b = Config{Role: Controlled, AssociationID: 9, Identity: idB, Trust: idA.Pin(), Settings: s, CommonAddr: 0x1234}
	return a, b
}

func newPair(t *testing.T, mod func(a, b *Config)) *pair {
	t.Helper()
	ca, cb := configs()
	if mod != nil {
		mod(&ca, &cb)
	}
	p := &pair{t: t, now: time.Now(), a: &station{}, b: &station{}}
	p.a.e = p.endpoint(p.a, ca)
	p.b.e = p.endpoint(p.b, cb)
	return p
}

func (p *pair) endpoint(s *station, c Config) *Endpoint {
	p.t.Helper()
	c.OnEvent = func(e Event) { s.events = append(s.events, e) }
	e, err := New(c)
	if err != nil {
		p.t.Fatal(err)
	}
	return e
}

func (p *pair) other(s *station) *station {
	if s == p.a {
		return p.b
	}
	return p.a
}

func (p *pair) send(from *station, out [][]byte) {
	for _, b := range out {
		p.q = append(p.q, frame{from, b})
	}
}

// run delivers the queued frames and what they cause, until nothing is left.
func (p *pair) run() {
	for len(p.q) > 0 {
		f := p.q[0]
		p.q = p.q[1:]
		if p.drop != nil && p.drop(f.from, f.b) {
			continue
		}
		to := p.other(f.from)
		data, out, err := to.e.Receive(p.now, f.b)
		if data != nil {
			to.data = append(to.data, data)
		}
		if err != nil {
			to.errs = append(to.errs, err)
		}
		p.send(to, out)
	}
}

func (p *pair) up() {
	p.send(p.a, p.a.e.Up(p.now))
	p.send(p.b, p.b.e.Up(p.now))
	p.run()
}

// tick runs the timers of both stations at the current time.
func (p *pair) tick() {
	p.send(p.a, p.a.e.Tick(p.now))
	p.send(p.b, p.b.e.Tick(p.now))
	p.run()
}

// advance moves the clock forward by d, running every timer due on the way.
func (p *pair) advance(d time.Duration) {
	end := p.now.Add(d)
	for {
		p.run()
		next := end
		for _, s := range []*station{p.a, p.b} {
			if dl := s.e.Deadline(); !dl.IsZero() && dl.Before(next) {
				next = dl
			}
		}
		if next.After(p.now) {
			p.now = next
		}
		p.tick()
		if !p.now.Before(end) {
			return
		}
	}
}

// until advances the clock until cond holds, for at most limit.
func (p *pair) until(cond func() bool, limit time.Duration) bool {
	end := p.now.Add(limit)
	for p.run(); !cond(); p.run() {
		next := time.Time{}
		for _, s := range []*station{p.a, p.b} {
			if dl := s.e.Deadline(); !dl.IsZero() && (next.IsZero() || dl.Before(next)) {
				next = dl
			}
		}
		if next.IsZero() || next.After(end) {
			return false
		}
		if next.After(p.now) {
			p.now = next
		}
		p.tick()
	}
	return true
}

func (p *pair) ready() bool { return p.a.e.Ready() && p.b.e.Ready() }

func (p *pair) mustReady() {
	p.t.Helper()
	if !p.until(p.ready, time.Minute) {
		p.t.Fatalf("no session: controlling %+v (errs %v), controlled %+v (errs %v)",
			p.a.e.Status(), p.a.errs, p.b.e.Status(), p.b.errs)
	}
}

// exchange sends appData both ways and checks it arrives.
func (p *pair) exchange() {
	p.t.Helper()
	for _, s := range []*station{p.a, p.b} {
		to := p.other(s)
		n := len(to.data)
		out, err := s.e.Protect(p.now, appData)
		if err != nil {
			p.t.Fatalf("%s: protect: %v", s.e.Role(), err)
		}
		p.send(s, out)
		p.run()
		if len(to.data) != n+1 || !bytes.Equal(to.data[n], appData) {
			p.t.Fatalf("%s: received %x, errs %v", to.e.Role(), to.data, to.errs)
		}
	}
}

func TestAssociation(t *testing.T) {
	for _, dpa := range []uint8{HMACSHA256.Code, HMACSHA256Serial.Code, AES256GCM} {
		dp, _ := DataProtectionByCode(dpa)
		t.Run(dp.String(), func(t *testing.T) {
			p := newPair(t, func(a, b *Config) { a.DataProtection = dpa })
			p.up()
			p.mustReady()
			p.exchange()
			p.exchange()
			for _, s := range []*station{p.a, p.b} {
				st := s.e.Status()
				if !st.Up || !st.Associated || !st.Ready || st.AIM != 7 || st.AIS != 9 || st.MAC != HMACSHA256.Name || st.Data != dp.String() || st.Err != nil {
					t.Errorf("%s: status %+v", s.e.Role(), st)
				}
				if !bytes.Equal(st.Remote.Raw, p.other(s).e.cfg.Identity.Certificate.Raw) {
					t.Errorf("%s: remote certificate", s.e.Role())
				}
				if s.count(StatSuccessfulAssociations) != 1 || s.count(StatSuccessfulSessionKeyChanges) != 1 || s.count(StatSuccessfulDataAuthentications) != 2 {
					t.Errorf("%s: statistics %v", s.e.Role(), s.e.Statistics())
				}
				if !s.hasEvent("STAS_PROC_SUCC") || !s.hasEvent("SKEY_PROC_SUCC") || len(s.errs) != 0 {
					t.Errorf("%s: events %v, errs %v", s.e.Role(), s.events, s.errs)
				}
			}
			if p.a.e.Status().State != "idle" || p.b.e.Status().State != "session idle" {
				t.Errorf("states %q, %q", p.a.e.Status().State, p.b.e.Status().State)
			}
		})
	}
}

func TestSegmentedAssociation(t *testing.T) {
	small := asdu.Params{CauseSize: 2, CommonAddrSize: 2, IOASize: 3, MaxSize: 64}
	p := newPair(t, func(a, b *Config) { a.Params, b.Params = small, small })
	var segments int
	p.drop = func(_ *station, b []byte) bool {
		if !ParseASC(b[6]).FIN {
			segments++
		}
		return false
	}
	p.up()
	p.mustReady()
	p.exchange()
	if segments == 0 {
		t.Error("nothing segmented")
	}
}

func TestSecureDataRefusals(t *testing.T) {
	p := newPair(t, nil)
	if _, err := p.a.e.Protect(p.now, appData); !errors.Is(err, ErrNotReady) {
		t.Errorf("protect before the session: %v", err)
	}
	p.up()
	p.mustReady()

	out, _ := p.a.e.Protect(p.now, appData)
	bad := bytes.Clone(out[0])
	bad[len(bad)-1] ^= 1
	b := p.b
	receive := func(raw []byte) error {
		_, _, err := b.e.Receive(p.now, raw)
		return err
	}
	receiveWhole := func(whole []byte) error {
		_, err := deliver(b.e, p.now, wire(t, whole))
		return err
	}
	if err := receive(bad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("tampered: %v", err)
	}
	if err := receive(out[0]); err != nil {
		t.Errorf("genuine: %v", err)
	}
	if err := receive(out[0]); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed: %v", err)
	}
	if err := receive(appData); !errors.Is(err, ErrUnsecured) {
		t.Errorf("unsecured: %v", err)
	}
	if err := receive(appData[:3]); err == nil {
		t.Error("short ASDU accepted")
	}
	forge := func(sd SecureData, data []byte) []byte {
		w, err := protect(asdu.IEC104, Header{CommonAddr: 0x1234}, sd, data, p.a.e.dp, p.a.e.sess.control)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	if err := receiveWhole(forge(SecureData{AIM: 7, AIS: 8, Sequence: 50}, appData)); !errors.Is(err, ErrUnexpected) {
		t.Errorf("other association: %v", err)
	}
	if err := receiveWhole(forge(SecureData{AIM: 7, AIS: 9, Sequence: 0}, appData)); !errors.Is(err, ErrReplay) {
		t.Errorf("sequence 0: %v", err)
	}
	// A length that does not match the ASDU, under a valid MAC.
	h := Header{Type: asdu.S_SD_NA_1, Cause: asdu.CauseDataProtection, CommonAddr: 0x1234}
	in, _ := Encode(h, asdu.IEC104, SecureData{AIM: 7, AIS: 9, Sequence: 60, Payload: []byte{9, 0, 1, 2, 3}})
	if err := receiveWhole(append(in, p.a.e.dp.MAC.sum(p.a.e.sess.control, in)...)); !errors.Is(err, ErrMessage) {
		t.Errorf("wrong length: %v", err)
	}
	if b.count(StatDataAuthenticationErrors) != 1 || b.count(StatUnexpectedMessages) != 4 || !b.hasEvent("DATA_AUTN_ERR") {
		t.Errorf("statistics %v", b.e.Statistics())
	}
	if _, err := p.a.e.Protect(p.now, appData[:2]); err == nil {
		t.Error("protected a short ASDU")
	}
	if _, err := protect(asdu.IEC104, h, SecureData{}, nil, p.a.e.dp, p.a.e.sess.control); !errors.Is(err, ErrMessage) {
		t.Errorf("protected nothing: %v", err)
	}

	// Data is held back while the controlling station changes the keys.
	if err := p.a.e.Renew(); err != nil {
		t.Fatal(err)
	}
	sp, _ := deliver(b.e, p.now, p.a.e.Tick(p.now))
	kh, _ := deliver(p.a.e, p.now, sp)
	if _, err := p.a.e.Protect(p.now, appData); !errors.Is(err, ErrNotReady) {
		t.Errorf("protect during the change: %v", err)
	}
	p.send(p.a, kh)
	p.mustReady()
	p.exchange()
	if p.a.count(StatSuccessfulSessionKeyChanges) != 2 {
		t.Errorf("session key changes %d", p.a.count(StatSuccessfulSessionKeyChanges))
	}
}

func TestRetransmission(t *testing.T) {
	p := newPair(t, nil)
	// The first of every kind of request is lost.
	seen := map[byte]bool{}
	dropped := 0
	p.drop = func(from *station, b []byte) bool {
		if from != p.a || seen[b[0]] || b[0] == byte(asdu.S_SD_NA_1) {
			return false
		}
		seen[b[0]] = true
		dropped++
		return true
	}
	p.up()
	if p.ready() {
		t.Fatal("ready without the association request")
	}
	if dl := p.a.e.Deadline(); !dl.Equal(p.now.Add(time.Second)) {
		t.Errorf("deadline %v after now", dl.Sub(p.now))
	}
	p.mustReady()
	if dropped != 4 || p.a.count(StatReplyTimeouts) != uint32(dropped) {
		t.Errorf("dropped %d, reply timeouts %d", dropped, p.a.count(StatReplyTimeouts))
	}
	p.exchange()
}

func TestProcedureFailure(t *testing.T) {
	p := newPair(t, nil)
	lost := true
	p.drop = func(from *station, _ []byte) bool { return lost && from == p.a }
	p.up()
	p.advance(3 * time.Second)
	if err := p.a.e.Err(); !errors.Is(err, ErrProcedure) {
		t.Fatalf("err %v", err)
	}
	if p.a.count(StatMaxReplyTimeouts) != 1 || p.a.count(StatAssociationFailures) != 1 || !p.a.hasEvent("STAS_PROC_FAIL") {
		t.Errorf("statistics %v", p.a.e.Statistics())
	}
	if dl := p.a.e.Deadline(); !dl.Equal(p.now.Add(time.Second)) {
		t.Errorf("first retry after %v", dl.Sub(p.now))
	}
	p.advance(4 * time.Second) // the retry fails as well
	if dl := p.a.e.Deadline(); !dl.Equal(p.now.Add(2 * time.Second)) {
		t.Errorf("second retry after %v", dl.Sub(p.now))
	}
	if st := p.a.e.Status(); st.Err == nil || st.Ready {
		t.Errorf("status %+v", st)
	}
	lost = false
	p.mustReady()
	if p.a.e.Err() != nil {
		t.Errorf("err after success: %v", p.a.e.Err())
	}

	// A Session Key Change that fails makes the next attempt a Station
	// Association.
	lost = true
	if err := p.a.e.Renew(); err != nil {
		t.Fatal(err)
	}
	p.advance(4 * time.Second)
	if p.a.count(StatSessionKeyChangeFailures) != 1 {
		t.Fatalf("session key change failures %d", p.a.count(StatSessionKeyChangeFailures))
	}
	var first byte
	p.drop = func(from *station, b []byte) bool {
		if first == 0 && from == p.a {
			first = b[0]
		}
		return false
	}
	if !p.until(func() bool { return p.a.count(StatSuccessfulAssociations) == 2 && p.ready() }, time.Minute) {
		t.Fatal("no new association")
	}
	if first != byte(asdu.S_AQ_NA_1) || p.a.count(StatSuccessfulAssociations) != 2 {
		t.Errorf("retried with type %d, associations %d", first, p.a.count(StatSuccessfulAssociations))
	}
}

func TestConnectionLoss(t *testing.T) {
	p := newPair(t, nil)
	p.send(p.a, p.a.e.Up(p.now))
	p.b.e.Up(p.now)
	var aq [][]byte
	for _, f := range p.q {
		aq = append(aq, f.b)
	}
	p.q = nil
	ap, _ := deliver(p.b.e, p.now, aq)
	if len(ap) != 2 || p.b.e.Status().State != "wait for update key change request" {
		t.Fatalf("answer %d frames, state %q", len(ap), p.b.e.Status().State)
	}
	p.a.e.Down()
	p.b.e.Down()
	p.a.e.Down() // again: nothing
	if p.a.count(StatAssociationFailures) != 1 || p.b.count(StatAssociationFailures) != 1 {
		t.Errorf("failures %d, %d", p.a.count(StatAssociationFailures), p.b.count(StatAssociationFailures))
	}
	if !p.a.e.Deadline().IsZero() || p.a.e.Tick(p.now) != nil || p.b.e.Tick(p.now) != nil {
		t.Error("timers run while down")
	}
	p.up()
	p.mustReady()

	// Lost during the Session Key Change.
	_ = p.a.e.Renew()
	p.send(p.a, p.a.e.Tick(p.now))
	p.q = nil
	p.a.e.Down()
	if p.a.count(StatSessionKeyChangeFailures) != 1 {
		t.Errorf("session key change failures %d", p.a.count(StatSessionKeyChangeFailures))
	}
	p.up()
	p.mustReady()
	// The controlled station lost while waiting for the key change request.
	_ = p.a.e.Renew()
	p.send(p.a, p.a.e.Tick(p.now))
	f := p.q[0]
	p.q = nil
	_, _, _ = p.b.e.Receive(p.now, f.b)
	p.b.e.Down()
	if p.b.count(StatSessionKeyChangeFailures) != 1 {
		t.Errorf("controlled session key change failures %d", p.b.count(StatSessionKeyChangeFailures))
	}
}

// step delivers one frame by hand and returns what the receiver sends.
func step(t *testing.T, to *Endpoint, now time.Time, frames [][]byte) [][]byte {
	t.Helper()
	var all [][]byte
	for _, f := range frames {
		_, out, err := to.Receive(now, f)
		if err != nil {
			t.Fatalf("%s: %v", to.Role(), err)
		}
		all = append(all, out...)
	}
	return all
}

// wire is a whole message as its segments.
func wire(t *testing.T, whole []byte) [][]byte {
	t.Helper()
	segs, _, err := Segment(whole, asdu.IEC104, 249, 0)
	if err != nil {
		t.Fatal(err)
	}
	return segs
}

// unwire is the whole message of a single segment.
func unwire(seg []byte) []byte { return append(bytes.Clone(seg[:6]), seg[7:]...) }

// same compares two series of segments without their ASC sequence numbers.
func same(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(unwire(a[i]), unwire(b[i])) {
			return false
		}
	}
	return true
}

// deliver passes a series of segments to e and returns the first error and
// everything it sends.
func deliver(e *Endpoint, now time.Time, frames [][]byte) (out [][]byte, err error) {
	for _, f := range frames {
		_, o, ferr := e.Receive(now, f)
		out = append(out, o...)
		if err == nil {
			err = ferr
		}
	}
	return out, err
}

func TestDuplicates(t *testing.T) {
	p := newPair(t, nil)
	a, b, now := p.a.e, p.b.e, p.now
	b.Up(now)
	aq := a.Up(now)
	ap := step(t, b, now, aq)
	if again := step(t, b, now, aq); !same(again, ap) {
		t.Error("association response not repeated")
	}
	uh := step(t, a, now, ap)
	if _, err := deliver(a, now, ap); !errors.Is(err, ErrUnexpected) {
		t.Errorf("association response again: %v", err)
	}
	up := step(t, b, now, uh)
	if again := step(t, b, now, uh); !same(again, up) {
		t.Error("update key change response not repeated")
	}
	sq := step(t, a, now, up)
	sp := step(t, b, now, sq)
	if again := step(t, b, now, sq); len(again) != 1 || !bytes.Equal(unwire(again[0])[:len(sp[0])-17], unwire(sp[0])[:len(sp[0])-17]) {
		t.Error("session response repeated with other random data")
	}
	kh := step(t, a, now, sp)
	kp := step(t, b, now, kh)
	if again := step(t, b, now, kh); !same(again, kp) {
		t.Error("session key change response not repeated")
	}
	if out := step(t, a, now, kp); out != nil || !a.Ready() || !b.Ready() {
		t.Fatal("no session")
	}
	if _, err := deliver(a, now, kp); !errors.Is(err, ErrUnexpected) {
		t.Errorf("session key change response again: %v", err)
	}
	if _, err := deliver(a, now, up); !errors.Is(err, ErrUnexpected) {
		t.Errorf("update key change response again: %v", err)
	}
	if _, err := deliver(a, now, sp); !errors.Is(err, ErrUnexpected) {
		t.Errorf("session response again: %v", err)
	}
	// After the request timeout the repeated requests are unexpected.
	now = now.Add(4 * time.Second)
	b.Tick(now)
	for _, f := range [][][]byte{uh, kh} {
		if _, err := deliver(b, now, f); !errors.Is(err, ErrUnexpected) {
			t.Errorf("type %d after the timeout: %v", f[0][0], err)
		}
	}
	// A message of the wrong direction.
	if _, err := deliver(a, now, aq); !errors.Is(err, ErrMessage) {
		t.Errorf("association request at the controlling station: %v", err)
	}
}

func TestControlledRequestTimeouts(t *testing.T) {
	p := newPair(t, nil)
	a, b, now := p.a.e, p.b.e, p.now
	b.Up(now)
	aq := a.Up(now)
	step(t, b, now, aq)
	if dl := b.Deadline(); !dl.Equal(now.Add(3 * time.Second)) {
		t.Errorf("deadline %v", dl.Sub(now))
	}
	b.Tick(now.Add(3 * time.Second))
	if p.b.count(StatRequestTimeouts) != 1 || p.b.count(StatAssociationFailures) != 1 {
		t.Errorf("statistics %v", b.Statistics())
	}
	// Session requests without an association.
	sq, _ := Encode(Header{Cause: asdu.CauseSessionKey, CommonAddr: 1}, asdu.IEC104, SessionRequest{AIM: 7, AIS: 9, Protocol: Version1, Random: seq(32, 0)})
	kh, _ := Encode(Header{Cause: asdu.CauseSessionKey, CommonAddr: 1}, asdu.IEC104, SessionKeyChangeRequest{AIM: 7, AIS: 9, DataProtection: 4, Wrapped: seq(72, 0), Tag: seq(16, 0)})
	uh, _ := Encode(Header{Cause: asdu.CauseAssociation, CommonAddr: 1}, asdu.IEC104, UpdateKeyChangeRequest{AIM: 7, AIS: 9, KeyWrap: 2, MAC: 4, Random: seq(32, 0), Tag: seq(16, 0)})
	for _, f := range [][]byte{sq, kh, uh} {
		if _, err := deliver(b, now, wire(t, f)); !errors.Is(err, ErrUnexpected) {
			t.Errorf("type %d without an association: %v", f[0], err)
		}
	}

	// The Session Key Change times out after the session response.
	p = newPair(t, nil)
	p.up()
	p.mustReady()
	_ = p.a.e.Renew()
	p.drop = func(from *station, b []byte) bool { return from == p.a && b[0] == byte(asdu.S_KH_NA_1) }
	p.tick()
	p.now = p.now.Add(3 * time.Second)
	p.send(p.b, p.b.e.Tick(p.now))
	if p.b.count(StatSessionKeyChangeFailures) != 1 || p.b.count(StatRequestTimeouts) != 1 {
		t.Errorf("controlled statistics %v", p.b.e.Statistics())
	}
}

func TestControlledRefusals(t *testing.T) {
	p := newPair(t, nil)
	p.up()
	p.mustReady()
	b, now := p.b.e, p.now
	hdr := func(c asdu.Cause) Header { return Header{Cause: c, CommonAddr: 0x1234} }
	enc := func(c asdu.Cause, m Message) []byte {
		w, err := Encode(hdr(c), asdu.IEC104, m)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	cases := []struct {
		name string
		b    []byte
		err  error
		stat Stat
	}{
		{"version 2 association", enc(asdu.CauseAssociation, AssociationRequest{AIM: 7, Protocol: ProtocolInfo{Major: 2}, Certificate: idA.Certificate.Raw}), ErrMessage, StatProtocolInformationErrors},
		{"version 2 session", enc(asdu.CauseSessionKey, SessionRequest{AIM: 7, AIS: 9, Protocol: ProtocolInfo{Major: 2}, Random: seq(32, 0)}), ErrMessage, StatProtocolInformationErrors},
		{"broadcast session", enc(asdu.CauseSessionKey, SessionRequest{AIM: 7, AIS: 9, Protocol: ProtocolInfo{Major: 1, Broadcast: true}, Random: seq(32, 0)}), ErrMessage, StatProtocolInformationErrors},
		{"other association", enc(asdu.CauseSessionKey, SessionRequest{AIM: 8, AIS: 9, Protocol: Version1, Random: seq(32, 0)}), ErrUnexpected, StatUnexpectedMessages},
		{"short random", enc(asdu.CauseSessionKey, SessionRequest{AIM: 7, AIS: 9, Protocol: Version1, Random: seq(2, 0)}), ErrMessage, StatUnexpectedMessages},
		{"no certificate", enc(asdu.CauseAssociation, AssociationRequest{AIM: 7, Protocol: Version1}), ErrCertificate, StatRemoteCertificateFailures},
		{"garbage certificate", enc(asdu.CauseAssociation, AssociationRequest{AIM: 7, Protocol: Version1, Certificate: []byte{1, 2, 3}}), ErrCertificate, StatRemoteCertificateFailures},
	}
	for _, c := range cases {
		before := p.b.count(c.stat)
		if _, err := deliver(b, now, wire(t, c.b)); !errors.Is(err, c.err) {
			t.Errorf("%s: %v", c.name, err)
		}
		if p.b.count(c.stat) != before+1 {
			t.Errorf("%s: %s not counted", c.name, c.stat)
		}
	}
	// A Session Key Change Request whose MAC does not verify, and one whose
	// keys do not unwrap.
	_ = p.a.e.Renew()
	sq := p.a.e.Tick(now)
	sp := step(t, b, now, sq)
	kh := step(t, p.a.e, now, sp)
	bad := bytes.Clone(kh[0])
	bad[len(bad)-1] ^= 1
	if _, _, err := b.Receive(now, bad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("tampered key change request: %v", err)
	}
	var v SessionKeyChangeRequest
	_, m, _ := Decode(unwire(kh[0]), asdu.IEC104, Control)
	v = m.(SessionKeyChangeRequest)
	v.Wrapped = seq(72, 0)
	v.Tag = nil
	in, _ := encode(hdr(asdu.CauseSessionKey), asdu.IEC104, v, false)
	v.Tag = b.mal.sum(b.keys.auth, b.spRandom, in)
	if _, err := deliver(b, now, wire(t, enc(asdu.CauseSessionKey, v))); !errors.Is(err, ErrAuthentication) {
		t.Errorf("unwrappable keys: %v", err)
	}
	if p.b.count(StatKeyAuthenticationErrors) != 2 || !p.b.hasEvent("KEY_AUTN_ERR") {
		t.Errorf("key authentication errors %d", p.b.count(StatKeyAuthenticationErrors))
	}
	// The genuine one still completes the change.
	kp := step(t, b, now, kh)
	step(t, p.a.e, now, kp)
	if !p.ready() {
		t.Error("no session after the refusals")
	}
	// A tampered session response at the controlling station.
	_ = p.a.e.Renew()
	sp = step(t, b, now, p.a.e.Tick(now))
	bad = bytes.Clone(sp[0])
	bad[len(bad)-1] ^= 1
	if _, _, err := p.a.e.Receive(now, bad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("tampered session response: %v", err)
	}
}

func TestSessionInitiation(t *testing.T) {
	// The controlled station's keys wear out: it asks for new ones.
	p := newPair(t, func(_, b *Config) { b.Settings.KeyUses = 2 })
	p.up()
	p.mustReady()
	p.exchange()
	p.now = p.now.Add(2 * time.Second)
	p.tick()
	if p.b.count(StatKeyInvalidationsCount) != 1 || !p.b.hasEvent("SKEY_INV_USECNT") {
		t.Fatalf("controlled statistics %v", p.b.e.Statistics())
	}
	p.mustReady()
	p.exchange()
	if p.a.count(StatSuccessfulSessionKeyChanges) != 2 {
		t.Errorf("session key changes %d", p.a.count(StatSuccessfulSessionKeyChanges))
	}

	// Expired by time.
	p = newPair(t, func(_, b *Config) { b.Settings.KeyLifetime = time.Minute })
	p.up()
	p.mustReady()
	p.now = p.now.Add(time.Minute)
	if _, err := p.b.e.Protect(p.now, appData); !errors.Is(err, ErrNotReady) {
		t.Errorf("protect with expired keys: %v", err)
	}
	p.tick()
	if p.b.count(StatKeyInvalidationsTime) != 1 {
		t.Fatalf("controlled statistics %v", p.b.e.Statistics())
	}
	p.mustReady()
	p.exchange()
}

func TestRestartCrossing(t *testing.T) {
	sa, sb := &MemoryStore{}, &MemoryStore{}
	p := newPair(t, func(a, b *Config) { a.Store, b.Store = sa, sb })
	p.up()
	p.mustReady()

	// Both restart: the association is kept, the session is not.
	q := newPair(t, func(a, b *Config) { a.Store, b.Store = sa, sb })
	if st := q.a.e.Status(); !st.Associated || st.Ready || st.Remote == nil {
		t.Fatalf("restored %+v", st)
	}
	sq := q.a.e.Up(q.now)
	if len(sq) != 1 || sq[0][0] != byte(asdu.S_SQ_NA_1) {
		t.Fatalf("first message %x", sq)
	}
	q.b.e.Up(q.now)
	if dl := q.b.e.Deadline(); !dl.Equal(q.now.Add(time.Second)) {
		t.Errorf("initiation after %v", dl.Sub(q.now))
	}
	q.now = q.now.Add(time.Second)
	si := q.b.e.Tick(q.now)
	if len(si) != 1 || si[0][0] != byte(asdu.S_SI_NA_1) {
		t.Fatalf("initiation %x", si)
	}
	bad := bytes.Clone(si[0])
	bad[len(bad)-1] ^= 1
	if _, _, err := q.a.e.Receive(q.now, bad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("tampered initiation: %v", err)
	}
	// The initiation request crosses the session request.
	q.send(q.b, si)
	q.send(q.a, sq)
	q.mustReady()
	q.exchange()

	// The controlling station keeps running; the controlled one restarts
	// and asks before the controlling station's request.
	r := &pair{t: t, now: q.now, a: q.a, b: &station{}}
	_, cb := configs()
	cb.Store = sb
	r.b.e = r.endpoint(r.b, cb)
	r.a.e.Down()
	r.b.e.Up(r.now)
	r.now = r.now.Add(time.Second)
	r.send(r.b, r.b.e.Tick(r.now))
	r.run() // the controlling station is not up: nothing happens
	r.send(r.a, r.a.e.Up(r.now))
	r.mustReady()
	r.exchange()

}

func TestCertificates(t *testing.T) {
	name := func(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
	ca := mustIdentity(IdentityOptions{CA: true, Subject: name("CA")})
	other := mustIdentity(IdentityOptions{CA: true, Subject: name("other CA")})
	x := func(cn string) *Identity {
		return mustIdentity(IdentityOptions{Curve: X25519, Issuer: ca, Subject: name(cn)})
	}
	xa, xb := x("controlling"), x("controlled")
	expired := mustIdentity(IdentityOptions{NotBefore: time.Now().AddDate(-2, 0, 0), NotAfter: time.Now().AddDate(-1, 0, 0)})
	authorities := Trust{Authorities: []*x509.Certificate{ca.Certificate}}
	// forged carries a broken signature of the authority.
	forged := &Identity{Key: xa.Key}
	der := bytes.Clone(xa.Certificate.Raw)
	der[len(der)-1] ^= 1
	forged.Certificate, _ = x509.ParseCertificate(der)

	type check func(p *pair) bool
	refusedBy := func(s func(p *pair) *station, stat Stat) check {
		return func(p *pair) bool { return s(p).count(stat) > 0 && !p.ready() }
	}
	ctl := func(p *pair) *station { return p.b }
	cng := func(p *pair) *station { return p.a }
	ok := func(p *pair) bool { return p.ready() }
	cases := []struct {
		name  string
		mod   func(a, b *Config)
		check check
	}{
		{"untrusted", func(_, b *Config) { b.Trust = Trust{} }, refusedBy(ctl, StatRemoteAuthorizationFailures)},
		{"untrusted response", func(a, _ *Config) { a.Trust = Trust{} }, refusedBy(cng, StatRemoteAuthorizationFailures)},
		{"public key", func(a, b *Config) {
			b.Trust = Trust{PublicKeys: [][]byte{subjectPublicKey(idA.Certificate)}}
		}, ok},
		{"expired", func(a, b *Config) { a.Identity, b.Trust = expired, expired.Pin(); a.IgnoreValidity = true }, refusedBy(ctl, StatRemoteCertificateFailures)},
		{"expired ignored", func(a, b *Config) {
			a.Identity, b.Trust = expired, expired.Pin()
			a.IgnoreValidity, b.IgnoreValidity = true, true
		}, ok},
		{"own expired", func(a, b *Config) { a.Identity, b.Trust = expired, expired.Pin() }, refusedBy(cng, StatLocalCertificateExpirations)},
		{"X25519", func(a, b *Config) { a.Identity, b.Identity, a.Trust, b.Trust = xa, xb, authorities, authorities }, ok},
		{"curves differ", func(a, b *Config) { a.Identity, b.Trust = xa, authorities }, refusedBy(ctl, StatRemoteCertificateFailures)},
		{"other authority", func(a, b *Config) {
			a.Identity, b.Identity, a.Trust, b.Trust = xa, xb, authorities, Trust{Authorities: []*x509.Certificate{other.Certificate}}
		}, refusedBy(ctl, StatRemoteAuthorizationFailures)},
		{"subject not listed", func(a, b *Config) {
			a.Identity, b.Identity, a.Trust = xa, xb, authorities
			b.Trust = Trust{Authorities: authorities.Authorities, Subjects: [][]byte{other.Certificate.RawSubject}}
		}, refusedBy(ctl, StatRemoteAuthorizationFailures)},
		{"subject listed", func(a, b *Config) {
			a.Identity, b.Identity, a.Trust = xa, xb, authorities
			b.Trust = Trust{Authorities: authorities.Authorities, Subjects: [][]byte{xa.Certificate.RawSubject}}
		}, ok},
		{"bad signature", func(a, b *Config) {
			a.Identity, b.Identity, a.Trust = forged, xb, authorities
			b.Trust = authorities
		}, refusedBy(ctl, StatRemoteCertificateFailures)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPair(t, c.mod)
			p.up()
			p.until(func() bool { return c.check(p) }, 10*time.Second)
			if !c.check(p) {
				t.Errorf("controlling %+v %v %v, controlled %+v %v %v", p.a.e.Status(), p.a.errs, p.a.e.Statistics(),
					p.b.e.Status(), p.b.errs, p.b.e.Statistics())
			}
		})
	}
}

func TestAlgorithms(t *testing.T) {
	cases := []struct {
		name string
		mod  func(a, b *Config)
		stat Stat
	}{
		{"MAC not accepted", func(a, b *Config) { b.AcceptMAC = []uint8{HMACSHA256Serial.Code} }, StatKeyAuthAlgorithmFailures},
		{"data protection not accepted", func(a, b *Config) {
			a.DataProtection, b.AcceptDataProtection = AES256GCM, []uint8{HMACSHA256.Code}
		}, StatDataProtectionAlgorithmFailures},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPair(t, c.mod)
			p.up()
			p.advance(5 * time.Second)
			if p.ready() || p.b.count(c.stat) == 0 || !errors.Is(p.b.lastErr(), ErrAlgorithm) {
				t.Errorf("ready %v, %s %d, err %v", p.ready(), c.stat, p.b.count(c.stat), p.b.lastErr())
			}
		})
	}
	p := newPair(t, func(a, b *Config) {
		a.MAC, b.AcceptMAC = HMACSHA256Serial.Code, []uint8{HMACSHA256Serial.Code}
	})
	p.up()
	p.mustReady()
	p.exchange()
	if p.b.e.Status().MAC != HMACSHA256Serial.Name {
		t.Errorf("MAC %q", p.b.e.Status().MAC)
	}
}

// A controlling station that keeps its session keys over a reconnect, as
// github.com/cB-Sigma/iec60870 does: the controlled station accepts its data
// under them, holds its own and asks for new keys.
func TestControlledReconnect(t *testing.T) {
	p := newPair(t, nil)
	p.up()
	p.mustReady()
	p.exchange()
	p.b.e.Down()
	p.b.e.Up(p.now)
	if p.b.e.Ready() {
		t.Fatal("controlled station ready with the keys of the earlier connection")
	}
	if _, err := p.b.e.Protect(p.now, appData); !errors.Is(err, ErrNotReady) {
		t.Errorf("protect: %v", err)
	}
	out, err := p.a.e.Protect(p.now, appData)
	if err != nil {
		t.Fatal(err)
	}
	if data, _, err := p.b.e.Receive(p.now, out[0]); err != nil || !bytes.Equal(data, appData) {
		t.Errorf("data under the earlier keys: %x, %v", data, err)
	}
	// Replays of the earlier connection are still refused.
	if _, _, err := p.b.e.Receive(p.now, out[0]); !errors.Is(err, ErrReplay) {
		t.Errorf("replay: %v", err)
	}
	if dl := p.b.e.Deadline(); !dl.Equal(p.now.Add(time.Second)) {
		t.Errorf("initiation after %v", dl.Sub(p.now))
	}
	p.mustReady()
	p.exchange()
	if p.a.count(StatSuccessfulSessionKeyChanges) != 2 {
		t.Errorf("session key changes %d", p.a.count(StatSuccessfulSessionKeyChanges))
	}
}
