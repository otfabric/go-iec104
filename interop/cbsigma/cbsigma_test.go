// SPDX-License-Identifier: MIT

package cbsigma

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	cb "github.com/cB-Sigma/iec60870/sec"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/sec"
)

// seq returns n octets b, b+1, ...
func seq(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b + byte(i)
	}
	return out
}

// Every message, encoded by both from the same field values, and decoded by
// go-iec104 from what cB-Sigma encoded.
func TestEncodings(t *testing.T) {
	pairs := []struct {
		dir    sec.Direction
		ours   sec.Message
		theirs cb.Message
	}{
		{sec.Control, sec.AssociationRequest{AIM: 7, Protocol: sec.Version1, Certificate: seq(300, 0)},
			cb.AssociationRequest{AIM: 7, PRI: cb.ConformingPRI, CertData: seq(300, 0)}},
		{sec.Monitor, sec.AssociationResponse{AIM: 7, AIS: 9, Certificate: seq(3, 0xc0), Random: seq(32, 0x10)},
			cb.AssociationResponse{AIM: 7, AIS: 9, CertData: seq(3, 0xc0), Random: seq(32, 0x10)}},
		{sec.Control, sec.UpdateKeyChangeRequest{AIM: 7, AIS: 9, KeyWrap: 2, MAC: 3, Random: seq(32, 0x20), Tag: seq(8, 0x80)},
			cb.UpdateKeyChangeRequest{AIM: 7, AIS: 9, KWA: 2, MAL: 3, Random: seq(32, 0x20), MAC: seq(8, 0x80)}},
		{sec.Monitor, sec.UpdateKeyChangeResponse{AIM: 7, AIS: 9, Tag: seq(16, 0x80)},
			cb.UpdateKeyChangeResponse{AIM: 7, AIS: 9, MAC: seq(16, 0x80)}},
		{sec.Monitor, sec.SessionInitiationRequest{AIM: 7, AIS: 9, Random: seq(64, 0x30), Tag: seq(16, 0x80)},
			cb.SessionInitiationRequest{AIM: 7, AIS: 9, Random: seq(64, 0x30), MAC: seq(16, 0x80)}},
		{sec.Control, sec.SessionRequest{AIM: 7, AIS: 9, Protocol: sec.Version1, Random: seq(4, 0x40)},
			cb.SessionRequest{AIM: 7, AIS: 9, PRI: cb.ConformingPRI, Random: seq(4, 0x40)}},
		{sec.Monitor, sec.SessionResponse{AIM: 7, AIS: 9, Random: seq(32, 0x50), Tag: seq(16, 0x80)},
			cb.SessionResponse{AIM: 7, AIS: 9, Random: seq(32, 0x50), MAC: seq(16, 0x80)}},
		{sec.Control, sec.SessionKeyChangeRequest{AIM: 7, AIS: 9, DataProtection: 11, Wrapped: seq(72, 0x60), Tag: seq(16, 0x80)},
			cb.SessionKeyChangeRequest{AIM: 7, AIS: 9, DPA: 11, Wrapped: seq(72, 0x60), MAC: seq(16, 0x80)}},
		{sec.Monitor, sec.SessionKeyChangeResponse{AIM: 7, AIS: 9, Tag: seq(16, 0x80)},
			cb.SessionKeyChangeResponse{AIM: 7, AIS: 9, MAC: seq(16, 0x80)}},
		{sec.Monitor, sec.SecureData{AIM: 7, AIS: 9, Sequence: 0x01020304, Payload: seq(40, 0x70)},
			cb.SecureData{AIM: 7, AIS: 9, DSQ: 0x01020304, Rest: seq(40, 0x70)}},
	}
	for _, p := range pairs {
		cause, _ := sec.PermittedCause(p.ours.Type(), p.dir)
		ours, err := sec.Encode(sec.Header{Cause: cause, Originator: 5, CommonAddr: 0x1234}, asdu.IEC104, p.ours)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := cb.Encode(cb.DUI{Cause: uint8(cause), Originator: 5, CA: 0x1234}, cb.Params104, p.theirs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ours, theirs) {
			t.Errorf("%s:\n ours   %x\n theirs %x", p.ours.Type(), ours, theirs)
		}
		if _, _, err := sec.Decode(theirs, asdu.IEC104, p.dir); err != nil {
			t.Errorf("%s: decoding theirs: %v", p.ours.Type(), err)
		}
		// Segmented alike.
		mine, _, err1 := sec.Segment(ours, asdu.IEC104, 249, 5)
		their, _, err2 := cb.Segment(theirs, cb.Params104, 249, 5)
		if err1 != nil || err2 != nil || fmt.Sprintf("%x", mine) != fmt.Sprintf("%x", their) {
			t.Errorf("%s: segments differ: %v %v", p.ours.Type(), err1, err2)
		}
	}
}

// pair runs one go-iec104 endpoint against one cB-Sigma endpoint.
type pair struct {
	t      *testing.T
	ours   *sec.Endpoint
	theirs *cb.Endpoint
	now    time.Time
	toOurs [][]byte // application data delivered to ours
	toThem [][]byte
}

// pump delivers out, from ours, to theirs and what follows both ways, until
// both are quiet.
func (p *pair) pump(out [][]byte) {
	p.t.Helper()
	for range 100 {
		for _, f := range out {
			in, err := p.theirs.Receive(f)
			if err != nil {
				p.t.Errorf("cB-Sigma: %v", err)
			}
			if in.Kind == cb.Data {
				p.toThem = append(p.toThem, in.ASDU)
			}
		}
		back := p.theirs.Outbox()
		out = nil
		for _, f := range back {
			d, o, err := p.ours.Receive(p.now, f)
			if err != nil {
				p.t.Errorf("go-iec104: %v", err)
			}
			if d != nil {
				p.toOurs = append(p.toOurs, d)
			}
			out = append(out, o...)
		}
		if len(out) == 0 && len(back) == 0 {
			return
		}
	}
	p.t.Fatal("no end to the exchange")
}

func (p *pair) ready() bool { return p.ours.Ready() && p.theirs.KeysValid() }

func (p *pair) mustReady(what string) {
	p.t.Helper()
	if !p.ready() {
		p.t.Fatalf("%s: go-iec104 %+v, cB-Sigma %+v", what, p.ours.Status(), p.theirs.Status())
	}
}

// exchange sends application data of n objects both ways.
func (p *pair) exchange(n int) {
	p.t.Helper()
	a := measurements(len(p.toThem), n)
	segs, err := p.ours.Protect(p.now, a)
	if err != nil {
		p.t.Fatal(err)
	}
	p.pump(segs)
	if len(p.toThem) == 0 || !bytes.Equal(p.toThem[len(p.toThem)-1], a) {
		p.t.Fatalf("to cB-Sigma: %d ASDUs", len(p.toThem))
	}
	segs, err = p.theirs.Wrap(a)
	if err != nil {
		p.t.Fatal(err)
	}
	n0 := len(p.toOurs)
	for _, s := range segs {
		d, out, err := p.ours.Receive(p.now, s)
		if err != nil {
			p.t.Fatal(err)
		}
		if d != nil {
			p.toOurs = append(p.toOurs, d)
		}
		p.pump(out)
	}
	if len(p.toOurs) != n0+1 || !bytes.Equal(p.toOurs[n0], a) {
		p.t.Fatalf("to go-iec104: %d ASDUs", len(p.toOurs)-n0)
	}
}

// measurements is an M_ME_NC_1 ASDU with n objects, segmented above 30.
func measurements(tag, n int) []byte {
	b := []byte{13, byte(n), 3, 0, 1, 0}
	for k := range n {
		b = append(b, byte(tag), byte(k), 0, 1, 2, 3, 4, 0)
	}
	return b
}

type side struct {
	ours   *sec.Identity
	theirs cb.Identity
}

func identities(t *testing.T) side {
	t.Helper()
	ours, err := sec.NewIdentity(sec.IdentityOptions{Subject: pkix.Name{CommonName: "go-iec104"}})
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := cb.NewIdentity(cb.Secp256r1, "cB-Sigma", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return side{ours, theirs}
}

func (s side) oursConfig(t *testing.T, role sec.Role) sec.Config {
	t.Helper()
	c, err := x509.ParseCertificate(s.theirs.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	return sec.Config{Role: role, AssociationID: 7, Identity: s.ours, CommonAddr: 1,
		Trust: sec.Trust{Fingerprints: [][32]byte{sec.Fingerprint(c)}}}
}

func (s side) theirsConfig(controlling bool) cb.Config {
	c := cb.Config{Controlling: controlling, Link: cb.TCP, Params: cb.Params104, MaxASDU: 249, CA: 1,
		Key: s.theirs.Key, Certificate: s.theirs.Certificate,
		Trust: cb.Trust{Fingerprints: [][32]byte{sec.Fingerprint(s.ours.Certificate)}}}
	if controlling {
		c.AIM = 9
	} else {
		c.AIS = 9
	}
	return c
}

func newPair(t *testing.T, s side, oc sec.Config, tc cb.Config) *pair {
	t.Helper()
	ours, err := sec.New(oc)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := cb.NewEndpoint(tc)
	if err != nil {
		t.Fatal(err)
	}
	return &pair{t: t, ours: ours, theirs: theirs, now: time.Now()}
}

// Complete associations in both roles with every data protection algorithm
// both implement, data both ways, short and segmented, and a renewal by the
// controlling station.
func TestAssociation(t *testing.T) {
	for _, controlling := range []bool{true, false} {
		for _, dpa := range []uint8{4, 3, 8, 11} {
			name := fmt.Sprintf("go-iec104 %s/DPA %d", map[bool]string{true: "controlling", false: "controlled"}[controlling], dpa)
			t.Run(name, func(t *testing.T) {
				s := identities(t)
				role := sec.Controlled
				if controlling {
					role = sec.Controlling
				}
				oc := s.oursConfig(t, role)
				oc.DataProtection = dpa
				tc := s.theirsConfig(!controlling)
				tc.DPA = dpa
				p := newPair(t, s, oc, tc)
				p.theirs.LinkUp()
				out := p.ours.Up(p.now)
				p.pump(out)
				p.mustReady("association")
				for _, n := range []int{1, 20, 30} {
					p.exchange(n)
				}
				if controlling {
					if err := p.ours.Renew(); err != nil {
						t.Fatal(err)
					}
					p.pump(p.ours.Tick(p.now))
				} else {
					if err := p.theirs.StartSessionKeyChange(); err != nil {
						t.Fatal(err)
					}
					p.pump(nil)
				}
				p.mustReady("renewal")
				p.exchange(3)
				st := p.ours.Statistics()
				if st[sec.StatSuccessfulAssociations] != 1 || st[sec.StatSuccessfulSessionKeyChanges] != 2 || st[sec.StatDiscardedMessages] != 0 {
					t.Errorf("statistics %v", st)
				}
			})
		}
	}
}

// cB-Sigma, controlled, restarts with its association kept: its Session
// Initiation Request crosses the Session Request of go-iec104.
func TestCrossingInitiation(t *testing.T) {
	s := identities(t)
	store := &cb.MemoryKeyStore{}
	mk := func() *cb.Endpoint {
		tc := s.theirsConfig(false)
		tc.Store = store
		e, err := cb.NewEndpoint(tc)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Start(); err != nil {
			t.Fatal(err)
		}
		return e
	}
	ours, err := sec.New(s.oursConfig(t, sec.Controlling))
	if err != nil {
		t.Fatal(err)
	}
	p := &pair{t: t, ours: ours, theirs: mk(), now: time.Now()}
	p.theirs.LinkUp()
	p.pump(p.ours.Up(p.now))
	p.mustReady("association")

	p.ours.Down()
	p.theirs = mk()
	p.theirs.LinkUp()
	sq := p.ours.Up(p.now) // our Session Request
	// Their Session Initiation Request reaches us while we wait for the
	// Session Response.
	for _, f := range p.theirs.Outbox() {
		if _, out, err := p.ours.Receive(p.now, f); err != nil || len(out) != 0 {
			t.Fatalf("crossing initiation: %d frames, %v", len(out), err)
		}
	}
	p.pump(sq)
	p.mustReady("after the crossing")
	p.exchange(2)
}

// go-iec104, controlled, restarts with its association kept, and later
// reconnects; cB-Sigma keeps its session keys over both.
func TestControlledRestartAndReconnect(t *testing.T) {
	s := identities(t)
	store := &sec.MemoryStore{}
	mk := func() *sec.Endpoint {
		oc := s.oursConfig(t, sec.Controlled)
		oc.Store = store
		e, err := sec.New(oc)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	theirs, err := cb.NewEndpoint(s.theirsConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	p := &pair{t: t, ours: mk(), theirs: theirs, now: time.Now()}
	p.theirs.LinkUp()
	p.ours.Up(p.now)
	p.pump(nil)
	p.mustReady("association")

	initiate := func(what string) {
		t.Helper()
		if p.ours.Ready() {
			t.Fatalf("%s: ready with the keys of the earlier connection", what)
		}
		p.now = p.now.Add(2 * time.Second) // a third of the request timeout
		if d := p.ours.Deadline(); d.IsZero() || d.After(p.now) {
			t.Fatalf("%s: initiation due at %v", what, d)
		}
		p.pump(p.ours.Tick(p.now)) // the Session Initiation Request
		p.mustReady(what)
		p.exchange(2)
	}

	p.ours = mk()
	p.theirs.LinkDown()
	p.theirs.LinkUp()
	p.pump(p.ours.Up(p.now))
	initiate("after the restart")

	// A reconnect: what cB-Sigma sends under the keys it kept is accepted
	// meanwhile.
	p.ours.Down()
	p.theirs.LinkDown()
	p.theirs.LinkUp()
	p.pump(p.ours.Up(p.now))
	a := measurements(77, 2)
	segs, err := p.theirs.Wrap(a)
	if err != nil {
		t.Fatal(err)
	}
	if d, _, err := p.ours.Receive(p.now, segs[0]); err != nil || !bytes.Equal(d, a) {
		t.Fatalf("data under the kept keys: %x, %v", d, err)
	}
	initiate("after the reconnect")
}

// Curve25519 station certificates issued by an authority, each side with an
// authority of its own, in both roles.
func TestAuthorityCurve25519(t *testing.T) {
	for _, controlling := range []bool{true, false} {
		ourCA, err := sec.NewIdentity(sec.IdentityOptions{Subject: pkix.Name{CommonName: "go-iec104 CA"}, CA: true})
		if err != nil {
			t.Fatal(err)
		}
		ourID, err := sec.NewIdentity(sec.IdentityOptions{Curve: sec.X25519, Subject: pkix.Name{CommonName: "go-iec104"}, Issuer: ourCA})
		if err != nil {
			t.Fatal(err)
		}
		caKey, _ := cb.GenerateKey(cb.Secp256r1)
		caSigner, _ := cb.SignerFor(caKey)
		now := time.Now()
		caDER, err := cb.BuildCertificate(cb.CertTemplate{Subject: pkix.Name{CommonName: "cB-Sigma CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, caKey.PublicKey(), cb.Secp256r1, caSigner)
		if err != nil {
			t.Fatal(err)
		}
		caCert, _ := cb.ParseCertificate(caDER)
		key, _ := cb.GenerateKey(cb.Curve25519)
		theirDER, err := cb.BuildCertificate(cb.CertTemplate{Subject: pkix.Name{CommonName: "cB-Sigma"}, Issuer: caCert,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, key.PublicKey(), cb.Curve25519, caSigner)
		if err != nil {
			t.Fatal(err)
		}
		theirCA, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		role := sec.Controlled
		if controlling {
			role = sec.Controlling
		}
		oc := sec.Config{Role: role, AssociationID: 7, Identity: ourID, CommonAddr: 1,
			Trust: sec.Trust{Authorities: []*x509.Certificate{theirCA}}}
		tc := cb.Config{Controlling: !controlling, Link: cb.TCP, Params: cb.Params104, MaxASDU: 249, CA: 1, AIM: 9, AIS: 9,
			Key: key, Certificate: theirDER, Trust: cb.Trust{CAs: [][]byte{ourCA.Certificate.Raw}}}
		p := newPair(t, side{}, oc, tc)
		p.theirs.LinkUp()
		p.pump(p.ours.Up(now))
		p.mustReady(fmt.Sprintf("go-iec104 %s", role))
		p.exchange(1)
	}
}
