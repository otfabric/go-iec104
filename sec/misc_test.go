// SPDX-License-Identifier: MIT

package sec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/asdu"
)

func TestConfig(t *testing.T) {
	bad := []func(c *Config){
		func(c *Config) { c.AssociationID = 0 },
		func(c *Config) { c.Role = 5 },
		func(c *Config) { c.MAC = 99 },
		func(c *Config) { c.DataProtection = 99 },
		func(c *Config) { c.Params = asdu.Params{CauseSize: 3, CommonAddrSize: 2} },
		func(c *Config) { c.Identity = &Identity{Certificate: idA.Certificate, Key: idB.Key} },
		func(c *Config) { c.Identity = &Identity{} },
		func(c *Config) { c.Settings.ReplyTimeout = -1 },
		func(c *Config) { c.Settings.RequestTimeout = 4 * time.Hour },
		func(c *Config) { c.Settings.MaxReplyTimeouts = 256 },
		func(c *Config) { c.Settings.KeyLifetime = 15 * 24 * time.Hour },
		func(c *Config) { c.Settings.KeyUses = 1 << 31 },
	}
	for i, mod := range bad {
		c, _ := configs()
		mod(&c)
		if _, err := New(c); !errors.Is(err, ErrConfig) && !errors.Is(err, ErrCertificate) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	_, c := configs()
	c.Settings = Settings{}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if s := e.cfg.Settings; s.KeyUses != 2000 || s.KeyLifetime != 30*time.Minute || s.ReplyTimeout != 2*time.Second || s.RequestTimeout != 6*time.Second || s.MaxReplyTimeouts != 3 {
		t.Errorf("controlled defaults %+v", s)
	}
	if e.Role() != Controlled || e.cfg.DataProtection != HMACSHA256.Code {
		t.Error("role or data protection")
	}
	if !errors.Is(e.Reassociate(), ErrConfig) || !errors.Is(e.Renew(), ErrConfig) {
		t.Error("a controlled station started a procedure")
	}
	if _, err := New(Config{Role: Controlling, AssociationID: 1, Store: failingStore{load: true}}); err == nil {
		t.Error("store that does not load")
	}
}

type failingStore struct{ load bool }

func (f failingStore) Load() (State, bool, error) {
	if f.load {
		return State{}, false, errors.New("broken")
	}
	return State{}, false, nil
}

func (failingStore) Save(State) error { return errors.New("full") }

func TestLifecycle(t *testing.T) {
	p := newPair(t, func(_, b *Config) { b.Store = failingStore{} })
	a := p.a.e
	ch := a.Changed()
	if !a.Deadline().IsZero() {
		t.Error("deadline before the connection")
	}
	l1, l2 := new(int), new(int)
	p.send(p.a, a.Attach(l1, p.now))
	p.b.e.Attach("server", p.now)
	select {
	case <-ch:
	default:
		t.Error("Attach did not announce a change")
	}
	if !a.Owns(l1) || a.Owns(l2) {
		t.Error("owner")
	}
	p.mustReady()
	a.Detach(l2) // not the owner: ignored
	if !a.Ready() {
		t.Error("detached by another connection")
	}
	p.send(p.a, a.Attach(l2, p.now)) // takes the association over
	if a.Owns(l1) || !a.Owns(l2) || a.Ready() {
		t.Error("take-over")
	}
	p.b.e.Attach("server 2", p.now)
	p.mustReady()
	a.Detach(l2)
	if a.Owns(l2) || a.Status().Up {
		t.Error("detached")
	}
	if !p.b.hasEvent("KEY_STORE_ERR") {
		t.Error("store error not reported")
	}
	for _, ev := range p.b.events {
		if ev.Mnemonic == "KEY_STORE_ERR" && (ev.Stat != NumStats || ev.Severity != Alarm || ev.Err == nil) {
			t.Errorf("store event %+v", ev)
		}
	}

	// Reassociate, and the key lifetime of the controlling station.
	p = newPair(t, nil)
	p.up()
	p.mustReady()
	if err := p.a.e.Reassociate(); err != nil {
		t.Fatal(err)
	}
	if !p.until(func() bool { return p.a.count(StatSuccessfulAssociations) == 2 && p.ready() }, time.Minute) {
		t.Fatal("no new association")
	}
	if dl := p.a.e.Deadline(); !dl.Equal(p.now.Add(15 * time.Minute)) {
		t.Errorf("key change due after %v", dl.Sub(p.now))
	}
	p.advance(15 * time.Minute)
	p.mustReady()
	if p.a.count(StatSuccessfulSessionKeyChanges) != 3 {
		t.Errorf("session key changes %d", p.a.count(StatSuccessfulSessionKeyChanges))
	}
	// And its key uses.
	p = newPair(t, func(a, _ *Config) { a.Settings.KeyUses = 4 })
	p.up()
	p.mustReady()
	p.exchange()
	p.exchange()
	if dl := p.a.e.Deadline(); !dl.Equal(p.now) {
		t.Errorf("key change due after %v", dl.Sub(p.now))
	}
	if !p.until(func() bool { return p.a.count(StatSuccessfulSessionKeyChanges) == 2 && p.ready() }, time.Minute) {
		t.Fatal("keys not changed after their uses")
	}
	p.exchange()
	if p.a.count(StatSuccessfulSessionKeyChanges) != 2 {
		t.Errorf("session key changes %d", p.a.count(StatSuccessfulSessionKeyChanges))
	}
}

func TestNoIdentity(t *testing.T) {
	// A controlling station without an identity can use only a kept
	// association.
	p := newPair(t, func(a, _ *Config) { a.Identity = nil })
	p.up()
	if err := p.a.e.Err(); !errors.Is(err, ErrConfig) || !p.a.e.Deadline().IsZero() {
		t.Errorf("err %v, deadline %v", err, p.a.e.Deadline())
	}
	// A controlled one cannot answer an association request.
	q := newPair(t, func(_, b *Config) { b.Identity = nil })
	q.up()
	if q.b.count(StatUnexpectedMessages) == 0 || !errors.Is(q.b.lastErr(), ErrConfig) {
		t.Errorf("controlled: %v", q.b.errs)
	}
	// With the association of an earlier run both work.
	sa, sb := &MemoryStore{}, &MemoryStore{}
	r := newPair(t, func(a, b *Config) { a.Store, b.Store = sa, sb })
	r.up()
	r.mustReady()
	s := newPair(t, func(a, b *Config) { a.Store, b.Store, a.Identity, b.Identity = sa, sb, nil, nil })
	s.up()
	s.mustReady()
	s.exchange()

	// A kept association of another station is not used.
	st, _, _ := sa.Load()
	st.AIM = 99
	other := &MemoryStore{}
	_ = other.Save(st)
	u := newPair(t, func(a, _ *Config) { a.Store = other })
	if u.a.e.Status().Associated {
		t.Error("used the association of another station")
	}
}

func TestStores(t *testing.T) {
	dir := t.TempDir()
	f := FileStore{Path: filepath.Join(dir, "keys.json")}
	if _, ok, err := f.Load(); ok || err != nil {
		t.Fatalf("empty store: %v %v", ok, err)
	}
	p := newPair(t, func(a, b *Config) { b.Store = f })
	p.up()
	p.mustReady()
	fi, err := os.Stat(f.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store file %v, %v", fi, err)
	}
	st, ok, err := f.Load()
	if err != nil || !ok || st.AIM != 7 || st.AIS != 9 || len(st.ControlKey) != 32 || st.DataProtection != HMACSHA256.Code {
		t.Fatalf("stored %+v %v %v", st.AIM, ok, err)
	}
	_, cb := configs()
	cb.Store = f
	if e, err := New(cb); err != nil || !e.Status().Associated {
		t.Errorf("restored: %v", err)
	}
	if err := os.WriteFile(f.Path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cb); err == nil {
		t.Error("corrupt store loaded")
	}
	if err := (FileStore{Path: filepath.Join(dir, "missing", "keys.json")}).Save(State{}); err == nil {
		t.Error("saved into a missing directory")
	}
	if err := os.Mkdir(filepath.Join(dir, "unreadable"), 0); err == nil {
		if _, _, err := (FileStore{Path: filepath.Join(dir, "unreadable", "x")}).Load(); err == nil && os.Getuid() != 0 {
			t.Error("loaded from an unreadable directory")
		}
	}
}

func TestIdentities(t *testing.T) {
	ca := mustIdentity(IdentityOptions{CA: true})
	for _, id := range []*Identity{idA, mustIdentity(IdentityOptions{Curve: X25519, Issuer: ca})} {
		certPEM, keyPEM, err := id.PEM()
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseIdentity(certPEM, keyPEM)
		if err != nil || !back.Certificate.Equal(id.Certificate) {
			t.Fatalf("round trip: %v", err)
		}
		dir := t.TempDir()
		cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
		if os.WriteFile(cf, certPEM, 0o600) != nil || os.WriteFile(kf, keyPEM, 0o600) != nil {
			t.Fatal("writing the PEM files")
		}
		if _, err := LoadIdentity(cf, kf); err != nil {
			t.Errorf("load: %v", err)
		}
		if _, err := LoadIdentity(filepath.Join(dir, "none"), kf); err == nil {
			t.Error("loaded a missing certificate")
		}
		if _, err := LoadIdentity(cf, filepath.Join(dir, "none")); err == nil {
			t.Error("loaded a missing key")
		}
	}
	certPEM, keyPEM, _ := idA.PEM()
	_, otherKey, _ := idB.PEM()
	sec1, _ := x509.MarshalECPrivateKey(idA.Key.(*ecdsa.PrivateKey))
	if _, err := ParseIdentity(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})); err != nil {
		t.Errorf("SEC 1 key: %v", err)
	}
	edPub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)
	edPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER})
	for name, c := range map[string][2][]byte{
		"no certificate": {keyPEM, keyPEM},
		"no key":         {certPEM, certPEM[:0]},
		"garbage key":    {certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})},
		"other key":      {certPEM, otherKey},
		"Ed25519 key":    {certPEM, edPEM},
	} {
		if _, err := ParseIdentity(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}})
	if _, err := ParseCertificates(append(keyPEM, bad...)); !errors.Is(err, ErrCertificate) {
		t.Errorf("bad certificate: %v", err)
	}
	if cs, err := ParseCertificates(append(keyPEM, certPEM...)); err != nil || len(cs) != 1 {
		t.Errorf("certificates %d, %v", len(cs), err)
	}
	if _, err := NewIdentity(IdentityOptions{Curve: X25519}); !errors.Is(err, ErrConfig) {
		t.Errorf("self-signed X25519: %v", err)
	}
	xca := mustIdentity(IdentityOptions{Curve: X25519, Issuer: ca})
	if _, err := NewIdentity(IdentityOptions{Issuer: xca}); !errors.Is(err, ErrConfig) {
		t.Errorf("X25519 issuer: %v", err)
	}
	if _, err := NewIdentity(IdentityOptions{Curve: 7}); !errors.Is(err, ErrConfig) {
		t.Errorf("curve 7: %v", err)
	}
	if pin := idA.Pin(); len(pin.Fingerprints) != 1 || pin.Fingerprints[0] != Fingerprint(idA.Certificate) {
		t.Error("pin")
	}
	if _, _, err := (&Identity{Certificate: idA.Certificate, Key: edKey}).check(); !errors.Is(err, ErrConfig) {
		t.Errorf("Ed25519 key: %v", err)
	}
	edCert := &x509.Certificate{PublicKey: edPub}
	if _, _, err := publicKey(edCert); !errors.Is(err, ErrCertificate) {
		t.Errorf("Ed25519 certificate: %v", err)
	}
	if subjectPublicKey(edCert) != nil {
		t.Error("subject public key of an Ed25519 certificate")
	}
}

func TestRBAC(t *testing.T) {
	cases := []struct {
		t    asdu.TypeID
		perm Permission
	}{
		{asdu.C_SC_NA_1, PermOperateControls},
		{asdu.C_SE_TC_1, PermOperateControls},
		{asdu.C_IC_NA_1, PermMonitorData},
		{asdu.C_RD_NA_1, PermMonitorData},
		{asdu.C_RP_NA_1, PermConfigOperation},
		{asdu.P_ME_NB_1, PermConfigOperation},
		{asdu.F_SC_NA_1, PermFileRead},
		{asdu.F_DR_TA_1, PermFileRead},
		{asdu.F_AF_NA_1, PermFileRead},
		{asdu.F_FR_NA_1, PermFileWrite},
		{asdu.F_SG_NA_1, PermFileWrite},
		{asdu.C_CS_NA_1, 0},
		{asdu.C_TS_TA_1, 0},
	}
	for _, c := range cases {
		if got := RequiredPermission(c.t); got != c.perm {
			t.Errorf("%s: %b, want %b", c.t, got, c.perm)
		}
	}
	viewer := []AccessRole{RoleViewer}
	if Authorized(viewer, asdu.C_SC_NA_1) || !Authorized(viewer, asdu.C_IC_NA_1) || !Authorized(viewer, asdu.C_CS_NA_1) {
		t.Error("viewer")
	}
	if !RoleInstaller.Has(PermFileRead) || RoleSecAudit.Has(PermFileWrite) || len(Roles) != 7 {
		t.Error("roles")
	}
	p := newPair(t, func(_, b *Config) { b.Roles = viewer })
	if p.b.e.Permits(asdu.C_SC_NA_1) || !p.b.e.Permits(asdu.F_SC_NA_1) || !p.a.e.Permits(asdu.C_SC_NA_1) {
		t.Error("permits")
	}
	p.b.e.Refused(asdu.C_SC_NA_1)
	if p.b.count(StatOperationAuthorizationFailures) != 1 || !p.b.hasEvent("OPER_NOT_AUTR") {
		t.Error("refusal not counted")
	}
}
