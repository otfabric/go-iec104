// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/otfabric/go-iec104/asdu"
)

// sequenceLimit is where a controlling station changes the session keys so
// that a data sequence number never wraps to 0, which is never sent.
const sequenceLimit = 0xffffff00

// maxBackoff bounds the wait between attempts of a controlling station whose
// key management procedure failed.
const maxBackoff = time.Minute

// Procedures of a controlling station.
type kmState uint8

const (
	kmIdle kmState = iota
	kmAssociation
	kmUpdateKeyChange
	kmSession
	kmSessionKeyChange
)

var kmNames = [...]string{"idle", "wait for association response", "wait for update key change response",
	"wait for session response", "wait for session key change response"}

// States of a controlled station's Session Key Change.
type skcState uint8

const (
	skcNoAssociation skcState = iota
	skcIdle
	skcWaitKeyChange
)

var skcNames = [...]string{"no association", "session idle", "wait for session key change request"}

// Status describes an association. It holds no keys.
type Status struct {
	Role Role
	// Up reports whether a connection with data transfer started carries
	// the association.
	Up bool
	// Associated reports valid update keys; Ready valid session keys that
	// may be used now.
	Associated, Ready bool
	// State names the state of the key management.
	State    string
	AIM, AIS uint16
	MAC      string // the MAC algorithm of the association
	Data     string // the data protection algorithm of the session
	// Remote is the remote station's certificate, nil before an
	// association.
	Remote *x509.Certificate
	// Err is why the last key management procedure failed, nil after a
	// success.
	Err error
}

// Endpoint is one station's end of an association: the Station Association,
// Session Key Change and Secure Data state machines of either role.
//
// It does no I/O and keeps no time of its own. The caller reports the
// connection with [Endpoint.Up] and [Endpoint.Down], passes every received
// ASDU to [Endpoint.Receive], every application ASDU to send to
// [Endpoint.Protect], and calls [Endpoint.Tick] at [Endpoint.Deadline]. Each
// returns the wire ASDUs to send, in order, on the connection that carries
// the association.
//
// The connections of a redundancy group share one association: the one
// with data transfer started carries it. [Endpoint.Attach] and
// [Endpoint.Detach] do the bookkeeping for callers that run several.
//
// An Endpoint is safe for concurrent use.
type Endpoint struct {
	mu      sync.Mutex
	cfg     Config
	priv    *ecdh.PrivateKey
	curve   Curve
	reasm   reassembler
	seq     uint8 // ASC sequence number of the next segment sent
	up      bool
	owner   any
	clock   time.Time // the latest time the caller passed
	stats   Statistics
	events  []Event
	changed chan struct{}
	err     error

	// the association
	st       State
	assoc    bool // valid update keys
	keys     updateKeys
	mal      MACAlgorithm
	remote   *x509.Certificate
	remoteDH *ecdh.PublicKey

	// controlling station
	km          kmState
	replyAt     time.Time
	replies     int    // reply timeouts in the running procedure
	lastRequest []byte // whole request last sent, for retransmission and MACs
	pending     updateKeys
	pendingAIS  uint16
	newKeys     sessionKeys
	sessRequest []byte // the Session Request sent
	suspended   bool
	solicited   bool
	lastSI      []byte // the Session Initiation Request received (controlling) or sent (controlled)
	retryAt     time.Time
	backoff     time.Duration
	reassociate bool
	renew       bool
	preferAssoc bool

	// controlled station
	waitUH    bool
	saTimer   time.Time
	apSent    []byte
	apRandom  []byte
	uhValid   []byte
	upSent    []byte
	skc       skcState
	skcTimer  time.Time
	sqRecv    []byte
	spRandom  []byte
	khValid   []byte
	kpSent    []byte
	siPending bool
	siTimer   time.Time
	siAt      time.Time // no Session Initiation Request before this

	// the session
	session  bool
	stale    bool // controlled: the session keys are of an earlier connection
	sess     sessionKeys
	dp       DataProtection
	keySince time.Time
	keyUses  uint32
	txSeq    uint32
	rxSeq    uint32
}

// New returns an Endpoint for cfg. It loads the association kept in
// cfg.Store: update keys stay valid, session keys do not.
func New(cfg Config) (*Endpoint, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	e := &Endpoint{cfg: cfg, changed: make(chan struct{})}
	if cfg.Rand == nil {
		e.cfg.Rand = rand.Reader
	}
	e.reasm = reassembler{p: cfg.Params, discarded: func() { e.inc(StatDiscardedMessages, nil) }}
	if cfg.Identity != nil {
		e.curve, e.priv, _ = cfg.Identity.check()
	}
	st, ok, err := cfg.Store.Load()
	if err != nil {
		return nil, fmt.Errorf("sec: loading the association: %w", err)
	}
	if ok {
		e.load(st)
	}
	return e, nil
}

// load takes a kept association.
func (e *Endpoint) load(st State) {
	e.st = st
	mal, ok := MACByCode(st.MAC)
	keys := updateKeys{enc: st.EncryptionKey, auth: st.AuthenticationKey}
	if !ok || !keys.valid() || st.AIM == 0 || st.AIS == 0 || st.KeyWrap != KeyWrapAES256 {
		return
	}
	if e.cfg.Role == Controlling && st.AIM != e.cfg.AssociationID || e.cfg.Role == Controlled && st.AIS != e.cfg.AssociationID {
		return
	}
	e.assoc, e.keys, e.mal = true, keys, mal
	if len(st.RemoteCertificate) > 0 {
		if c, err := x509.ParseCertificate(st.RemoteCertificate); err == nil {
			e.remote = c
			_, e.remoteDH, _ = publicKey(c)
		}
	}
	e.sess = sessionKeys{control: st.ControlKey, monitor: st.MonitorKey}
	e.dp, _ = DataProtectionByCode(st.DataProtection)
	if e.cfg.Role == Controlled {
		e.skc = skcIdle
	}
}

// Role returns the station role of the Endpoint.
func (e *Endpoint) Role() Role { return e.cfg.Role }

// Changed returns a channel that is closed at the next change of the
// association that callers may wait for: session keys became valid or
// invalid, a procedure failed, or work is due ([Endpoint.Reassociate],
// [Endpoint.Renew]).
func (e *Endpoint) Changed() <-chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.changed
}

func (e *Endpoint) notify() {
	close(e.changed)
	e.changed = make(chan struct{})
}

// unlock releases the lock and delivers the events collected meanwhile.
func (e *Endpoint) unlock() {
	ev := e.events
	e.events = nil
	e.mu.Unlock()
	if e.cfg.OnEvent != nil {
		for _, x := range ev {
			e.cfg.OnEvent(x)
		}
	}
}

func (e *Endpoint) inc(s Stat, err error) {
	e.stats[s]++
	if name, sev, ok := s.Event(); ok {
		e.events = append(e.events, Event{Stat: s, Mnemonic: name, Severity: sev, Count: e.stats[s], Err: err})
	}
}

// Statistics returns the counters of the association.
func (e *Endpoint) Statistics() Statistics {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// Status describes the association.
func (e *Endpoint) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{Role: e.cfg.Role, Up: e.up, Associated: e.assoc, Ready: e.ready(), AIM: e.st.AIM, AIS: e.st.AIS,
		Remote: e.remote, Err: e.err}
	if e.cfg.Role == Controlling {
		s.State = kmNames[e.km]
	} else {
		s.State = skcNames[e.skc]
		if e.waitUH {
			s.State = "wait for update key change request"
		}
	}
	if e.assoc {
		s.MAC = e.mal.Name
	}
	if e.session {
		s.Data = e.dp.String()
	}
	return s
}

// Ready reports whether application data can be protected now.
func (e *Endpoint) Ready() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ready()
}

func (e *Endpoint) ready() bool { return e.up && e.session && !e.suspended && !e.stale }

// Err returns why the last key management procedure failed, or nil.
func (e *Endpoint) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// Permits reports whether the roles of the controlling station allow a
// request of type t (see [Config.Roles]). The controlled station answers a
// refused request with a negative confirmation with cause
// [asdu.CauseNotAuthorized]; call [Endpoint.Refused] to count it.
func (e *Endpoint) Permits(t asdu.TypeID) bool {
	if e.cfg.Roles == nil {
		return true
	}
	return Authorized(e.cfg.Roles, t)
}

// Refused counts a request refused by role-based access control.
func (e *Endpoint) Refused(t asdu.TypeID) {
	e.mu.Lock()
	defer e.unlock()
	e.inc(StatOperationAuthorizationFailures, fmt.Errorf("sec: %s not permitted by the roles of the controlling station", t))
	e.inc(StatDiscardedMessages, nil)
}

// Reassociate asks a controlling station to run the Station Association
// again, at the next Tick when no procedure is running.
func (e *Endpoint) Reassociate() error {
	e.mu.Lock()
	defer e.unlock()
	if e.cfg.Role != Controlling {
		return fmt.Errorf("%w: only the controlling station starts the Station Association", ErrConfig)
	}
	e.reassociate, e.retryAt = true, time.Time{}
	e.notify()
	return nil
}

// Renew asks a controlling station to change the session keys, at the next
// Tick when no procedure is running.
func (e *Endpoint) Renew() error {
	e.mu.Lock()
	defer e.unlock()
	if e.cfg.Role != Controlling {
		return fmt.Errorf("%w: only the controlling station changes the session keys", ErrConfig)
	}
	e.renew, e.retryAt = true, time.Time{}
	e.notify()
	return nil
}

// Attach reports that data transfer started on the connection owner; it
// carries the association from now on. A connection that carried it before
// is detached first. It returns what to send.
func (e *Endpoint) Attach(owner any, now time.Time) [][]byte {
	e.mu.Lock()
	defer e.unlock()
	if e.up {
		e.down()
	}
	e.owner = owner
	return e.upLocked(now)
}

// Detach reports that data transfer stopped or the connection owner ended.
// It is ignored when owner does not carry the association.
func (e *Endpoint) Detach(owner any) {
	e.mu.Lock()
	defer e.unlock()
	if e.up && e.owner == owner {
		e.down()
		e.owner = nil
	}
}

// Owns reports whether owner carries the association.
func (e *Endpoint) Owns(owner any) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.up && e.owner == owner
}

// Up reports that the connection is established with data transfer
// started. Every connection begins with fresh session keys. A controlling
// station starts the key management: the Station Association when it has no
// update keys, otherwise a Session Key Change. A controlled station holds
// what it sends until new session keys arrive, accepts data under the
// previous ones meanwhile, and asks for new ones with a Session Initiation
// Request unless the controlling station changes them first. It returns
// what to send.
func (e *Endpoint) Up(now time.Time) [][]byte {
	e.mu.Lock()
	defer e.unlock()
	if e.up {
		e.down()
	}
	return e.upLocked(now)
}

func (e *Endpoint) upLocked(now time.Time) [][]byte {
	e.clock, e.up, e.err = now, true, nil
	e.reasm.reset()
	var out [][]byte
	if e.cfg.Role == Controlling {
		e.session = false
		e.retryAt, e.backoff = time.Time{}, 0
		out = e.controllingDue(now)
	} else {
		// Every connection starts with fresh session keys: what this
		// station sends waits for them rather than go out under keys the
		// controlling station may have dropped. What it receives under the
		// previous keys is still accepted, from a controlling station that
		// kept them. A controlling station usually changes them when the
		// connection starts; asking at the same moment would cross its
		// request, so the controlled station waits a little before it asks.
		e.stale = e.session
		e.siAt = now.Add(e.cfg.Settings.RequestTimeout / 3)
	}
	e.notify()
	return out
}

// Down reports that the connection was lost or data transfer stopped. A
// running procedure fails. The keys stay: the next connection uses them.
func (e *Endpoint) Down() {
	e.mu.Lock()
	defer e.unlock()
	e.down()
}

func (e *Endpoint) down() {
	if !e.up {
		return
	}
	e.up = false
	e.reasm.reset()
	if e.cfg.Role == Controlling {
		switch e.km {
		case kmAssociation, kmUpdateKeyChange:
			e.inc(StatAssociationFailures, errors.New("sec: connection lost"))
		case kmSession, kmSessionKeyChange:
			e.inc(StatSessionKeyChangeFailures, errors.New("sec: connection lost"))
		case kmIdle:
		}
		e.km, e.replyAt, e.replies, e.suspended = kmIdle, time.Time{}, 0, false
	} else {
		if e.waitUH {
			e.inc(StatAssociationFailures, errors.New("sec: connection lost"))
		}
		if e.skc == skcWaitKeyChange {
			e.inc(StatSessionKeyChangeFailures, errors.New("sec: connection lost"))
			e.skc = skcIdle
		}
		e.waitUH, e.saTimer, e.skcTimer, e.siTimer, e.siPending = false, time.Time{}, time.Time{}, time.Time{}, false
	}
	e.notify()
}

// Deadline returns when [Endpoint.Tick] must be called next; the zero time
// when no timer runs. A time not after the latest time passed in means at
// once.
func (e *Endpoint) Deadline() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.up {
		return time.Time{}
	}
	var next time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	if e.cfg.Role == Controlling {
		consider(e.replyAt)
		if e.km == kmIdle && (e.assoc || e.priv != nil) {
			if e.retryAt.After(e.clock) {
				consider(e.retryAt)
			} else if !e.session || e.reassociate || e.renew || e.keysWornOut() {
				consider(e.clock)
			}
			if e.session {
				consider(e.keySince.Add(e.cfg.Settings.KeyLifetime))
			}
		}
	} else {
		consider(e.saTimer)
		consider(e.skcTimer)
		consider(e.siTimer)
		if e.initiationDue() {
			consider(e.siAt)
		}
		if e.session {
			consider(e.keySince.Add(e.cfg.Settings.KeyLifetime))
		}
	}
	return next
}

// Tick runs the timers. It returns what to send.
func (e *Endpoint) Tick(now time.Time) [][]byte {
	e.mu.Lock()
	defer e.unlock()
	e.clock = now
	if !e.up {
		return nil
	}
	if e.cfg.Role == Controlling {
		return e.tickControlling(now)
	}
	return e.tickControlled(now)
}

func (e *Endpoint) keysWornOut() bool {
	s := e.cfg.Settings
	return e.session && (e.keyUses >= s.KeyUses || e.txSeq >= sequenceLimit || e.rxSeq >= sequenceLimit)
}

func (e *Endpoint) keysExpired(now time.Time) bool {
	return e.session && !now.Before(e.keySince.Add(e.cfg.Settings.KeyLifetime))
}

// --- sending ---

func (e *Endpoint) header(t asdu.TypeID) Header {
	c, _ := PermittedCause(t, e.cfg.Role.sends())
	return Header{Type: t, Cause: c, Originator: e.cfg.Originator, CommonAddr: e.cfg.CommonAddr}
}

// macInput is a message this station sends, without its MAC.
func (e *Endpoint) macInput(m Message) []byte {
	b, _ := encode(e.header(m.Type()), e.cfg.Params, m, false)
	return b
}

// macInputOf is a received message without its MAC.
func (e *Endpoint) macInputOf(h Header, m Message) []byte {
	b, _ := encode(h, e.cfg.Params, m, false)
	return b
}

// emit encodes a message and appends its segments to out. It returns the
// whole message.
func (e *Endpoint) emit(out *[][]byte, m Message) []byte {
	whole, err := Encode(e.header(m.Type()), e.cfg.Params, m)
	if err != nil {
		return nil
	}
	e.send(out, whole)
	return whole
}

func (e *Endpoint) send(out *[][]byte, whole []byte) {
	segs, next, err := Segment(whole, e.cfg.Params, e.maxSize(), e.seq)
	if err != nil {
		return
	}
	e.seq = next
	*out = append(*out, segs...)
	e.inc(StatMessagesSent, nil)
}

func (e *Endpoint) maxSize() int {
	if e.cfg.Params.MaxSize > 0 {
		return e.cfg.Params.MaxSize
	}
	return 249
}

func (e *Endpoint) random(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(e.cfg.Rand, b); err != nil {
		panic(fmt.Sprintf("sec: random source failed: %v", err))
	}
	return b
}

// fail ends the running procedure of a controlling station and schedules
// the next attempt.
func (e *Endpoint) fail(now time.Time, err error) {
	phase := e.km
	switch phase {
	case kmAssociation, kmUpdateKeyChange:
		e.inc(StatAssociationFailures, err)
	case kmSession, kmSessionKeyChange:
		e.inc(StatSessionKeyChangeFailures, err)
		// A station that does not answer the Session Key Change may have
		// lost the association: associate anew next time.
		e.preferAssoc = true
	case kmIdle:
	}
	e.km, e.replyAt, e.replies, e.suspended = kmIdle, time.Time{}, 0, false
	e.err = err
	e.backoff = min(max(2*e.backoff, e.cfg.Settings.ReplyTimeout), maxBackoff)
	e.retryAt = now.Add(e.backoff)
	e.notify()
}

// --- controlling station ---

func (e *Endpoint) tickControlling(now time.Time) [][]byte {
	var out [][]byte
	if !e.replyAt.IsZero() && !now.Before(e.replyAt) {
		e.inc(StatReplyTimeouts, nil)
		e.replies++
		if e.replies >= e.cfg.Settings.MaxReplyTimeouts {
			e.inc(StatMaxReplyTimeouts, nil)
			cause := fmt.Errorf("%w: no answer to %s after %d attempts", ErrProcedure, kmNames[e.km], e.replies)
			if e.err != nil {
				cause = fmt.Errorf("%w: %s after %d attempts: %w", ErrProcedure, kmNames[e.km], e.replies, e.err)
			}
			e.fail(now, cause)
			return nil
		}
		e.send(&out, e.lastRequest)
		e.replyAt = now.Add(e.cfg.Settings.ReplyTimeout)
		return out
	}
	return e.controllingDue(now)
}

// controllingDue starts the procedure that is due, if any.
func (e *Endpoint) controllingDue(now time.Time) [][]byte {
	if e.km != kmIdle || !e.up || now.Before(e.retryAt) {
		return nil
	}
	var out [][]byte
	switch {
	case e.reassociate || !e.assoc || e.preferAssoc && e.priv != nil:
		if e.priv == nil {
			if e.err == nil {
				e.err = fmt.Errorf("%w: no station identity for the Station Association", ErrConfig)
				e.notify()
			}
			e.reassociate = false
			return nil
		}
		e.startAssociation(&out, now)
	case !e.session || e.renew || e.keysWornOut() || e.keysExpired(now):
		e.startSessionKeyChange(&out, now)
	}
	return out
}

func (e *Endpoint) startAssociation(out *[][]byte, now time.Time) {
	e.reassociate, e.preferAssoc = false, false
	if !e.cfg.IgnoreValidity {
		c := e.cfg.Identity.Certificate
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			e.inc(StatLocalCertificateExpirations, nil)
			e.fail(now, fmt.Errorf("%w: our certificate is outside its validity period", ErrCertificate))
			return
		}
	}
	m := AssociationRequest{AIM: e.cfg.AssociationID, Protocol: Version1, Certificate: e.cfg.Identity.Certificate.Raw}
	e.lastRequest = e.emit(out, m)
	e.km, e.replyAt, e.replies = kmAssociation, now.Add(e.cfg.Settings.ReplyTimeout), 0
}

func (e *Endpoint) startSessionKeyChange(out *[][]byte, now time.Time) {
	e.renew = false
	if !e.solicited {
		e.lastSI = nil
	}
	m := SessionRequest{AIM: e.st.AIM, AIS: e.st.AIS, Protocol: Version1, Random: e.random(32)}
	e.sessRequest = e.emit(out, m)
	e.lastRequest = e.sessRequest
	e.km, e.replyAt, e.replies = kmSession, now.Add(e.cfg.Settings.ReplyTimeout), 0
}

func (e *Endpoint) succeeded() {
	e.km, e.replyAt, e.replies = kmIdle, time.Time{}, 0
	e.backoff, e.retryAt, e.err = 0, time.Time{}, nil
}

func (e *Endpoint) receiveControlling(now time.Time, out *[][]byte, whole []byte, h Header, m Message) ([]byte, error) {
	switch v := m.(type) {
	case AssociationResponse:
		if e.km != kmAssociation {
			return e.unexpected("association response")
		}
		if v.AIM != e.cfg.AssociationID || v.AIS == 0 {
			return e.unexpected("association response with association IDs %d/%d", v.AIM, v.AIS)
		}
		if err := checkRandom(v.Random, "association response"); err != nil {
			return e.discard(StatUnexpectedMessages, err)
		}
		cert, pub, notAuth, err := e.cfg.Trust.verify(v.Certificate, e.curve, now, e.cfg.IgnoreValidity)
		if err != nil {
			e.err = err
			if notAuth {
				return e.discard(StatRemoteAuthorizationFailures, err)
			}
			return e.discard(StatRemoteCertificateFailures, err)
		}
		mal, _ := MACByCode(e.cfg.MAC)
		random := e.random(32)
		keys, err := deriveUpdateKeys(mal, e.priv, pub, random, v.Random)
		if err != nil {
			return e.discard(StatRemoteCertificateFailures, err)
		}
		uh := UpdateKeyChangeRequest{AIM: e.cfg.AssociationID, AIS: v.AIS, KeyWrap: KeyWrapAES256, MAC: mal.Code, Random: random}
		uh.Tag = mal.sum(keys.auth, v.Random, e.macInput(uh))
		e.pending, e.pendingAIS, e.remote, e.remoteDH = keys, v.AIS, cert, pub
		e.lastRequest = e.emit(out, uh)
		e.km, e.replyAt, e.replies = kmUpdateKeyChange, now.Add(e.cfg.Settings.ReplyTimeout), 0
		return nil, nil

	case UpdateKeyChangeResponse:
		if e.km != kmUpdateKeyChange {
			return e.unexpected("update key change response")
		}
		mal, _ := MACByCode(e.cfg.MAC)
		if !mal.verify(e.pending.auth, v.Tag, e.lastRequest, e.macInputOf(h, v)) {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: update key change response", ErrAuthentication))
		}
		if v.AIM != e.cfg.AssociationID || v.AIS != e.pendingAIS {
			return e.unexpected("update key change response with association IDs %d/%d", v.AIM, v.AIS)
		}
		e.st = State{AIM: v.AIM, AIS: v.AIS, MAC: mal.Code, KeyWrap: KeyWrapAES256,
			EncryptionKey: e.pending.enc, AuthenticationKey: e.pending.auth, RemoteCertificate: e.remote.Raw}
		e.keys, e.mal, e.assoc, e.session = e.pending, mal, true, false
		e.sess = sessionKeys{}
		e.save()
		e.inc(StatSuccessfulAssociations, nil)
		e.succeeded()
		e.startSessionKeyChange(out, now)
		return nil, nil

	case SessionResponse:
		if e.km != kmSession {
			return e.unexpected("session response")
		}
		// A response to a request the controlled station solicited covers
		// its Session Initiation Request as well. Whether it did depends on
		// which crossed which on the wire, so both forms are accepted.
		in := append(bytes.Clone(e.sessRequest), e.macInputOf(h, v)...)
		ok := e.mal.verify(e.keys.auth, v.Tag, in)
		if !ok && e.lastSI != nil {
			ok = e.mal.verify(e.keys.auth, v.Tag, in, e.lastSI)
		}
		if !ok {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: session response", ErrAuthentication))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected("session response with association IDs %d/%d", v.AIM, v.AIS)
		}
		if err := checkRandom(v.Random, "session response"); err != nil {
			return e.discard(StatUnexpectedMessages, err)
		}
		e.newKeys = sessionKeys{control: e.random(32), monitor: e.random(32)}
		wrapped, err := keyWrap(e.keys.enc, append(bytes.Clone(e.newKeys.control), e.newKeys.monitor...))
		if err != nil {
			return e.discard(StatKeyAuthenticationErrors, err)
		}
		kh := SessionKeyChangeRequest{AIM: e.st.AIM, AIS: e.st.AIS, DataProtection: e.cfg.DataProtection, Wrapped: wrapped}
		kh.Tag = e.mal.sum(e.keys.auth, v.Random, e.macInput(kh))
		e.suspended = true
		e.lastRequest = e.emit(out, kh)
		e.km, e.replyAt, e.replies = kmSessionKeyChange, now.Add(e.cfg.Settings.ReplyTimeout), 0
		return nil, nil

	case SessionKeyChangeResponse:
		if e.km != kmSessionKeyChange {
			return e.unexpected("session key change response")
		}
		if !e.mal.verify(e.keys.auth, v.Tag, e.lastRequest, e.macInputOf(h, v)) {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: session key change response", ErrAuthentication))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected("session key change response with association IDs %d/%d", v.AIM, v.AIS)
		}
		dp, _ := DataProtectionByCode(e.cfg.DataProtection)
		e.installSession(now, e.newKeys, dp)
		e.inc(StatSuccessfulSessionKeyChanges, nil)
		e.succeeded()
		e.suspended, e.solicited, e.lastSI = false, false, nil
		e.notify()
		return nil, nil

	case SessionInitiationRequest:
		if e.km != kmIdle && e.km != kmSession {
			return e.unexpected("session initiation request during %s", kmNames[e.km])
		}
		if !e.assoc || !e.sess.available() || v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected("session initiation request without a matching association")
		}
		if !e.mal.verify(e.keys.auth, v.Tag, e.sess.control, e.sess.monitor, e.macInputOf(h, v)) {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: session initiation request", ErrAuthentication))
		}
		if e.km == kmSession {
			// It crossed our Session Request: the controlled station may
			// answer that one as solicited.
			e.solicited, e.lastSI = true, whole
			return nil, nil
		}
		e.session, e.solicited, e.lastSI = false, true, whole
		e.retryAt = time.Time{}
		e.startSessionKeyChange(out, now)
		e.notify()
		return nil, nil

	case SecureData:
		return e.receiveData(h, whole, v)
	}
	return e.unexpected("%s at the controlling station", h.Type)
}

// --- controlled station ---

func (e *Endpoint) tickControlled(now time.Time) [][]byte {
	if !e.saTimer.IsZero() && !now.Before(e.saTimer) {
		e.saTimer = time.Time{}
		if e.waitUH {
			e.inc(StatRequestTimeouts, nil)
			e.inc(StatAssociationFailures, errors.New("sec: no update key change request"))
			e.waitUH = false
		} else {
			e.uhValid, e.upSent = nil, nil
		}
	}
	if !e.skcTimer.IsZero() && !now.Before(e.skcTimer) {
		e.skcTimer = time.Time{}
		if e.skc == skcWaitKeyChange {
			e.inc(StatRequestTimeouts, nil)
			e.inc(StatSessionKeyChangeFailures, errors.New("sec: no session key change request"))
			e.skc = skcIdle
		} else {
			e.khValid, e.kpSent = nil, nil
		}
	}
	if e.session && e.skc != skcNoAssociation {
		switch {
		case e.keysExpired(now):
			e.session = false
			e.inc(StatKeyInvalidationsTime, nil)
			e.notify()
		case e.keyUses >= e.cfg.Settings.KeyUses:
			e.session = false
			e.inc(StatKeyInvalidationsCount, nil)
			e.notify()
		}
	}
	if e.siPending && !e.siTimer.IsZero() && !now.Before(e.siTimer) {
		e.siPending, e.siTimer = false, time.Time{}
		e.inc(StatRequestTimeouts, nil)
	}
	return e.maybeInitiation(now)
}

func (e *Endpoint) initiationDue() bool {
	return e.cfg.Role == Controlled && e.up && (!e.session || e.stale) && !e.siPending && e.skc == skcIdle && e.assoc && e.sess.available()
}

// maybeInitiation sends the Session Initiation Request of a controlled
// station whose session keys are not valid, and again after each request
// timeout.
func (e *Endpoint) maybeInitiation(now time.Time) [][]byte {
	if !e.initiationDue() || now.Before(e.siAt) {
		return nil
	}
	var out [][]byte
	m := SessionInitiationRequest{AIM: e.st.AIM, AIS: e.st.AIS, Random: e.random(32)}
	m.Tag = e.mal.sum(e.keys.auth, e.sess.control, e.sess.monitor, e.macInput(m))
	e.lastSI = e.emit(&out, m)
	e.siPending, e.siTimer = true, now.Add(e.cfg.Settings.RequestTimeout)
	return out
}

func (e *Endpoint) receiveControlled(now time.Time, out *[][]byte, whole []byte, h Header, m Message) ([]byte, error) {
	switch v := m.(type) {
	case AssociationRequest:
		if !v.Protocol.isVersion1() {
			return e.discard(StatProtocolInformationErrors, fmt.Errorf("%w: protocol version %d.%d", ErrMessage, v.Protocol.Major, v.Protocol.Minor))
		}
		if e.priv == nil {
			return e.discard(StatUnexpectedMessages, fmt.Errorf("%w: no station identity for the Station Association", ErrConfig))
		}
		cert, pub, notAuth, err := e.cfg.Trust.verify(v.Certificate, e.curve, now, e.cfg.IgnoreValidity)
		if err != nil {
			if notAuth {
				return e.discard(StatRemoteAuthorizationFailures, err)
			}
			return e.discard(StatRemoteCertificateFailures, err)
		}
		e.remote, e.remoteDH = cert, pub
		if e.waitUH && e.apSent != nil {
			// The request again: the same response, with the same random data.
			e.send(out, e.apSent)
			return nil, nil
		}
		e.apRandom = e.random(32)
		ap := AssociationResponse{AIM: v.AIM, AIS: e.cfg.AssociationID, Certificate: e.cfg.Identity.Certificate.Raw, Random: e.apRandom}
		e.apSent = e.emit(out, ap)
		e.waitUH, e.saTimer = true, now.Add(e.cfg.Settings.RequestTimeout)
		return nil, nil

	case UpdateKeyChangeRequest:
		if !e.waitUH {
			if !e.saTimer.IsZero() && e.uhValid != nil && bytes.Equal(whole, e.uhValid) {
				e.send(out, e.upSent)
				return nil, nil
			}
			return e.unexpected("update key change request")
		}
		mal, ok := MACByCode(v.MAC)
		if !accepts(e.cfg.AcceptMAC, v.MAC, ok) {
			return e.discard(StatKeyAuthAlgorithmFailures, fmt.Errorf("%w: MAC algorithm %d", ErrAlgorithm, v.MAC))
		}
		if err := checkRandom(v.Random, "update key change request"); err != nil {
			return e.discard(StatUnexpectedMessages, err)
		}
		keys, err := deriveUpdateKeys(mal, e.priv, e.remoteDH, v.Random, e.apRandom)
		if err != nil {
			return e.discard(StatKeyAuthenticationErrors, err)
		}
		if !mal.verify(keys.auth, v.Tag, e.apRandom, e.macInputOf(h, v)) {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: update key change request", ErrAuthentication))
		}
		if v.AIS != e.cfg.AssociationID || v.AIM == 0 {
			return e.unexpected("update key change request with association IDs %d/%d", v.AIM, v.AIS)
		}
		if v.KeyWrap != KeyWrapAES256 {
			return e.discard(StatKeyWrapAlgorithmFailures, fmt.Errorf("%w: key wrap algorithm %d", ErrAlgorithm, v.KeyWrap))
		}
		up := UpdateKeyChangeResponse{AIM: v.AIM, AIS: e.cfg.AssociationID}
		up.Tag = mal.sum(keys.auth, whole, e.macInput(up))
		e.st = State{AIM: v.AIM, AIS: e.cfg.AssociationID, MAC: mal.Code, KeyWrap: v.KeyWrap,
			EncryptionKey: keys.enc, AuthenticationKey: keys.auth, RemoteCertificate: e.remote.Raw,
			ControlKey: e.sess.control, MonitorKey: e.sess.monitor, DataProtection: e.dp.Code}
		e.keys, e.mal, e.assoc = keys, mal, true
		e.save()
		e.upSent = e.emit(out, up)
		e.uhValid = whole
		e.waitUH, e.saTimer = false, now.Add(e.cfg.Settings.RequestTimeout)
		e.inc(StatSuccessfulAssociations, nil)
		if e.skc == skcNoAssociation {
			e.skc = skcIdle
		}
		return nil, nil

	case SessionRequest:
		if e.skc == skcNoAssociation {
			return e.unexpected("session request without an association")
		}
		if !v.Protocol.isVersion1() || v.Protocol.Broadcast {
			return e.discard(StatProtocolInformationErrors, fmt.Errorf("%w: session request protocol information", ErrMessage))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected("session request with association IDs %d/%d", v.AIM, v.AIS)
		}
		if err := checkRandom(v.Random, "session request"); err != nil {
			return e.discard(StatUnexpectedMessages, err)
		}
		e.sqRecv = whole
		if e.skc == skcWaitKeyChange && e.spRandom != nil {
			// The request again: answered with the same random data.
			e.sendSessionResponse(out, now, e.spRandom)
			return nil, nil
		}
		e.solicited = e.siPending
		e.siPending, e.siTimer = false, time.Time{}
		e.sendSessionResponse(out, now, e.random(32))
		return nil, nil

	case SessionKeyChangeRequest:
		switch e.skc {
		case skcNoAssociation:
			return e.unexpected("session key change request without an association")
		case skcIdle:
			if !e.skcTimer.IsZero() && e.khValid != nil && bytes.Equal(whole, e.khValid) {
				e.send(out, e.kpSent)
				return nil, nil
			}
			return e.unexpected("session key change request")
		case skcWaitKeyChange:
		}
		if !e.mal.verify(e.keys.auth, v.Tag, e.spRandom, e.macInputOf(h, v)) {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: session key change request", ErrAuthentication))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected("session key change request with association IDs %d/%d", v.AIM, v.AIS)
		}
		dp, ok := DataProtectionByCode(v.DataProtection)
		if !accepts(e.cfg.AcceptDataProtection, v.DataProtection, ok) {
			return e.discard(StatDataProtectionAlgorithmFailures, fmt.Errorf("%w: data protection algorithm %d", ErrAlgorithm, v.DataProtection))
		}
		plain, err := keyUnwrap(e.keys.enc, v.Wrapped)
		if err != nil || len(plain) != 64 {
			return e.discard(StatKeyAuthenticationErrors, fmt.Errorf("%w: wrapped session keys", ErrAuthentication))
		}
		kp := SessionKeyChangeResponse{AIM: e.st.AIM, AIS: e.st.AIS}
		kp.Tag = e.mal.sum(e.keys.auth, whole, e.macInput(kp))
		e.kpSent = e.emit(out, kp)
		e.khValid = whole
		e.skc, e.skcTimer = skcIdle, now.Add(e.cfg.Settings.RequestTimeout)
		e.inc(StatSuccessfulSessionKeyChanges, nil)
		e.installSession(now, sessionKeys{control: plain[:32], monitor: plain[32:]}, dp)
		e.solicited = false
		e.notify()
		return nil, nil

	case SecureData:
		return e.receiveData(h, whole, v)
	}
	return e.unexpected("%s at the controlled station", h.Type)
}

func (e *Endpoint) sendSessionResponse(out *[][]byte, now time.Time, random []byte) {
	sp := SessionResponse{AIM: e.st.AIM, AIS: e.st.AIS, Random: random}
	in := append(bytes.Clone(e.sqRecv), e.macInput(sp)...)
	if e.solicited && e.lastSI != nil {
		in = append(in, e.lastSI...)
	}
	sp.Tag = e.mal.sum(e.keys.auth, in)
	e.spRandom = random
	e.emit(out, sp)
	e.skc, e.skcTimer = skcWaitKeyChange, now.Add(e.cfg.Settings.RequestTimeout)
}

// --- both ---

func (e *Endpoint) installSession(now time.Time, k sessionKeys, dp DataProtection) {
	e.sess, e.dp, e.session, e.stale = k, dp, true, false
	e.keySince, e.keyUses, e.txSeq, e.rxSeq = now, 0, 0, 0
	e.st.ControlKey, e.st.MonitorKey, e.st.DataProtection = k.control, k.monitor, dp.Code
	e.save()
}

func (e *Endpoint) save() {
	if err := e.cfg.Store.Save(e.st.clone()); err != nil {
		e.events = append(e.events, Event{Stat: NumStats, Mnemonic: "KEY_STORE_ERR", Severity: Alarm,
			Err: fmt.Errorf("sec: saving the association: %w", err)})
	}
}

func (e *Endpoint) discard(s Stat, err error) ([]byte, error) {
	e.inc(s, err)
	e.inc(StatDiscardedMessages, nil)
	return nil, err
}

func (e *Endpoint) unexpected(format string, a ...any) ([]byte, error) {
	return e.discard(StatUnexpectedMessages, fmt.Errorf("%w: "+format, append([]any{ErrUnexpected}, a...)...))
}

// Receive takes one ASDU received on the connection that carries the
// association. It returns the application ASDU it carried, if any, and what
// to send. An error says why a message was discarded; the association goes
// on.
func (e *Endpoint) Receive(now time.Time, raw []byte) (data []byte, out [][]byte, err error) {
	e.mu.Lock()
	defer e.unlock()
	e.clock = now
	h, _, err := parseHeader(raw, e.cfg.Params)
	if err != nil {
		e.inc(StatDiscardedMessages, nil)
		return nil, nil, err
	}
	if !h.Type.IsSecurity() {
		e.inc(StatMessagesReceived, nil)
		e.inc(StatDiscardedMessages, nil)
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsecured, h.Type)
	}
	whole := e.reasm.add(raw)
	if whole == nil {
		return nil, nil, nil
	}
	e.inc(StatMessagesReceived, nil)
	h, m, err := Decode(whole, e.cfg.Params, e.cfg.Role.receives())
	if err != nil {
		data, err = e.discard(StatUnexpectedMessages, err)
		return data, nil, err
	}
	if e.cfg.Role == Controlling {
		data, err = e.receiveControlling(now, &out, whole, h, m)
	} else {
		data, err = e.receiveControlled(now, &out, whole, h, m)
	}
	return data, out, err
}

// receiveData verifies Secure Data and returns the ASDU it carries.
func (e *Endpoint) receiveData(h Header, whole []byte, v SecureData) ([]byte, error) {
	if !e.session {
		return e.unexpected("secure data without session keys")
	}
	key := e.sess.control
	if e.cfg.Role == Controlling {
		key = e.sess.monitor
	}
	plain, err := open(whole, e.cfg.Params, v, e.dp, key)
	if err != nil {
		if errors.Is(err, ErrAuthentication) {
			return e.discard(StatDataAuthenticationErrors, err)
		}
		return e.discard(StatUnexpectedMessages, err)
	}
	if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
		return e.unexpected("secure data with association IDs %d/%d", v.AIM, v.AIS)
	}
	if v.Sequence == 0 || v.Sequence <= e.rxSeq {
		return e.discard(StatUnexpectedMessages, fmt.Errorf("%w: sequence number %d after %d", ErrReplay, v.Sequence, e.rxSeq))
	}
	e.rxSeq = v.Sequence
	e.keyUses++
	e.inc(StatSuccessfulDataAuthentications, nil)
	return plain, nil
}

// Protect wraps an application ASDU in Secure Data and returns its segments.
// It returns [ErrNotReady] while no session keys may be used; the caller
// waits for [Endpoint.Changed]. The segments must be sent in order and
// before anything else this Endpoint returns later: the receiver accepts
// only increasing sequence numbers.
func (e *Endpoint) Protect(now time.Time, data []byte) ([][]byte, error) {
	e.mu.Lock()
	defer e.unlock()
	e.clock = now
	if !e.ready() || e.txSeq == 0xffffffff {
		return nil, ErrNotReady
	}
	if e.cfg.Role == Controlled && (e.keysExpired(now) || e.keyUses >= e.cfg.Settings.KeyUses) {
		return nil, ErrNotReady
	}
	h, _, err := parseHeader(data, e.cfg.Params)
	if err != nil {
		return nil, err
	}
	key := e.sess.monitor
	if e.cfg.Role == Controlling {
		key = e.sess.control
	}
	whole, err := protect(e.cfg.Params, Header{Originator: h.Originator, CommonAddr: h.CommonAddr},
		SecureData{AIM: e.st.AIM, AIS: e.st.AIS, Sequence: e.txSeq + 1}, data, e.dp, key)
	if err != nil {
		return nil, err
	}
	e.txSeq++
	e.keyUses++
	var out [][]byte
	e.send(&out, whole)
	return out, nil
}

// protect builds a whole Secure Data message around an application ASDU.
// With a MAC algorithm the MAC covers the message from its data unit
// identifier to the end of the ASDU; with AES-256-GCM the data unit
// identifier and the association IDs are the additional data, the nonce is
// the sequence number, and the length and ASDU are encrypted.
func protect(p asdu.Params, h Header, sd SecureData, data []byte, dp DataProtection, key []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 0xffff {
		return nil, fmt.Errorf("%w: application data of %d octets", ErrMessage, len(data))
	}
	h.Type, h.Cause = asdu.S_SD_NA_1, asdu.CauseDataProtection
	plain := binary.LittleEndian.AppendUint16(make([]byte, 0, 2+len(data)), uint16(len(data)))
	plain = append(plain, data...)
	if dp.MAC == nil {
		g, err := newGCM(key)
		if err != nil {
			return nil, err
		}
		aad := appendIDs(h.append(nil, p), sd.AIM, sd.AIS)
		sd.Payload = g.Seal(nil, gcmNonce(sd.Sequence), plain, aad)
		return Encode(h, p, sd)
	}
	sd.Payload = plain
	in, err := Encode(h, p, sd)
	if err != nil {
		return nil, err
	}
	return append(in, dp.MAC.sum(key, in)...), nil
}

// open verifies (and decrypts) a whole Secure Data message and returns the
// application ASDU.
func open(whole []byte, p asdu.Params, sd SecureData, dp DataProtection, key []byte) ([]byte, error) {
	var plain []byte
	if dp.MAC == nil {
		g, err := newGCM(key)
		if err != nil {
			return nil, err
		}
		n := headerLen(p) + 4
		if plain, err = g.Open(nil, gcmNonce(sd.Sequence), sd.Payload, whole[:n]); err != nil {
			return nil, fmt.Errorf("%w: secure data", ErrAuthentication)
		}
	} else {
		n := len(sd.Payload) - dp.MAC.Len
		if n < 2 || !dp.MAC.verify(key, sd.Payload[n:], whole[:len(whole)-dp.MAC.Len]) {
			return nil, fmt.Errorf("%w: secure data", ErrAuthentication)
		}
		plain = sd.Payload[:n]
	}
	if len(plain) < 3 || int(binary.LittleEndian.Uint16(plain)) != len(plain)-2 {
		return nil, fmt.Errorf("%w: secure data length does not match its ASDU", ErrMessage)
	}
	return plain[2:], nil
}
