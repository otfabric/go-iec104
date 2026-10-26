// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/logx"
	"github.com/otfabric/go-iec104/sec"
)

// associations are the associations of a redundancy group: one per
// controlling station, by its AIM, made when that station is first heard.
type associations struct {
	group       string
	params      asdu.Params
	newEndpoint func(group string, aim uint16) (*sec.Endpoint, error)

	mu    sync.Mutex
	byAIM map[uint16]*sec.Endpoint
}

// get returns the association of the controlling station aim, making it
// on first use.
func (a *associations) get(aim uint16) (*sec.Endpoint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ep, ok := a.byAIM[aim]; ok {
		return ep, nil
	}
	ep, err := a.newEndpoint(a.group, aim)
	if err != nil {
		return nil, err
	}
	if ep == nil || ep.Role() != sec.Controlled {
		return nil, fmt.Errorf("%w: security of redundancy group %q, AIM %d: the endpoint needs the controlled role",
			iec104.ErrInvalidOption, a.group, aim)
	}
	if a.byAIM == nil {
		a.byAIM = map[uint16]*sec.Endpoint{}
	}
	a.byAIM[aim] = ep
	return ep, nil
}

// errUnbound is why a session discards what it receives before the
// controlling station has said which association it uses.
var errUnbound = errors.New("no association yet: waiting for a security message")

// route is the security of one session, the link.Security of its link. It
// binds the session to the association of the controlling station that
// the first security message names, and from then on hands everything to
// that association, which other sessions of the same station (a client
// redundancy group) share.
//
// The link calls it from its protocol goroutine only; ep is published for
// the session's other goroutines.
type route struct {
	set *associations
	log *logx.Logger

	ep      atomic.Pointer[sec.Endpoint]
	owner   any // the link, while data transfer is started and ep is nil
	started bool
}

// endpoint returns the association of the session, nil until it is bound.
func (r *route) endpoint() *sec.Endpoint { return r.ep.Load() }

func (r *route) Attach(owner any, now time.Time) [][]byte {
	if ep := r.endpoint(); ep != nil {
		return ep.Attach(owner, now)
	}
	r.owner, r.started = owner, true
	return nil
}

func (r *route) Detach(owner any) {
	if ep := r.endpoint(); ep != nil {
		ep.Detach(owner)
		return
	}
	r.owner, r.started = nil, false
}

// Owns reports true for a started session that is not bound yet, so that
// the link hands it what it receives.
func (r *route) Owns(owner any) bool {
	if ep := r.endpoint(); ep != nil {
		return ep.Owns(owner)
	}
	return r.started && r.owner == owner
}

func (r *route) Receive(now time.Time, raw []byte) ([]byte, [][]byte, error) {
	if ep := r.endpoint(); ep != nil {
		return ep.Receive(now, raw)
	}
	aim, ok := sec.AssociationOf(raw, r.set.params)
	if !ok {
		if len(raw) > 0 && !asdu.TypeID(raw[0]).IsSecurity() {
			return nil, nil, fmt.Errorf("%w: %s", sec.ErrUnsecured, asdu.TypeID(raw[0]))
		}
		return nil, nil, errUnbound
	}
	ep, err := r.set.get(aim)
	if err != nil {
		r.log.Warn("no association for the controlling station", "aim", aim, "error", err)
		return nil, nil, err
	}
	r.ep.Store(ep)
	r.log.Debug("session bound to the association of the controlling station", "aim", aim)
	out := ep.Attach(r.owner, now)
	r.owner = nil
	data, more, err := ep.Receive(now, raw)
	return data, append(out, more...), err
}

func (r *route) Protect(now time.Time, data []byte) ([][]byte, error) {
	if ep := r.endpoint(); ep != nil {
		return ep.Protect(now, data)
	}
	return nil, sec.ErrNotReady
}

func (r *route) Tick(now time.Time) [][]byte {
	if ep := r.endpoint(); ep != nil {
		return ep.Tick(now)
	}
	return nil
}

func (r *route) Deadline() time.Time {
	if ep := r.endpoint(); ep != nil {
		return ep.Deadline()
	}
	return time.Time{}
}

// Changed is nil until the session is bound: binding happens on the link's
// own goroutine, which looks again afterwards.
func (r *route) Changed() <-chan struct{} {
	if ep := r.endpoint(); ep != nil {
		return ep.Changed()
	}
	return nil
}
