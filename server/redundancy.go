// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
)

// DefaultEventQueue is the number of events a redundancy group buffers when
// [WithEventQueue] is not used.
const DefaultEventQueue = 1024

// RedundancyGroup declares a redundancy group of a controlled station: the
// connections of one controlling station (or of several that back each
// other up), of which one has data transfer started at a time.
//
// Each group has its own event queue, see [Server.Enqueue].
type RedundancyGroup struct {
	// Name identifies the group in [Session.Group], logs and
	// [Server.Pending].
	Name string

	// Allow lists the clients that belong to the group, as IP addresses
	// ("10.0.0.5") or prefixes ("10.0.0.0/24"). An empty list accepts any
	// client that no earlier group claimed, so a catch-all group goes last.
	Allow []string
}

// WithRedundancyGroups declares the redundancy groups of the station. A
// connection belongs to the first group that allows its address; one that no
// group allows is closed before any protocol exchange.
//
// Without this option there is one group, "default", for every client.
func WithRedundancyGroups(groups ...RedundancyGroup) Option {
	return func(o *options) { o.groups = groups }
}

// WithEventQueue sets how many events each redundancy group buffers for
// [Server.Enqueue]. When the queue is full the oldest event is dropped.
// Default [DefaultEventQueue].
func WithEventQueue(size int) Option {
	return func(o *options) { o.queueSize = size }
}

// queued is one event of a group's queue.
type queued struct {
	raw []byte
	// owner is the session the event is in flight on: handed to its link,
	// and not yet acknowledged by the controlling station.
	owner *Session
	// epoch is the started period of that session the event was sent in,
	// written by the link at the moment it is sent; 0 while the event is
	// still on its way to the link.
	epoch atomic.Uint64
}

// group is a redundancy group at run time.
type group struct {
	srv   *Server
	name  string
	allow []netip.Prefix // empty: any client
	limit int

	mu       sync.Mutex
	queue    []*queued // oldest first
	active   *Session
	dropped  uint64
	overflow bool
	pumping  bool
	wake     chan struct{}
	// sending is the session the pump is handing an event to, and
	// cancelSend gives that up: a connection whose window is full must not
	// hold the queue when another has become the active one.
	sending    *Session
	cancelSend context.CancelFunc
}

func newGroups(srv *Server, decl []RedundancyGroup, limit int) ([]*group, error) {
	if limit == 0 {
		limit = DefaultEventQueue
	}
	if limit < 0 {
		return nil, fmt.Errorf("%w: event queue size %d, want > 0", iec104.ErrInvalidOption, limit)
	}
	if len(decl) == 0 {
		decl = []RedundancyGroup{{Name: "default"}}
	}
	seen := map[string]bool{}
	var out []*group
	for _, d := range decl {
		if d.Name == "" || seen[d.Name] {
			return nil, fmt.Errorf("%w: redundancy group names must be unique and not empty, got %q",
				iec104.ErrInvalidOption, d.Name)
		}
		seen[d.Name] = true
		g := &group{srv: srv, name: d.Name, limit: limit, wake: make(chan struct{}, 1)}
		for _, a := range d.Allow {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				addr, aerr := netip.ParseAddr(a)
				if aerr != nil {
					return nil, fmt.Errorf("%w: redundancy group %q: %q is neither an address nor a prefix",
						iec104.ErrInvalidOption, d.Name, a)
				}
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			g.allow = append(g.allow, p.Masked())
		}
		out = append(out, g)
	}
	return out, nil
}

func (g *group) allows(remote net.Addr) bool {
	if len(g.allow) == 0 {
		return true
	}
	tcp, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range g.allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (g *group) signal() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// enqueue appends an event, dropping the oldest one when the queue is full.
func (g *group) enqueue(raw []byte) {
	warn := false
	g.mu.Lock()
	if len(g.queue) >= g.limit {
		// Prefer an event that is not in flight; either way the oldest.
		drop := 0
		for i, q := range g.queue {
			if q.owner == nil {
				drop = i
				break
			}
		}
		g.queue = append(g.queue[:drop], g.queue[drop+1:]...)
		g.dropped++
		if !g.overflow {
			g.overflow = true
			warn = true
		}
	}
	g.queue = append(g.queue, &queued{raw: raw})
	start := !g.pumping
	g.pumping = true
	g.mu.Unlock()
	if warn {
		// Not under mu: the logger is the application's.
		g.srv.log.Warn("event queue full, dropping the oldest events", "group", g.name, "size", g.limit)
	}
	if start {
		go g.pump()
	}
	g.signal()
}

// acked removes an event the controlling station has acknowledged.
func (g *group) acked(item *queued) {
	g.mu.Lock()
	for i, q := range g.queue {
		if q == item {
			g.queue = append(g.queue[:i], g.queue[i+1:]...)
			break
		}
	}
	if g.overflow && len(g.queue) <= g.limit/2 {
		g.overflow = false
	}
	g.mu.Unlock()
}

// release makes the events that were in flight on s pending again: they
// were not acknowledged, so they are sent on the next active connection.
// Only events sent in a started period up to epoch are released: one that
// is still on its way to the link either fails there, which the pump puts
// right, or goes out in a later period, of which this is not the end.
// The caller holds g.mu.
func (g *group) release(s *Session, epoch uint64) {
	for _, q := range g.queue {
		if q.owner != s {
			continue
		}
		if e := q.epoch.Load(); e != 0 && e <= epoch {
			q.owner = nil
			q.epoch.Store(0)
		}
	}
}

// releaseAll is release for a session that has ended.
func (g *group) releaseAll(s *Session) {
	for _, q := range g.queue {
		if q.owner == s {
			q.owner = nil
			q.epoch.Store(0)
		}
	}
}

// The three functions below keep the group in step with its connections.
// They are called from the protocol goroutine of the session's link, at the
// moment its data transfer state changes, and not from the dispatcher: the
// dispatcher may be busy in a Handler while the state has long moved on,
// and events sent in the meantime must be attributed to the right period.

// started makes s the active connection of the group. A connection that
// was active before keeps its link but no longer receives queued events;
// what it had not acknowledged is sent again on s.
func (g *group) started(s *Session) {
	g.mu.Lock()
	prev := g.active
	if prev != nil && prev != s {
		g.releaseAll(prev)
	}
	g.active = s
	if g.sending != nil && g.sending != s {
		g.cancelSend()
	}
	g.mu.Unlock()
	g.signal()
	// Not under mu: the logger is the application's.
	if prev != nil && prev != s {
		g.srv.log.Info("redundancy group switched over", "group", g.name, "session", s.id, "previous", prev.id)
	}
}

// stopped is called when the started period epoch of s ends.
func (g *group) stopped(s *Session, epoch uint64) {
	g.mu.Lock()
	g.release(s, epoch)
	g.handOver(s)
	g.mu.Unlock()
	g.signal()
}

// ended is called when s is gone.
func (g *group) ended(s *Session) {
	g.mu.Lock()
	g.releaseAll(s)
	g.handOver(s)
	g.mu.Unlock()
	g.signal()
}

// handOver finds another active connection when s was it. The caller holds
// g.mu.
func (g *group) handOver(s *Session) {
	if g.active != s {
		return
	}
	g.active = nil
	// Another connection of the group may have data transfer started.
	for _, other := range g.srv.Sessions() {
		if other != s && other.group == g && other.transferring() {
			g.active = other
			break
		}
	}
}

// next returns the oldest pending event and the session to send it on,
// waiting until there is one. It returns nil when the server is closed.
func (g *group) next() (*queued, *Session) {
	for {
		g.mu.Lock()
		if s := g.active; s != nil && s.transferring() {
			for _, q := range g.queue {
				if q.owner == nil {
					q.owner = s
					q.epoch.Store(0)
					g.mu.Unlock()
					return q, s
				}
			}
		}
		g.mu.Unlock()
		select {
		case <-g.wake:
		case <-g.srv.done:
			return nil, nil
		}
	}
}

// pump delivers the queue to the active connection, in order. Send blocks
// while the connection's window is full, which is the flow control.
func (g *group) pump() {
	for {
		item, s := g.next()
		if item == nil {
			return
		}
		ctx, cancel := context.WithCancel(s.ctx)
		g.mu.Lock()
		g.sending, g.cancelSend = s, cancel
		if g.active != s {
			cancel() // switched over since next chose s
		}
		g.mu.Unlock()
		err := s.lk.Load().SendQueued(ctx, item.raw, func() { g.acked(item) }, &item.epoch)
		g.mu.Lock()
		g.sending, g.cancelSend = nil, nil
		g.mu.Unlock()
		cancel()
		if err != nil {
			g.mu.Lock()
			if item.owner == s {
				item.owner = nil
				item.epoch.Store(0)
			}
			g.mu.Unlock()
			// The session is stopping or gone: its state change wakes next().
		}
	}
}

func (g *group) pending() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.queue)
}

// Enqueue queues an event (spontaneous or periodic data) for every
// redundancy group. Each group delivers its queue, in order, to the one
// connection that has data transfer started, and keeps an event until the
// controlling station has acknowledged it:
//
//   - while no connection of a group is started, events wait in the queue;
//   - when the active connection is lost or stopped before it acknowledged
//     an event, the event is sent again on the next active connection, so a
//     controlling station may see an event twice across a switchover but
//     does not miss one;
//   - when the queue is full ([WithEventQueue]) the oldest event is dropped.
//
// Enqueue never blocks. Compare [Server.Broadcast], which sends immediately
// to every started session and buffers nothing.
func (s *Server) Enqueue(a *asdu.ASDU) error {
	raw, err := a.Encode(s.opts.asduParams)
	if err != nil {
		return err
	}
	if s.isClosed() {
		return ErrServerClosed
	}
	for _, g := range s.groups {
		g.enqueue(raw)
	}
	return nil
}

// Pending returns the number of events a redundancy group holds: queued, or
// sent and not yet acknowledged. An unknown name returns 0.
func (s *Server) Pending(group string) int {
	for _, g := range s.groups {
		if g.name == group {
			return g.pending()
		}
	}
	return 0
}

// Dropped returns how many events a redundancy group has dropped because
// its queue was full.
func (s *Server) Dropped(group string) uint64 {
	for _, g := range s.groups {
		if g.name == group {
			g.mu.Lock()
			defer g.mu.Unlock()
			return g.dropped
		}
	}
	return 0
}

// Group returns the name of the redundancy group the session belongs to.
func (s *Session) Group() string { return s.group.name }
