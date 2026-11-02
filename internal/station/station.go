// SPDX-License-Identifier: MIT

package station

import (
	"crypto/tls"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

// Station is a go-iec104 server that behaves as a fixture prescribes: the
// library in the role of the controlled station. It is written against the
// public API only, the way an application would be.
type Station struct {
	ca asdu.CommonAddr

	mu       sync.Mutex
	points   []*stationPoint // sorted by address
	commands map[asdu.IOA]*stationCommand
	clock    time.Time
	files    []File                    // of the fixture
	accepted []Upload                  // of the fixture
	uploads  map[asdu.IOA]uploadedFile // delivered by controlling stations
	started  map[uint64]bool           // sessions with data transfer started

	Server *server.Server
	Addr   string // host:port; the station listens on all interfaces
}

// FirstUploadIOA is the first address the station takes files at when the
// fixture has no uploads. Files delivered can be fetched again and appear in
// the directory.
const FirstUploadIOA asdu.IOA = 40000

// FixtureFileTime is the creation time the directory gives the files of the
// fixture.
var FixtureFileTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type uploadedFile struct {
	name uint16
	file server.File
	at   time.Time
}

// OpenFile implements server.FileSource.
func (st *Station) OpenFile(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (server.File, bool) {
	if ca != st.ca {
		return server.File{}, false
	}
	for _, f := range st.files {
		if f.IOA == ioa && f.Name == name {
			return server.NewFile(f.Content(), f.SectionSize), true
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if u, ok := st.uploads[ioa]; ok && u.name == name {
		return u.file, true
	}
	return server.File{}, false
}

// AcceptFile implements server.FileSink.
func (st *Station) AcceptFile(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, length int) bool {
	if ca != st.ca {
		return false
	}
	if len(st.accepted) == 0 {
		return ioa >= FirstUploadIOA
	}
	for _, u := range st.accepted {
		if u.IOA == ioa && u.Name == name {
			return length >= 1 && length <= u.MaxSize
		}
	}
	return false
}

// StoreFile implements server.FileSink.
func (st *Station) StoreFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, name uint16, f server.File) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.uploads[ioa] = uploadedFile{name: name, file: f, at: time.Now().UTC().Truncate(time.Millisecond)}
	return nil
}

// Uploaded returns the content of the file delivered at ioa.
func (st *Station) Uploaded(ioa asdu.IOA) ([]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.uploads[ioa]
	if !ok {
		return nil, false
	}
	var all []byte
	for _, sec := range u.file.Sections {
		all = append(all, sec...)
	}
	return all, true
}

// directory lists the files of the fixture and the delivered ones, by address.
func (st *Station) directory(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA) []asdu.FileDirectoryEntry {
	if ca != st.ca || ioa != 0 {
		return nil
	}
	var out []asdu.FileDirectoryEntry
	for _, f := range st.files {
		out = append(out, asdu.FileDirectoryEntry{IOA: f.IOA, Name: f.Name, Length: uint32(f.Size), Time: asdu.At(FixtureFileTime)})
	}
	st.mu.Lock()
	for a, u := range st.uploads {
		out = append(out, asdu.FileDirectoryEntry{IOA: a, Name: u.name, Length: uint32(u.file.Len()), Time: asdu.At(u.at)})
	}
	st.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].IOA < out[j].IOA })
	return out
}

type stationPoint struct {
	Point
	quality asdu.Quality
}

type stationCommand struct {
	Command
	target   *stationPoint
	selected bool
}

// Start serves the fixture with go-iec104 on all interfaces, so that
// a client container can reach it through the Docker host gateway.
func Start(t testing.TB, fx *Fixture, opts ...server.Option) *Station {
	t.Helper()
	return start(t, fx, nil, opts...)
}

// StartTLS is Start with TLS, by [server.WithTLS].
func StartTLS(t testing.TB, fx *Fixture, cfg *tls.Config, opts ...server.Option) *Station {
	t.Helper()
	return start(t, fx, cfg, opts...)
}

// StartGroup is Start with all connections in one redundancy group, in the
// sense of IEC 60870-5-104 edition 2, clause 10 (redundant connections). A connection in STARTDT that gets a STOPDT act
// queues one event, for the next connection to start: the single point with the
// lowest address as it is then, without time tag, with cause 3. A takeover
// queues nothing, and neither does a connection that ends.
func StartGroup(t testing.TB, fx *Fixture, opts ...server.Option) *Station {
	t.Helper()
	var st *Station
	ready := make(chan struct{})
	opts = append([]server.Option{
		server.WithRedundancyGroups(server.RedundancyGroup{Name: GroupName}),
		// Sessions report once the server exists, and a session can be
		// accepted only after that; the station is set right after.
		server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
			<-ready
			st.follow(s, state)
		}),
	}, opts...)
	st = start(t, fx, nil, opts...)
	close(ready)
	return st
}

// GroupName is the redundancy group of a station from [StartGroup].
const GroupName = "station"

// follow queues the event of a redundancy group when a started connection stops.
func (st *Station) follow(s *server.Session, state iec104.State) {
	st.mu.Lock()
	was := st.started[s.ID()]
	st.started[s.ID()] = state == iec104.StateStarted
	if state == iec104.StateDisconnected {
		delete(st.started, s.ID())
	}
	var ev *asdu.ASDU
	if was && state == iec104.StateStopped {
		for _, p := range st.points {
			if p.Type == "M_SP_NA_1" {
				ev = asdu.New(asdu.CauseSpontaneous, st.ca, p.object(asdu.Timestamp{}))
				break
			}
		}
	}
	st.mu.Unlock()
	if ev != nil {
		_ = st.Server.Enqueue(ev)
	}
}

func start(t testing.TB, fx *Fixture, tlsConfig *tls.Config, opts ...server.Option) *Station {
	t.Helper()
	st := &Station{ca: fx.Station.CommonAddr, commands: map[asdu.IOA]*stationCommand{}, started: map[uint64]bool{}}
	byIOA := map[asdu.IOA]*stationPoint{}
	for _, p := range fx.Points {
		sp := &stationPoint{Point: p}
		for _, f := range p.Quality {
			switch f {
			case "OV":
				sp.quality |= asdu.QualityOverflow
			case "BL":
				sp.quality |= asdu.QualityBlocked
			case "SB":
				sp.quality |= asdu.QualitySubstituted
			case "NT":
				sp.quality |= asdu.QualityNotTopical
			case "IV":
				sp.quality |= asdu.QualityInvalid
			}
		}
		st.points = append(st.points, sp)
		byIOA[p.IOA] = sp
	}
	for _, c := range fx.Commands {
		st.commands[c.IOA] = &stationCommand{Command: c, target: byIOA[c.Target]}
	}

	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, st.interrogation)
	mux.HandleFunc(asdu.C_CI_NA_1, st.counterInterrogation)
	mux.HandleFunc(asdu.C_RD_NA_1, st.read)
	mux.HandleFunc(asdu.C_CS_NA_1, st.clockSync)
	mux.HandleFunc(asdu.C_TS_TA_1, func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(st.own(req)) })
	mux.Handle(server.HandlerFunc(st.command), server.ProcessCommands...)
	if len(fx.Files) > 0 {
		st.files, st.accepted, st.uploads = fx.Files, fx.Uploads, map[asdu.IOA]uploadedFile{}
		files := server.NewFileServer(st)
		files.Sink, files.Directory = st, st.directory
		mux.Handle(files, server.FileTypes...)
	}

	params := apci.DefaultParams()
	options := []server.Option{server.WithParams(params), server.WithCommonAddrs(st.ca)}
	if tlsConfig != nil {
		options = append(options, server.WithTLS(tlsConfig))
	}
	srv, err := server.New(mux, append(options, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	st.Server = srv
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ListenAndServe("0.0.0.0:0") }()
	deadline := time.Now().Add(5 * time.Second)
	for srv.Addr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the station does not listen")
		}
		time.Sleep(time.Millisecond)
	}
	st.Addr = srv.Addr().String()
	return st
}

// own returns req addressed to this station: a request to the broadcast
// address is answered with the station's own address.
func (st *Station) own(req *asdu.ASDU) *asdu.ASDU {
	if req.CommonAddr == st.ca {
		return req
	}
	r := *req
	r.CommonAddr = st.ca
	return &r
}

func (p *stationPoint) object(tag asdu.Timestamp) asdu.InformationObject {
	num, _ := p.Value.(float64)
	switch p.Type {
	case "M_SP_NA_1":
		on, _ := p.Value.(bool)
		return asdu.SinglePoint{IOA: p.IOA, Value: on, Quality: p.quality, Time: tag}
	case "M_DP_NA_1":
		return asdu.DoublePoint{IOA: p.IOA, Value: asdu.DoubleState(num), Quality: p.quality, Time: tag}
	case "M_ST_NA_1":
		return asdu.StepPosition{IOA: p.IOA, Value: int8(num), Transient: p.Transient, Quality: p.quality, Time: tag}
	case "M_BO_NA_1":
		return asdu.Bitstring32{IOA: p.IOA, Value: uint32(num), Quality: p.quality, Time: tag}
	case "M_ME_NA_1":
		return asdu.MeasuredNormalized{IOA: p.IOA, Value: asdu.Normalized(num), Quality: p.quality, Time: tag}
	case "M_ME_NB_1":
		return asdu.MeasuredScaled{IOA: p.IOA, Value: int16(num), Quality: p.quality, Time: tag}
	case "M_ME_NC_1":
		return asdu.MeasuredFloat{IOA: p.IOA, Value: float32(num), Quality: p.quality, Time: tag}
	default: // M_IT_NA_1
		it := asdu.IntegratedTotal{IOA: p.IOA, Value: int32(num), Sequence: p.Sequence, Time: tag}
		for _, f := range p.Quality {
			switch f {
			case "CY":
				it.Carry = true
			case "CA":
				it.Adjusted = true
			case "IV":
				it.Invalid = true
			}
		}
		return it
	}
}

// report builds the answer to an interrogation: the selected points in
// address order, consecutive points of one type sharing an ASDU.
func (st *Station) report(cause asdu.Cause, originator uint8, selected func(*stationPoint) bool) []*asdu.ASDU {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []*asdu.ASDU
	var cur *asdu.ASDU
	last := ""
	for _, p := range st.points {
		if !selected(p) {
			continue
		}
		if cur == nil || p.Type != last || len(cur.Objects) >= 20 {
			cur = asdu.New(cause, st.ca, p.object(asdu.Timestamp{}))
			cur.Originator = originator
			out = append(out, cur)
			last = p.Type
			continue
		}
		cur.Objects = append(cur.Objects, p.object(asdu.Timestamp{}))
	}
	return out
}

func (st *Station) interrogation(s *server.Session, req *asdu.ASDU) {
	req = st.own(req)
	qoi := req.First().(asdu.Interrogation).Qualifier
	selected := func(p *stationPoint) bool { return p.Type != "M_IT_NA_1" }
	if qoi != asdu.QOIStation {
		group := int(qoi) - int(asdu.QOIStation)
		selected = func(p *stationPoint) bool { return p.InGroup(group) }
	}
	data := st.report(qoi.Cause(), req.Originator, selected)
	// The groups are QOI 21..36, and a group without points has nothing to
	// answer. Neither has any other qualifier: a point has no other group.
	if qoi != asdu.QOIStation && len(data) == 0 {
		_ = s.Negative(req)
		return
	}
	_ = s.Confirm(req)
	for _, a := range data {
		_ = s.Send(s.Context(), a)
	}
	_ = s.Terminate(req)
}

func (st *Station) counterInterrogation(s *server.Session, req *asdu.ASDU) {
	req = st.own(req)
	ci := req.First().(asdu.CounterInterrogation)
	if ci.Request != asdu.CounterGeneral || ci.Freeze != asdu.FreezeRead {
		_ = s.Negative(req)
		return
	}
	_ = s.Confirm(req)
	for _, a := range st.report(ci.Cause(), req.Originator, func(p *stationPoint) bool { return p.Type == "M_IT_NA_1" }) {
		_ = s.Send(s.Context(), a)
	}
	_ = s.Terminate(req)
}

func (st *Station) read(s *server.Session, req *asdu.ASDU) {
	ioa := req.First().Address()
	st.mu.Lock()
	var obj asdu.InformationObject
	for _, p := range st.points {
		if p.IOA == ioa {
			obj = p.object(asdu.Timestamp{})
		}
	}
	st.mu.Unlock()
	if obj == nil {
		_ = s.Reject(req, asdu.CauseUnknownIOA)
		return
	}
	a := asdu.New(asdu.CauseRequest, st.ca, obj)
	a.Originator = req.Originator
	_ = s.Send(s.Context(), a)
}

func (st *Station) clockSync(s *server.Session, req *asdu.ASDU) {
	st.mu.Lock()
	st.clock = req.First().(asdu.ClockSync).Time.Time
	st.mu.Unlock()
	_ = s.Confirm(st.own(req))
}

// ClockTime returns the time of the last clock synchronization.
func (st *Station) ClockTime() time.Time {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.clock
}

// decodeCommand returns the fixture type, the value and the select bit of a
// process command, and whether the value is one the type permits.
func decodeCommand(obj asdu.InformationObject) (typ string, value any, sel, valid bool) {
	switch c := obj.(type) {
	case asdu.SingleCommand:
		return "C_SC_NA_1", c.Value, c.Select, true
	case asdu.DoubleCommand:
		return "C_DC_NA_1", float64(c.Value), c.Select, c.Value == asdu.DoubleOff || c.Value == asdu.DoubleOn
	case asdu.StepCommand:
		return "C_RC_NA_1", float64(c.Value), c.Select, c.Value == asdu.StepLower || c.Value == asdu.StepHigher
	case asdu.SetpointNormalized:
		return "C_SE_NA_1", float64(c.Value), c.Select, true
	case asdu.SetpointScaled:
		return "C_SE_NB_1", float64(c.Value), c.Select, true
	case asdu.SetpointFloat:
		return "C_SE_NC_1", float64(c.Value), c.Select, true
	}
	return "", nil, false, false
}

func (st *Station) command(s *server.Session, req *asdu.ASDU) {
	req = st.own(req)
	typ, value, sel, valid := decodeCommand(req.First())

	st.mu.Lock()
	cmd := st.commands[req.First().Address()]
	if cmd == nil || cmd.Type != typ {
		st.mu.Unlock()
		_ = s.Reject(req, asdu.CauseUnknownIOA)
		return
	}
	var report *asdu.ASDU
	outcome := "rejected"
	switch {
	case req.Cause == asdu.CauseDeactivation:
		cmd.selected = false
		outcome = "confirmed"
	case !valid:
	case sel:
		cmd.selected = true
		outcome = "confirmed"
	case cmd.SelectRequired && !cmd.selected:
	default:
		cmd.selected = false
		next := value
		if typ == "C_RC_NA_1" {
			step := -1.0
			if value.(float64) == float64(asdu.StepHigher) {
				step = 1
			}
			pos := cmd.target.Value.(float64) + step
			if pos < -64 || pos > 63 {
				break // the step position is at its limit
			}
			next = pos
		}
		cmd.target.Value = next
		report = asdu.New(asdu.Cause(cmd.ReportCause), st.ca, cmd.target.object(asdu.Now()))
		outcome = "executed"
	}
	st.mu.Unlock()

	switch outcome {
	case "rejected":
		_ = s.Negative(req)
	case "confirmed":
		_ = s.Confirm(req)
	default:
		// Confirmation, then the new state of the target, then termination.
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), report)
		_ = s.Terminate(req)
	}
}

// Loopback returns the address of the station on the loopback interface.
func (st *Station) Loopback() string {
	_, port, _ := net.SplitHostPort(st.Addr)
	return net.JoinHostPort("127.0.0.1", port)
}
