// SPDX-License-Identifier: MIT

package station

import (
	"crypto/tls"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

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
	uploads  map[asdu.IOA]uploadedFile // delivered by controlling stations

	Server *server.Server
	Addr   string // host:port; the station listens on all interfaces
}

// FirstUploadIOA is the first address the station takes files at. Files
// delivered there can be fetched again and appear in the directory.
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
func (st *Station) AcceptFile(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA, _ uint16, _ int) bool {
	return ca == st.ca && ioa >= FirstUploadIOA
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

// StartTLS is Start with TLS on the listener.
func StartTLS(t testing.TB, fx *Fixture, cfg *tls.Config, opts ...server.Option) *Station {
	t.Helper()
	return start(t, fx, cfg, opts...)
}

func start(t testing.TB, fx *Fixture, tlsConfig *tls.Config, opts ...server.Option) *Station {
	t.Helper()
	st := &Station{ca: fx.Station.CommonAddr, commands: map[asdu.IOA]*stationCommand{}}
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
		st.files, st.uploads = fx.Files, map[asdu.IOA]uploadedFile{}
		files := server.NewFileServer(st)
		files.Sink, files.Directory = st, st.directory
		mux.Handle(files, server.FileTypes...)
	}

	params := apci.DefaultParams()
	srv, err := server.New(mux, append([]server.Option{
		server.WithParams(params), server.WithCommonAddrs(st.ca)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	st.Server = srv
	st.Addr = ln.Addr().String()
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
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
func (st *Station) report(cause asdu.Cause, originator uint8, counters bool) []*asdu.ASDU {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []*asdu.ASDU
	var cur *asdu.ASDU
	last := ""
	for _, p := range st.points {
		if (p.Type == "M_IT_NA_1") != counters {
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
	if qoi != asdu.QOIStation {
		_ = s.Negative(req)
		return
	}
	_ = s.Confirm(req)
	for _, a := range st.report(qoi.Cause(), req.Originator, false) {
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
	for _, a := range st.report(ci.Cause(), req.Originator, true) {
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
