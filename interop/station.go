//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

// station is a go-iec104 server that behaves as the fixture prescribes: the
// library under test in the role of the controlled station. It is written
// against the public API only, the way an application would be.
type station struct {
	ca asdu.CommonAddr

	mu       sync.Mutex
	points   []*stationPoint // sorted by address
	commands map[asdu.IOA]*stationCommand
	clock    time.Time

	srv  *server.Server
	addr string
}

type stationPoint struct {
	fixturePoint
	quality asdu.Quality
}

type stationCommand struct {
	fixtureCommand
	target   *stationPoint
	selected bool
}

// startStation serves the fixture with go-iec104 on all interfaces, so that
// a client container can reach it through the Docker host gateway.
func startStation(t testing.TB, fx *fixture, opts ...server.Option) *station {
	t.Helper()
	st := &station{ca: fx.Station.CommonAddr, commands: map[asdu.IOA]*stationCommand{}}
	byIOA := map[asdu.IOA]*stationPoint{}
	for _, p := range fx.Points {
		sp := &stationPoint{fixturePoint: p}
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
		st.commands[c.IOA] = &stationCommand{fixtureCommand: c, target: byIOA[c.Target]}
	}

	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, st.interrogation)
	mux.HandleFunc(asdu.C_CI_NA_1, st.counterInterrogation)
	mux.HandleFunc(asdu.C_RD_NA_1, st.read)
	mux.HandleFunc(asdu.C_CS_NA_1, st.clockSync)
	mux.HandleFunc(asdu.C_TS_TA_1, func(s *server.Session, req *asdu.ASDU) { _ = s.Confirm(st.own(req)) })
	mux.Handle(server.HandlerFunc(st.command), server.ProcessCommands...)

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
	st.srv = srv
	st.addr = ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return st
}

// own returns req addressed to this station: a request to the broadcast
// address is answered with the station's own address.
func (st *station) own(req *asdu.ASDU) *asdu.ASDU {
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
func (st *station) report(cause asdu.Cause, originator uint8, counters bool) []*asdu.ASDU {
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

func (st *station) interrogation(s *server.Session, req *asdu.ASDU) {
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

func (st *station) counterInterrogation(s *server.Session, req *asdu.ASDU) {
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

func (st *station) read(s *server.Session, req *asdu.ASDU) {
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

func (st *station) clockSync(s *server.Session, req *asdu.ASDU) {
	st.mu.Lock()
	st.clock = req.First().(asdu.ClockSync).Time.Time
	st.mu.Unlock()
	_ = s.Confirm(st.own(req))
}

func (st *station) clockTime() time.Time {
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

func (st *station) command(s *server.Session, req *asdu.ASDU) {
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
