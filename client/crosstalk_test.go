// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// The tests in this file are about one thing: a request takes the answers
// that are its own and nothing else. Several requests share a connection,
// and so do spontaneous data and other stations behind the same link; what
// tells their ASDUs apart is the type, the cause, the common address and
// the information object address, and nothing else.
//
// talkative is a station that answers every request correctly, and around
// every ASDU of the answer sends what every other procedure would send: for
// the same common address and the same information object address wherever
// the procedure has one, and all of it once more as another station. Only
// what is truly indistinguishable from the answer to the request under test
// is left out; that is what ErrBusy is for. The confirmations in the chatter
// are negative and its values are not the station's, so a request that
// takes any of it fails or returns the wrong data.

const (
	xCA    asdu.CommonAddr = 1
	xOther asdu.CommonAddr = 2
	xIOA   asdu.IOA        = 7 // the address of the point, the command and the file
)

type chatter struct {
	procedure string
	// addressed procedures concern one information object: the station
	// also runs them for another object.
	addressed bool
	asdus     func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU
}

// mirror is a confirmation or termination. The chatter refuses: a request
// that takes one of these for its own answer fails.
func mirror(cause asdu.Cause, ca asdu.CommonAddr, o asdu.InformationObject) *asdu.ASDU {
	a := asdu.New(cause, ca, o)
	a.Negative = true
	return a
}

// everything is what the procedures of a station send.
var everything = []chatter{
	{"single command", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		o := asdu.SingleCommand{IOA: ioa, Value: true}
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, o), mirror(asdu.CauseActivationTerm, ca, o)}
	}},
	{"single command deactivation", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{mirror(asdu.CauseDeactivationCon, ca, asdu.SingleCommand{IOA: ioa, Value: true})}
	}},
	{"setpoint", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		o := asdu.SetpointScaled{IOA: ioa, Value: 5}
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, o), mirror(asdu.CauseActivationTerm, ca, o)}
	}},
	{"interrogation", false, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		var out []*asdu.ASDU
		for _, qoi := range []asdu.QOI{asdu.QOIStation, asdu.QOIGroup(1)} {
			o := asdu.Interrogation{Qualifier: qoi}
			out = append(out, mirror(asdu.CauseActivationCon, ca, o),
				asdu.New(qoi.Cause(), ca, asdu.SinglePoint{IOA: ioa, Value: false}),
				mirror(asdu.CauseActivationTerm, ca, o))
		}
		return out
	}},
	{"counter interrogation", false, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		o := asdu.CounterInterrogation{Request: asdu.CounterGeneral}
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, o),
			asdu.New(o.Cause(), ca, asdu.IntegratedTotal{IOA: ioa, Value: -1}),
			mirror(asdu.CauseActivationTerm, ca, o)}
	}},
	{"read", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{asdu.New(asdu.CauseRequest, ca, asdu.MeasuredScaled{IOA: ioa, Value: -1})}
	}},
	{"clock synchronization", false, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, asdu.ClockSync{Time: asdu.At(time.Unix(1, 0))})}
	}},
	{"test command", false, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, asdu.TestCommand{Counter: 9, Time: asdu.At(time.Unix(1, 0))})}
	}},
	{"reset process", false, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, asdu.ResetProcess{Qualifier: asdu.ResetProcessGeneral})}
	}},
	{"directory", false, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{asdu.New(asdu.CauseRequest, ca,
			asdu.FileDirectoryEntry{IOA: ioa, Name: 1, Length: 1, Status: asdu.FileLastOfDirectory, Time: asdu.At(time.Unix(1, 0))})}
	}},
	{"file transfer", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{
			asdu.New(asdu.CauseFileTransfer, ca, asdu.FileReady{IOA: ioa, Name: 1, Length: 1}),
			asdu.New(asdu.CauseFileTransfer, ca, asdu.SectionReady{IOA: ioa, Name: 1, Section: 1, Length: 1}),
			asdu.New(asdu.CauseFileTransfer, ca, asdu.FileSegment{IOA: ioa, Name: 1, Section: 1, Data: []byte{0xEE}}),
			asdu.New(asdu.CauseFileTransfer, ca, asdu.FileLastSegment{IOA: ioa, Name: 1, Section: 1, Qualifier: 3, Checksum: 0xEE}),
		}
	}},
	{"process data", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{
			asdu.New(asdu.CauseSpontaneous, ca, asdu.SinglePoint{IOA: ioa, Value: false}),
			asdu.New(asdu.CauseSpontaneous, ca, asdu.MeasuredScaled{IOA: ioa, Value: -1}),
			asdu.New(asdu.CausePeriodic, ca, asdu.MeasuredScaled{IOA: ioa, Value: -1}),
			asdu.New(asdu.CauseBackground, ca, asdu.SinglePoint{IOA: ioa, Value: false}),
			asdu.New(asdu.CauseReturnRemote, ca, asdu.SinglePoint{IOA: ioa, Value: false}),
			asdu.New(asdu.CauseSpontaneous, ca, asdu.IntegratedTotal{IOA: ioa, Value: -1}),
		}
	}},
	{"refusals of other commands", true, func(ca asdu.CommonAddr, ioa asdu.IOA) []*asdu.ASDU {
		return []*asdu.ASDU{mirror(asdu.CauseActivationCon, ca, asdu.DoubleCommand{IOA: ioa, Value: 1}), mirror(asdu.CauseUnknownIOA, ca, asdu.StepCommand{IOA: ioa, Value: 1})}
	}},
}

type talkative struct {
	// own is the procedure of the request under test: the one thing the
	// station does not chatter about for its own common address.
	own atomic.Pointer[[]string]
	// quiet turns the chatter off, for a reference run.
	quiet atomic.Bool

	files *server.FileServer
	mu    sync.Mutex
	put   map[asdu.IOA][]byte
	sent  atomic.Int64
}

var xContent = bytes.Repeat([]byte{0x5A, 0xA5, 0x01}, 700)

func newTalkative() *talkative {
	st := &talkative{put: map[asdu.IOA][]byte{}}
	st.files = server.NewFileServer(server.FileSourceFunc(
		func(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA, _ uint16) (server.File, bool) {
			return server.NewFile(xContent, 800), ca == xCA && ioa == xIOA
		}))
	st.files.Sink = st
	st.files.Directory = func(*server.Session, asdu.CommonAddr, asdu.IOA) []asdu.FileDirectoryEntry {
		return []asdu.FileDirectoryEntry{{IOA: xIOA, Name: 1, Length: uint32(len(xContent))}, {IOA: xIOA + 2, Name: 1, Length: 3}}
	}
	return st
}

func (st *talkative) AcceptFile(*server.Session, asdu.CommonAddr, asdu.IOA, uint16, int) bool {
	return true
}

func (st *talkative) StoreFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, f server.File) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.put[ioa] = bytes.Join(f.Sections, nil)
	return nil
}

// chat sends what every other procedure would send.
func (st *talkative) chat(s *server.Session) {
	if st.quiet.Load() {
		return
	}
	own := *st.own.Load()
	say := func(as []*asdu.ASDU) {
		for _, a := range as {
			_ = s.Send(s.Context(), a)
			st.sent.Add(1)
		}
	}
	for _, c := range everything {
		mine := false
		for _, o := range own {
			mine = mine || o == c.procedure
		}
		if !mine {
			say(c.asdus(xCA, xIOA))
		}
		// The procedure under test included: for another object, and as
		// another station behind the same link.
		if c.addressed {
			say(c.asdus(xCA, xIOA+50))
		}
		say(c.asdus(xOther, xIOA))
	}
}

func (st *talkative) HandleASDU(s *server.Session, req *asdu.ASDU) {
	st.chat(s)
	defer st.chat(s)
	send := func(a *asdu.ASDU) {
		_ = s.Send(s.Context(), a)
		st.chat(s)
	}
	switch o := req.First().(type) {
	case asdu.SingleCommand, asdu.SetpointScaled:
		if req.Cause == asdu.CauseDeactivation {
			_ = s.Reply(req, asdu.CauseDeactivationCon, false)
			return
		}
		_ = s.Confirm(req)
	case asdu.Interrogation:
		_ = s.Confirm(req)
		st.chat(s)
		send(asdu.New(o.Qualifier.Cause(), req.CommonAddr, asdu.SinglePoint{IOA: xIOA, Value: true}, asdu.SinglePoint{IOA: xIOA + 1, Value: true}))
		send(asdu.New(o.Qualifier.Cause(), req.CommonAddr, asdu.MeasuredScaled{IOA: xIOA + 2, Value: 77}))
		_ = s.Terminate(req)
	case asdu.CounterInterrogation:
		_ = s.Confirm(req)
		st.chat(s)
		send(asdu.New(o.Cause(), req.CommonAddr, asdu.IntegratedTotal{IOA: xIOA, Value: 42}))
		_ = s.Terminate(req)
	case asdu.Read:
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr, asdu.MeasuredScaled{IOA: o.IOA, Value: 1234}))
	case asdu.ClockSync, asdu.TestCommand, asdu.ResetProcess:
		_ = s.Confirm(req)
	default:
		st.files.HandleASDU(s, req)
	}
}

// requests are the request methods of a client, each with the procedures
// whose ASDUs answer it and a check of what it returned.
var requests = []struct {
	name string
	own  []string
	run  func(ctx context.Context, c *client.Client, st *talkative) error
}{
	{"Command", []string{"single command"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		return c.Command(ctx, xCA, asdu.SingleCommand{IOA: xIOA, Value: true})
	}},
	{"Deactivate", []string{"single command deactivation"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		return c.Deactivate(ctx, xCA, asdu.SingleCommand{IOA: xIOA, Value: true})
	}},
	{"Command setpoint", []string{"setpoint"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		return c.Command(ctx, xCA, asdu.SetpointScaled{IOA: xIOA, Value: 5})
	}},
	{"Interrogate", []string{"interrogation"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		data, err := c.Interrogate(ctx, xCA, asdu.QOIStation)
		if err != nil {
			return err
		}
		return wantData(data, asdu.QOIStation.Cause(), "true true 77")
	}},
	{"Interrogate group", []string{"interrogation"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		data, err := c.Interrogate(ctx, xCA, asdu.QOIGroup(1))
		if err != nil {
			return err
		}
		return wantData(data, asdu.QOIGroup(1).Cause(), "true true 77")
	}},
	{"CounterInterrogate", []string{"counter interrogation"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		data, err := c.CounterInterrogate(ctx, xCA, asdu.CounterGeneral, asdu.FreezeRead)
		if err != nil {
			return err
		}
		return wantData(data, asdu.CauseCounterGeneral, "42")
	}},
	{"Read", []string{"read"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		a, err := c.Read(ctx, xCA, xIOA)
		if err != nil {
			return err
		}
		return wantData([]*asdu.ASDU{a}, asdu.CauseRequest, "1234")
	}},
	{"ClockSync", []string{"clock synchronization"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		return c.ClockSync(ctx, xCA, time.Now())
	}},
	{"TestCommand", []string{"test command"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		return c.TestCommand(ctx, xCA)
	}},
	{"ResetProcess", []string{"reset process"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		return c.ResetProcess(ctx, xCA, asdu.ResetProcessGeneral)
	}},
	{"GetFile", []string{"file transfer"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		got, err := c.GetFile(ctx, xCA, xIOA, 1)
		if err == nil && !bytes.Equal(got, xContent) {
			err = fmt.Errorf("fetched %d octets that are not the file", len(got))
		}
		return err
	}},
	{"PutFile", []string{"file transfer"}, func(ctx context.Context, c *client.Client, st *talkative) error {
		if err := c.PutFile(ctx, xCA, xIOA, 1, xContent[:900], xContent[900:]); err != nil {
			return err
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		if !bytes.Equal(st.put[xIOA], xContent) {
			return fmt.Errorf("the station stored %d octets that are not the file", len(st.put[xIOA]))
		}
		return nil
	}},
	{"ListFiles", []string{"directory"}, func(ctx context.Context, c *client.Client, _ *talkative) error {
		dir, err := c.ListFiles(ctx, xCA, 0)
		if err != nil {
			return err
		}
		if len(dir) != 2 || dir[0].IOA != xIOA || dir[1].IOA != xIOA+2 || dir[0].Length != uint32(len(xContent)) {
			return fmt.Errorf("directory %+v is not the station's", dir)
		}
		return nil
	}},
}

// exclusive names what a request shares with others that cannot run at the
// same time: one command procedure per object, one interrogation per
// station, one transfer per file.
func exclusive(request string) string {
	switch request {
	case "Command", "Deactivate":
		return "the single command"
	case "Interrogate", "Interrogate group":
		return "the interrogation"
	case "GetFile", "PutFile":
		return "the file"
	}
	return request
}

// settle returns when everything the station has sent so far has been
// taken in: answers arrive in the order they were sent, and this one is
// like no other.
func settle(t *testing.T, c *client.Client) {
	t.Helper()
	a, err := c.Read(context.Background(), xCA, 9999)
	if err != nil || a.First().Address() != 9999 {
		t.Fatalf("settling: %v, %v", a, err)
	}
}

// wantData checks what a request collected: only ASDUs of the station that
// was asked, with the cause of the request, holding the values the station
// answered with. The chatter carries other values.
func wantData(data []*asdu.ASDU, cause asdu.Cause, want string) error {
	var got []string
	for _, a := range data {
		if a.CommonAddr != xCA || a.Cause != cause {
			return fmt.Errorf("collected %s, which does not answer the request", a)
		}
		for _, o := range a.Objects {
			switch v := o.(type) {
			case asdu.SinglePoint:
				got = append(got, fmt.Sprint(v.Value))
			case asdu.MeasuredScaled:
				got = append(got, fmt.Sprint(v.Value))
			case asdu.IntegratedTotal:
				got = append(got, fmt.Sprint(v.Value))
			default:
				return fmt.Errorf("collected %s, which does not answer the request", a)
			}
		}
	}
	if s := strings.Join(got, " "); s != want {
		return fmt.Errorf("the request returned the values %q, want %q", s, want)
	}
	return nil
}

// Every request, alone on the connection with a station that will not stop
// talking about everything else.
func TestRequestTakesOnlyItsOwnAnswers(t *testing.T) {
	st := newTalkative()
	c := dial(t, serveHandler(t, st))
	ctx := context.Background()
	for _, r := range requests {
		t.Run(r.name, func(t *testing.T) {
			own := r.own
			st.own.Store(&own)
			// The reference: the station answers and says nothing else.
			st.quiet.Store(true)
			settle(t, c)
			if err := r.run(ctx, c, st); err != nil {
				t.Fatalf("with a quiet station: %v", err)
			}
			st.quiet.Store(false)
			before := st.sent.Load()
			for i := 0; i < 3; i++ {
				if err := r.run(ctx, c, st); err != nil {
					t.Fatalf("with a talkative station: %v", err)
				}
			}
			if st.sent.Load() == before {
				t.Fatal("the station did not chatter")
			}
		})
	}
}

// Every pair of requests at once on one connection, again and again: each
// returns what it returns alone.
func TestRequestsInPairs(t *testing.T) {
	st := newTalkative()
	st.quiet.Store(true)
	none := []string{}
	st.own.Store(&none)
	c := dial(t, serveHandler(t, st))
	ctx := context.Background()
	rounds := 25
	if testing.Short() {
		rounds = 5
	}
	for i, a := range requests {
		for _, b := range requests[i+1:] {
			if exclusive(a.name) == exclusive(b.name) {
				// The same procedure for the same object: one at a time,
				// which is what ErrBusy says.
				continue
			}
			t.Run(a.name+"+"+b.name, func(t *testing.T) {
				for round := 0; round < rounds; round++ {
					var wg sync.WaitGroup
					for _, r := range []int{0, 1} {
						wg.Add(1)
						go func() {
							defer wg.Done()
							req := a
							if r == 1 {
								req = b
							}
							if err := req.run(ctx, c, st); err != nil {
								t.Errorf("round %d: %s next to the other: %v", round, req.name, err)
							}
						}()
					}
					wg.Wait()
					if t.Failed() {
						return
					}
				}
			})
		}
	}
}

// All of them at once, each in its own loop.
func TestRequestsAllAtOnce(t *testing.T) {
	st := newTalkative()
	st.quiet.Store(true)
	none := []string{}
	st.own.Store(&none)
	c := dial(t, serveHandler(t, st), client.WithRequestTimeout(10*time.Second))
	ctx := context.Background()
	// One request of each procedure: two of one procedure for the same
	// object are not told apart.
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for _, r := range requests {
		if seen[exclusive(r.name)] {
			continue
		}
		seen[exclusive(r.name)] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				if err := r.run(ctx, c, st); err != nil {
					t.Errorf("%s, call %d: %v", r.name, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
