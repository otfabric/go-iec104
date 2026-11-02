//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/station"
)

// scenario is one operation of a reference client and the outcome expected
// of a station that serves the baseline fixture.
type scenario struct {
	// mutates marks operations that change the station: they get a fresh
	// station (and a fresh reference server to compare with).
	mutates bool
	args    string
	want    string
}

// needs returns the features a reference client must declare to run the
// scenario.
func (sc scenario) needs() []string {
	var out []string
	if strings.Contains(sc.args, "--with-time") {
		out = append(out, featTimeTaggedCommands)
	}
	if strings.HasPrefix(sc.args, "file-get") {
		out = append(out, featFileClient)
	}
	return out
}

// fileASDUs is what a download of n segments in one section looks like.
func fileASDUs(sections ...int) string {
	s := "F_FR_NA_1/13"
	for _, segments := range sections {
		s += ",F_SR_NA_1/13" + strings.Repeat(",F_SG_NA_1/13", segments) + ",F_LS_NA_1/13"
	}
	return s + ",F_LS_NA_1/13"
}

const giASDUs = "C_IC_NA_1/7,M_SP_NA_1/20,M_DP_NA_1/20,M_ST_NA_1/20,M_BO_NA_1/20,M_SP_NA_1/20," +
	"M_ME_NA_1/20,M_ME_NB_1/20,M_ME_NC_1/20,M_ME_NB_1/20,C_IC_NA_1/10"

var scenarios = []scenario{
	{false, "connect", "exit=0 ok=true error=- conf= term=false asdus="},
	{false, "interrogate", "exit=0 ok=true error=- conf=7 term=true asdus=" + giASDUs},
	{false, "interrogate --common-address 65535", "exit=0 ok=true error=- conf=7 term=true asdus=" + giASDUs},
	{false, "interrogate --common-address 7", "exit=1 ok=false error=negative-confirmation conf=46n term=false asdus=C_IC_NA_1/46"},
	{false, "interrogate --qoi 21", "exit=1 ok=false error=negative-confirmation conf=7n term=false asdus=C_IC_NA_1/7"},
	{false, "counter-interrogate", "exit=0 ok=true error=- conf=7 term=true asdus=C_CI_NA_1/7,M_IT_NA_1/37,C_CI_NA_1/10"},
	{false, "counter-interrogate --qcc 69", "exit=1 ok=false error=negative-confirmation conf=7n term=false asdus=C_CI_NA_1/7"},
	{false, "read --ioa 100", "exit=0 ok=true error=- conf= term=false asdus=M_SP_NA_1/5"},
	{false, "read --ioa 202", "exit=0 ok=true error=- conf= term=false asdus=M_ME_NC_1/5"},
	{false, "read --ioa 300", "exit=0 ok=true error=- conf= term=false asdus=M_IT_NA_1/5"},
	{false, "read --ioa 999", "exit=1 ok=false error=negative-confirmation conf=47n term=false asdus=C_RD_NA_1/47"},
	{false, "clock-sync --time 2026-10-09T15:35:12.345Z", "exit=0 ok=true error=- conf=7 term=false asdus=C_CS_NA_1/7"},
	{false, "test-command", "exit=0 ok=true error=- conf=7 term=false asdus=C_TS_TA_1/7"},
	{false, "monitor --duration-ms 300", "exit=0 ok=true error=- conf= term=false asdus="},
	{false, "command --type C_SC_NA_1 --ioa 999 --value true", "exit=1 ok=false error=negative-confirmation conf=47n term=false asdus=C_SC_NA_1/47"},
	{false, "command --type C_DC_NA_1 --ioa 500 --value 1", "exit=1 ok=false error=negative-confirmation conf=47n term=false asdus=C_DC_NA_1/47"},
	{false, "command --type C_DC_NA_1 --ioa 501 --value 3", "exit=1 ok=false error=negative-confirmation conf=7n term=false asdus=C_DC_NA_1/7"},
	{false, "command --type C_DC_NA_1 --ioa 501 --value 0 --mode select", "exit=1 ok=false error=negative-confirmation conf=7n term=false asdus=C_DC_NA_1/7"},
	{false, "command --type C_SC_NA_1 --ioa 510 --value true", "exit=1 ok=false error=negative-confirmation conf=7n term=false asdus=C_SC_NA_1/7"},
	{true, "command --type C_SC_NA_1 --ioa 500 --value false", "exit=0 ok=true error=- conf=7 term=true asdus=C_SC_NA_1/7,M_SP_TB_1/11,C_SC_NA_1/10"},
	{true, "command --type C_SC_NA_1 --ioa 500 --value false --with-time --qualifier 2", "exit=0 ok=true error=- conf=7 term=true asdus=C_SC_TA_1/7,M_SP_TB_1/11,C_SC_TA_1/10"},
	{true, "command --type C_DC_NA_1 --ioa 501 --value 1 --mode sbo", "exit=0 ok=true error=- conf=7,7 term=true asdus=C_DC_NA_1/7,C_DC_NA_1/7,M_DP_TB_1/3,C_DC_NA_1/10"},
	{true, "command --type C_RC_NA_1 --ioa 505 --value 2", "exit=0 ok=true error=- conf=7 term=true asdus=C_RC_NA_1/7,M_ST_TB_1/11,C_RC_NA_1/10"},
	{true, "command --type C_RC_NA_1 --ioa 505 --value 1 --with-time", "exit=0 ok=true error=- conf=7 term=true asdus=C_RC_TA_1/7,M_ST_TB_1/11,C_RC_TA_1/10"},
	{true, "command --type C_SE_NA_1 --ioa 503 --value -12345", "exit=0 ok=true error=- conf=7 term=true asdus=C_SE_NA_1/7,M_ME_TD_1/11,C_SE_NA_1/10"},
	{true, "command --type C_SE_NB_1 --ioa 504 --value -7 --with-time", "exit=0 ok=true error=- conf=7 term=true asdus=C_SE_TB_1/7,M_ME_TE_1/11,C_SE_TB_1/10"},
	{true, "command --type C_SE_NC_1 --ioa 502 --value 49.5 --mode sbo --with-time", "exit=0 ok=true error=- conf=7,7 term=true asdus=C_SE_TC_1/7,C_SE_TC_1/7,M_ME_TF_1/11,C_SE_TC_1/10"},
	{true, "command --type C_SC_NA_1 --ioa 510 --value false --mode sbo", "exit=0 ok=true error=- conf=7,7 term=true asdus=C_SC_NA_1/7,C_SC_NA_1/7,M_SP_TB_1/11,C_SC_NA_1/10"},
	{true, "command --type C_SC_NA_1 --ioa 510 --value true --mode cancel", "exit=0 ok=true error=- conf=7,9 term=false asdus=C_SC_NA_1/7,C_SC_NA_1/9"},
	{true, "command --type C_SC_NA_1 --ioa 510 --value true --mode select", "exit=0 ok=true error=- conf=7 term=false asdus=C_SC_NA_1/7"},
	// File transfer: 1000 octets in one section, 5000 in sections of 2048,
	// segments of 236.
	{false, "file-get --ioa 30000", "exit=0 ok=true error=- conf= term=false asdus=" + fileASDUs(5)},
	{false, "file-get --ioa 30001", "exit=0 ok=true error=- conf= term=false asdus=" + fileASDUs(9, 9, 4)},
	{false, "file-get --ioa 39999", "exit=1 ok=false error=negative-confirmation conf= term=false asdus=F_SC_NA_1/47"},
	{false, "file-get --ioa 30000 --name 9", "exit=1 ok=false error=negative-confirmation conf= term=false asdus=F_SC_NA_1/47"},
}

// reference returns the server a scenario's outcome is compared with: the
// one of the client's own stack, or for file transfer, which not every
// stack serves, any reference that does. It returns nil when there is none.
func reference(t *testing.T, a adapter, sc scenario) *adapter {
	if !strings.HasPrefix(sc.args, "file-get") || a.has(t, featFileServer) {
		return &a
	}
	for _, other := range adapters(t) {
		if other.has(t, featFileServer) {
			return &other
		}
	}
	return nil
}

// TestServerScenarios drives a go-iec104 station with every reference client
// and checks two things for each operation: that the outcome is what the
// standard prescribes, and that the client cannot tell the go-iec104 station
// from the reference server of its own stack. The second check compares the
// complete result documents: every ASDU, in order, field by field.
func TestServerScenarios(t *testing.T) {
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			fx := loadFixture(t, a)
			sharedStation := station.Start(t, fx)
			// The reference servers the scenarios that leave the station
			// alone are compared with, by adapter.
			shared := map[string]*refServer{}
			for _, sc := range scenarios {
				if sc.mutates || !a.hasAll(t, sc.needs()...) {
					continue
				}
				if other := reference(t, a, sc); other != nil && shared[other.name] == nil {
					shared[other.name] = startServer(t, *other)
				}
			}
			for _, sc := range scenarios {
				t.Run(strings.ReplaceAll(sc.args, " ", "_"), func(t *testing.T) {
					a.need(t, sc.needs()...)
					st := sharedStation
					if sc.mutates {
						st = station.Start(t, fx)
					}
					args := strings.Fields(sc.args)
					got := runClient(t, a, st.Addr, args...)
					readBug := args[0] == "read" && a.knownReadBug(t)
					if s := got.summary(); s != sc.want {
						if readBug {
							t.Skipf("known bug of %s (it cannot decode the mirrored C_RD_NA_1): got %s", a.name, s)
						}
						t.Fatalf("%s client against go-iec104:\n got  %s\n want %s", a.name, s, sc.want)
					}
					if readBug {
						t.Skipf("known bug of %s: its server cannot receive a read, so there is nothing to compare with", a.name)
					}

					other := reference(t, a, sc)
					if other == nil {
						t.Logf("no reference serves this: the outcome is checked, the documents are not compared")
						return
					}
					ref := shared[other.name]
					if sc.mutates {
						ref = startServer(t, *other)
					}
					want := runClientAgainst(t, a, ref, args...)
					if s := want.summary(); s != sc.want {
						t.Fatalf("%s client against the %s server (the comparison is void):\n got  %s\n want %s",
							a.name, other.name, s, sc.want)
					}
					if g, w := got.normalized(), want.normalized(); g != w {
						t.Errorf("%s client sees a difference between go-iec104 and the %s server.\n"+
							"--- go-iec104 ---\n%s\n--- %s server ---\n%s", a.name, other.name, g, other.name, w)
					}
				})
			}
		})
	}
}

// TestServerValues checks the data, not just the shape: what a reference
// client reads from a go-iec104 station is the fixture, and commands change
// it.
func TestServerValues(t *testing.T) {
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			fx := loadFixture(t, a)
			st := station.Start(t, fx)

			r := runClient(t, a, st.Addr, "interrogate")
			if got, want := observeResult(r, 20), fx.Expected(false); !station.SameObserved(got, want) {
				t.Errorf("interrogation:\n got  %v\n want %v", got, want)
			}
			r = runClient(t, a, st.Addr, "counter-interrogate")
			if got, want := observeResult(r, 37), fx.Expected(true); !station.SameObserved(got, want) {
				t.Errorf("counter interrogation:\n got  %v\n want %v", got, want)
			}

			// A clock synchronization arrives with the time the client sent.
			runClient(t, a, st.Addr, "clock-sync", "--time", "2026-10-09T15:35:12.345Z")
			want := time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)
			if got := st.ClockTime(); !got.Equal(want) {
				t.Errorf("clock set to %v, want %v", got, want)
			}

			// A set point is reported with a time tag and is visible afterwards.
			r = runClient(t, a, st.Addr, "command", "--type", "C_SE_NC_1", "--ioa", "502", "--value", "49.5")
			var reported bool
			for _, as := range r.ASDUs {
				if as.Type == "M_ME_TF_1" && as.Cot == 11 && len(as.Objects) == 1 {
					o := as.Objects[0]
					stamp, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(o["time"]))
					if o["ioa"] == 202.0 && o["value"] == 49.5 && time.Since(stamp).Abs() < time.Minute {
						reported = true
					}
				}
			}
			if !reported {
				t.Errorf("set point not reported as M_ME_TF_1 with a current time tag: %s", r.normalized())
			}
			r = runClient(t, a, st.Addr, "read", "--ioa", "202")
			if got := observeResult(r, 5); len(got) != 1 || got[0].Value != 49.5 {
				t.Errorf("read after set point: %v", got)
			}

			// Step commands move the position one step at a time.
			for i := 0; i < 3; i++ {
				runClient(t, a, st.Addr, "command", "--type", "C_RC_NA_1", "--ioa", "505", "--value", "2")
			}
			r = runClient(t, a, st.Addr, "read", "--ioa", "102")
			start := fx.Point(102).Value.(float64)
			if got := observeResult(r, 5); len(got) != 1 || got[0].Value != start+3 {
				t.Errorf("step position after three steps up from %v: %v", start, got)
			}

			// Select-before-operate: the selection is consumed by the execute.
			r = runClient(t, a, st.Addr, "command", "--type", "C_SC_NA_1", "--ioa", "510", "--value", "false", "--mode", "sbo")
			if !r.OK {
				t.Errorf("select and execute: %s", r.summary())
			}
			r = runClient(t, a, st.Addr, "command", "--type", "C_SC_NA_1", "--ioa", "510", "--value", "true")
			if r.OK || r.Error == nil || r.Error.Code != "negative-confirmation" {
				t.Errorf("execute without a new select was accepted: %s", r.summary())
			}
			r = runClient(t, a, st.Addr, "read", "--ioa", "100")
			if got := observeResult(r, 5); len(got) != 1 || got[0].Value != false {
				t.Errorf("single point after select and execute: %v", got)
			}
		})
	}
}

// TestServerSessions checks the connection handling a reference client
// exercises on a go-iec104 server: tight flow-control windows, the idle test
// and several controlling stations at once.
func TestServerSessions(t *testing.T) {
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			fx := loadFixture(t, a)
			st := station.Start(t, fx)

			// k=1, w=1: the client acknowledges every I frame and may not
			// have more than one of its own outstanding.
			r := runClient(t, a, st.Addr, "interrogate", "--k", "1", "--w", "1")
			if got, want := observeResult(r, 20), fx.Expected(false); !r.OK || !station.SameObserved(got, want) {
				t.Errorf("interrogation with k=1 w=1: %s", r.summary())
			}

			// An idle connection: the client's t3 (2s) expires several times
			// and go-iec104 must answer each TESTFR act within t1 (2s).
			r = runClient(t, a, st.Addr, "connect", "--hold-ms", "7000", "--t1", "2", "--t2", "1", "--t3", "2",
				"--timeout-ms", "3000")
			if !r.OK || !r.StopDT {
				t.Errorf("connection idle for 7s with t3=2s: %s", r.summary())
			}

			// Three clients at once, each with its own session.
			results := make(chan *result, 3)
			for i := 0; i < 3; i++ {
				go func() { results <- runClient(t, a, st.Addr, "interrogate", "--collect-ms", "500") }()
			}
			for i := 0; i < 3; i++ {
				r := <-results
				if got, want := observeResult(r, 20), fx.Expected(false); !r.OK || !station.SameObserved(got, want) {
					t.Errorf("concurrent interrogation %d: %s", i, r.summary())
				}
			}
		})
	}
}

// TestServerEventQueue: events a go-iec104 station queued while no
// controlling station was connected reach a reference client in order, and
// the client's acknowledgements empty the queue.
func TestServerEventQueue(t *testing.T) {
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			fx := loadFixture(t, a)
			st := station.Start(t, fx)
			const n = 30
			for i := 1; i <= n; i++ {
				ev := asdu.New(asdu.CauseSpontaneous, fx.Station.CommonAddr,
					asdu.MeasuredScaled{IOA: 201, Value: int16(i), Time: asdu.Now()})
				if err := st.Server.Enqueue(ev); err != nil {
					t.Fatal(err)
				}
			}
			if got := st.Server.Pending("default"); got != n {
				t.Fatalf("Pending = %d, want %d", got, n)
			}

			// w = 1: the client acknowledges every event at once. With a
			// larger w the last few would still be unacknowledged when the
			// client closes, and the station would rightly keep them for the
			// next connection.
			r := runClient(t, a, st.Addr, "monitor", "--duration-ms", "5000", "--max-asdus", "30",
				"--k", "1", "--w", "1", "--collect-ms", "500")
			if !r.OK || len(r.ASDUs) != n {
				t.Fatalf("monitor: %s", r.summary())
			}
			for i, as := range r.ASDUs {
				if as.Type != "M_ME_TE_1" || as.Cot != 3 || len(as.Objects) != 1 || as.Objects[0]["value"] != float64(i+1) {
					t.Fatalf("event %d: %s %v", i+1, as.Type, as.Objects)
				}
			}
			eventually(t, 5*time.Second, "queue acknowledged", func() bool { return st.Server.Pending("default") == 0 })

			// The next controlling station gets only what is new.
			if err := st.Server.Enqueue(asdu.New(asdu.CauseSpontaneous, fx.Station.CommonAddr,
				asdu.SinglePoint{IOA: 100, Value: false, Time: asdu.Now()})); err != nil {
				t.Fatal(err)
			}
			r = runClient(t, a, st.Addr, "monitor", "--duration-ms", "3000", "--max-asdus", "1", "--collect-ms", "300",
				"--k", "1", "--w", "1")
			if !r.OK || len(r.ASDUs) != 1 || r.ASDUs[0].Type != "M_SP_TB_1" {
				t.Fatalf("second monitor: %s", r.summary())
			}
		})
	}
}

// featureCase is one operation of a reference client against a go-iec104 station
// with the fixture extended, as iec104-interop states it for its own stations in
// tests/feature-cases.tsv.
type featureCase struct {
	args string
	want string
}

// runCases runs cases against the station.
func runCases(t *testing.T, a adapter, st *station.Station, cases []featureCase, dockerArgs ...string) {
	t.Helper()
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.args, " ", "_"), func(t *testing.T) {
			r := runClientWith(t, a, st.Addr, dockerArgs, strings.Fields(tc.args)...)
			if s := r.featureSummary(); s != tc.want {
				if strings.HasPrefix(tc.args, "read") && a.knownReadBug(t) {
					t.Skipf("known bug of %s, it cannot decode the mirrored C_RD_NA_1: got %s", a.name, s)
				}
				t.Errorf("%s client against go-iec104:\n got  %s\n want %s", a.name, s, tc.want)
			}
		})
	}
}

// TestServerGroups: the reference clients interrogate the groups of a go-iec104
// station, value by value.
func TestServerGroups(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx := loadExtended(t, a)
		st := station.Start(t, fx)
		const ok = "exit=0 ok=true error=- conf=7 term=true asdus=C_IC_NA_1/7,"
		const refused = "exit=1 ok=false error=negative-confirmation conf=7n term=false asdus=C_IC_NA_1/7"
		runCases(t, a, st, []featureCase{
			{"interrogate", ok + "M_SP_NA_1/20,M_DP_NA_1/20,M_BO_NA_1/20,M_ME_NB_1/20,M_ME_NC_1/20,C_IC_NA_1/10"},
			{"interrogate --qoi 21", ok + "M_SP_NA_1/21,M_DP_NA_1/21,C_IC_NA_1/10"},
			{"interrogate --qoi 22", ok + "M_BO_NA_1/22,C_IC_NA_1/10"},
			{"interrogate --qoi 23", ok + "M_BO_NA_1/23,M_ME_NB_1/23,C_IC_NA_1/10"},
			{"interrogate --qoi 36", ok + "M_ME_NB_1/36,C_IC_NA_1/10"},
			{"interrogate --qoi 30", refused},
			{"interrogate --qoi 21 --common-address 65535", ok + "M_SP_NA_1/21,M_DP_NA_1/21,C_IC_NA_1/10"},
			{"interrogate --qoi 21 --common-address 7", "exit=1 ok=false error=negative-confirmation conf=46n term=false asdus=C_IC_NA_1/46"},
		})
		for _, group := range []int{1, 2, 3, 16} {
			want := fx.ExpectedGroup(group)
			if len(want) == 0 {
				t.Fatalf("fixture extended has no point in group %d", group)
			}
			r := runClient(t, a, st.Addr, "interrogate", "--qoi", strconv.Itoa(20+group))
			if got := observeResult(r, 20+group); !station.SameObserved(got, want) {
				t.Errorf("group %d:\n got  %v\n want %v", group, got, want)
			}
		}
		// The baseline has no group, so all of them are refused there.
		base := station.Start(t, loadFixture(t, a))
		if s := runClient(t, a, base.Addr, "interrogate", "--qoi", "21").summary(); s != refused {
			t.Errorf("a group of a fixture without groups:\n got  %s\n want %s", s, refused)
		}
	}, featGroups, featBitstringQ)
}

// TestServerBitstringQuality: what a reference client reads from a go-iec104
// station is the value and the quality of the fixture.
func TestServerBitstringQuality(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx := loadExtended(t, a)
		st := station.Start(t, fx)
		var want []station.Observed
		for _, o := range fx.Expected(false) {
			if o.Type == "M_BO_NA_1" {
				want = append(want, o)
			}
		}
		if len(want) != 3 || want[0].Quality != "" || want[1].Quality != "OV IV" || want[2].Quality != "BL SB NT" {
			t.Fatalf("fixture extended changed: %v", want)
		}
		var got []station.Observed
		for _, o := range observeResult(runClient(t, a, st.Addr, "interrogate"), 20) {
			if o.Type == "M_BO_NA_1" {
				got = append(got, o)
			}
		}
		if !station.SameObserved(got, want) {
			t.Errorf("interrogation:\n got  %v\n want %v", got, want)
		}
		for _, w := range want {
			r := runClient(t, a, st.Addr, "read", "--ioa", strconv.Itoa(int(w.IOA)))
			if got := observeResult(r, 5); len(got) != 1 || got[0] != w {
				t.Errorf("read %d: got %v, want %v (%s)", w.IOA, got, w, r.summary())
			}
		}
	}, featBitstringQ)
}

// fileASDUsUp is what the file-put of n sections brings back from the station.
func fileASDUsUp(n int) string {
	return "F_SC_NA_1/13" + strings.Repeat(",F_SC_NA_1/13,F_AF_NA_1/13", n) + ",F_AF_NA_1/13"
}

// TestServerUpload: the reference clients send a file to a go-iec104 station,
// which has what the fixture's rule says, and refuses what its uploads do not take.
func TestServerUpload(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx := loadExtended(t, a)
		up := fx.Uploads[0]
		for _, tc := range []struct {
			size, sectionSize, sections int
		}{{1000, 1000, 1}, {5000, 2048, 3}, {up.MaxSize, 2048, 4}} {
			t.Run(strconv.Itoa(tc.size), func(t *testing.T) {
				st := station.Start(t, fx)
				r := runClient(t, a, st.Addr, "file-put", "--ioa", strconv.Itoa(int(up.IOA)),
					"--size", strconv.Itoa(tc.size), "--section-size", strconv.Itoa(tc.sectionSize))
				want := fmt.Sprintf("exit=0 ok=true error=- conf= term=false asdus=%s file=%d/%d/%d",
					fileASDUsUp(tc.sections), tc.size, tc.size, tc.sections)
				if s := r.featureSummary(); s != want {
					t.Errorf("file-put:\n got  %s\n want %s", s, want)
				}
				if r.File == nil || r.File.SHA256 != fileHash(up.IOA, tc.size) {
					t.Errorf("file-put reports %+v, want sha256 %s", r.File, fileHash(up.IOA, tc.size))
				}
				got, ok := st.Uploaded(up.IOA)
				if !ok {
					t.Fatal("the station has no file")
				}
				sum := sha256.Sum256(got)
				if h := hex.EncodeToString(sum[:]); !bytes.Equal(got, fileContent(up.IOA, tc.size)) || h != fileHash(up.IOA, tc.size) {
					t.Errorf("the station has %d octets with sha256 %s, want %d with %s", len(got), h, tc.size, fileHash(up.IOA, tc.size))
				}
				// It is in the directory, and can be fetched again.
				if a.has(t, featDirectoryClient) {
					d := runClient(t, a, st.Addr, "file-dir")
					want := []resultDirectory{{int(fx.Files[0].IOA), int(fx.Files[0].Name), fx.Files[0].Size, 0},
						{int(fx.Files[1].IOA), int(fx.Files[1].Name), fx.Files[1].Size, 0},
						{int(up.IOA), int(up.Name), tc.size, 32}}
					if !slices.Equal(d.Directory, want) {
						t.Errorf("directory: %+v, want %+v", d.Directory, want)
					}
				}
				if a.has(t, featFileClient) {
					g := runClient(t, a, st.Addr, "file-get", "--ioa", strconv.Itoa(int(up.IOA)), "--name", strconv.Itoa(int(up.Name)))
					if !g.OK || g.File == nil || g.File.SHA256 != fileHash(up.IOA, tc.size) {
						t.Errorf("file-get of the file sent: %s", g.featureSummary())
					}
				}
			})
		}

		st := station.Start(t, fx)
		const ok = "exit=1 ok=false error=negative-confirmation conf= term=false asdus=F_FR_NA_1/47 file="
		runCases(t, a, st, []featureCase{
			{"file-put --ioa 39999 --size 1000", ok + "1000/0/0"},
			{"file-put --ioa 31000 --name 9 --size 1000", ok + "1000/0/0"},
			{"file-put --ioa 31000 --size 8193 --section-size 2048", ok + "8193/0/0"},
			{"file-put --ioa 30000 --size 1000", ok + "1000/0/0"},
		})
		for _, ioa := range []asdu.IOA{39999, 31000, 30000} {
			if _, stored := st.Uploaded(ioa); stored {
				t.Errorf("a refused upload is stored at %d", ioa)
			}
		}
	}, featUploadClient)
}

// TestServerDirectory: a reference client lists the files of a go-iec104 station.
func TestServerDirectory(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		const prefix = "exit=0 ok=true error=- conf= term=false asdus=F_DR_TA_1/5 directory="
		runCases(t, a, station.Start(t, loadExtended(t, a)), []featureCase{{"file-dir", prefix + "30000:1:1000:0,30001:2:5000:32"}})
		fx := loadFixture(t, a)
		st := station.Start(t, fx)
		runCases(t, a, st, []featureCase{{"file-dir", prefix + "30000:1:1000:0,30001:1:5000:32"}})
		// Against the fixture, not a copy of it.
		r := runClient(t, a, st.Addr, "file-dir")
		if len(r.Directory) != len(fx.Files) {
			t.Fatalf("directory: %+v, want the files of %+v", r.Directory, fx.Files)
		}
		for i, f := range fx.Files {
			if e := r.Directory[i]; e.IOA != int(f.IOA) || e.NOF != int(f.Name) || e.LOF != f.Size {
				t.Errorf("entry %d: %+v, want %+v", i, e, f)
			}
		}
	}, featDirectoryClient)
}

// TestServerRedundancy: a reference client with two connections to a go-iec104
// station in a redundancy group, switching over in both ways.
func TestServerRedundancy(t *testing.T) {
	const station1 = "C_IC_NA_1/7,M_SP_NA_1/20,M_DP_NA_1/20,M_BO_NA_1/20,M_ME_NB_1/20,M_ME_NC_1/20,C_IC_NA_1/10"
	forEachAdapter(t, func(t *testing.T, a adapter) {
		fx := loadExtended(t, a)
		for _, tc := range []struct {
			name, want, flags string
		}{
			{"stopdt", "exit=0 ok=true error=- conf=7,7 term=true asdus=" + station1 + ",M_SP_NA_1/3," + station1 + " redundancy=7/8/0/true", ""},
			{"takeover", "exit=0 ok=true error=- conf=7,7 term=true asdus=" + station1 + "," + station1 + " redundancy=7/7/0/false", "--switchover takeover"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				st := station.StartGroup(t, fx)
				r := runClient(t, a, st.Addr, append([]string{"redundancy"}, strings.Fields(tc.flags)...)...)
				if s := r.featureSummary(); s != tc.want {
					t.Errorf("%s client against go-iec104:\n got  %s\n want %s", a.name, s, tc.want)
				}
				if r.Redundancy == nil || r.Redundancy.Switchover != tc.name {
					t.Errorf("redundancy: %+v", r.Redundancy)
				}
				if !r.Connected || !r.StartDT || !r.StopDT {
					t.Errorf("connected %v, startdt %v, stopdt %v", r.Connected, r.StartDT, r.StopDT)
				}
				// The event of the last STOPDT waits for the next connection.
				eventually(t, 5*time.Second, "one event left in the queue", func() bool {
					return st.Server.Pending(station.GroupName) == 1
				})
			})
		}
		t.Run("event value", func(t *testing.T) {
			// The event carries the state of the station. The command's
			// connection ends without STOPDT, which queues nothing.
			st := station.StartGroup(t, fx)
			if r := runClient(t, a, st.Addr, "command", "--type", "C_SC_NA_1", "--ioa", "500", "--value", "false"); !r.OK {
				t.Fatalf("command: %s", r.summary())
			}
			eventually(t, 5*time.Second, "the command's connection closed", func() bool { return len(st.Server.Sessions()) == 0 })
			if p := st.Server.Pending(station.GroupName); p != 0 {
				t.Errorf("Pending = %d after a connection ended, want 0", p)
			}
			r := runClient(t, a, st.Addr, "redundancy")
			if !r.OK {
				t.Fatalf("redundancy: %s", r.featureSummary())
			}
			want := fx.Expected(false)[0]
			want.Value = false
			got := observeResult(r, int(asdu.CauseSpontaneous))
			if len(got) != 1 || got[0] != want {
				t.Errorf("queued events: %v, want %v", got, want)
			}
			for _, as := range r.ASDUs {
				if as.Cot == int(asdu.CauseSpontaneous) && as.Originator != 0 {
					t.Errorf("queued event with originator %d", as.Originator)
				}
			}
		})
		t.Run("no group", func(t *testing.T) {
			// The same station without a group has no queue.
			st := station.Start(t, fx)
			r := runClient(t, a, st.Addr, "redundancy", "--timeout-ms", "2000")
			want := "exit=1 ok=false error=timeout conf=7 term=true asdus=" + station1 + " redundancy=7/0/0/false"
			if s := r.featureSummary(); s != want {
				t.Errorf("%s client against go-iec104:\n got  %s\n want %s", a.name, s, want)
			}
		})
	}, featRedundClient)
}
