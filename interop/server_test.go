//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"fmt"
	"strings"
	"testing"
	"time"
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
			sharedStation := startStation(t, fx)
			sharedRef := startServer(t, a)
			for _, sc := range scenarios {
				t.Run(strings.ReplaceAll(sc.args, " ", "_"), func(t *testing.T) {
					st, ref := sharedStation, sharedRef
					if sc.mutates {
						st, ref = startStation(t, fx), startServer(t, a)
					}
					args := strings.Fields(sc.args)
					got := runClient(t, a, st.addr, args...)
					if s := got.summary(); s != sc.want {
						t.Fatalf("%s client against go-iec104:\n got  %s\n want %s", a.name, s, sc.want)
					}
					want := runClientAgainst(t, a, ref, args...)
					if s := want.summary(); s != sc.want {
						t.Fatalf("%s client against its own server (the comparison is void):\n got  %s\n want %s", a.name, s, sc.want)
					}
					if g, w := got.normalized(), want.normalized(); g != w {
						t.Errorf("%s client sees a difference between go-iec104 and its own server.\n"+
							"--- go-iec104 ---\n%s\n--- %s server ---\n%s", a.name, g, a.name, w)
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
			st := startStation(t, fx)

			r := runClient(t, a, st.addr, "interrogate")
			if got, want := observeResult(r, 20), fx.expected(false); !sameObserved(got, want) {
				t.Errorf("interrogation:\n got  %v\n want %v", got, want)
			}
			r = runClient(t, a, st.addr, "counter-interrogate")
			if got, want := observeResult(r, 37), fx.expected(true); !sameObserved(got, want) {
				t.Errorf("counter interrogation:\n got  %v\n want %v", got, want)
			}

			// A clock synchronization arrives with the time the client sent.
			runClient(t, a, st.addr, "clock-sync", "--time", "2026-10-09T15:35:12.345Z")
			want := time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)
			if got := st.clockTime(); !got.Equal(want) {
				t.Errorf("clock set to %v, want %v", got, want)
			}

			// A set point is reported with a time tag and is visible afterwards.
			r = runClient(t, a, st.addr, "command", "--type", "C_SE_NC_1", "--ioa", "502", "--value", "49.5")
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
			r = runClient(t, a, st.addr, "read", "--ioa", "202")
			if got := observeResult(r, 5); len(got) != 1 || got[0].Value != 49.5 {
				t.Errorf("read after set point: %v", got)
			}

			// Step commands move the position one step at a time.
			for i := 0; i < 3; i++ {
				runClient(t, a, st.addr, "command", "--type", "C_RC_NA_1", "--ioa", "505", "--value", "2")
			}
			r = runClient(t, a, st.addr, "read", "--ioa", "102")
			start := fx.point(102).Value.(float64)
			if got := observeResult(r, 5); len(got) != 1 || got[0].Value != start+3 {
				t.Errorf("step position after three steps up from %v: %v", start, got)
			}

			// Select-before-operate: the selection is consumed by the execute.
			r = runClient(t, a, st.addr, "command", "--type", "C_SC_NA_1", "--ioa", "510", "--value", "false", "--mode", "sbo")
			if !r.OK {
				t.Errorf("select and execute: %s", r.summary())
			}
			r = runClient(t, a, st.addr, "command", "--type", "C_SC_NA_1", "--ioa", "510", "--value", "true")
			if r.OK || r.Error == nil || r.Error.Code != "negative-confirmation" {
				t.Errorf("execute without a new select was accepted: %s", r.summary())
			}
			r = runClient(t, a, st.addr, "read", "--ioa", "100")
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
			st := startStation(t, fx)

			// k=1, w=1: the client acknowledges every I frame and may not
			// have more than one of its own outstanding.
			r := runClient(t, a, st.addr, "interrogate", "--k", "1", "--w", "1")
			if got, want := observeResult(r, 20), fx.expected(false); !r.OK || !sameObserved(got, want) {
				t.Errorf("interrogation with k=1 w=1: %s", r.summary())
			}

			// An idle connection: the client's t3 (2s) expires several times
			// and go-iec104 must answer each TESTFR act within t1 (2s).
			r = runClient(t, a, st.addr, "connect", "--hold-ms", "7000", "--t1", "2", "--t2", "1", "--t3", "2",
				"--timeout-ms", "3000")
			if !r.OK || !r.StopDT {
				t.Errorf("connection idle for 7s with t3=2s: %s", r.summary())
			}

			// Three clients at once, each with its own session.
			results := make(chan *result, 3)
			for i := 0; i < 3; i++ {
				go func() { results <- runClient(t, a, st.addr, "interrogate", "--collect-ms", "500") }()
			}
			for i := 0; i < 3; i++ {
				r := <-results
				if got, want := observeResult(r, 20), fx.expected(false); !r.OK || !sameObserved(got, want) {
					t.Errorf("concurrent interrogation %d: %s", i, r.summary())
				}
			}
		})
	}
}
