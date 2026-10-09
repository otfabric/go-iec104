//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

// fixture is the simulated station the reference images are built with. The
// tests read it from the image under test, so expectations follow the image
// rather than a copy that could drift.
type fixture struct {
	Name    string `json:"name"`
	Station struct {
		CommonAddr asdu.CommonAddr `json:"commonAddress"`
	} `json:"station"`
	Points   []fixturePoint   `json:"points"`
	Commands []fixtureCommand `json:"commands"`
}

type fixturePoint struct {
	IOA       asdu.IOA `json:"ioa"`
	Type      string   `json:"type"`
	Value     any      `json:"value"` // bool for M_SP_NA_1, float64 otherwise
	Transient bool     `json:"transient"`
	Sequence  uint8    `json:"sequence"`
	Quality   []string `json:"quality"`
}

type fixtureCommand struct {
	IOA            asdu.IOA `json:"ioa"`
	Type           string   `json:"type"`
	Target         asdu.IOA `json:"target"`
	ReportCause    int      `json:"reportCause"`
	SelectRequired bool     `json:"selectRequired"`
}

var (
	fixtureOnce sync.Map // image -> *fixture
)

// loadFixture returns the baseline fixture baked into the image of a.
func loadFixture(t testing.TB, a adapter) *fixture {
	t.Helper()
	if fx, ok := fixtureOnce.Load(a.image); ok {
		return fx.(*fixture)
	}
	out, stderr, err := docker("run", "--rm", a.image, "print-fixture", "baseline")
	if err != nil {
		t.Fatalf("print-fixture from %s: %v\n%s", a.image, err, stderr)
	}
	fx := &fixture{}
	if err := json.Unmarshal([]byte(out), fx); err != nil {
		t.Fatalf("fixture of %s is not JSON: %v", a.image, err)
	}
	sort.Slice(fx.Points, func(i, j int) bool { return fx.Points[i].IOA < fx.Points[j].IOA })
	for i := range fx.Commands {
		if fx.Commands[i].ReportCause == 0 {
			fx.Commands[i].ReportCause = int(asdu.CauseReturnRemote)
		}
	}
	fixtureOnce.Store(a.image, fx)
	return fx
}

func (fx *fixture) point(ioa asdu.IOA) *fixturePoint {
	for i := range fx.Points {
		if fx.Points[i].IOA == ioa {
			return &fx.Points[i]
		}
	}
	return nil
}

// observed is one information object reduced to what the fixture states
// about a point, so that fixture, go-iec104 objects and reference client
// documents can be compared with ==.
type observed struct {
	IOA     asdu.IOA
	Type    string
	Value   any // bool or float64
	Quality string
}

func (o observed) String() string {
	return fmt.Sprintf("{%d %s %v [%s]}", o.IOA, o.Type, o.Value, o.Quality)
}

func joinFlags(flags []string) string {
	s := ""
	for i, f := range flags {
		if i > 0 {
			s += " "
		}
		s += f
	}
	return s
}

// expected returns what the station reports for the points selected by
// counters (integrated totals or everything else), in address order.
func (fx *fixture) expected(counters bool) []observed {
	var out []observed
	for _, p := range fx.Points {
		if (p.Type == "M_IT_NA_1") != counters {
			continue
		}
		out = append(out, observed{p.IOA, p.Type, p.Value, joinFlags(p.Quality)})
	}
	return out
}

func qualityFlags(q asdu.Quality) string {
	var flags []string
	for _, f := range []struct {
		bit  asdu.Quality
		name string
	}{
		{asdu.QualityOverflow, "OV"}, {asdu.QualityBlocked, "BL"}, {asdu.QualitySubstituted, "SB"},
		{asdu.QualityNotTopical, "NT"}, {asdu.QualityInvalid, "IV"},
	} {
		if q.Has(f.bit) {
			flags = append(flags, f.name)
		}
	}
	return joinFlags(flags)
}

// baseTypeName maps the CP56Time2a monitoring types to the type the fixture
// names.
func baseTypeName(t asdu.TypeID) string {
	switch t {
	case asdu.M_SP_TB_1:
		return "M_SP_NA_1"
	case asdu.M_DP_TB_1:
		return "M_DP_NA_1"
	case asdu.M_ST_TB_1:
		return "M_ST_NA_1"
	case asdu.M_BO_TB_1:
		return "M_BO_NA_1"
	case asdu.M_ME_TD_1:
		return "M_ME_NA_1"
	case asdu.M_ME_TE_1:
		return "M_ME_NB_1"
	case asdu.M_ME_TF_1:
		return "M_ME_NC_1"
	case asdu.M_IT_TB_1:
		return "M_IT_NA_1"
	default:
		return t.String()
	}
}

// observe reduces the objects of ASDUs decoded by go-iec104.
func observe(t testing.TB, asdus []*asdu.ASDU) []observed {
	t.Helper()
	var out []observed
	for _, a := range asdus {
		name := baseTypeName(a.Type)
		for _, obj := range a.Objects {
			o := observed{IOA: obj.Address(), Type: name}
			switch v := obj.(type) {
			case asdu.SinglePoint:
				o.Value, o.Quality = v.Value, qualityFlags(v.Quality)
			case asdu.DoublePoint:
				o.Value, o.Quality = float64(v.Value), qualityFlags(v.Quality)
			case asdu.StepPosition:
				o.Value, o.Quality = float64(v.Value), qualityFlags(v.Quality)
			case asdu.Bitstring32:
				o.Value, o.Quality = float64(v.Value), qualityFlags(v.Quality)
			case asdu.MeasuredNormalized:
				o.Value, o.Quality = float64(v.Value), qualityFlags(v.Quality)
			case asdu.MeasuredScaled:
				o.Value, o.Quality = float64(v.Value), qualityFlags(v.Quality)
			case asdu.MeasuredFloat:
				o.Value, o.Quality = float64(v.Value), qualityFlags(v.Quality)
			case asdu.IntegratedTotal:
				var flags []string
				if v.Carry {
					flags = append(flags, "CY")
				}
				if v.Adjusted {
					flags = append(flags, "CA")
				}
				if v.Invalid {
					flags = append(flags, "IV")
				}
				o.Value, o.Quality = float64(v.Value), joinFlags(flags)
			default:
				t.Fatalf("unexpected object %T in %s", obj, a)
			}
			out = append(out, o)
		}
	}
	return out
}

// observeResult reduces the objects a reference client received with the
// given cause of transmission.
func observeResult(r *result, cot int) []observed {
	var out []observed
	for _, a := range r.ASDUs {
		if a.Cot != cot {
			continue
		}
		for _, obj := range a.Objects {
			o := observed{Type: a.Type, Value: obj["value"]}
			if ioa, ok := obj["ioa"].(float64); ok {
				o.IOA = asdu.IOA(ioa)
			}
			if q, ok := obj["quality"].([]any); ok {
				flags := make([]string, len(q))
				for i := range q {
					flags[i], _ = q[i].(string)
				}
				o.Quality = joinFlags(flags)
			}
			out = append(out, o)
		}
	}
	return out
}

func sameObserved(a, b []observed) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
