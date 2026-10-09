// SPDX-License-Identifier: MIT

package station

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

// Fixture describes a simulated station: its points, the commands that act
// on them and the files it offers. The format is the one of
// otfabric/iec104-interop.
type Fixture struct {
	Name    string `json:"name"`
	Station struct {
		CommonAddr asdu.CommonAddr `json:"commonAddress"`
	} `json:"station"`
	Points   []Point   `json:"points"`
	Commands []Command `json:"commands"`
	Files    []File    `json:"files"`
}

// File is a file the station offers. Its content is not stored:
// octet i is (i + ioa) mod 251.
type File struct {
	IOA         asdu.IOA `json:"ioa"`
	Name        uint16   `json:"name"`
	Size        int      `json:"size"`
	SectionSize int      `json:"sectionSize"`
}

// Content returns the octets of the file.
func (f File) Content() []byte {
	b := make([]byte, f.Size)
	for i := range b {
		b[i] = byte((i + int(f.IOA)) % 251)
	}
	return b
}

type Point struct {
	IOA       asdu.IOA `json:"ioa"`
	Type      string   `json:"type"`
	Value     any      `json:"value"` // bool for M_SP_NA_1, float64 otherwise
	Transient bool     `json:"transient"`
	Sequence  uint8    `json:"sequence"`
	Quality   []string `json:"quality"`
}

type Command struct {
	IOA            asdu.IOA `json:"ioa"`
	Type           string   `json:"type"`
	Target         asdu.IOA `json:"target"`
	ReportCause    int      `json:"reportCause"`
	SelectRequired bool     `json:"selectRequired"`
}

// Point returns the point at ioa, or nil.
func (fx *Fixture) Point(ioa asdu.IOA) *Point {
	for i := range fx.Points {
		if fx.Points[i].IOA == ioa {
			return &fx.Points[i]
		}
	}
	return nil
}

// Observed is one information object reduced to what the fixture states
// about a point, so that fixture, go-iec104 objects and reference client
// documents can be compared with ==.
type Observed struct {
	IOA     asdu.IOA
	Type    string
	Value   any // bool or float64
	Quality string
}

func (o Observed) String() string {
	return fmt.Sprintf("{%d %s %v [%s]}", o.IOA, o.Type, o.Value, o.Quality)
}

// JoinFlags joins quality flags the way [Observed] holds them.
func JoinFlags(flags []string) string {
	s := ""
	for i, f := range flags {
		if i > 0 {
			s += " "
		}
		s += f
	}
	return s
}

// Expected returns what the station reports for the points selected by
// counters (integrated totals or everything else), in address order.
func (fx *Fixture) Expected(counters bool) []Observed {
	var out []Observed
	for _, p := range fx.Points {
		if (p.Type == "M_IT_NA_1") != counters {
			continue
		}
		out = append(out, Observed{p.IOA, p.Type, p.Value, JoinFlags(p.Quality)})
	}
	return out
}

// QualityFlags returns the flags of q in the order fixtures use.
func QualityFlags(q asdu.Quality) string {
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
	return JoinFlags(flags)
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

// Observe reduces the objects of ASDUs decoded by go-iec104.
func Observe(t testing.TB, asdus []*asdu.ASDU) []Observed {
	t.Helper()
	var out []Observed
	for _, a := range asdus {
		name := baseTypeName(a.Type)
		for _, obj := range a.Objects {
			o := Observed{IOA: obj.Address(), Type: name}
			switch v := obj.(type) {
			case asdu.SinglePoint:
				o.Value, o.Quality = v.Value, QualityFlags(v.Quality)
			case asdu.DoublePoint:
				o.Value, o.Quality = float64(v.Value), QualityFlags(v.Quality)
			case asdu.StepPosition:
				o.Value, o.Quality = float64(v.Value), QualityFlags(v.Quality)
			case asdu.Bitstring32:
				o.Value, o.Quality = float64(v.Value), QualityFlags(v.Quality)
			case asdu.MeasuredNormalized:
				o.Value, o.Quality = float64(v.Value), QualityFlags(v.Quality)
			case asdu.MeasuredScaled:
				o.Value, o.Quality = float64(v.Value), QualityFlags(v.Quality)
			case asdu.MeasuredFloat:
				o.Value, o.Quality = float64(v.Value), QualityFlags(v.Quality)
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
				o.Value, o.Quality = float64(v.Value), JoinFlags(flags)
			default:
				t.Fatalf("unexpected object %T in %s", obj, a)
			}
			out = append(out, o)
		}
	}
	return out
}

// SameObserved reports whether two reductions are equal.
func SameObserved(a, b []Observed) bool {
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

//go:embed baseline.json
var baseline []byte

// Baseline returns a fresh copy of the baseline fixture: twelve points of
// eight types, seven commands of six types and two files.
func Baseline(t testing.TB) *Fixture {
	t.Helper()
	fx, err := Parse(baseline)
	if err != nil {
		t.Fatalf("baseline fixture: %v", err)
	}
	return fx
}

// Parse reads a fixture and puts its points in address order.
func Parse(data []byte) (*Fixture, error) {
	fx := &Fixture{}
	if err := json.Unmarshal(data, fx); err != nil {
		return nil, err
	}
	sort.Slice(fx.Points, func(i, j int) bool { return fx.Points[i].IOA < fx.Points[j].IOA })
	for i := range fx.Commands {
		if fx.Commands[i].ReportCause == 0 {
			fx.Commands[i].ReportCause = int(asdu.CauseReturnRemote)
		}
	}
	return fx, nil
}
