//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"sync"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/internal/station"
)

// fixture is the simulated station the reference images are built with. The
// tests read it from the image under test, so expectations follow the image
// rather than a copy that could drift.
type fixture = station.Fixture

var fixtureOnce sync.Map // image -> *fixture

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
	fx, err := station.Parse([]byte(out))
	if err != nil {
		t.Fatalf("fixture of %s is not JSON: %v", a.image, err)
	}
	fixtureOnce.Store(a.image, fx)
	return fx
}

// observeResult reduces the objects a reference client received with the
// given cause of transmission.
func observeResult(r *result, cot int) []station.Observed {
	var out []station.Observed
	for _, a := range r.ASDUs {
		if a.Cot != cot {
			continue
		}
		for _, obj := range a.Objects {
			o := station.Observed{Type: a.Type, Value: obj["value"]}
			if ioa, ok := obj["ioa"].(float64); ok {
				o.IOA = asdu.IOA(ioa)
			}
			if q, ok := obj["quality"].([]any); ok {
				flags := make([]string, len(q))
				for i := range q {
					flags[i], _ = q[i].(string)
				}
				o.Quality = station.JoinFlags(flags)
			}
			out = append(out, o)
		}
	}
	return out
}
