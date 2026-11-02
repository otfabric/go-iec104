//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"crypto/sha256"
	"encoding/hex"
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

// extendedFeatures are what a station needs to serve the fixture extended.
var extendedFeatures = []string{featGroups, featBitstringQ}

// extendedFlags makes a reference server serve the fixture extended.
var extendedFlags = []string{"--fixture", "/fixtures/extended/fixture.json"}

var extendedOnce sync.Map // image -> *fixture

// loadExtended returns the fixture extended baked into the image of a. Only an
// image of container contract 1.3 has one, so the caller first checks that a
// declares a feature of that version.
func loadExtended(t testing.TB, a adapter) *fixture {
	t.Helper()
	if fx, ok := extendedOnce.Load(a.image); ok {
		return fx.(*fixture)
	}
	out, stderr, err := docker("run", "--rm", a.image, "print-fixture", "extended")
	if err != nil {
		t.Fatalf("print-fixture extended from %s: %v\n%s", a.image, err, stderr)
	}
	fx, err := station.Parse([]byte(out))
	if err != nil {
		t.Fatalf("fixture extended of %s is not JSON: %v", a.image, err)
	}
	extendedOnce.Store(a.image, fx)
	return fx
}

// fileContent is the file of n octets a fixture defines at ioa.
func fileContent(ioa asdu.IOA, n int) []byte {
	return station.File{IOA: ioa, Size: n}.Content()
}

// fileHash is the lower-case SHA-256 of the file of n octets at ioa.
func fileHash(ioa asdu.IOA, n int) string {
	sum := sha256.Sum256(fileContent(ioa, n))
	return hex.EncodeToString(sum[:])
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
