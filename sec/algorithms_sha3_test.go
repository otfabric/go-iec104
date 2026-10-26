// SPDX-License-Identifier: MIT

//go:build go1.24

package sec

import "testing"

func TestSHA3(t *testing.T) {
	for _, m := range []MACAlgorithm{HMACSHA3_256, HMACSHA3_256Serial} {
		t.Run(m.Name, func(t *testing.T) {
			p := newPair(t, func(a, _ *Config) { a.MAC = m.Code })
			p.up()
			p.mustReady()
			p.exchange()
			if p.b.e.Status().MAC != m.Name {
				t.Errorf("MAC %q", p.b.e.Status().MAC)
			}
		})
	}
}
