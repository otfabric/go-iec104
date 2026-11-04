// SPDX-License-Identifier: MIT

package e2e_test

import (
	"fmt"
	"testing"

	"github.com/otfabric/go-iec104/internal/station"
)

// A fixture's report cause must be a cause of transmission (1..63); 0 means
// the default, return information caused by a remote command.
func TestStationFixtureReportCause(t *testing.T) {
	for _, c := range []struct {
		cause int
		ok    bool
	}{{-1, false}, {0, true}, {1, true}, {11, true}, {63, true}, {64, false}, {256 + 11, false}} {
		_, err := station.Parse(fmt.Appendf(nil, `{"station": {"commonAddress": 1},
			"points": [{"ioa": 100, "type": "M_SP_NA_1", "value": true}],
			"commands": [{"ioa": 500, "type": "C_SC_NA_1", "target": 100, "reportCause": %d}]}`, c.cause))
		if (err == nil) != c.ok {
			t.Errorf("report cause %d: %v", c.cause, err)
		}
	}
}
