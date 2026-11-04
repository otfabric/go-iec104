// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

// Section numbers and file lengths that do not fit their fields never wrap
// into valid-looking ones.
func TestSectionNumberAndFileLength(t *testing.T) {
	for _, c := range []struct {
		i    int
		want uint8
	}{{-2, 0}, {-1, 0}, {0, 1}, {253, 254}, {254, 255}, {255, 0}, {511, 0}, {math.MaxInt, 0}, {math.MinInt, 0}} {
		if got := sectionNumber(c.i); got != c.want {
			t.Errorf("sectionNumber(%d) = %d, want %d", c.i, got, c.want)
		}
	}
	for _, c := range []struct {
		n    int
		want uint32
	}{{0, 0}, {1, 1}, {asdu.MaxFileLength, asdu.MaxFileLength}, {asdu.MaxFileLength + 1, asdu.MaxFileLength + 1},
		{math.MaxInt, asdu.MaxFileLength + 1}, {-1, asdu.MaxFileLength + 1}} {
		if got := fileLength(c.n); got != c.want {
			t.Errorf("fileLength(%d) = %d, want %d", c.n, got, c.want)
		}
	}
	// What fileLength returns for a length that does not fit, the encoder refuses.
	a := asdu.New(asdu.CauseFileTransfer, 1, asdu.FileReady{IOA: 1, Name: 1, Length: fileLength(math.MaxInt)})
	if _, err := a.Encode(asdu.IEC104); err == nil {
		t.Error("encoded a file length past 24 bits")
	}
}
