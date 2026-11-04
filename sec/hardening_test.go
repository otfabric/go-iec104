// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

// Length fields at the edges of their octets: the largest value that fits
// is encoded, the next one is refused, never wrapped.
func TestAppendLenLimits(t *testing.T) {
	for _, c := range []struct {
		size, n int
		want    []byte // nil: refused
	}{
		{1, 0, []byte{0}},
		{1, 255, []byte{0xff}},
		{1, 256, nil},
		{2, 256, []byte{0x00, 0x01}},
		{2, 65535, []byte{0xff, 0xff}},
		{2, 65536, nil},
	} {
		got, err := appendLen(nil, make([]byte, c.n), c.size, "test")
		switch {
		case c.want == nil && !errors.Is(err, ErrMessage):
			t.Errorf("%d octets in %d: %v, want ErrMessage", c.n, c.size, err)
		case c.want != nil && (err != nil || !bytes.Equal(got, c.want)):
			t.Errorf("%d octets in %d: % X, %v, want % X", c.n, c.size, got, err, c.want)
		}
	}
}

func TestProtectLengthLimits(t *testing.T) {
	key := seq(32, 0xa0)
	for _, code := range []uint8{HMACSHA256.Code, AES256GCM} {
		dp, _ := DataProtectionByCode(code)
		h := Header{CommonAddr: 1}
		if _, err := protect(asdu.IEC104, h, SecureData{AIM: 1, AIS: 1}, make([]byte, 0x10000), dp, key); !errors.Is(err, ErrMessage) {
			t.Errorf("%s: 65536 octets: %v, want ErrMessage", dp, err)
		}
		w, err := protect(asdu.IEC104, h, SecureData{AIM: 1, AIS: 1}, make([]byte, 0xffff), dp, key)
		if err != nil {
			t.Fatalf("%s: 65535 octets: %v", dp, err)
		}
		_, m, err := Decode(w, asdu.IEC104, Control)
		if err != nil {
			t.Fatalf("%s: decode: %v", dp, err)
		}
		plain, err := open(w, asdu.IEC104, m.(SecureData), dp, key)
		if err != nil || len(plain) != 0xffff {
			t.Errorf("%s: open: %d octets, %v", dp, len(plain), err)
		}
	}
}

func TestSessionInitiationRandomLimits(t *testing.T) {
	for _, n := range []int{3, 4, 64, 65, 255, 256} {
		m := SessionInitiationRequest{AIM: 1, AIS: 2, Random: make([]byte, n)}
		b, err := m.appendBody(nil, false)
		if valid := n >= 4 && n <= 64; valid != (err == nil) {
			t.Errorf("%d octets of random data: %v", n, err)
			continue
		}
		if err == nil && int(b[4]) != n {
			t.Errorf("%d octets of random data: length octet %d", n, b[4])
		}
	}
}

func TestWrapStep(t *testing.T) {
	for _, c := range []struct{ n, j, i int }{{2, 0, 1}, {2, 5, 2}, {64, 5, 64}} {
		if got := wrapStep(c.n, c.j, c.i); got != uint64(c.n*c.j+c.i) {
			t.Errorf("wrapStep(%d, %d, %d) = %d", c.n, c.j, c.i, got)
		}
	}
	if got := wrapStep(-1, 1, 0); got != 0 {
		t.Errorf("negative step = %d, want 0", got)
	}
	// Wrapping keys of every length the protocol carries round-trips.
	kek := seq(32, 0x10)
	for n := 16; n <= 64; n += 8 {
		data := seq(n, byte(n))
		w, err := keyWrap(kek, data)
		if err != nil {
			t.Fatal(err)
		}
		back, err := keyUnwrap(kek, w)
		if err != nil || !bytes.Equal(back, data) {
			t.Errorf("%d octets: %x, %v", n, back, err)
		}
		w[len(w)-1] ^= 1
		if _, err := keyUnwrap(kek, w); err == nil {
			t.Errorf("%d octets: unwrapped altered data", n)
		}
	}
}

// LoadIdentity cleans the paths it is given; a path through a directory
// and back resolves to the same files, and a directory is not a key.
func TestLoadIdentityPaths(t *testing.T) {
	certPEM, keyPEM, err := mustIdentity(IdentityOptions{}).PEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if os.WriteFile(cf, certPEM, 0o600) != nil || os.WriteFile(kf, keyPEM, 0o600) != nil {
		t.Fatal("writing the PEM files")
	}
	if _, err := LoadIdentity(sub+"/../c.pem", sub+"/./../k.pem"); err != nil {
		t.Errorf("path through a directory: %v", err)
	}
	if _, err := LoadIdentity(cf, sub); err == nil {
		t.Error("loaded a directory as the key")
	}
	if _, err := LoadIdentity(kf, cf); err == nil {
		t.Error("loaded a key as the certificate")
	}
}
