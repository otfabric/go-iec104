// SPDX-License-Identifier: MIT

package apci

import (
	"errors"
	"fmt"
	"time"
)

// DefaultPort is the IANA-registered TCP port for IEC 60870-5-104.
const DefaultPort = 2404

// DefaultTLSPort is the port IEC 62351-3 assigns to IEC 60870-5-104 over TLS.
const DefaultTLSPort = 19998

// ErrInvalidParams reports protocol parameters outside the ranges the
// standard permits. It is wrapped with detail; test with errors.Is.
var ErrInvalidParams = errors.New("apci: invalid parameters")

// Params holds the IEC 60870-5-104 protocol parameters. Both stations of a
// connection must be configured with compatible values; they are not
// negotiated on the wire.
type Params struct {
	// K is the maximum number of I frames a station may have outstanding
	// (sent but not acknowledged) before it stops sending. Range 1..32767,
	// default 12.
	K int

	// W is the number of received I frames after which a station must send
	// an acknowledgement at the latest. Range 1..32767, default 8. The
	// standard recommends W <= 2K/3.
	W int

	// T0 is the connection establishment timeout. Default 30s.
	T0 time.Duration

	// T1 is the timeout for an acknowledgement of a sent I frame or a
	// confirmation of a sent U frame. When it expires the connection is
	// closed. Default 15s.
	T1 time.Duration

	// T2 is the longest a station waits before acknowledging received I
	// frames when it has none of its own to send. Must be less than T1.
	// Default 10s.
	T2 time.Duration

	// T3 is the idle time after which a TESTFR act is sent. Zero disables
	// the idle test. Default 20s.
	T3 time.Duration
}

// DefaultParams returns the default values from IEC 60870-5-104 clause 9.
func DefaultParams() Params {
	return Params{
		K:  12,
		W:  8,
		T0: 30 * time.Second,
		T1: 15 * time.Second,
		T2: 10 * time.Second,
		T3: 20 * time.Second,
	}
}

// WithDefaults returns p with every zero K, W, T0, T1 and T2 replaced by its
// default. T3 is left alone because zero is a meaningful value for it.
func (p Params) WithDefaults() Params {
	d := DefaultParams()
	if p.K == 0 {
		p.K = d.K
	}
	if p.W == 0 {
		p.W = d.W
	}
	if p.T0 == 0 {
		p.T0 = d.T0
	}
	if p.T1 == 0 {
		p.T1 = d.T1
	}
	if p.T2 == 0 {
		p.T2 = d.T2
	}
	return p
}

// Validate reports whether p is usable. It enforces the hard limits of the
// standard (1 <= W <= K <= 32767, positive timers, T2 < T1) and not its
// recommendations.
func (p Params) Validate() error {
	switch {
	case p.K < 1 || p.K > SeqMask:
		return fmt.Errorf("%w: k=%d, want 1..%d", ErrInvalidParams, p.K, SeqMask)
	case p.W < 1 || p.W > p.K:
		return fmt.Errorf("%w: w=%d, want 1..k (%d)", ErrInvalidParams, p.W, p.K)
	case p.T0 <= 0:
		return fmt.Errorf("%w: t0=%s, want > 0", ErrInvalidParams, p.T0)
	case p.T1 <= 0:
		return fmt.Errorf("%w: t1=%s, want > 0", ErrInvalidParams, p.T1)
	case p.T2 <= 0 || p.T2 >= p.T1:
		return fmt.Errorf("%w: t2=%s, want 0 < t2 < t1 (%s)", ErrInvalidParams, p.T2, p.T1)
	case p.T3 < 0:
		return fmt.Errorf("%w: t3=%s, want >= 0", ErrInvalidParams, p.T3)
	}
	return nil
}
