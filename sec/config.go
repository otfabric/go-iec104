// SPDX-License-Identifier: MIT

package sec

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/otfabric/go-iec104/asdu"
)

// Config configures one end of an association.
type Config struct {
	// Role of the station: Controlling (the client) or Controlled (the
	// server).
	Role Role

	// AssociationID is this station's half of the association ID, 1 to
	// 65535: the AIM of a controlling station, the AIS of a controlled one.
	AssociationID uint16

	// Identity is the station's certificate and private key, needed for
	// the Station Association. Without it only an association kept in
	// Store can be used.
	Identity *Identity

	// Trust says which remote stations may associate.
	Trust Trust

	// IgnoreValidity accepts certificates outside their validity period,
	// for devices without a reliable clock.
	IgnoreValidity bool

	// MAC is the MAC algorithm a controlling station selects for the key
	// management messages and the key derivation; default
	// [HMACSHA256].Code.
	MAC uint8

	// DataProtection is the algorithm a controlling station selects for
	// Secure Data: a MAC algorithm code or [AES256GCM]; default MAC.
	DataProtection uint8

	// AcceptMAC and AcceptDataProtection limit what a controlled station
	// accepts. Empty accepts every algorithm this package implements.
	AcceptMAC            []uint8
	AcceptDataProtection []uint8

	// Settings are the timers and key usage limits.
	Settings Settings

	// Store keeps the association over reconnects and restarts. Nil keeps
	// it in a MemoryStore of the Endpoint.
	Store KeyStore

	// Params are the ASDU field sizes; zero means asdu.IEC104.
	Params asdu.Params

	// CommonAddr and Originator fill the data unit identifier of the key
	// management messages this station sends.
	CommonAddr asdu.CommonAddr
	Originator uint8

	// Roles are the roles of the controlling station at a controlled
	// station, for [Endpoint.Permits]. Nil applies no role-based access
	// control: every request is permitted.
	Roles []AccessRole

	// OnEvent is called for every security event (a statistic with an
	// event mnemonic was incremented). It is called without locks held,
	// on the goroutine that drove the Endpoint, and must not block.
	OnEvent func(Event)

	// Rand is the source of random data and keys; nil uses crypto/rand.
	Rand io.Reader
}

// Settings are the timers and key usage limits of an association. A zero
// field takes its default.
type Settings struct {
	// ReplyTimeout is how long a controlling station waits for each answer
	// of the remote station before it sends the request again. Default 2 s.
	ReplyTimeout time.Duration

	// MaxReplyTimeouts is how many times in a row a controlling station
	// waits in vain before the procedure fails. Default 3.
	MaxReplyTimeouts int

	// RequestTimeout is how long a controlled station waits for the next
	// request of a procedure it answered. Default 6 s.
	RequestTimeout time.Duration

	// KeyLifetime and KeyUses limit how long and for how many messages a
	// pair of session keys is used: a controlling station changes them when
	// either is reached, a controlled station stops accepting them.
	// Defaults 15 minutes and 1000 messages at a controlling station,
	// twice that at a controlled one, which must allow more than its peer.
	KeyLifetime time.Duration
	KeyUses     uint32
}

func (s Settings) withDefaults(r Role) Settings {
	f := time.Duration(1)
	if r == Controlled {
		f = 2
	}
	if s.ReplyTimeout == 0 {
		s.ReplyTimeout = 2 * time.Second
	}
	if s.MaxReplyTimeouts == 0 {
		s.MaxReplyTimeouts = 3
	}
	if s.RequestTimeout == 0 {
		s.RequestTimeout = 6 * time.Second
	}
	if s.KeyLifetime == 0 {
		s.KeyLifetime = f * 15 * time.Minute
	}
	if s.KeyUses == 0 {
		s.KeyUses = uint32(f) * 1000
	}
	return s
}

func (s Settings) validate() error {
	switch {
	case s.ReplyTimeout < 0 || s.ReplyTimeout > time.Hour:
		return fmt.Errorf("%w: reply timeout %v, want at most 1 h", ErrConfig, s.ReplyTimeout)
	case s.RequestTimeout < 0 || s.RequestTimeout > 3*time.Hour:
		return fmt.Errorf("%w: request timeout %v, want at most 3 h", ErrConfig, s.RequestTimeout)
	case s.MaxReplyTimeouts < 0 || s.MaxReplyTimeouts > 255:
		return fmt.Errorf("%w: max reply timeouts %d, want 1 to 255", ErrConfig, s.MaxReplyTimeouts)
	case s.KeyLifetime < 0 || s.KeyLifetime > 14*24*time.Hour:
		return fmt.Errorf("%w: key lifetime %v, want at most two weeks", ErrConfig, s.KeyLifetime)
	case s.KeyUses > 1<<31-1:
		return fmt.Errorf("%w: key uses %d, want at most 2^31-1", ErrConfig, s.KeyUses)
	}
	return nil
}

func (c *Config) check() error {
	if c.Params == (asdu.Params{}) {
		c.Params = asdu.IEC104
	}
	if err := checkParams(c.Params); err != nil {
		return err
	}
	if c.Role != Controlling && c.Role != Controlled {
		return fmt.Errorf("%w: role %d", ErrConfig, c.Role)
	}
	if c.AssociationID == 0 {
		return fmt.Errorf("%w: association ID must be 1 to 65535", ErrConfig)
	}
	if err := c.Settings.validate(); err != nil {
		return err
	}
	c.Settings = c.Settings.withDefaults(c.Role)
	if c.MAC == 0 {
		c.MAC = HMACSHA256.Code
	}
	if c.DataProtection == 0 {
		c.DataProtection = c.MAC
	}
	if _, ok := MACByCode(c.MAC); !ok {
		return fmt.Errorf("%w: MAC algorithm %d", ErrConfig, c.MAC)
	}
	if _, ok := DataProtectionByCode(c.DataProtection); !ok {
		return fmt.Errorf("%w: data protection algorithm %d", ErrConfig, c.DataProtection)
	}
	if c.Identity != nil {
		if _, _, err := c.Identity.check(); err != nil {
			return err
		}
	}
	if c.Store == nil {
		c.Store = &MemoryStore{}
	}
	c.AcceptMAC = slices.Clone(c.AcceptMAC)
	c.AcceptDataProtection = slices.Clone(c.AcceptDataProtection)
	c.Roles = slices.Clone(c.Roles)
	return nil
}

// accepts reports whether code is implemented and, when the list is not
// empty, in it.
func accepts(list []uint8, code uint8, known bool) bool {
	return known && (len(list) == 0 || slices.Contains(list, code))
}
