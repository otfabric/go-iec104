//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/station"
	"github.com/otfabric/go-iec104/sec"
	"github.com/otfabric/go-iec104/server"
)

// The application-layer security of IEC 62351-5 (the A-Profile of
// IEC TS 60870-5-7), against the references that declare
// secureAuthentication: the security flags of the container contract on one
// side, package sec on the other.

// secrets is the key material of the secure tests, written to a directory
// the reference containers mount at /secrets.
type secrets struct {
	dir string
	ca  *sec.Identity
	// Signed by ca, on secp256r1 and on X25519.
	station, scada, xStation, xScada *sec.Identity
	// Self-signed, trusted by pin.
	pinStation, pinScada *sec.Identity
}

func newSecrets(t testing.TB) *secrets {
	t.Helper()
	id := func(name string, o sec.IdentityOptions) *sec.Identity {
		o.Subject = pkix.Name{CommonName: name}
		i, err := sec.NewIdentity(o)
		if err != nil {
			t.Fatalf("identity %s: %v", name, err)
		}
		return i
	}
	s := &secrets{dir: t.TempDir()}
	s.ca = id("go-iec104 interop CA", sec.IdentityOptions{CA: true})
	s.station = id("station", sec.IdentityOptions{Issuer: s.ca})
	s.scada = id("scada", sec.IdentityOptions{Issuer: s.ca})
	s.xStation = id("x25519 station", sec.IdentityOptions{Issuer: s.ca, Curve: sec.X25519})
	s.xScada = id("x25519 scada", sec.IdentityOptions{Issuer: s.ca, Curve: sec.X25519})
	s.pinStation = id("pinned station", sec.IdentityOptions{})
	s.pinScada = id("pinned scada", sec.IdentityOptions{})
	// The containers run as uid 10001.
	if err := os.Chmod(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, i := range map[string]*sec.Identity{"ca": s.ca, "station": s.station, "scada": s.scada,
		"x-station": s.xStation, "x-scada": s.xScada, "pin-station": s.pinStation, "pin-scada": s.pinScada} {
		cert, key, err := i.PEM()
		if err != nil {
			t.Fatal(err)
		}
		for file, data := range map[string][]byte{name + ".pem": cert, name + ".key": key} {
			if err := os.WriteFile(filepath.Join(s.dir, file), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return s
}

// mount is the "docker run" argument that gives a container the secrets.
func (s *secrets) mount() []string { return []string{"-v", s.dir + ":/secrets:ro"} }

// authority trusts every station certificate the CA signed.
func (s *secrets) authority() sec.Trust {
	return sec.Trust{Authorities: []*x509.Certificate{s.ca.Certificate}}
}

// flags are the security flags of a reference for the identity name, which
// trusts the certificates of the file trust: "ca" or a pinned certificate.
func flags(name, trust string) []string {
	return []string{"--secure", "--security-cert", "/secrets/" + name + ".pem",
		"--security-key", "/secrets/" + name + ".key", "--security-trust", "/secrets/" + trust + ".pem"}
}

// secureParams acknowledge within a second: the key management messages
// shift the count of I frames, and an acknowledgement should not wait for
// the default ten seconds.
func secureParams() apci.Params {
	p := apci.DefaultParams()
	p.T2 = time.Second
	return p
}

func secureAdapters(t *testing.T) []adapter {
	var out []adapter
	for _, a := range adapters(t) {
		if a.has(t, featSecure) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		t.Skipf("no reference declares %s", featSecure)
	}
	return out
}

// TestSecureClient: the go-iec104 client, with security, against the
// secure reference stations.
func TestSecureClient(t *testing.T) {
	s := newSecrets(t)
	tests := []struct {
		name       string
		serverArgs []string
		cfg        sec.Config // the controlling station's
		// refused is the cause the command is refused with, 0 when it is
		// executed; dialFails says the association is refused.
		refused   asdu.Cause
		dialFails bool
	}{
		{name: "authority",
			serverArgs: flags("station", "ca"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.scada, Trust: s.authority()}},
		{name: "AES-256-GCM, other association IDs",
			serverArgs: append(flags("station", "ca"), "--association-id", "3"),
			cfg:        sec.Config{AssociationID: 4711, Identity: s.scada, Trust: s.authority(), DataProtection: sec.AES256GCM}},
		{name: "X25519",
			serverArgs: flags("x-station", "ca"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.xScada, Trust: s.authority()}},
		{name: "pinned",
			serverArgs: flags("pin-station", "pin-scada"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.pinScada, Trust: s.pinStation.Pin()}},
		{name: "viewer may not command",
			serverArgs: append(flags("station", "ca"), "--roles", "viewer"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.scada, Trust: s.authority()},
			refused:    asdu.CauseNotAuthorized},
		{name: "operator may command",
			serverArgs: append(flags("station", "ca"), "--roles", "viewer,operator"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.scada, Trust: s.authority()}},
		{name: "untrusted controlling station",
			serverArgs: flags("station", "ca"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.pinScada, Trust: s.authority()},
			dialFails:  true},
		{name: "untrusted station",
			serverArgs: flags("station", "ca"),
			cfg:        sec.Config{AssociationID: 5, Identity: s.scada, Trust: s.pinStation.Pin()},
			dialFails:  true},
	}
	for _, a := range secureAdapters(t) {
		t.Run(a.name, func(t *testing.T) {
			fx := loadFixture(t, a)
			ca := fx.Station.CommonAddr
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					srv := startServerWith(t, a, s.mount(), tt.serverArgs...)
					srv.waitEvent(t, "secure ready", func(e event) bool { return e["event"] == "ready" && e["secure"] == true })

					cfg := tt.cfg
					cfg.Role, cfg.CommonAddr = sec.Controlling, ca
					ep, err := sec.New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					opts := []client.Option{client.WithSecurity(ep), client.WithParams(secureParams()),
						client.WithRequestTimeout(5 * time.Second)}
					if tt.dialFails {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						c, err := client.Dial(ctx, srv.addr, opts...)
						if err == nil {
							_ = c.Close()
							t.Fatal("Dial succeeded; want the association refused")
						}
						if errors.Is(err, context.DeadlineExceeded) {
							t.Logf("Dial: %v (no answer rather than a refusal)", err)
						}
						return
					}
					c := dial(t, srv.addr, opts...)
					ais := uint16(1)
					if i := slices.Index(tt.serverArgs, "--association-id"); i >= 0 {
						n, _ := strconv.Atoi(tt.serverArgs[i+1])
						ais = uint16(n)
					}
					if st := ep.Status(); !st.Ready || st.AIM != cfg.AssociationID || st.AIS != ais {
						t.Fatalf("connected with the association %+v, want it ready with AIM %d and AIS %d",
							st, cfg.AssociationID, ais)
					}

					ctx := context.Background()
					data, err := c.Interrogate(ctx, ca, asdu.QOIStation)
					if err != nil {
						t.Fatalf("Interrogate: %v", err)
					}
					if got, want := station.Observe(t, data), fx.Expected(false); !station.SameObserved(got, want) {
						t.Errorf("interrogation:\n got  %v\n want %v", got, want)
					}

					err = c.Command(ctx, ca, asdu.SingleCommand{IOA: 500, Value: false})
					if tt.refused != 0 {
						negative(t, err, tt.refused)
						return
					}
					if err != nil {
						t.Fatalf("Command: %v", err)
					}
					srv.waitEvent(t, "command", func(e event) bool {
						return e["event"] == "command" && e["ioa"] == float64(500) && e["outcome"] == "executed"
					})
				})
			}
		})
	}
}

// secureSummary is the summary with whether the association was
// established.
func secureSummary(r *result) string {
	secured := "null"
	if r.Secured != nil {
		secured = fmt.Sprint(*r.Secured)
	}
	return r.summary() + " secured=" + secured
}

// TestSecureServer: the secure reference clients against a go-iec104
// station with security. The station keeps one association per controlling
// station and configures each by its AIM, which the cases use: AIM 5 is
// trusted through the authority, 6 by pin, 7 is a viewer, and 8 is refused.
func TestSecureServer(t *testing.T) {
	s := newSecrets(t)
	interrogation := "ok=true error=- conf=7 term=true asdus=C_IC_NA_1/7,M_SP_NA_1/20,M_DP_NA_1/20,M_ST_NA_1/20," +
		"M_BO_NA_1/20,M_SP_NA_1/20,M_ME_NA_1/20,M_ME_NB_1/20,M_ME_NC_1/20,M_ME_NB_1/20,C_IC_NA_1/10"
	command := "ok=true error=- conf=7 term=true asdus=C_SC_NA_1/7,M_SP_TB_1/11,C_SC_NA_1/10"
	tests := []struct {
		name string
		args string
		want string
		// reference is the server flags of the reference station the
		// result is compared with; empty compares nothing.
		reference []string
	}{
		{"authority", "interrogate --association-id 5 " + strings.Join(flags("scada", "ca"), " "),
			"exit=0 " + interrogation + " secured=true", flags("station", "ca")},
		{"AES-256-GCM", "command --type C_SC_NA_1 --ioa 500 --value false --dpa 11 --association-id 5 " + strings.Join(flags("scada", "ca"), " "),
			"exit=0 " + command + " secured=true", flags("station", "ca")},
		{"pinned", "interrogate --association-id 6 " + strings.Join(flags("pin-scada", "pin-station"), " "),
			"exit=0 " + interrogation + " secured=true", flags("pin-station", "pin-scada")},
		{"viewer may interrogate", "interrogate --association-id 7 " + strings.Join(flags("scada", "ca"), " "),
			"exit=0 " + interrogation + " secured=true", append(flags("station", "ca"), "--roles", "viewer")},
		{"viewer may not command", "command --type C_SC_NA_1 --ioa 500 --value false --association-id 7 " + strings.Join(flags("scada", "ca"), " "),
			"exit=1 ok=false error=negative-confirmation conf=17n term=false asdus=C_SC_NA_1/17 secured=true",
			append(flags("station", "ca"), "--roles", "viewer")},
		// cB-Sigma's own station would refuse the acknowledgement of the
		// file with cause 17 (see INTEROPERABILITY.md): nothing to compare.
		{"viewer may download", "file-get --ioa 30000 --association-id 7 " + strings.Join(flags("scada", "ca"), " "),
			"exit=0 ok=true error=- conf= term=false asdus=" + fileASDUs(5) + " secured=true", nil},
		{"refused station", "interrogate --timeout-ms 2000 --association-id 8 " + strings.Join(flags("scada", "ca"), " "),
			"exit=1 ok=false error=security-failed conf= term=false asdus= secured=false", nil},
		{"untrusted controlling station", "interrogate --timeout-ms 2000 --association-id 5 " + strings.Join(flags("pin-scada", "ca"), " "),
			"exit=1 ok=false error=security-failed conf= term=false asdus= secured=false", flags("station", "ca")},
		{"untrusted station", "interrogate --timeout-ms 2000 --association-id 5 " + strings.Join(flags("scada", "pin-station"), " "),
			"exit=1 ok=false error=security-failed conf= term=false asdus= secured=false", flags("station", "ca")},
		{"no security", "interrogate --timeout-ms 2000",
			"exit=1 ok=false error=timeout conf= term=false asdus= secured=null", flags("station", "ca")},
	}
	factory := func(fx *fixture) server.Option {
		return server.WithSecurity(func(_ string, aim uint16) (*sec.Endpoint, error) {
			cfg := sec.Config{Role: sec.Controlled, AssociationID: 9, Identity: s.station, Trust: s.authority(),
				CommonAddr: fx.Station.CommonAddr}
			switch aim {
			case 5:
			case 6:
				cfg.Identity, cfg.Trust = s.pinStation, s.pinScada.Pin()
			case 7:
				cfg.Roles = []sec.AccessRole{sec.RoleViewer}
			default:
				return nil, fmt.Errorf("no association for AIM %d", aim)
			}
			return sec.New(cfg)
		})
	}
	for _, a := range secureAdapters(t) {
		t.Run(a.name, func(t *testing.T) {
			fx := loadFixture(t, a)
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					st := station.Start(t, fx, factory(fx), server.WithParams(secureParams()))
					args := strings.Fields(tt.args)
					got := runClientWith(t, a, st.Addr, s.mount(), args...)
					if s := secureSummary(got); s != tt.want {
						t.Fatalf("%s client against go-iec104:\n got  %s\n want %s", a.name, s, tt.want)
					}
					if tt.reference == nil {
						return
					}
					ref := startServerWith(t, a, s.mount(), tt.reference...)
					want := runClientAgainstWith(t, a, ref, s.mount(), args...)
					if s := secureSummary(want); s != tt.want {
						t.Fatalf("%s client against the %s server (the comparison is void):\n got  %s\n want %s",
							a.name, a.name, s, tt.want)
					}
					if g, w := got.normalized(), want.normalized(); g != w {
						t.Errorf("%s client sees a difference between go-iec104 and the %s server.\n"+
							"--- go-iec104 ---\n%s\n--- %s server ---\n%s", a.name, a.name, g, a.name, w)
					}
				})
			}
		})
	}
}
