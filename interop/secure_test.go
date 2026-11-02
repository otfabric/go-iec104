//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
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
		skipNoReference(t, "no reference declares "+featSecure)
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

// transport is the key material of the TLS tests, made when the test runs and
// written to a directory the reference containers mount at /secrets: what
// make_identities of iec104-interop makes, on secp256r1, the keys in PKCS #8.
type transport struct {
	dir                   string
	authority, otherCA    *x509.CertPool
	station, scada, rogue tls.Certificate
}

func newTransport(t testing.TB) *transport {
	t.Helper()
	dir := t.TempDir()
	// The containers run as uid 10001.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issue := func(name string, template, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			t.Fatal(err)
		}
		template.SerialNumber = serial
		template.Subject = pkix.Name{CommonName: name}
		template.NotBefore, template.NotAfter = now.Add(-time.Hour), now.Add(48*time.Hour)
		template.BasicConstraintsValid = true
		if parent == nil {
			parent, signer = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		for file, data := range map[string][]byte{name + ".pem": certPEM, name + ".key": keyPEM} {
			if err := os.WriteFile(filepath.Join(dir, file), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key, pair
	}
	authority := func() *x509.Certificate {
		return &x509.Certificate{IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	}
	leaf := func(hosts ...string) *x509.Certificate {
		return &x509.Certificate{DNSNames: hosts, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement}
	}
	ca, caKey, _ := issue("ca", authority(), nil, nil)
	other, _, _ := issue("other-ca", authority(), nil, nil)
	tr := &transport{dir: dir, authority: x509.NewCertPool(), otherCA: x509.NewCertPool()}
	tr.authority.AddCert(ca)
	tr.otherCA.AddCert(other)
	_, _, tr.station = issue("station", leaf(tlsStationName), ca, caKey)
	_, _, tr.scada = issue("scada", leaf(), ca, caKey)
	_, _, tr.rogue = issue("rogue", leaf(), nil, nil)
	return tr
}

// tlsStationName is what the go-iec104 client checks in the certificate of a
// station. The address is of no use for that: the contract does not check one.
const tlsStationName = "station"

func (tr *transport) mount() []string { return []string{"-v", tr.dir + ":/secrets:ro"} }

// tlsFlags are the transport security flags of a reference.
func tlsFlags(name, trust string) []string {
	return []string{"--tls", "--tls-cert", "/secrets/" + name + ".pem", "--tls-key", "/secrets/" + name + ".key",
		"--tls-trust", "/secrets/" + trust + ".pem"}
}

func tlsClientConfig(id tls.Certificate, trust *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{id}, RootCAs: trust, ServerName: tlsStationName}
}

// TestTLSClient: the go-iec104 client, with client.WithTLS, against the reference
// stations with --tls, and that neither side gives in to the wrong certificate.
func TestTLSClient(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		tr := newTransport(t)
		fx := loadExtended(t, a)
		ca := fx.Station.CommonAddr
		srv := startServerWith(t, a, tr.mount(), append(append([]string{}, extendedFlags...), tlsFlags("station", "ca")...)...)
		srv.waitEvent(t, "tls ready", func(e event) bool { return e["event"] == "ready" && e["tls"] == true })
		ctx := context.Background()

		c := dial(t, srv.addr, client.WithTLS(tlsClientConfig(tr.scada, tr.authority)))
		totals, err := c.CounterInterrogate(ctx, ca, asdu.CounterGeneral, asdu.FreezeRead)
		if err != nil {
			t.Fatalf("CounterInterrogate: %v", err)
		}
		if got, want := station.Observe(t, totals), fx.Expected(true); !station.SameObserved(got, want) {
			t.Errorf("counter interrogation:\n got  %v\n want %v", got, want)
		}
		data, err := c.Interrogate(ctx, ca, asdu.QOIGroup(2))
		if err != nil {
			t.Fatalf("Interrogate group 2: %v", err)
		}
		if got, want := station.Observe(t, data), fx.ExpectedGroup(2); !station.SameObserved(got, want) {
			t.Errorf("group 2:\n got  %v\n want %v", got, want)
		}
		if err := c.Command(ctx, ca, asdu.SingleCommand{IOA: 500, Value: false}); err != nil {
			t.Errorf("Command: %v", err)
		}
		_ = c.Close()

		// Each of these must fail: a stack that ignored the trust, or TLS
		// altogether, would pass the part above and not this.
		refused := func(what string, addr string, opts ...client.Option) {
			t.Helper()
			short, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if c, err := client.Dial(short, addr, opts...); err == nil {
				_ = c.Close()
				t.Errorf("%s: connected", what)
			}
		}
		refused("a controlling station nobody trusts", srv.addr, client.WithTLS(tlsClientConfig(tr.rogue, tr.authority)))
		refused("a station of another authority", srv.addr, client.WithTLS(tlsClientConfig(tr.scada, tr.otherCA)))
		refused("a client without TLS", srv.addr)
		plain := startServer(t, a, extendedFlags...)
		refused("a station without TLS", plain.addr, client.WithTLS(tlsClientConfig(tr.scada, tr.authority)))

		// The station survived all that.
		c = dial(t, srv.addr, client.WithTLS(tlsClientConfig(tr.scada, tr.authority)))
		if _, err := c.CounterInterrogate(ctx, ca, asdu.CounterGeneral, asdu.FreezeRead); err != nil {
			t.Errorf("CounterInterrogate after the refusals: %v", err)
		}
	}, append([]string{featTLSServer}, extendedFeatures...)...)
}

// TestTLSServer: the reference clients with --tls against a go-iec104 station with
// server.WithTLS.
func TestTLSServer(t *testing.T) {
	forEachAdapter(t, func(t *testing.T, a adapter) {
		tr := newTransport(t)
		fx := loadExtended(t, a)
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tr.station},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: tr.authority}
		var started atomic.Int64
		follow := server.WithStateHandler(func(_ *server.Session, state iec104.State, _ error) {
			if state == iec104.StateStarted {
				started.Add(1)
			}
		})
		good := strings.Join(tlsFlags("scada", "ca"), " ")

		t.Run("mutual", func(t *testing.T) {
			runCases(t, a, station.StartTLS(t, fx, cfg), []featureCase{
				{"counter-interrogate " + good, "exit=0 ok=true error=- conf=7 term=true asdus=C_CI_NA_1/7,M_IT_NA_1/37,C_CI_NA_1/10 tls=true"},
				{"interrogate --qoi 21 " + good, "exit=0 ok=true error=- conf=7 term=true asdus=C_IC_NA_1/7,M_SP_NA_1/21,M_DP_NA_1/21,C_IC_NA_1/10 tls=true"},
				{"command --type C_SC_NA_1 --ioa 500 --value false " + good, "exit=0 ok=true error=- conf=7 term=true asdus=C_SC_NA_1/7,M_SP_TB_1/11,C_SC_NA_1/10 tls=true"},
			}, tr.mount()...)
		})

		// Each of these must fail, and the station must have started nothing.
		const refused = "exit=1 ok=false error=tls-failed conf= term=false asdus= tls=false"
		st := station.StartTLS(t, fx, cfg, follow)
		runCases(t, a, st, []featureCase{
			{"counter-interrogate --timeout-ms 3000 " + strings.Join(tlsFlags("rogue", "ca"), " "), refused},
			{"counter-interrogate --timeout-ms 3000 " + strings.Join(tlsFlags("scada", "other-ca"), " "), refused},
		}, tr.mount()...)
		t.Run("client without TLS", func(t *testing.T) {
			r := runClient(t, a, st.Addr, "counter-interrogate", "--timeout-ms", "3000")
			if r.exit == 0 || r.OK || r.StartDT || len(r.ASDUs) != 0 {
				t.Errorf("a client without TLS got through: %s", r.summary())
			}
		})
		if n := started.Load(); n != 0 {
			t.Errorf("%d connections started data transfer", n)
		}
		t.Run("station without TLS", func(t *testing.T) {
			runCases(t, a, station.Start(t, fx), []featureCase{
				{"counter-interrogate --timeout-ms 3000 " + good, refused},
			}, tr.mount()...)
		})
	}, featTLSClient, featGroups, featBitstringQ)
}
