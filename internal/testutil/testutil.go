// SPDX-License-Identifier: MIT

// Package testutil holds helpers shared by the client and server tests.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
)

// Params returns protocol parameters with timers short enough for tests.
func Params() apci.Params {
	return apci.Params{K: 12, W: 8, T0: 2 * time.Second, T1: 2 * time.Second, T2: 200 * time.Millisecond, T3: 0}
}

// Eventually polls cond until it holds or five seconds have passed.
func Eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Metrics counts the callbacks of iec104.Metrics.
type Metrics struct {
	mu                                         sync.Mutex
	Connects, Disconnects, Sent, Received, Bad int
	SentByFormat, ReceivedByFormat             map[apci.Format]int
	LastDisconnect                             error
}

var _ iec104.Metrics = (*Metrics)(nil)

// Snapshot returns a copy of the counters.
func (m *Metrics) Snapshot() (connects, disconnects, sent, received, bad int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Connects, m.Disconnects, m.Sent, m.Received, m.Bad
}

// OnConnect counts a connection.
func (m *Metrics) OnConnect(net.Addr) {
	m.mu.Lock()
	m.Connects++
	m.mu.Unlock()
}

// OnDisconnect counts a disconnection.
func (m *Metrics) OnDisconnect(_ net.Addr, err error) {
	m.mu.Lock()
	m.Disconnects++
	m.LastDisconnect = err
	m.mu.Unlock()
}

// OnFrameSent counts a sent frame.
func (m *Metrics) OnFrameSent(_ net.Addr, f apci.Frame, _ int) {
	m.mu.Lock()
	m.Sent++
	if m.SentByFormat == nil {
		m.SentByFormat = map[apci.Format]int{}
	}
	m.SentByFormat[f.Format]++
	m.mu.Unlock()
}

// OnFrameReceived counts a received frame.
func (m *Metrics) OnFrameReceived(_ net.Addr, f apci.Frame, _ int) {
	m.mu.Lock()
	m.Received++
	if m.ReceivedByFormat == nil {
		m.ReceivedByFormat = map[apci.Format]int{}
	}
	m.ReceivedByFormat[f.Format]++
	m.mu.Unlock()
}

// OnDecodeError counts an undecodable ASDU.
func (m *Metrics) OnDecodeError(net.Addr, error) {
	m.mu.Lock()
	m.Bad++
	m.mu.Unlock()
}

// TLSConfigs returns a server and a client configuration that trust a
// freshly generated self-signed certificate for 127.0.0.1.
func TLSConfigs(t testing.TB) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-iec104 test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	client = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return server, client
}
