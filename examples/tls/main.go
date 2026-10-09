// SPDX-License-Identifier: MIT

// Command tls shows IEC 60870-5-104 over TLS (IEC 62351-3) with certificates
// on both sides: the station only accepts control centres whose certificate
// its authority signed, and tells them apart by it.
//
// The certificates are made on the fly so that the example runs as it is. A
// real installation loads them with tls.LoadX509KeyPair and an
// x509.CertPool from its PKI.
//
//	go run ./examples/tls
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// authority is a certificate authority for the example.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newAuthority() *authority {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example plant CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &authority{cert, key, pool}
}

// issue signs a certificate for name, usable on either side.
func (a *authority) issue(name string, serial int64) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	ca := newAuthority()

	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		// Who is asking? The verified certificate of the control centre.
		who := "unknown"
		if tc, ok := s.Conn().(*tls.Conn); ok && len(tc.ConnectionState().PeerCertificates) > 0 {
			who = tc.ConnectionState().PeerCertificates[0].Subject.CommonName
		}
		fmt.Println("  station: interrogation from", who)
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr, asdu.SinglePoint{IOA: 100, Value: true}))
		_ = s.Terminate(req)
	})
	srv, err := server.New(mux, server.WithCommonAddrs(1), server.WithTLS(&tls.Config{
		Certificates: []tls.Certificate{ca.issue("station 1", 2)},
		ClientAuth:   tls.RequireAndVerifyClientCert, // no certificate, no session
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	}))
	if err != nil {
		log.Fatal(err)
	}
	// With WithTLS, ListenAndServe listens with TLS; the default port is 19998.
	go func() { _ = srv.ListenAndServe("127.0.0.1:0") }()
	defer func() { _ = srv.Close() }()
	for srv.Addr() == nil {
		time.Sleep(time.Millisecond)
	}
	addr := srv.Addr().String()
	ctx := context.Background()

	// A control centre with a certificate of the plant's authority.
	c, err := client.Dial(ctx, addr, client.WithTLS(&tls.Config{
		Certificates: []tls.Certificate{ca.issue("control centre north", 3)},
		RootCAs:      ca.pool, // the station must present a certificate of this authority
		MinVersion:   tls.VersionTLS12,
	}))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
	fmt.Printf("with a certificate: %d ASDUs, error %v\n", len(data), err)

	// Without a certificate the station drops the connection.
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = client.Dial(short, addr, client.WithTLS(&tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}))
	fmt.Println("without a certificate:", err != nil)

	// A certificate of another authority is no better.
	other := newAuthority()
	_, err = client.Dial(short, addr, client.WithTLS(&tls.Config{
		Certificates: []tls.Certificate{other.issue("stranger", 9)}, RootCAs: ca.pool, MinVersion: tls.VersionTLS12,
	}))
	fmt.Println("with a foreign certificate:", err != nil)
}
