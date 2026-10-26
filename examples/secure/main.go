// SPDX-License-Identifier: MIT

// Command secure shows the application-layer security of IEC 62351-5 as
// IEC TS 60870-5-7 applies it to IEC 60870-5-104: a Station Association
// with certificates of a plant authority, session keys, every ASDU as
// Secure Data, and role-based access control at the station.
//
// The identities are made on the fly so that the example runs as it is. A
// real installation loads them with sec.LoadIdentity and keeps the
// association in a sec.FileStore so that it survives a restart.
//
//	go run ./examples/secure
package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/sec"
	"github.com/otfabric/go-iec104/server"
)

func identity(cn string, issuer *sec.Identity, ca bool) *sec.Identity {
	id, err := sec.NewIdentity(sec.IdentityOptions{Subject: pkix.Name{CommonName: cn}, Issuer: issuer, CA: ca})
	if err != nil {
		log.Fatal(err)
	}
	return id
}

func main() {
	authority := identity("example plant authority", nil, true)
	stationID := identity("station 1", authority, false)
	centreID := identity("control centre north", authority, false)
	// Each side accepts the other's certificate, as signed by the authority.
	authorities := []*x509.Certificate{authority.Certificate}
	stationTrust := sec.Trust{Authorities: authorities, Subjects: [][]byte{centreID.Certificate.RawSubject}}
	centreTrust := sec.Trust{Authorities: authorities, Subjects: [][]byte{stationID.Certificate.RawSubject}}

	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		// The handler sees verified application data only.
		fmt.Println("  station: interrogation from", s.Security().Status().Remote.Subject.CommonName)
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr, asdu.SinglePoint{IOA: 100, Value: true}))
		_ = s.Terminate(req)
	})
	mux.HandleFunc(asdu.C_SC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		fmt.Println("  station: never reached, the role does not permit commands")
	})
	srv, err := server.New(mux, server.WithCommonAddrs(1),
		// One association per controlling station, by its AIM. This station
		// knows one: the control centre, AIM 1.
		server.WithSecurity(func(group string, aim uint16) (*sec.Endpoint, error) {
			if aim != 1 {
				return nil, fmt.Errorf("no association for controlling station %d", aim)
			}
			return sec.New(sec.Config{
				Role: sec.Controlled, AssociationID: 1, Identity: stationID, Trust: stationTrust,
				CommonAddr: 1,
				// The control centre may look, not operate.
				Roles: []sec.AccessRole{sec.RoleViewer},
				OnEvent: func(e sec.Event) {
					fmt.Printf("  station event: %s (%s)\n", e.Mnemonic, e.Severity)
				},
			})
		}))
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe("127.0.0.1:0") }()
	defer func() { _ = srv.Close() }()
	for srv.Addr() == nil {
		time.Sleep(time.Millisecond)
	}

	ep, err := sec.New(sec.Config{
		Role: sec.Controlling, AssociationID: 1, Identity: centreID, Trust: centreTrust,
		CommonAddr:     1,
		DataProtection: sec.AES256GCM, // encrypted as well as authenticated
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	// Dial returns once the association and the session keys are in place.
	c, err := client.Dial(ctx, srv.Addr().String(), client.WithSecurity(ep))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	st := ep.Status()
	fmt.Printf("associated with %q: MAC %s, data %s\n", st.Remote.Subject.CommonName, st.MAC, st.Data)

	data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
	fmt.Printf("interrogation: %d ASDUs, error %v\n", len(data), err)

	err = c.Command(ctx, 1, asdu.SingleCommand{IOA: 6001, Value: true})
	var neg *iec104.NegativeError
	if errors.As(err, &neg) {
		fmt.Println("command refused:", neg.Cause())
	} else {
		fmt.Println("command:", err)
	}

	stats := ep.Statistics()
	fmt.Printf("authenticated %d ASDUs from the station, %d session key change(s)\n",
		stats[sec.StatSuccessfulDataAuthentications], stats[sec.StatSuccessfulSessionKeyChanges])
}
