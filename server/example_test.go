// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

func Example() {
	mux := server.NewMux()

	// General interrogation: confirm, send the points, terminate.
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		qoi := req.First().(asdu.Interrogation).Qualifier
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(qoi.Cause(), req.CommonAddr,
			asdu.SinglePoint{IOA: 1001, Value: true},
			asdu.MeasuredFloat{IOA: 4001, Value: 49.98}))
		_ = s.Terminate(req)
	})

	// One handler for every process command type.
	mux.Handle(server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		if req.First().Address() != 6001 {
			_ = s.Reject(req, asdu.CauseUnknownIOA)
			return
		}
		_ = s.Confirm(req)
	}), server.ProcessCommands...)

	srv, err := server.New(mux, server.WithCommonAddrs(1))
	if err != nil {
		log.Fatal(err)
	}

	// Spontaneous data to every control centre that has started data transfer.
	go func() {
		for now := range time.Tick(time.Second) {
			_, _ = srv.Broadcast(context.Background(), asdu.New(asdu.CauseSpontaneous, 1,
				asdu.MeasuredFloat{IOA: 4001, Value: 50, Time: asdu.At(now)}))
		}
	}()

	log.Fatal(srv.ListenAndServe(":2404"))
}

func ExampleWithTLS() {
	cert, err := tls.LoadX509KeyPair("station.crt", "station.key")
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(server.NewMux(), server.WithTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Add ClientAuth and ClientCAs to authenticate controlling stations.
	}))
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.ListenAndServe("")) // :19998
}
