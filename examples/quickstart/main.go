// SPDX-License-Identifier: MIT

// Command quickstart is the smallest complete program: a controlled station
// with two points and a controlling station that interrogates it, in one
// process, over a real TCP connection on loopback.
//
//	go run ./examples/quickstart
package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

func main() {
	// --- The controlled station (server) ---------------------------------
	// A Mux routes requests by type identification and refuses everything
	// it has no handler for, the way the standard prescribes.
	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		// An interrogation: confirm, send the data, terminate.
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr,
			asdu.SinglePoint{IOA: 100, Value: true},
			asdu.SinglePoint{IOA: 101, Value: false}))
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr,
			asdu.MeasuredFloat{IOA: 200, Value: 49.98}))
		_ = s.Terminate(req)
	})
	srv, err := server.New(mux, server.WithCommonAddrs(1))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0") // production: srv.ListenAndServe(":2404")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// --- The controlling station (client) --------------------------------
	ctx := context.Background()
	c, err := client.Dial(ctx, ln.Addr().String()) // connects and starts data transfer
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Interrogate blocks until the station has terminated the interrogation
	// and returns everything it sent in answer.
	data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range data {
		for _, obj := range a.Objects {
			switch o := obj.(type) {
			case asdu.SinglePoint:
				fmt.Printf("%s  ioa=%d  %v\n", a.Type, o.IOA, o.Value)
			case asdu.MeasuredFloat:
				fmt.Printf("%s  ioa=%d  %.2f\n", a.Type, o.IOA, o.Value)
			}
		}
	}
}
