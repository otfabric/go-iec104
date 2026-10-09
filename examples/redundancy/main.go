// SPDX-License-Identifier: MIT

// Command redundancy shows a redundancy group: two connections to a
// station (here: two stations standing in for two paths), exactly one with
// data transfer started, failover when the active one is lost and a manual
// switchover.
//
//	go run ./examples/redundancy
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// path starts a station that answers a read with its own name.
func path(id int16) (*server.Server, string) {
	mux := server.NewMux()
	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr,
			asdu.MeasuredScaled{IOA: req.First().Address(), Value: id}))
	})
	srv, err := server.New(mux, server.WithCommonAddrs(1))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, ln.Addr().String()
}

func main() {
	srvA, addrA := path(1)
	srvB, addrB := path(2)
	defer func() { _, _ = srvA.Close(), srvB.Close() }()

	ctx := context.Background()
	g, err := client.NewGroup([]string{addrA, addrB},
		client.WithReconnect(client.Reconnect{MinDelay: 100 * time.Millisecond, MaxDelay: time.Second}),
		// Called whenever data transfer moves to another connection.
		client.WithSwitchHandler(func(active *client.Client) {
			if active == nil {
				fmt.Println("  switch: no connection is started")
				return
			}
			fmt.Println("  switch: data transfer now on", active.Addr())
		}))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Connect(ctx); err != nil { // returns when one connection is started
		log.Fatal(err)
	}

	// Requests go to whichever connection is started.
	ask := func(what string) {
		a, err := g.Read(ctx, 1, 100)
		if err != nil {
			fmt.Printf("%-28s %v\n", what+":", err)
			return
		}
		fmt.Printf("%-28s answered by path %d\n", what+":", a.First().(asdu.MeasuredScaled).Value)
	}
	standbyReady := func() {
		for {
			stopped := 0
			for _, c := range g.Clients() {
				if c.State() == iec104.StateStopped {
					stopped++
				}
			}
			if stopped == 1 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	ask("at the start")
	standbyReady() // the other connection is established and supervised, not started

	// A manual switchover: STOPDT on one connection, STARTDT on the other.
	if err := g.Switchover(ctx); err != nil {
		log.Fatal(err)
	}
	ask("after a switchover")
	if err := g.Switchover(ctx); err != nil {
		log.Fatal(err)
	}
	ask("after switching back")

	// The first path dies: the group fails over by itself.
	active := g.Active()
	if active.Addr() == addrA {
		_ = srvA.Close()
	} else {
		_ = srvB.Close()
	}
	for g.Active() == active || g.Active() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	ask("after losing the active path")
}
