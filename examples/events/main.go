// SPDX-License-Identifier: MIT

// Command events shows how a station reports on its own: an event queue that
// keeps events while no control centre is connected and repeats what was
// not acknowledged, next to data that is simply sent to whoever listens.
//
//	go run ./examples/events
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

func main() {
	srv, err := server.New(server.NewMux(),
		server.WithCommonAddrs(1),
		server.WithEventQueue(1000), // per redundancy group; the oldest are dropped when full
		// A new control centre is told that the station is up.
		server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
			if state == iec104.StateStarted {
				_ = s.Send(s.Context(), asdu.New(asdu.CauseInitialized, 1,
					asdu.EndOfInitialization{Cause: asdu.InitLocalPowerOn}))
			}
		}))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// Events that happen while nobody is connected are kept.
	for i := 1; i <= 3; i++ {
		ev := asdu.New(asdu.CauseSpontaneous, 1, asdu.SinglePoint{IOA: 100, Value: i%2 == 1, Time: asdu.Now()})
		if err := srv.Enqueue(ev); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("queued before any connection:", srv.Pending("default"))

	var received atomic.Int64
	ctx := context.Background()
	c, err := client.Dial(ctx, ln.Addr().String(),
		// Acknowledge every I frame at once (w = 1) instead of after eight,
		// so that the queue empties quickly.
		client.WithParams(apci.Params{W: 1}),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			received.Add(1)
			fmt.Printf("  received: %s %v\n", a, a.First())
		})))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Cyclic data needs no queue: it is sent to every started connection and
	// lost for those that are not there.
	cyclic := asdu.New(asdu.CausePeriodic, 1, asdu.MeasuredFloat{IOA: 200, Value: 49.98})
	if n, err := srv.Broadcast(ctx, cyclic); err != nil || n != 1 {
		log.Fatalf("broadcast reached %d sessions: %v", n, err)
	}

	// One more event while connected.
	_ = srv.Enqueue(asdu.New(asdu.CauseSpontaneous, 1, asdu.DoublePoint{IOA: 101, Value: asdu.DoubleOn, Time: asdu.Now()}))

	for received.Load() < 6 || srv.Pending("default") > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Println("queue after the control centre acknowledged:", srv.Pending("default"), "dropped:", srv.Dropped("default"))
}
