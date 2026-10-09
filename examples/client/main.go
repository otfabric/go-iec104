// SPDX-License-Identifier: MIT

// Command client is a small IEC 60870-5-104 controlling station: it
// connects, runs a general interrogation, synchronizes the clock,
// optionally operates a switch and then prints whatever the station
// reports until interrupted.
//
//	go run ./examples/client -addr 127.0.0.1:2404 -ca 1 -operate 6001
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
)

func describe(a *asdu.ASDU) {
	for _, obj := range a.Objects {
		switch o := obj.(type) {
		case asdu.SinglePoint:
			fmt.Printf("  %-9s ioa=%-6d %-5v quality=%s %s\n", a.Type, o.IOA, o.Value, o.Quality, stamp(o.Time))
		case asdu.DoublePoint:
			fmt.Printf("  %-9s ioa=%-6d %-5s quality=%s %s\n", a.Type, o.IOA, o.Value, o.Quality, stamp(o.Time))
		case asdu.MeasuredFloat:
			fmt.Printf("  %-9s ioa=%-6d %-9.3f quality=%s %s\n", a.Type, o.IOA, o.Value, o.Quality, stamp(o.Time))
		case asdu.MeasuredScaled:
			fmt.Printf("  %-9s ioa=%-6d %-9d quality=%s %s\n", a.Type, o.IOA, o.Value, o.Quality, stamp(o.Time))
		case asdu.MeasuredNormalized:
			fmt.Printf("  %-9s ioa=%-6d %-9.5f quality=%s %s\n", a.Type, o.IOA, o.Value.Float64(), o.Quality, stamp(o.Time))
		default:
			fmt.Printf("  %-9s ioa=%-6d %+v\n", a.Type, obj.Address(), obj)
		}
	}
}

func stamp(t asdu.Timestamp) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:2404", "station address")
	ca := flag.Uint("ca", 1, "common address of the station")
	operate := flag.Uint("operate", 0, "information object address of a single command to switch on (0: none)")
	debug := flag.Bool("debug", false, "log every APDU")
	flag.Parse()
	station := asdu.CommonAddr(*ca)

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	c, err := client.Dial(ctx, *addr,
		client.WithLogger(iec104.NewSlogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))),
		client.WithReconnect(client.Reconnect{}),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			// Interrogation answers are printed from the result below.
			if a.Cause == asdu.CauseSpontaneous || a.Cause == asdu.CausePeriodic || a.Cause == asdu.CauseReturnRemote {
				fmt.Println(a)
				describe(a)
			}
		})))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	data, err := c.Interrogate(ctx, station, asdu.QOIStation)
	if err != nil {
		log.Fatalf("interrogation: %v", err)
	}
	fmt.Printf("general interrogation: %d ASDUs\n", len(data))
	for _, a := range data {
		describe(a)
	}

	if err := c.ClockSync(ctx, station, time.Now()); err != nil {
		log.Printf("clock synchronization: %v", err)
	}

	if *operate != 0 {
		cmd := asdu.SingleCommand{IOA: asdu.IOA(*operate), Value: true}
		// Select before operate: both steps must be confirmed.
		cmd.Select = true
		err := c.Command(ctx, station, cmd)
		if err == nil {
			cmd.Select = false
			err = c.Command(ctx, station, cmd)
		}
		var neg *iec104.NegativeError
		switch {
		case errors.As(err, &neg):
			log.Printf("command refused by the station: %s", neg.Cause())
		case err != nil:
			log.Printf("command: %v", err)
		default:
			fmt.Printf("command on %d executed\n", *operate)
		}
	}

	fmt.Println("waiting for spontaneous data, Ctrl-C to stop")
	<-ctx.Done()
}
