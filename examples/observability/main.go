// SPDX-License-Identifier: MIT

// Command observability shows what the library tells its application:
// structured logs, connection states and metrics, on both sides, and the
// options that make a client resilient (reconnect, retries, a start
// handler).
//
//	go run ./examples/observability
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// counters is a metrics sink: plug in Prometheus, OpenTelemetry or expvar
// the same way. Embedding NopMetrics leaves only what matters here to write.
type counters struct {
	iec104.NopMetrics
	framesIn, framesOut, requests, failures, retries atomic.Int64
	slowest                                          atomic.Int64 // nanoseconds
}

func (c *counters) OnFrameSent(net.Addr, apci.Frame, int)     { c.framesOut.Add(1) }
func (c *counters) OnFrameReceived(net.Addr, apci.Frame, int) { c.framesIn.Add(1) }

// The methods of iec104.RequestMetrics: one call per request of the client.
func (c *counters) OnRequest(net.Addr, asdu.TypeID, asdu.CommonAddr) { c.requests.Add(1) }
func (c *counters) OnRequestDone(_ net.Addr, _ asdu.TypeID, _ asdu.CommonAddr, d time.Duration, err error) {
	if err != nil {
		c.failures.Add(1)
	}
	if int64(d) > c.slowest.Load() {
		c.slowest.Store(int64(d))
	}
}
func (c *counters) OnRetry(net.Addr, asdu.TypeID, asdu.CommonAddr, int, error) { c.retries.Add(1) }

func main() {
	// One slog handler for both sides; Debug would log every APDU.
	logger := iec104.NewSlogLogger(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var reads atomic.Int64
	mux := server.NewMux()
	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		if reads.Add(1) == 1 {
			return // the first read is lost in the station: the client retries
		}
		_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, req.CommonAddr, asdu.MeasuredFloat{IOA: req.First().Address(), Value: 21.5}))
	})
	srv, err := server.New(mux, server.WithCommonAddrs(1), server.WithLogger(logger),
		server.WithStateHandler(func(s *server.Session, state iec104.State, err error) {
			fmt.Printf("station: session %d is %s (%v)\n", s.ID(), state, err)
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

	m := &counters{}
	ctx := context.Background()
	c, err := client.Dial(ctx, ln.Addr().String(),
		client.WithLogger(logger),
		client.WithMetrics(m),
		client.WithStateHandler(func(state iec104.State, err error) {
			fmt.Printf("client: %s (%v)\n", state, err)
		}),
		// Every wait for the station is bounded.
		client.WithRequestTimeout(300*time.Millisecond),
		// Requests that only read are repeated; commands never are.
		client.WithRetry(client.Retry{Attempts: 3, Backoff: 50 * time.Millisecond}),
		// A lost connection is re-established with a growing delay...
		client.WithReconnect(client.Reconnect{MinDelay: 100 * time.Millisecond, MaxDelay: 5 * time.Second}),
		// ...and this runs on every fresh connection, typically an interrogation.
		client.WithStartHandler(func(ctx context.Context, c *client.Client) {
			fmt.Println("client: connection started, time to interrogate")
		}))
	if err != nil {
		log.Fatal(err)
	}

	a, err := c.Read(ctx, 1, 4001)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("read after one retry: %v\n", a.First().(asdu.MeasuredFloat).Value)

	// The station drops the connection; the client comes back by itself.
	for _, s := range srv.Sessions() {
		_ = s.Close()
	}
	for c.State() != iec104.StateDisconnected && c.State() != iec104.StateConnecting {
		time.Sleep(time.Millisecond)
	}
	for c.State() != iec104.StateStarted {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := c.Read(ctx, 1, 4001); err != nil {
		log.Fatal(err)
	}
	_ = c.Close()

	fmt.Printf("metrics: %d frames sent, %d received; %d requests, %d failed, %d retries; slowest %s\n",
		m.framesOut.Load(), m.framesIn.Load(), m.requests.Load(), m.failures.Load(), m.retries.Load(),
		time.Duration(m.slowest.Load()).Round(time.Millisecond))
}
