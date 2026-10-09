// SPDX-License-Identifier: MIT

// Command commands shows command transmission from both sides: direct
// execution, select-before-operate, cancelling a selection, a set point with
// a time tag, and what a refusal looks like.
//
//	go run ./examples/commands
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// breaker is a switch that only operates after it was selected.
type breaker struct {
	mu       sync.Mutex
	closed   bool
	selected bool
	limit    float32 // a set point
}

func (b *breaker) handle(s *server.Session, req *asdu.ASDU) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch cmd := req.First().(type) {
	case asdu.SingleCommand:
		switch {
		case cmd.IOA != 6001:
			_ = s.Reject(req, asdu.CauseUnknownIOA) // no such object
		case req.Cause == asdu.CauseDeactivation:
			b.selected = false
			_ = s.Confirm(req) // deactivation confirmation
		case cmd.Select:
			b.selected = true
			_ = s.Confirm(req)
		case !b.selected:
			_ = s.Negative(req) // execute without select: refused
		default:
			b.selected, b.closed = false, cmd.Value
			_ = s.Confirm(req)
			// Report the new state, then conclude the command.
			_ = s.Send(s.Context(), asdu.New(asdu.CauseReturnRemote, req.CommonAddr,
				asdu.SinglePoint{IOA: 100, Value: b.closed, Time: asdu.Now()}))
			_ = s.Terminate(req)
		}
	case asdu.SetpointFloat:
		if cmd.IOA != 6100 {
			_ = s.Reject(req, asdu.CauseUnknownIOA)
			return
		}
		b.limit = cmd.Value
		_ = s.Confirm(req)
		_ = s.Terminate(req)
	default:
		// Registered for every process command, but only these two exist here.
		_ = s.Reject(req, asdu.CauseUnknownIOA)
	}
}

func main() {
	b := &breaker{}
	mux := server.NewMux()
	mux.Handle(server.HandlerFunc(b.handle), server.ProcessCommands...)
	srv, err := server.New(mux, server.WithCommonAddrs(1))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	ctx := context.Background()
	c, err := client.Dial(ctx, ln.Addr().String(),
		// Reports and terminations arrive here, in order.
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			if a.Cause == asdu.CauseReturnRemote {
				fmt.Println("  report:", a, a.First())
			}
		})))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	show := func(what string, err error) {
		var neg *iec104.NegativeError
		switch {
		case err == nil:
			fmt.Printf("%-34s confirmed\n", what)
		case errors.As(err, &neg):
			// The station answered, and the answer was no.
			fmt.Printf("%-34s refused (%s)\n", what, neg.Cause())
		default:
			fmt.Printf("%-34s failed: %v\n", what, err)
		}
	}
	execute := asdu.SingleCommand{IOA: 6001, Value: true}
	sel := execute
	sel.Select = true

	show("execute without select", c.Command(ctx, 1, execute))
	show("select", c.Command(ctx, 1, sel))
	show("execute", c.Command(ctx, 1, execute))
	show("select", c.Command(ctx, 1, sel))
	show("cancel the selection", c.Deactivate(ctx, 1, sel))
	show("execute after the cancellation", c.Command(ctx, 1, execute))
	show("command to an unknown object", c.Command(ctx, 1, asdu.SingleCommand{IOA: 9999, Value: true}))
	// A non-zero Time selects the type with CP56Time2a (C_SE_TC_1 here).
	show("set point with time tag", c.Command(ctx, 1, asdu.SetpointFloat{IOA: 6100, Value: 42.5, Time: asdu.Now()}))
}
