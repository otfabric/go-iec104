// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// R2-3a: Server.Close returns while the state handler is still running for
// a session whose connection the peer closed: Session.onClose removes the
// session from the server before it calls the state handler, and
// Server.Close only waits for the sessions it still finds registered.
func TestReview2ServerCloseDoesNotWaitForDisconnectNotification(t *testing.T) {
	inside := make(chan struct{})
	release := make(chan struct{})
	var running atomic.Bool
	srv, addr := serve(t, server.HandlerFunc(confirmAll),
		server.WithStateHandler(func(s *server.Session, st iec104.State, err error) {
			if st == iec104.StateDisconnected {
				running.Store(true)
				close(inside)
				<-release
				running.Store(false)
			}
		}))
	c, err := client.New(addr, client.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = c.Close() // the peer goes away
	<-inside
	done := make(chan struct{})
	go func() { _ = srv.Close(); close(done) }()
	select {
	case <-done:
		if running.Load() {
			t.Errorf("Server.Close returned while the state handler was still running")
		}
	case <-time.After(time.Second):
		// Close waits for the handler: as documented.
	}
	close(release)
	<-done
}

// R2-3b: Server.Close returns while a Handler is still running, when that
// Handler has closed its own session: Session.Close removes the session
// from the server, and Server.Close no longer knows it.
func TestReview2ServerCloseDoesNotWaitForHandlerThatClosedItsSession(t *testing.T) {
	inside := make(chan struct{})
	release := make(chan struct{})
	var running atomic.Bool
	srv, addr := serve(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		running.Store(true)
		_ = s.Close()
		close(inside)
		<-release
		running.Store(false)
	}))
	c, err := client.New(addr, client.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go func() { _ = c.Close() }() }()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = c.Send(context.Background(), asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 1, Value: true}))
	<-inside
	done := make(chan struct{})
	go func() { _ = srv.Close(); close(done) }()
	select {
	case <-done:
		if running.Load() {
			t.Errorf("Server.Close returned while a Handler was still running")
		}
	case <-time.After(time.Second):
	}
	close(release)
	<-done
}
