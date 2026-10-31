// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
)

// Close while Connect waits for the answer to STARTDT: Connect reports
// ErrClosed, as it does when Close comes during the dial, and not the
// canceled context that Close uses to stop it.
func TestCloseDuringStartDTReportsErrClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		// A peer that takes the connection and never answers.
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = conn.Close() })
	}()

	stopped := make(chan struct{}, 1)
	c, err := client.New(ln.Addr().String(), client.WithParams(testutil.Params()),
		client.WithStateHandler(func(s iec104.State, _ error) {
			if s == iec104.StateStopped {
				stopped <- struct{}{}
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the link did not come up")
	}
	_ = c.Close()
	if err := <-done; !errors.Is(err, iec104.ErrClosed) {
		t.Fatalf("Connect: %v, want ErrClosed", err)
	}
}
