// SPDX-License-Identifier: MIT

package server_test

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// R2-6: a controlling station that sends STARTDT act while its STOPDT act is
// still waiting for the acknowledgement of an I frame. The link goes from
// "stopping" straight back to started, which it does not report (the
// started period never ended), so nothing wakes the group's pump: an event
// that was refused during "stopping" stays in the queue on a started
// connection until something else is enqueued.
func TestReview2EventStuckAfterStartDuringStopping(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	write := func(f apci.Frame) {
		t.Helper()
		b, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	read := func(d time.Duration) (apci.Frame, error) {
		_ = conn.SetReadDeadline(time.Now().Add(d))
		return apci.ReadFrame(br)
	}
	write(apci.NewU(apci.StartDTAct))
	if f, err := read(time.Second); err != nil || f.Function != apci.StartDTCon {
		t.Fatalf("STARTDT con: %v %v", f, err)
	}
	enqueue(t, srv, 1, 1)
	if f, err := read(time.Second); err != nil || f.Format != apci.FormatI {
		t.Fatalf("event 1: %v %v", f, err)
	}
	write(apci.NewU(apci.StopDTAct)) // event 1 is not acknowledged: the station is "stopping"
	time.Sleep(100 * time.Millisecond)
	enqueue(t, srv, 2, 2) // refused by the link, waits for the next start
	time.Sleep(100 * time.Millisecond)
	write(apci.NewU(apci.StartDTAct))
	if f, err := read(time.Second); err != nil || f.Function != apci.StartDTCon {
		t.Fatalf("second STARTDT con: %v %v", f, err)
	}
	write(apci.NewS(1)) // now acknowledge event 1; the connection is healthy and started
	f, err := read(1500 * time.Millisecond)
	if err != nil {
		t.Errorf("event 2 was not sent on the started connection: %v (pending %d)", err, srv.Pending("default"))
		enqueue(t, srv, 3, 3)
		if f, err := read(time.Second); err == nil {
			t.Logf("after another Enqueue the queue moves again: %v", f)
		}
		return
	}
	if f.Format != apci.FormatI {
		t.Errorf("got %v, want event 2", f)
	}
}

// A connection that no longer acknowledges, its window full, must not hold
// the event queue once the controlling station has started data transfer
// on another connection: the events follow at once, not after t1.
func TestOrderingFullWindowDoesNotHoldTheQueue(t *testing.T) {
	srv, addr := serve(t, server.HandlerFunc(confirmAll))
	k := int(testutil.Params().K)
	type peer struct {
		conn net.Conn
		br   *bufio.Reader
	}
	open := func() *peer {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		p := &peer{conn, bufio.NewReader(conn)}
		b, _ := apci.NewU(apci.StartDTAct).MarshalBinary()
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if f, err := apci.ReadFrame(p.br); err != nil || f.Function != apci.StartDTCon {
			t.Fatalf("STARTDT con: %v %v", f, err)
		}
		return p
	}
	count := func(p *peer, n int, d time.Duration) int {
		got := 0
		_ = p.conn.SetReadDeadline(time.Now().Add(d))
		for got < n {
			f, err := apci.ReadFrame(p.br)
			if err != nil {
				break
			}
			if f.Format == apci.FormatI {
				got++
			}
		}
		return got
	}
	a := open()
	enqueue(t, srv, 1, k+3)
	if got := count(a, k, time.Second); got != k {
		t.Fatalf("the first connection received %d events, want the %d its window holds", got, k)
	}
	// The window of the first connection is full and stays so. The
	// controlling station moves to its other connection.
	b := open()
	begin := time.Now()
	got := count(b, k, time.Second)
	ack, _ := apci.NewS(uint16(got)).MarshalBinary()
	if _, err := b.conn.Write(ack); err != nil {
		t.Fatal(err)
	}
	got += count(b, 3, time.Second)
	if got != k+3 {
		t.Errorf("the second connection received %d of %d events within %v", got, k+3, time.Since(begin).Round(time.Millisecond))
	}
}
