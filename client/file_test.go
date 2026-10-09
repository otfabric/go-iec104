// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

// serveHandler runs a server with h and returns its address.
func serveHandler(t *testing.T, h server.Handler) string {
	t.Helper()
	srv, err := server.New(h, server.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// A download from the library's own file server, over a single connection
// and over a redundancy group. The procedure itself is tested in package
// server; the faults a station can produce are below.
func TestGetFile(t *testing.T) {
	content := make([]byte, 3000)
	for i := range content {
		content[i] = byte(i % 251)
	}
	mux := server.NewMux()
	mux.Handle(server.NewFileServer(server.FileSourceFunc(
		func(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, name uint16) (server.File, bool) {
			return server.NewFile(content, 1024), ioa == 7 && name == 2
		})), server.FileTypes...)
	addr := serveHandler(t, mux)
	ctx := context.Background()

	c := dial(t, addr)
	got, err := c.GetFile(ctx, 1, 7, 2)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("GetFile: %d octets, %v", len(got), err)
	}
	if _, err := c.GetFile(ctx, 1, 8, 2); negativeCause(t, err) != asdu.CauseUnknownIOA {
		t.Errorf("unknown file: %v", err)
	}

	g, err := client.NewGroup([]string{addr}, client.WithParams(testutil.Params()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if _, err := g.GetFile(ctx, 1, 7, 2); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("Group.GetFile before Connect: %v", err)
	}
	if err := g.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := g.GetFile(ctx, 1, 7, 2); err != nil || !bytes.Equal(got, content) {
		t.Errorf("Group.GetFile: %d octets, %v", len(got), err)
	}

	// Not connected, and closed.
	idle, err := client.New(addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idle.GetFile(ctx, 1, 7, 2); !errors.Is(err, iec104.ErrNotConnected) {
		t.Errorf("GetFile without a connection: %v", err)
	}
	_ = c.Close()
	if _, err := c.GetFile(ctx, 1, 7, 2); !errors.Is(err, iec104.ErrClosed) {
		t.Errorf("GetFile on a closed client: %v", err)
	}
}

// script is a station that answers each file transfer ASDU of the
// controlling station with the next entry of a list, and records what it
// received.
type script struct {
	mu      sync.Mutex
	answers [][]asdu.InformationObject
	got     []asdu.InformationObject
	hold    chan struct{} // when not nil, the first answer waits for it
}

func (sc *script) HandleASDU(s *server.Session, a *asdu.ASDU) {
	sc.mu.Lock()
	sc.got = append(sc.got, a.First())
	var answer []asdu.InformationObject
	if len(sc.answers) > 0 {
		answer, sc.answers = sc.answers[0], sc.answers[1:]
	}
	hold := sc.hold
	sc.hold = nil
	sc.mu.Unlock()
	if hold != nil {
		<-hold
	}
	for _, o := range answer {
		_ = s.Send(s.Context(), asdu.New(asdu.CauseFileTransfer, a.CommonAddr, o))
	}
}

func (sc *script) received() []asdu.InformationObject {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return append([]asdu.InformationObject(nil), sc.got...)
}

func sum(b []byte) (s uint8) {
	for _, v := range b {
		s += v
	}
	return s
}

func TestFileDownloadFaults(t *testing.T) {
	data := []byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ready := asdu.FileReady{IOA: 1, Name: 1, Length: 10}
	section := asdu.SectionReady{IOA: 1, Name: 1, Section: 1, Length: 10}
	segment := asdu.FileSegment{IOA: 1, Name: 1, Section: 1, Data: data}
	lastSegment := asdu.FileLastSegment{IOA: 1, Name: 1, Section: 1, Qualifier: asdu.LastSectionNoDeactivation, Checksum: sum(data)}
	lastSection := asdu.FileLastSegment{IOA: 1, Name: 1, Section: 2, Qualifier: asdu.LastFileNoDeactivation, Checksum: sum(data)}
	objs := func(o ...asdu.InformationObject) []asdu.InformationObject { return o }
	badSegment, badSection := lastSegment, lastSection
	badSegment.Checksum++
	badSection.Checksum++
	short := section
	short.Length = 9
	notReady := ready
	notReady.Qualifier = asdu.FileNegative
	sectionNotReady := section
	sectionNotReady.Qualifier = asdu.FileNegative

	for _, tc := range []struct {
		name     string
		answers  [][]asdu.InformationObject
		negative bool   // want *iec104.NegativeError, else ErrProtocol
		lastAck  uint8  // qualifier of the last F_AF the station must get; 0: none
		wantData []byte // set for the one script that is correct
	}{
		{name: "correct", answers: [][]asdu.InformationObject{objs(ready), objs(section), objs(segment, lastSegment), objs(lastSection)},
			lastAck: asdu.AckFilePositive, wantData: data},
		{name: "file not ready", answers: [][]asdu.InformationObject{objs(notReady)}, negative: true},
		{name: "section not ready", answers: [][]asdu.InformationObject{objs(ready), objs(sectionNotReady)}, negative: true},
		{name: "section checksum", answers: [][]asdu.InformationObject{objs(ready), objs(section), objs(segment, badSegment)},
			lastAck: asdu.AckSectionNegative},
		{name: "section length", answers: [][]asdu.InformationObject{objs(ready), objs(short), objs(segment, lastSegment)},
			lastAck: asdu.AckSectionNegative},
		{name: "file checksum", answers: [][]asdu.InformationObject{objs(ready), objs(section), objs(segment, lastSegment), objs(badSection)},
			lastAck: asdu.AckFileNegative},
		{name: "file shorter than announced", answers: [][]asdu.InformationObject{objs(ready), objs(lastSection)},
			lastAck: asdu.AckFileNegative},
		{name: "more data than announced", answers: [][]asdu.InformationObject{objs(ready), objs(section), objs(segment, segment)}},
		{name: "section ready instead of file ready", answers: [][]asdu.InformationObject{objs(section)}},
		{name: "segment without section", answers: [][]asdu.InformationObject{objs(ready), objs(segment)}},
		{name: "last section inside a section", answers: [][]asdu.InformationObject{objs(ready), objs(section), objs(lastSection)}},
		{name: "last segment instead of last section", answers: [][]asdu.InformationObject{objs(ready), objs(lastSegment)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &script{answers: tc.answers}
			addr := serveHandler(t, sc)
			c := dial(t, addr)
			got, err := c.GetFile(context.Background(), 1, 1, 1)
			var neg *iec104.NegativeError
			switch {
			case tc.wantData != nil:
				if err != nil || !bytes.Equal(got, tc.wantData) {
					t.Fatalf("GetFile = %v, %v", got, err)
				}
			case tc.negative:
				if !errors.As(err, &neg) {
					t.Fatalf("error = %v, want *iec104.NegativeError", err)
				}
			default:
				if !errors.Is(err, iec104.ErrProtocol) {
					t.Fatalf("error = %v, want ErrProtocol", err)
				}
			}
			if err != nil && got != nil {
				t.Errorf("GetFile returned %d octets alongside an error", len(got))
			}
			var lastAck uint8
			testutil.Eventually(t, "the acknowledgement", func() bool {
				lastAck = 0
				for _, o := range sc.received() {
					if ack, ok := o.(asdu.FileAck); ok {
						lastAck = ack.Qualifier
					}
				}
				return lastAck == tc.lastAck
			})
		})
	}
}

func TestFileDownloadRefusedByMirror(t *testing.T) {
	// A station without file transfer mirrors the call with "unknown type".
	addr := serveHandler(t, nil)
	c := dial(t, addr)
	_, err := c.GetFile(context.Background(), 1, 1, 1)
	if got := negativeCause(t, err); got != asdu.CauseUnknownType {
		t.Errorf("cause = %s, want unknown-type", got)
	}
}

func TestFileDownloadBusyAndTimeout(t *testing.T) {
	hold := make(chan struct{})
	sc := &script{hold: hold}
	addr := serveHandler(t, sc)
	c := dial(t, addr, client.WithRequestTimeout(300*time.Millisecond))

	first := make(chan error, 1)
	go func() {
		_, err := c.GetFile(context.Background(), 1, 1, 1)
		first <- err
	}()
	testutil.Eventually(t, "the first call at the station", func() bool { return len(sc.received()) == 1 })
	if _, err := c.GetFile(context.Background(), 1, 1, 1); !errors.Is(err, iec104.ErrBusy) {
		t.Errorf("second transfer of the same file: %v, want ErrBusy", err)
	}
	// The station never answers: every wait is bounded by the request timeout.
	begin := time.Now()
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unanswered transfer: %v, want a deadline error", err)
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Errorf("unanswered transfer took %s", d)
	}
	close(hold)

	// A caller's deadline bounds the transfer as a whole.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.GetFile(ctx, 1, 2, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("transfer with a deadline: %v, want a deadline error", err)
	}
}

// The termination of one command must not be taken for the confirmation of
// the next command to the same object.
func TestTerminationIsNotAConfirmation(t *testing.T) {
	var mu sync.Mutex
	n := 0
	addr := serveHandler(t, server.HandlerFunc(func(s *server.Session, req *asdu.ASDU) {
		mu.Lock()
		n++
		odd := n%2 == 1
		mu.Unlock()
		if req.Type == asdu.C_IC_NA_1 {
			_ = s.Confirm(req)
			_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr, asdu.SinglePoint{IOA: asdu.IOA(n)}))
			_ = s.Terminate(req)
			return
		}
		if !odd {
			_ = s.Negative(req)
			return
		}
		_ = s.Confirm(req)
		_ = s.Terminate(req)
	}))
	c := dial(t, addr)
	ctx := context.Background()
	for i := 0; i < 200; i++ {
		if err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true}); err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
		// The termination of the first is on its way while this one is sent.
		err := c.Command(ctx, 1, asdu.SingleCommand{IOA: 1, Value: true})
		var neg *iec104.NegativeError
		if !errors.As(err, &neg) {
			t.Fatalf("command %d refused by the station: client returned %v", i, err)
		}
	}
	// Likewise an interrogation ends with its own termination.
	for i := 0; i < 200; i++ {
		data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
		if err != nil || len(data) != 1 {
			t.Fatalf("interrogation %d: %d ASDUs, %v", i, len(data), err)
		}
	}
}
