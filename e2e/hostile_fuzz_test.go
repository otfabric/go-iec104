// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

// pipeListener is a net.Listener of in-memory connections: DialContext
// hands one end of a net.Pipe to Accept. It is also a client.Dialer.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (l *pipeListener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	local, remote := net.Pipe()
	select {
	case l.conns <- remote:
		return local, nil
	case <-l.done:
	case <-ctx.Done():
	}
	_ = local.Close()
	_ = remote.Close()
	return nil, errors.New("pipe listener: not accepting")
}

// fuzzStation is a small station with every kind of handler a stream can
// reach: an interrogation that answers with data, a file to fetch, a sink
// that takes files and a directory.
func fuzzStation() *server.Mux {
	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		if _, ok := req.First().(asdu.Interrogation); !ok {
			_ = s.Reject(req, asdu.CauseUnknownIOA)
			return
		}
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr,
			asdu.SinglePoint{IOA: 100, Value: true}))
		_ = s.Terminate(req)
	})
	data := make([]byte, 600)
	for i := range data {
		data[i] = byte(i)
	}
	files := server.NewFileServer(server.FileSourceFunc(func(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, name uint16) (server.File, bool) {
		return server.NewFile(data, 256), ioa == 1 && name == 1
	}))
	files.Sink = fuzzSink{}
	files.Directory = func(*server.Session, asdu.CommonAddr, asdu.IOA) []asdu.FileDirectoryEntry {
		return []asdu.FileDirectoryEntry{{IOA: 1, Name: 1, Length: uint32(len(data))}}
	}
	mux.Handle(files, server.FileTypes...)
	return mux
}

type fuzzSink struct{}

func (fuzzSink) AcceptFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, length int) bool {
	return ioa == 2 && length <= 4096
}

func (fuzzSink) StoreFile(*server.Session, asdu.CommonAddr, asdu.IOA, uint16, server.File) error {
	return nil
}

// ownGoroutines returns the stacks of the goroutines that run code of this
// module, other than the caller. The fuzzing engine starts goroutines of
// its own while it runs, so counting all of them is not a leak check.
func ownGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var own []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "github.com/otfabric/go-iec104/") && !strings.Contains(g, "[running]") {
			own = append(own, g)
		}
	}
	return own
}

// fuzzParams keeps every iteration short: a stream that leaves the server
// waiting for an acknowledgement is ended by t1.
func fuzzParams() apci.Params {
	return apci.Params{K: 12, W: 8, T0: time.Second, T1: 100 * time.Millisecond, T2: 50 * time.Millisecond, T3: 0}
}

// FuzzServerStream writes a valid STARTDT act and then the input, in
// chunks, to a server on an in-memory connection, reading whatever the
// server sends. The first octet of the input sets the chunk size. The
// server must not panic, must keep reading or end the connection, must
// close within a bound, and must leave no goroutine behind.
func FuzzServerStream(f *testing.F) {
	enc := func(a *asdu.ASDU) []byte {
		raw, err := a.Encode(asdu.IEC104)
		if err != nil {
			f.Fatal(err)
		}
		return raw
	}
	frame := func(fr apci.Frame) []byte {
		b, err := fr.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	cat := func(chunk byte, parts ...[]byte) []byte {
		out := []byte{chunk}
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	ic := enc(asdu.New(asdu.CauseActivation, 1, asdu.Interrogation{Qualifier: asdu.QOIStation}))
	sel := enc(asdu.New(asdu.CauseFileTransfer, 1, asdu.FileCall{IOA: 1, Name: 1, Qualifier: asdu.FileSelect}))
	req := enc(asdu.New(asdu.CauseFileTransfer, 1, asdu.FileCall{IOA: 1, Name: 1, Qualifier: asdu.FileRequest}))
	ready := enc(asdu.New(asdu.CauseFileTransfer, 1, asdu.FileReady{IOA: 2, Name: 1, Length: 10}))
	dir := enc(asdu.New(asdu.CauseRequest, 1, asdu.FileCall{IOA: 0}))

	// Valid streams.
	f.Add(cat(255, frame(apci.NewU(apci.TestFRAct))))
	f.Add(cat(255, frame(apci.NewI(0, 0, ic))))
	f.Add(cat(1, frame(apci.NewI(0, 0, ic)), frame(apci.NewS(3)), frame(apci.NewU(apci.TestFRAct))))
	f.Add(cat(7, frame(apci.NewI(0, 0, sel)), frame(apci.NewI(1, 0, req)), frame(apci.NewI(2, 0, dir))))
	f.Add(cat(13, frame(apci.NewI(0, 0, ready)), frame(apci.NewU(apci.StopDTAct)), frame(apci.NewU(apci.StartDTAct))))
	// Malformed ones.
	f.Add(cat(3, []byte{0x68, 0xFF, 0x00}))
	f.Add(cat(2, []byte{0x68, 0x03, 0x07, 0, 0}))
	f.Add(cat(5, []byte{0x68, 0x04, 0x47, 0, 0, 0}))
	f.Add(cat(9, frame(apci.NewI(5, 0, ic))))
	f.Add(cat(4, frame(apci.NewI(0, 0, []byte{100, 0x7F, 6, 0, 1, 0, 0, 0, 0, 20}))))
	f.Add(cat(6, frame(apci.NewI(0, 0, []byte{100, 0x00, 6, 0, 1, 0}))))
	f.Add(cat(8, []byte("GET / HTTP/1.1\r\n\r\n")))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		chunk, stream := 1+int(input[0])%64, input[1:]
		baseline := ownGoroutines()

		srv, err := server.New(fuzzStation(), server.WithParams(fuzzParams()))
		if err != nil {
			t.Fatal(err)
		}
		ln := newPipeListener()
		served := make(chan error, 1)
		go func() { served <- srv.Serve(ln) }()
		conn, err := ln.DialContext(context.Background(), "pipe", "station")
		if err != nil {
			t.Fatal(err)
		}
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_, _ = io.Copy(io.Discard, conn)
		}()

		// Every write must be read within a bound longer than t1: a server
		// that stops reading has either ended the connection by then or
		// hangs.
		write := func(b []byte) bool {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * fuzzParams().T1))
			_, err := conn.Write(b)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("the server stopped reading without ending the connection")
			}
			return err == nil
		}
		if write(frame(apci.NewU(apci.StartDTAct))) {
			for len(stream) > 0 {
				n := min(chunk, len(stream))
				if !write(stream[:n]) {
					break
				}
				stream = stream[n:]
			}
		}

		closed := make(chan error, 1)
		go func() { closed <- srv.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Errorf("server Close: %v", err)
			}
		case <-time.After(2 * time.Second):
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("server Close hangs:\n%s", buf)
		}
		if err := <-served; !errors.Is(err, server.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
		_ = conn.Close()
		<-drained

		deadline := time.Now().Add(2 * time.Second)
		for len(ownGoroutines()) > len(baseline) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if now := ownGoroutines(); len(now) > len(baseline) {
			t.Fatalf("%d goroutines of go-iec104 before, %d after Close:\n%s", len(baseline), len(now),
				strings.Join(now, "\n\n"))
		}
	})
}
