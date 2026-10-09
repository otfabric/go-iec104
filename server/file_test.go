// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/internal/testutil"
	"github.com/otfabric/go-iec104/server"
)

func pattern(n, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i + seed) % 251)
	}
	return b
}

// fileStation serves files by address; every file has name 1.
type fileStation struct {
	files map[asdu.IOA]server.File

	mu   sync.Mutex
	done []error
}

func (st *fileStation) OpenFile(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (server.File, bool) {
	f, ok := st.files[ioa]
	return f, ok && ca == 1 && name == 1
}

func (st *fileStation) results() []error {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]error(nil), st.done...)
}

func serveFiles(t *testing.T, st *fileStation) string {
	t.Helper()
	fs := server.NewFileServer(st)
	fs.OnDone = func(_ *server.Session, _ asdu.CommonAddr, _ asdu.IOA, _ uint16, err error) {
		st.mu.Lock()
		st.done = append(st.done, err)
		st.mu.Unlock()
	}
	mux := server.NewMux()
	mux.Handle(fs, server.FileTypes...)
	_, addr := serve(t, mux)
	return addr
}

// recorder keeps the ASDUs a client receives.
type recorder struct {
	mu   sync.Mutex
	seen []*asdu.ASDU
}

func (r *recorder) HandleASDU(a *asdu.ASDU) {
	r.mu.Lock()
	r.seen = append(r.seen, a)
	r.mu.Unlock()
}

func (r *recorder) all() []*asdu.ASDU {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*asdu.ASDU(nil), r.seen...)
}

func TestNewFile(t *testing.T) {
	for _, tc := range []struct {
		size, sectionSize int
		want              []int
	}{
		{0, 100, nil},
		{1, 100, []int{1}},
		{100, 100, []int{100}},
		{101, 100, []int{100, 1}},
		{5000, 2048, []int{2048, 2048, 904}},
		{300, 0, []int{300}},
		{300, -1, []int{300}},
	} {
		f := server.NewFile(pattern(tc.size, 0), tc.sectionSize)
		var got []int
		for _, s := range f.Sections {
			got = append(got, len(s))
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) || f.Len() != tc.size {
			t.Errorf("NewFile(%d, %d): sections %v, Len %d; want %v", tc.size, tc.sectionSize, got, f.Len(), tc.want)
		}
	}
}

func TestFileDownload(t *testing.T) {
	sizes := map[asdu.IOA][2]int{ // size, section size
		1: {1, 1}, 2: {asdu.MaxSegmentLength, 0}, 3: {asdu.MaxSegmentLength + 1, 0},
		4: {1000, 1000}, 5: {5000, 2048}, 6: {0, 0}, 7: {4096, 2048}, 8: {70000, 30000},
	}
	st := &fileStation{files: map[asdu.IOA]server.File{}}
	for ioa, s := range sizes {
		st.files[ioa] = server.NewFile(pattern(s[0], int(ioa)), s[1])
	}
	addr := serveFiles(t, st)
	rec := &recorder{}
	c := connect(t, addr, client.WithHandler(rec))

	for ioa, s := range sizes {
		got, err := c.GetFile(context.Background(), 1, ioa, 1)
		if err != nil {
			t.Fatalf("GetFile %d (%d octets): %v", ioa, s[0], err)
		}
		if !bytes.Equal(got, pattern(s[0], int(ioa))) {
			t.Errorf("GetFile %d: got %d octets that differ from the %d served", ioa, len(got), s[0])
		}
	}
	testutil.Eventually(t, "every transfer reported", func() bool { return len(st.results()) == len(sizes) })
	for _, err := range st.results() {
		if err != nil {
			t.Errorf("OnDone: %v, want nil", err)
		}
	}

	// On the wire: cause 13 throughout, segments that fit an APDU, sections
	// numbered from 1 and the last section one past them.
	var sections, lastOfFile5 int
	for _, a := range rec.all() {
		if a.Cause != asdu.CauseFileTransfer || a.Negative {
			t.Errorf("unexpected ASDU %s", a)
		}
		switch o := a.First().(type) {
		case asdu.FileSegment:
			if len(o.Data) == 0 || len(o.Data) > asdu.MaxSegmentLength {
				t.Errorf("segment of %d octets", len(o.Data))
			}
		case asdu.SectionReady:
			if o.IOA == 5 {
				sections++
				if int(o.Section) != sections {
					t.Errorf("section %d announced as %d", sections, o.Section)
				}
			}
		case asdu.FileLastSegment:
			if o.IOA == 5 && o.Qualifier == asdu.LastFileNoDeactivation {
				lastOfFile5 = int(o.Section)
			}
		}
	}
	if sections != 3 || lastOfFile5 != 4 {
		t.Errorf("file 5: %d sections, last section named %d; want 3 and 4", sections, lastOfFile5)
	}
}

func TestFileRefused(t *testing.T) {
	st := &fileStation{files: map[asdu.IOA]server.File{1: server.NewFile(pattern(10, 0), 0)}}
	c := connect(t, serveFiles(t, st))
	ctx := context.Background()
	for _, tc := range []struct {
		what string
		ca   asdu.CommonAddr
		ioa  asdu.IOA
		name uint16
	}{{"unknown address", 1, 9, 1}, {"wrong name", 1, 1, 2}, {"other station", 2, 1, 1}} {
		_, err := c.GetFile(ctx, tc.ca, tc.ioa, tc.name)
		if got := cause(t, err); got != asdu.CauseUnknownIOA {
			t.Errorf("%s: cause = %s, want unknown-ioa", tc.what, got)
		}
	}
	if n := len(st.results()); n != 0 {
		t.Errorf("OnDone called %d times for refused files", n)
	}
	// The station still serves the file it has.
	if got, err := c.GetFile(ctx, 1, 1, 1); err != nil || len(got) != 10 {
		t.Errorf("GetFile after refusals: %d octets, %v", len(got), err)
	}
}

// What a file server answers to calls outside the procedure.
func TestFileServerOutOfOrder(t *testing.T) {
	st := &fileStation{files: map[asdu.IOA]server.File{1: server.NewFile(pattern(600, 0), 300)}}
	rec := &recorder{}
	c := connect(t, serveFiles(t, st), client.WithHandler(rec))
	ctx := context.Background()
	send := func(cause asdu.Cause, obj asdu.InformationObject) *asdu.ASDU {
		t.Helper()
		n := len(rec.all())
		if err := c.Send(ctx, asdu.New(cause, 1, obj)); err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(t, "an answer", func() bool { return len(rec.all()) > n })
		return rec.all()[n]
	}
	refusal := func(what string, a *asdu.ASDU, want asdu.Cause) {
		t.Helper()
		if !a.Negative || a.Cause != want {
			t.Errorf("%s: answered %s, want a negative mirror with cause %s", what, a, want)
		}
	}
	call := func(q uint8, section uint8) asdu.FileCall {
		return asdu.FileCall{IOA: 1, Name: 1, Section: section, Qualifier: q}
	}

	refusal("request before select", send(asdu.CauseFileTransfer, call(asdu.FileRequest, 0)), asdu.CauseUnknownIOA)
	refusal("ack before select", send(asdu.CauseFileTransfer,
		asdu.FileAck{IOA: 1, Name: 1, Section: 1, Qualifier: asdu.AckSectionPositive}), asdu.CauseUnknownIOA)
	refusal("wrong cause", send(asdu.CauseActivation, call(asdu.FileSelect, 0)), asdu.CauseUnknownCause)
	refusal("delete", send(asdu.CauseFileTransfer, call(asdu.FileDelete, 0)), asdu.CauseFileTransfer)

	if _, ok := send(asdu.CauseFileTransfer, call(asdu.FileSelect, 0)).First().(asdu.FileReady); !ok {
		t.Fatal("select was not answered with file ready")
	}
	refusal("section 2 before section 1", send(asdu.CauseFileTransfer, call(asdu.SectionRequest, 2)), asdu.CauseUnknownIOA)
	refusal("ack of a section that was not sent", send(asdu.CauseFileTransfer,
		asdu.FileAck{IOA: 1, Name: 1, Section: 2, Qualifier: asdu.AckSectionPositive}), asdu.CauseUnknownIOA)

	// Selecting again abandons the first transfer; so does a deactivation
	// and a negative acknowledgement.
	send(asdu.CauseFileTransfer, call(asdu.FileSelect, 0))
	if err := c.Send(ctx, asdu.New(asdu.CauseFileTransfer, 1, call(asdu.FileDeactivate, 0))); err != nil {
		t.Fatal(err)
	}
	send(asdu.CauseFileTransfer, call(asdu.FileSelect, 0))
	if err := c.Send(ctx, asdu.New(asdu.CauseFileTransfer, 1,
		asdu.FileAck{IOA: 1, Name: 1, Section: 1, Qualifier: asdu.AckSectionNegative})); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "three abandoned transfers", func() bool { return len(st.results()) == 3 })
	for _, err := range st.results() {
		if !errors.Is(err, server.ErrFileNotAcknowledged) {
			t.Errorf("OnDone: %v, want ErrFileNotAcknowledged", err)
		}
	}
	refusal("request after the transfer ended", send(asdu.CauseFileTransfer, call(asdu.FileRequest, 0)), asdu.CauseUnknownIOA)
}

// A transfer in progress goes away with its session and does not disturb a
// transfer of the same file on another one.
func TestFileTransfersPerSession(t *testing.T) {
	st := &fileStation{files: map[asdu.IOA]server.File{1: server.NewFile(pattern(3000, 0), 1000)}}
	addr := serveFiles(t, st)
	ctx := context.Background()

	rec := &recorder{}
	a := connect(t, addr, client.WithHandler(rec))
	if err := a.Send(ctx, asdu.New(asdu.CauseFileTransfer, 1, asdu.FileCall{IOA: 1, Name: 1, Qualifier: asdu.FileSelect})); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, "file ready", func() bool { return len(rec.all()) == 1 })

	b := connect(t, addr)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		c := connect(t, addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := c.GetFile(ctx, 1, 1, 1); err != nil || len(got) != 3000 {
				t.Errorf("concurrent GetFile: %d octets, %v", len(got), err)
			}
		}()
	}
	wg.Wait()
	_ = a.Close()
	if got, err := b.GetFile(ctx, 1, 1, 1); err != nil || len(got) != 3000 {
		t.Errorf("GetFile after another session closed: %d octets, %v", len(got), err)
	}
	for _, err := range st.results() {
		if err != nil {
			t.Errorf("OnDone: %v; the half-finished transfer must not be reported", err)
		}
	}
}
