// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	iec104 "github.com/otfabric/go-iec104"
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

// sink keeps the files controlling stations deliver.
type sink struct {
	mu     sync.Mutex
	files  map[asdu.IOA][]byte
	shape  map[asdu.IOA][]int // section lengths
	refuse asdu.IOA           // an address the station does not take
	broken asdu.IOA           // an address it cannot store
}

func (k *sink) AcceptFile(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, length int) bool {
	return ca == 1 && name == 1 && ioa != k.refuse && length <= 100000
}

func (k *sink) StoreFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, f server.File) error {
	if ioa == k.broken {
		return errors.New("disk full")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var all []byte
	var shape []int
	for _, s := range f.Sections {
		all = append(all, s...)
		shape = append(shape, len(s))
	}
	k.files[ioa], k.shape[ioa] = all, shape
	return nil
}

func (k *sink) get(ioa asdu.IOA) ([]byte, []int, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.files[ioa]
	return b, k.shape[ioa], ok
}

func serveSink(t *testing.T, k *sink, done *[]error, mu *sync.Mutex) string {
	t.Helper()
	fs := server.NewFileServer(nil)
	fs.Sink = k
	fs.OnDone = func(_ *server.Session, _ asdu.CommonAddr, _ asdu.IOA, _ uint16, err error) {
		mu.Lock()
		*done = append(*done, err)
		mu.Unlock()
	}
	mux := server.NewMux()
	mux.Handle(fs, server.FileTypes...)
	_, addr := serve(t, mux)
	return addr
}

func TestFileUpload(t *testing.T) {
	k := &sink{files: map[asdu.IOA][]byte{}, shape: map[asdu.IOA][]int{}, refuse: 66, broken: 77}
	var done []error
	var mu sync.Mutex
	addr := serveSink(t, k, &done, &mu)
	c := connect(t, addr)
	ctx := context.Background()

	uploads := map[asdu.IOA][]int{ // section lengths
		1: {1}, 2: {asdu.MaxSegmentLength}, 3: {asdu.MaxSegmentLength + 1}, 4: {1000},
		5: {2048, 2048, 904}, 6: {}, 7: {0, 10, 0}, 8: {30000, 30000, 10000},
	}
	for ioa, lengths := range uploads {
		var sections [][]byte
		var want []byte
		for i, n := range lengths {
			sec := pattern(n, int(ioa)+i)
			sections = append(sections, sec)
			want = append(want, sec...)
		}
		if err := c.PutFile(ctx, 1, ioa, 1, sections...); err != nil {
			t.Fatalf("PutFile %d %v: %v", ioa, lengths, err)
		}
		got, shape, ok := k.get(ioa)
		if !ok || !bytes.Equal(got, want) || fmt.Sprint(shape) != fmt.Sprint(lengths) {
			t.Errorf("file %d: stored %d octets in sections %v, want %d in %v", ioa, len(got), shape, len(want), lengths)
		}
	}

	// What the station does not take.
	for what, tc := range map[string]struct {
		ca   asdu.CommonAddr
		ioa  asdu.IOA
		name uint16
		size int
	}{"refused address": {1, 66, 1, 10}, "wrong name": {1, 9, 2, 10}, "too long": {1, 9, 1, 100001}} {
		err := c.PutFile(ctx, tc.ca, tc.ioa, tc.name, pattern(tc.size, 0))
		if got := cause(t, err); got != asdu.CauseUnknownIOA {
			t.Errorf("%s: cause = %s, want unknown-ioa", what, got)
		}
	}
	// A file that arrives intact but cannot be stored is not acknowledged.
	var neg *iec104.NegativeError
	if err := c.PutFile(ctx, 1, 77, 1, pattern(10, 0)); !errors.As(err, &neg) {
		t.Errorf("file the station cannot store: %v, want a negative acknowledgement", err)
	} else if ack, ok := neg.ASDU.First().(asdu.FileAck); !ok || ack.Qualifier != asdu.AckFileNegative {
		t.Errorf("file the station cannot store: answered %s", neg.ASDU)
	}
	if _, _, ok := k.get(77); ok {
		t.Error("the file that could not be stored is in the sink")
	}
	// More than the procedure can carry never leaves the client.
	if err := c.PutFile(ctx, 1, 9, 1, make([][]byte, 255)...); !errors.Is(err, asdu.ErrInvalidValue) {
		t.Errorf("255 sections: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	good, bad := 0, 0
	for _, err := range done {
		if err == nil {
			good++
		} else {
			bad++
		}
	}
	if good != len(uploads) || bad != 1 {
		t.Errorf("OnDone: %d transfers succeeded and %d failed; want %d and 1", good, bad, len(uploads))
	}
}

// A station without a sink refuses every file; one that only takes files
// refuses every download.
func TestFileServerRoles(t *testing.T) {
	mux := server.NewMux()
	mux.Handle(server.NewFileServer(&fileStation{files: map[asdu.IOA]server.File{1: server.NewFile(pattern(5, 0), 0)}}), server.FileTypes...)
	_, addr := serve(t, mux)
	c := connect(t, addr)
	ctx := context.Background()
	if got := cause(t, c.PutFile(ctx, 1, 1, 1, pattern(5, 0))); got != asdu.CauseUnknownIOA {
		t.Errorf("upload to a station without a sink: %s", got)
	}
	if _, err := c.ListFiles(ctx, 1, 0); cause(t, err) != asdu.CauseUnknownIOA {
		t.Errorf("directory of a station without one: %v", err)
	}
	if got, err := c.GetFile(ctx, 1, 1, 1); err != nil || len(got) != 5 {
		t.Errorf("download still works: %v", err)
	}

	var done []error
	var mu sync.Mutex
	c = connect(t, serveSink(t, &sink{files: map[asdu.IOA][]byte{}, shape: map[asdu.IOA][]int{}}, &done, &mu))
	if _, err := c.GetFile(ctx, 1, 1, 1); cause(t, err) != asdu.CauseUnknownIOA {
		t.Errorf("download from a station that only takes files: %v", err)
	}
}

// What a file server answers to a delivery that breaks the procedure.
func TestFileUploadFaults(t *testing.T) {
	k := &sink{files: map[asdu.IOA][]byte{}, shape: map[asdu.IOA][]int{}}
	var done []error
	var mu sync.Mutex
	rec := &recorder{}
	c := connect(t, serveSink(t, k, &done, &mu), client.WithHandler(rec))
	ctx := context.Background()
	send := func(obj asdu.InformationObject) {
		t.Helper()
		if err := c.Send(ctx, asdu.New(asdu.CauseFileTransfer, 1, obj)); err != nil {
			t.Fatal(err)
		}
	}
	answer := func(obj asdu.InformationObject) *asdu.ASDU {
		t.Helper()
		n := len(rec.all())
		send(obj)
		testutil.Eventually(t, "an answer", func() bool { return len(rec.all()) > n })
		return rec.all()[n]
	}
	refused := func(what string, a *asdu.ASDU) {
		t.Helper()
		if !a.Negative || a.Cause != asdu.CauseUnknownIOA {
			t.Errorf("%s: answered %s, want a negative mirror with unknown-ioa", what, a)
		}
	}
	ack := func(what string, a *asdu.ASDU, want uint8) {
		t.Helper()
		if v, ok := a.First().(asdu.FileAck); !ok || v.Qualifier != want {
			t.Errorf("%s: answered %s %+v, want acknowledgement %d", what, a, a.First(), want)
		}
	}
	data := pattern(10, 0)
	ready := asdu.FileReady{IOA: 1, Name: 1, Length: 10}
	section := asdu.SectionReady{IOA: 1, Name: 1, Section: 1, Length: 10}
	segment := asdu.FileSegment{IOA: 1, Name: 1, Section: 1, Data: data}
	lastSegment := asdu.FileLastSegment{IOA: 1, Name: 1, Section: 1, Qualifier: asdu.LastSectionNoDeactivation, Checksum: sum(data)}
	lastSection := asdu.FileLastSegment{IOA: 1, Name: 1, Section: 2, Qualifier: asdu.LastFileNoDeactivation, Checksum: sum(data)}
	begin := func() {
		t.Helper()
		if call, ok := answer(ready).First().(asdu.FileCall); !ok || call.Qualifier != asdu.FileRequest {
			t.Fatal("file ready was not answered with the call of the file")
		}
	}

	refused("section ready without file ready", answer(section))
	refused("segment without file ready", answer(segment))
	refused("last segment without file ready", answer(lastSegment))

	begin()
	refused("section 2 before section 1", answer(asdu.SectionReady{IOA: 1, Name: 1, Section: 2, Length: 10}))
	refused("a section longer than the file", answer(asdu.SectionReady{IOA: 1, Name: 1, Section: 1, Length: 11}))
	refused("segment before its section", answer(segment))

	// A section whose checksum is wrong.
	begin()
	answer(section)
	send(segment)
	bad := lastSegment
	bad.Checksum++
	ack("wrong section checksum", answer(bad), asdu.AckSectionNegative)

	// A section with more data than it announced.
	begin()
	answer(section)
	send(segment)
	send(segment)
	ack("too much data", answer(lastSegment), asdu.AckSectionNegative)

	// A file that ends before everything announced has arrived.
	begin()
	short := lastSection
	short.Section, short.Checksum = 1, 0
	ack("file shorter than announced", answer(short), asdu.AckFileNegative)

	// A file whose checksum is wrong.
	begin()
	answer(section)
	send(segment)
	ack("section", answer(lastSegment), asdu.AckSectionPositive)
	badFile := lastSection
	badFile.Checksum++
	ack("wrong file checksum", answer(badFile), asdu.AckFileNegative)

	// Abandoned by the controlling station, then delivered properly.
	begin()
	abandon := lastSection
	abandon.Qualifier = asdu.LastFileDeactivation
	send(abandon)
	begin()
	answer(section)
	send(segment)
	ack("section", answer(lastSegment), asdu.AckSectionPositive)
	ack("file", answer(lastSection), asdu.AckFilePositive)
	if got, _, ok := k.get(1); !ok || !bytes.Equal(got, data) {
		t.Errorf("the file delivered at last: %v", got)
	}

	testutil.Eventually(t, "every transfer reported", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(done) == 7
	})
	mu.Lock()
	defer mu.Unlock()
	failed := 0
	for _, err := range done {
		if err != nil {
			failed++
		}
	}
	if failed != 6 {
		t.Errorf("OnDone reported %d failures of %d transfers, want 6 of 7: %v", failed, len(done), done)
	}
}

func TestFileDirectory(t *testing.T) {
	when := asdu.At(time.Date(2026, 3, 4, 5, 6, 7, 8e6, time.UTC))
	entry := func(ioa asdu.IOA, n int) asdu.FileDirectoryEntry {
		return asdu.FileDirectoryEntry{IOA: ioa, Name: uint16(n), Length: uint32(n) * 100, Status: 1, Time: when}
	}
	dirs := map[asdu.IOA][]asdu.FileDirectoryEntry{
		// The default directory: scattered addresses.
		0: {entry(10, 1), entry(500, 2), entry(70000, 3)},
		// More consecutive addresses than one ASDU holds.
		1: nil,
		// A single file.
		2: {entry(9, 9)},
		// Runs and gaps; one entry arrives already marked as the last.
		3: {entry(1, 1), entry(2, 2), entry(3, 3), entry(8, 4), entry(9, 5)},
	}
	for i := 0; i < 50; i++ {
		dirs[1] = append(dirs[1], entry(asdu.IOA(1000+i), i))
	}
	dirs[3][1].Status |= asdu.FileLastOfDirectory

	fs := server.NewFileServer(nil)
	fs.Directory = func(_ *server.Session, ca asdu.CommonAddr, ioa asdu.IOA) []asdu.FileDirectoryEntry {
		if ca != 1 {
			return nil
		}
		return dirs[ioa]
	}
	mux := server.NewMux()
	mux.Handle(fs, server.FileTypes...)
	_, addr := serve(t, mux)
	rec := &recorder{}
	c := connect(t, addr, client.WithHandler(rec))
	ctx := context.Background()

	for ioa, want := range dirs {
		rec.mu.Lock()
		rec.seen = nil
		rec.mu.Unlock()
		got, err := c.ListFiles(ctx, 1, ioa)
		if err != nil {
			t.Fatalf("ListFiles %d: %v", ioa, err)
		}
		if len(got) != len(want) {
			t.Fatalf("directory %d: %d entries, want %d", ioa, len(got), len(want))
		}
		for i, e := range got {
			w := want[i]
			w.Status &^= asdu.FileLastOfDirectory
			if i == len(want)-1 {
				w.Status |= asdu.FileLastOfDirectory
			}
			if e != w {
				t.Errorf("directory %d entry %d: %+v, want %+v", ioa, i, e, w)
			}
		}
		for _, a := range rec.all() {
			if a.Type != asdu.F_DR_TA_1 || a.Cause != asdu.CauseRequest || !a.Sequence || len(a.Objects) > 18 {
				t.Errorf("directory %d sent as %s", ioa, a)
			}
		}
	}
	// The source's own entries were not touched.
	if dirs[3][1].Status&asdu.FileLastOfDirectory == 0 || dirs[0][2].Status&asdu.FileLastOfDirectory != 0 {
		t.Error("the directory callback's entries were modified")
	}
	// No such directory, no such station.
	_, err := c.ListFiles(ctx, 1, 99)
	if got := cause(t, err); got != asdu.CauseUnknownIOA {
		t.Errorf("unknown directory: %s", got)
	}
	_, err = c.ListFiles(ctx, 2, 0)
	if got := cause(t, err); got != asdu.CauseUnknownIOA {
		t.Errorf("directory of another station: %s", got)
	}
}

func sum(b []byte) (s uint8) {
	for _, v := range b {
		s += v
	}
	return s
}
