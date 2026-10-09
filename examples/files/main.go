// SPDX-License-Identifier: MIT

// Command files shows file transfer: a station that offers files, takes
// files and has a directory, and a controlling station that lists, fetches
// and delivers.
//
//	go run ./examples/files
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

// store is the file system of the station, by information object address.
// It is a server.FileSource (files to fetch) and a server.FileSink (files
// delivered).
type store struct {
	mu    sync.Mutex
	files map[asdu.IOA]entry
}

type entry struct {
	name    uint16
	data    []byte
	created time.Time
}

func (st *store) OpenFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, name uint16) (server.File, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	e, ok := st.files[ioa]
	if !ok || e.name != name {
		return server.File{}, false // refused: unknown information object address
	}
	// Sections of 4 KiB; the library cuts them into segments.
	return server.NewFile(e.data, 4096), true
}

func (st *store) AcceptFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, length int) bool {
	return ioa >= 30100 && length <= 1<<20 // where and how much this station takes
}

func (st *store) StoreFile(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, name uint16, f server.File) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.files[ioa] = entry{name, bytes.Join(f.Sections, nil), time.Now()}
	return nil // an error here makes the acknowledgement negative
}

func (st *store) directory(_ *server.Session, _ asdu.CommonAddr, _ asdu.IOA) []asdu.FileDirectoryEntry {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []asdu.FileDirectoryEntry
	for ioa, e := range st.files {
		out = append(out, asdu.FileDirectoryEntry{IOA: ioa, Name: e.name, Length: uint32(len(e.data)), Time: asdu.At(e.created)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IOA < out[j].IOA })
	return out
}

func main() {
	st := &store{files: map[asdu.IOA]entry{
		30000: {1, bytes.Repeat([]byte("disturbance record\n"), 800), time.Now().Add(-time.Hour)},
	}}
	files := server.NewFileServer(st) // serves downloads from st
	files.Sink = st                   // takes uploads
	files.Directory = st.directory    // answers directory calls
	files.OnDone = func(_ *server.Session, _ asdu.CommonAddr, ioa asdu.IOA, _ uint16, err error) {
		fmt.Printf("  station: transfer of file %d ended: %v\n", ioa, err)
	}
	mux := server.NewMux()
	mux.Handle(files, server.FileTypes...)
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
	c, err := client.Dial(ctx, ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	list := func() {
		dir, err := c.ListFiles(ctx, 1, 0)
		if err != nil {
			log.Fatalf("directory: %v", err)
		}
		for _, e := range dir {
			fmt.Printf("  file %d  name %d  %6d octets  %s\n", e.IOA, e.Name, e.Length, e.Time.Format(time.RFC3339))
		}
	}
	fmt.Println("directory:")
	list()

	// Download: select, call, sections, checksums and acknowledgements are
	// done by GetFile.
	data, err := c.GetFile(ctx, 1, 30000, 1)
	if err != nil {
		log.Fatalf("download: %v", err)
	}
	fmt.Printf("downloaded file 30000: %d octets\n", len(data))

	// Upload: every argument after the name is one section.
	settings := []byte("limit=42.5\nmode=auto\n")
	if err := c.PutFile(ctx, 1, 30100, 7, settings); err != nil {
		log.Fatalf("upload: %v", err)
	}
	fmt.Println("uploaded file 30100; directory:")
	list()

	// A file the station does not have is refused, not timed out.
	_, err = c.GetFile(ctx, 1, 39999, 1)
	fmt.Println("download of an unknown file:", err)
}
