// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"sync"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
)

// File is the content of a file a station offers, in sections. The
// controlling station calls the sections one after the other and
// acknowledges each.
type File struct {
	Sections [][]byte
}

// NewFile splits data into sections of sectionSize octets; the last one
// holds what remains. A sectionSize of 0 or less makes one section. Empty
// data makes a file without sections. The sections share the memory of
// data.
func NewFile(data []byte, sectionSize int) File {
	if sectionSize <= 0 {
		sectionSize = len(data)
	}
	var f File
	for len(data) > 0 {
		n := min(sectionSize, len(data))
		f.Sections = append(f.Sections, data[:n:n])
		data = data[n:]
	}
	return f
}

// Len returns the length of the file in octets.
func (f File) Len() int {
	n := 0
	for _, s := range f.Sections {
		n += len(s)
	}
	return n
}

// FileSource finds the files of a station. Implementations must be safe for
// concurrent use.
type FileSource interface {
	// OpenFile returns the file with the given common address, information
	// object address and name of file (NOF), and false when the station
	// has no such file. The file is read while the transfer runs and must
	// not change until [FileServer.OnDone] reports its end.
	OpenFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (File, bool)
}

// FileSourceFunc adapts a function to the [FileSource] interface.
type FileSourceFunc func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (File, bool)

// OpenFile calls f.
func (f FileSourceFunc) OpenFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) (File, bool) {
	return f(s, ca, ioa, name)
}

// FileSink takes the files controlling stations send to a station.
// Implementations must be safe for concurrent use.
type FileSink interface {
	// AcceptFile is asked when a controlling station announces a file of
	// length octets. Returning false refuses it.
	AcceptFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, length int) bool
	// StoreFile is called with a file that arrived complete, every checksum
	// verified, before it is acknowledged. An error makes the
	// acknowledgement negative.
	StoreFile(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, file File) error
}

// FileTypes lists the type identifications a [FileServer] handles, for
// registering it with [Mux.Handle]: the calls and acknowledgements of a
// controlling station that fetches a file or the directory, and what it
// sends when it delivers one.
var FileTypes = []asdu.TypeID{
	asdu.F_SC_NA_1, asdu.F_AF_NA_1,
	asdu.F_FR_NA_1, asdu.F_SR_NA_1, asdu.F_SG_NA_1, asdu.F_LS_NA_1,
}

// ErrFileNotAcknowledged is reported to [FileServer.OnDone] when the
// controlling station answers a section or the file with a negative
// acknowledgement, or abandons the transfer.
var ErrFileNotAcknowledged = errors.New("iec104: file transfer not acknowledged")

// FileServer is a [Handler] for the file transfer services of
// IEC 60870-5-101, 7.4.11: it serves files to controlling stations (monitor
// direction), takes files from them (control direction, with [FileServer.Sink])
// and answers calls of the directory (with [FileServer.Directory]).
//
// A controlling station fetches a file like this:
//
//	select file      F_SC_NA_1 (SCQ 1)  ->  F_FR_NA_1  file ready
//	request file     F_SC_NA_1 (SCQ 2)  ->  F_SR_NA_1  section ready
//	request section  F_SC_NA_1 (SCQ 6)  ->  F_SG_NA_1  segments, then
//	                                        F_LS_NA_1  last segment
//	ack section      F_AF_NA_1 (AFQ 3)  ->  F_SR_NA_1  next section, or
//	                                        F_LS_NA_1  last section
//	ack file         F_AF_NA_1 (AFQ 1)
//
// and delivers one like this, the station doing the calling:
//
//	file ready       F_FR_NA_1          ->  F_SC_NA_1 (SCQ 2)  call file
//	section ready    F_SR_NA_1          ->  F_SC_NA_1 (SCQ 6)  call section
//	segments         F_SG_NA_1, then
//	last segment     F_LS_NA_1 (LSQ 3)  ->  F_AF_NA_1 (AFQ 3)  ack section
//	last section     F_LS_NA_1 (LSQ 1)  ->  F_AF_NA_1 (AFQ 1)  ack file
//
// A file the [FileSource] does not have, or the [FileSink] does not accept,
// is refused by mirroring the request with cause "unknown information object
// address". A length or checksum that does not match what arrived is
// acknowledged negatively. A session transfers any number of files at once,
// one per address and direction; starting an address again starts over.
// Transfers end with their session.
//
// Register it for [FileTypes]:
//
//	mux.Handle(server.NewFileServer(source), server.FileTypes...)
//
// Deletion is not served: such a call is answered negatively.
type FileServer struct {
	// Sink, when not nil, takes the files controlling stations send. Without
	// it a file ready is refused. Set it before the server starts.
	Sink FileSink

	// Directory, when not nil, answers a call of the directory (F_SC_NA_1
	// with cause "request") with the entries it returns, sent as F_DR_TA_1.
	// ioa is the address the call names, 0 for the default directory. The
	// last entry is marked as such for the caller. Returning no entries, or
	// leaving Directory nil, refuses the call. Set it before the server
	// starts.
	Directory func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA) []asdu.FileDirectoryEntry

	// OnDone, when not nil, is called when a transfer ends: with nil once
	// the controlling station acknowledged the file, with
	// [ErrFileNotAcknowledged] or the error that stopped it otherwise. It
	// is not called for a transfer that ends because its session did. Set
	// it before the server starts.
	OnDone func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, err error)

	source FileSource

	mu        sync.Mutex
	transfers map[fileKey]*fileTransfer
	uploads   map[fileKey]*fileUpload
	watched   map[*Session]struct{}
}

type fileKey struct {
	s   *Session
	ca  asdu.CommonAddr
	ioa asdu.IOA
}

// fileTransfer is the state of one transfer. Only the handler of its
// session touches it after it is recorded, one ASDU at a time.
type fileTransfer struct {
	name    uint16
	file    File
	section int // index of the section called or to call next
}

// fileUpload is the state of one file a controlling station is sending.
// Like a fileTransfer it belongs to the handler of its session.
type fileUpload struct {
	name     uint16
	length   int // announced by file ready
	received int
	sections [][]byte
	open     bool  // a section was called and its segments are arriving
	nos      uint8 // name of the open section
	want     int   // its announced length
}

// NewFileServer returns a FileServer for the files of source. source may be
// nil for a station that only takes files or only has a directory.
func NewFileServer(source FileSource) *FileServer {
	return &FileServer{
		source:    source,
		transfers: make(map[fileKey]*fileTransfer),
		uploads:   make(map[fileKey]*fileUpload),
		watched:   make(map[*Session]struct{}),
	}
}

func fileChecksum(sections ...[]byte) (sum uint8) {
	for _, s := range sections {
		for _, v := range s {
			sum += v
		}
	}
	return sum
}

// HandleASDU serves one file transfer ASDU.
func (f *FileServer) HandleASDU(s *Session, a *asdu.ASDU) {
	if call, ok := a.First().(asdu.FileCall); ok && a.Cause == asdu.CauseRequest {
		f.directory(s, a, call)
		return
	}
	if a.Cause != asdu.CauseFileTransfer {
		_ = s.Reject(a, asdu.CauseUnknownCause)
		return
	}
	var err error
	switch o := a.First().(type) {
	case asdu.FileCall:
		err = f.call(s, a, o)
	case asdu.FileAck:
		err = f.ack(s, a, o)
	case asdu.FileReady, asdu.SectionReady, asdu.FileSegment, asdu.FileLastSegment:
		err = f.receive(s, a)
	default:
		err = s.Reject(a, asdu.CauseUnknownType)
	}
	if err != nil {
		key := fileKey{s, a.CommonAddr, a.First().Address()}
		s.log.Warn("file transfer stopped", "ca", a.CommonAddr, "ioa", uint32(key.ioa), "error", err)
		if t := f.take(key); t != nil {
			f.done(key, t, err)
		}
		if u := f.takeUpload(key); u != nil && f.OnDone != nil {
			f.OnDone(s, key.ca, key.ioa, u.name, err)
		}
	}
}

func (f *FileServer) get(key fileKey, name uint16) *fileTransfer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t := f.transfers[key]; t != nil && t.name == name {
		return t
	}
	return nil
}

func (f *FileServer) take(key fileKey) *fileTransfer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.transfers[key]
	delete(f.transfers, key)
	return t
}

func (f *FileServer) done(key fileKey, t *fileTransfer, err error) {
	if f.OnDone != nil {
		f.OnDone(key.s, key.ca, key.ioa, t.name, err)
	}
}

// put records a transfer and makes sure it goes away with its session.
func (f *FileServer) put(key fileKey, t *fileTransfer) {
	f.mu.Lock()
	f.transfers[key] = t
	_, watched := f.watched[key.s]
	f.watched[key.s] = struct{}{}
	f.mu.Unlock()
	if watched {
		return
	}
	go func() {
		<-key.s.Context().Done()
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.watched, key.s)
		for k := range f.transfers {
			if k.s == key.s {
				delete(f.transfers, k)
			}
		}
		for k := range f.uploads {
			if k.s == key.s {
				delete(f.uploads, k)
			}
		}
	}()
}

// watch makes sure the state of a session goes away with it.
func (f *FileServer) watch(s *Session) {
	f.mu.Lock()
	_, watched := f.watched[s]
	f.watched[s] = struct{}{}
	f.mu.Unlock()
	if watched {
		return
	}
	go func() {
		<-s.Context().Done()
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.watched, s)
		for k := range f.transfers {
			if k.s == s {
				delete(f.transfers, k)
			}
		}
		for k := range f.uploads {
			if k.s == s {
				delete(f.uploads, k)
			}
		}
	}()
}

func (f *FileServer) upload(key fileKey) *fileUpload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.uploads[key]
}

func (f *FileServer) takeUpload(key fileKey) *fileUpload {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.uploads[key]
	delete(f.uploads, key)
	return u
}

// receive handles what a controlling station sends when it delivers a file.
func (f *FileServer) receive(s *Session, a *asdu.ASDU) error {
	key := fileKey{s, a.CommonAddr, a.First().Address()}
	refuse := func() error { return s.Reject(a, asdu.CauseUnknownIOA) }
	finish := func(u *fileUpload, err error) {
		f.takeUpload(key)
		if f.OnDone != nil {
			f.OnDone(s, key.ca, key.ioa, u.name, err)
		}
	}

	switch o := a.First().(type) {
	case asdu.FileReady:
		if old := f.takeUpload(key); old != nil && f.OnDone != nil {
			f.OnDone(s, key.ca, key.ioa, old.name, ErrFileNotAcknowledged)
		}
		if f.Sink == nil || o.Qualifier&asdu.FileNegative != 0 ||
			!f.Sink.AcceptFile(s, a.CommonAddr, o.IOA, o.Name, int(o.Length)) {
			return refuse()
		}
		f.watch(s)
		f.mu.Lock()
		f.uploads[key] = &fileUpload{name: o.Name, length: int(o.Length)}
		f.mu.Unlock()
		return f.send(s, a.CommonAddr, asdu.FileCall{IOA: o.IOA, Name: o.Name, Qualifier: asdu.FileRequest})

	case asdu.SectionReady:
		u := f.upload(key)
		if u == nil || u.name != o.Name || u.open || o.Qualifier&asdu.FileNegative != 0 ||
			int(o.Section) != len(u.sections)+1 || u.received+int(o.Length) > u.length {
			return refuse()
		}
		u.open, u.nos, u.want = true, o.Section, int(o.Length)
		u.sections = append(u.sections, make([]byte, 0, o.Length))
		return f.send(s, a.CommonAddr, asdu.FileCall{IOA: o.IOA, Name: o.Name, Section: o.Section, Qualifier: asdu.SectionRequest})

	case asdu.FileSegment:
		u := f.upload(key)
		if u == nil || u.name != o.Name || !u.open || o.Section != u.nos {
			return refuse()
		}
		sec := &u.sections[len(u.sections)-1]
		if len(*sec)+len(o.Data) > u.want {
			// More than the section announced: it fails its acknowledgement.
			u.want = -1
			return nil
		}
		*sec = append(*sec, o.Data...)
		u.received += len(o.Data)
		return nil

	case asdu.FileLastSegment:
		u := f.upload(key)
		if u == nil || u.name != o.Name {
			return refuse()
		}
		ack := asdu.FileAck{IOA: o.IOA, Name: o.Name, Section: o.Section}
		switch o.Qualifier & 0x0f {
		case asdu.LastSectionNoDeactivation:
			if !u.open || o.Section != u.nos {
				return refuse()
			}
			sec := u.sections[len(u.sections)-1]
			u.open = false
			if len(sec) != u.want || fileChecksum(sec) != o.Checksum {
				ack.Qualifier = asdu.AckSectionNegative
				finish(u, fmt.Errorf("%w: length or checksum of section %d does not match", iec104.ErrProtocol, o.Section))
				return f.send(s, a.CommonAddr, ack)
			}
			ack.Qualifier = asdu.AckSectionPositive
			return f.send(s, a.CommonAddr, ack)

		case asdu.LastFileNoDeactivation:
			if u.open {
				return refuse()
			}
			var err error
			if u.received != u.length || fileChecksum(u.sections...) != o.Checksum {
				err = fmt.Errorf("%w: length or checksum of the file does not match (%d of %d octets)",
					iec104.ErrProtocol, u.received, u.length)
			} else {
				err = f.Sink.StoreFile(s, a.CommonAddr, o.IOA, o.Name, File{Sections: u.sections})
			}
			ack.Qualifier = asdu.AckFilePositive
			if err != nil {
				ack.Qualifier = asdu.AckFileNegative
			}
			finish(u, err)
			return f.send(s, a.CommonAddr, ack)
		}
		// "With deactivation": the controlling station abandons the transfer.
		finish(u, ErrFileNotAcknowledged)
		return nil
	}
	return nil
}

// directory answers a call of the directory.
func (f *FileServer) directory(s *Session, a *asdu.ASDU, call asdu.FileCall) {
	var entries []asdu.FileDirectoryEntry
	if f.Directory != nil {
		entries = append(entries, f.Directory(s, a.CommonAddr, call.IOA)...)
	}
	if len(entries) == 0 {
		_ = s.Reject(a, asdu.CauseUnknownIOA)
		return
	}
	for i := range entries {
		entries[i].Status &^= asdu.FileLastOfDirectory
	}
	entries[len(entries)-1].Status |= asdu.FileLastOfDirectory

	// A directory travels as sequences of elements: entries with
	// consecutive addresses share an ASDU, up to what an APDU holds.
	const perASDU = 18
	for len(entries) > 0 {
		n := 1
		for n < len(entries) && n < perASDU && entries[n].IOA == entries[n-1].IOA+1 {
			n++
		}
		out := asdu.New(asdu.CauseRequest, a.CommonAddr)
		out.Type, out.Sequence = asdu.F_DR_TA_1, true
		for _, e := range entries[:n] {
			out.Objects = append(out.Objects, e)
		}
		if err := s.Send(s.Context(), out); err != nil {
			s.log.Warn("directory not sent", "ca", a.CommonAddr, "error", err)
			return
		}
		entries = entries[n:]
	}
}

func (f *FileServer) send(s *Session, ca asdu.CommonAddr, obj asdu.InformationObject) error {
	return s.Send(s.Context(), asdu.New(asdu.CauseFileTransfer, ca, obj))
}

// sectionReady announces the next section, or the end of the file after the
// last one.
func (f *FileServer) sectionReady(key fileKey, t *fileTransfer) error {
	if t.section < len(t.file.Sections) {
		return f.send(key.s, key.ca, asdu.SectionReady{
			IOA: key.ioa, Name: t.name, Section: uint8(t.section + 1), Length: uint32(len(t.file.Sections[t.section])),
		})
	}
	return f.send(key.s, key.ca, asdu.FileLastSegment{
		IOA: key.ioa, Name: t.name, Section: uint8(t.section + 1),
		Qualifier: asdu.LastFileNoDeactivation, Checksum: fileChecksum(t.file.Sections...),
	})
}

func (f *FileServer) call(s *Session, a *asdu.ASDU, o asdu.FileCall) error {
	key := fileKey{s, a.CommonAddr, o.IOA}
	switch o.Qualifier & 0x0f {
	case asdu.FileSelect:
		if old := f.take(key); old != nil {
			f.done(key, old, ErrFileNotAcknowledged)
		}
		var file File
		ok := false
		if f.source != nil {
			file, ok = f.source.OpenFile(s, a.CommonAddr, o.IOA, o.Name)
		}
		if !ok {
			return s.Reject(a, asdu.CauseUnknownIOA)
		}
		if n := len(file.Sections); n > 254 || file.Len() > asdu.MaxFileLength {
			_ = s.Reject(a, asdu.CauseUnknownIOA)
			return fmt.Errorf("%w: file of %d sections and %d octets cannot be transferred",
				iec104.ErrProtocol, n, file.Len())
		}
		f.put(key, &fileTransfer{name: o.Name, file: file})
		return f.send(s, a.CommonAddr, asdu.FileReady{IOA: o.IOA, Name: o.Name, Length: uint32(file.Len())})

	case asdu.FileRequest:
		t := f.get(key, o.Name)
		if t == nil {
			return s.Reject(a, asdu.CauseUnknownIOA)
		}
		t.section = 0
		return f.sectionReady(key, t)

	case asdu.SectionRequest:
		t := f.get(key, o.Name)
		if t == nil || int(o.Section) != t.section+1 || t.section >= len(t.file.Sections) {
			return s.Reject(a, asdu.CauseUnknownIOA)
		}
		data := t.file.Sections[t.section]
		for rest := data; len(rest) > 0; {
			n := min(asdu.MaxSegmentLength, len(rest))
			seg := asdu.FileSegment{IOA: o.IOA, Name: o.Name, Section: o.Section, Data: rest[:n]}
			if err := f.send(s, a.CommonAddr, seg); err != nil {
				return err
			}
			rest = rest[n:]
		}
		return f.send(s, a.CommonAddr, asdu.FileLastSegment{
			IOA: o.IOA, Name: o.Name, Section: o.Section,
			Qualifier: asdu.LastSectionNoDeactivation, Checksum: fileChecksum(data),
		})

	case asdu.FileDeactivate, asdu.SectionDeactivate:
		if t := f.take(key); t != nil {
			f.done(key, t, ErrFileNotAcknowledged)
		}
		return nil
	}
	// Deletion, the selection of a section: not served.
	return s.Reply(a, asdu.CauseFileTransfer, true)
}

func (f *FileServer) ack(s *Session, a *asdu.ASDU, o asdu.FileAck) error {
	key := fileKey{s, a.CommonAddr, o.IOA}
	t := f.get(key, o.Name)
	if t == nil {
		return s.Reject(a, asdu.CauseUnknownIOA)
	}
	switch o.Qualifier & 0x0f {
	case asdu.AckSectionPositive:
		if int(o.Section) != t.section+1 || t.section >= len(t.file.Sections) {
			return s.Reject(a, asdu.CauseUnknownIOA)
		}
		t.section++
		return f.sectionReady(key, t)
	case asdu.AckFilePositive:
		f.take(key)
		f.done(key, t, nil)
		return nil
	}
	// A negative acknowledgement ends the transfer; the controlling station
	// selects the file again to repeat it.
	f.take(key)
	f.done(key, t, ErrFileNotAcknowledged)
	return nil
}
