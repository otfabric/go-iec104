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

// FileTypes lists the type identifications a [FileServer] handles, for
// registering it with [Mux.Handle].
var FileTypes = []asdu.TypeID{asdu.F_SC_NA_1, asdu.F_AF_NA_1}

// ErrFileNotAcknowledged is reported to [FileServer.OnDone] when the
// controlling station answers a section or the file with a negative
// acknowledgement, or abandons the transfer.
var ErrFileNotAcknowledged = errors.New("iec104: file transfer not acknowledged")

// FileServer is a [Handler] that serves files to controlling stations: the
// file transfer procedure in monitor direction (IEC 60870-5-101, 7.4.11).
//
//	select file      F_SC_NA_1 (SCQ 1)  ->  F_FR_NA_1  file ready
//	request file     F_SC_NA_1 (SCQ 2)  ->  F_SR_NA_1  section ready
//	request section  F_SC_NA_1 (SCQ 6)  ->  F_SG_NA_1  segments, then
//	                                        F_LS_NA_1  last segment
//	ack section      F_AF_NA_1 (AFQ 3)  ->  F_SR_NA_1  next section, or
//	                                        F_LS_NA_1  last section
//	ack file         F_AF_NA_1 (AFQ 1)
//
// A file the [FileSource] does not have is refused by mirroring the call
// with cause "unknown information object address". A session transfers any
// number of files at once, one per address; selecting an address again
// starts over. Transfers end with their session.
//
// Register it for [FileTypes]:
//
//	mux.Handle(server.NewFileServer(source), server.FileTypes...)
//
// The directory, deletion and the transfer in control direction are not
// served: such a call is answered negatively.
type FileServer struct {
	// OnDone, when not nil, is called when a transfer ends: with nil once
	// the controlling station acknowledged the file, with
	// [ErrFileNotAcknowledged] or the error that stopped it otherwise. It
	// is not called for a transfer that ends because its session did. Set
	// it before the server starts.
	OnDone func(s *Session, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, err error)

	source FileSource

	mu        sync.Mutex
	transfers map[fileKey]*fileTransfer
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

// NewFileServer returns a FileServer for the files of source.
func NewFileServer(source FileSource) *FileServer {
	return &FileServer{
		source:    source,
		transfers: make(map[fileKey]*fileTransfer),
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
	default:
		err = s.Reject(a, asdu.CauseUnknownType)
	}
	if err != nil {
		// Only a call or an acknowledgement gets here with an error.
		key := fileKey{s, a.CommonAddr, a.First().Address()}
		s.log.Warn("file transfer stopped", "ca", a.CommonAddr, "ioa", uint32(key.ioa), "error", err)
		if t := f.take(key); t != nil {
			f.done(key, t, err)
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
	}()
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
		file, ok := f.source.OpenFile(s, a.CommonAddr, o.IOA, o.Name)
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
	// The directory, deletion, the selection of a section: not served.
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
