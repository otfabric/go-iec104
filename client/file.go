// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
)

// GetFile downloads a file from the controlled station: the file transfer
// procedure in monitor direction (IEC 60870-5-101, 7.4.11). ioa is the
// information object address of the file and name its name of file (NOF).
//
// It selects and calls the file, then calls every section the station
// announces, checks the length and the checksum of each section and of the
// file, and acknowledges them. It returns the content once the file is
// acknowledged.
//
// A station that refuses the file (unknown address or name, file not ready)
// is reported as [*iec104.NegativeError]. A length or checksum that does not
// match is acknowledged negatively and reported as [iec104.ErrProtocol].
//
// The request timeout bounds every wait for the station, not the whole
// transfer; ctx bounds the transfer. The ASDUs of the transfer are also
// delivered to the [Handler]. Two transfers of the same file at once fail
// with [iec104.ErrBusy], and a download is never repeated by [WithRetry].
func (c *Client) GetFile(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA, name uint16) ([]byte, error) {
	req := asdu.New(asdu.CauseFileTransfer, ca, asdu.FileCall{IOA: ioa, Name: name, Qualifier: asdu.FileSelect})
	var data []byte
	// run bounds an attempt by the request timeout, which would be the whole
	// transfer: the download takes the caller's context and bounds its steps.
	err := c.run(ctx, req, false, func(context.Context) (err error) {
		data, err = c.getFile(ctx, req, ioa, name)
		return err
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

// fileStep is one "send, then wait for the station" of a transfer.
type fileStep struct {
	c    *Client
	x    *exchange
	ctx  context.Context
	ca   asdu.CommonAddr
	ioa  asdu.IOA
	name uint16
	// calls says that a call (F_SC_NA_1) from the station is a step of the
	// procedure, as it is when the client sends the file.
	calls bool
}

func (f *fileStep) send(obj asdu.InformationObject) error {
	a := asdu.New(asdu.CauseFileTransfer, f.ca, obj)
	a.Originator = f.c.opts.originator
	return f.c.Send(f.ctx, a)
}

// next returns the next information object of the transfer.
func (f *fileStep) next() (*asdu.ASDU, asdu.InformationObject, error) {
	ctx, cancel := f.ctx, func() {}
	if t := f.c.opts.requestTimeout; t > 0 {
		ctx, cancel = context.WithTimeout(f.ctx, t)
	}
	defer cancel()
	for {
		a, err := f.x.next(ctx)
		if err != nil {
			return nil, nil, err
		}
		// A mirror with the P/N bit or an "unknown ..." cause is the
		// station's refusal.
		if a.Negative || a.Cause.IsUnknown() {
			return nil, nil, &iec104.NegativeError{ASDU: a}
		}
		// A positive mirror of the client's own call is not part of a
		// download and is skipped.
		if a.Type == asdu.F_SC_NA_1 && !f.calls {
			continue
		}
		return a, a.First(), nil
	}
}

func fileChecksum(b []byte) (sum uint8) {
	for _, v := range b {
		sum += v
	}
	return sum
}

// ofTransfer reports whether a belongs to the transfer of the file at ioa
// that req began. A directory (F_DR_TA_1) does not: it answers a directory
// call, which may run at the same time and list this very file first.
func (c *Client) ofTransfer(req, a *asdu.ASDU, ioa asdu.IOA) bool {
	if !a.Type.IsFileTransfer() || a.Type == asdu.F_DR_TA_1 || !c.fromStation(req, a) {
		return false
	}
	o := a.First()
	return o != nil && o.Address() == ioa
}

func (c *Client) getFile(ctx context.Context, req *asdu.ASDU, ioa asdu.IOA, name uint16) ([]byte, error) {
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		return c.ofTransfer(req, a, ioa)
	})
	if err != nil {
		return nil, err
	}
	defer c.end(x)
	f := &fileStep{c: c, x: x, ctx: ctx, ca: req.CommonAddr, ioa: ioa, name: name}
	unexpected := func(o asdu.InformationObject, want string) error {
		return fmt.Errorf("%w: file transfer: got %T, want %s", iec104.ErrProtocol, o, want)
	}

	a, o, err := f.next()
	if err != nil {
		return nil, err
	}
	ready, ok := o.(asdu.FileReady)
	if !ok {
		return nil, unexpected(o, "file ready")
	}
	if a.Negative || ready.Qualifier&asdu.FileNegative != 0 {
		return nil, &iec104.NegativeError{ASDU: a}
	}
	if err := f.send(asdu.FileCall{IOA: ioa, Name: name, Qualifier: asdu.FileRequest}); err != nil {
		return nil, err
	}

	data := make([]byte, 0, ready.Length)
	for {
		a, o, err := f.next()
		if err != nil {
			return nil, err
		}
		var section asdu.SectionReady
		switch v := o.(type) {
		case asdu.FileLastSegment:
			if v.Qualifier != asdu.LastFileNoDeactivation && v.Qualifier != asdu.LastFileDeactivation {
				return nil, unexpected(o, "section ready or last section")
			}
			// Last section: the checksum covers the whole file.
			good := v.Checksum == fileChecksum(data) && uint32(len(data)) == ready.Length
			ack := asdu.FileAck{IOA: ioa, Name: name, Section: v.Section, Qualifier: asdu.AckFilePositive}
			if !good {
				ack.Qualifier = asdu.AckFileNegative
			}
			if err := f.send(ack); err != nil {
				return nil, err
			}
			if !good {
				return nil, fmt.Errorf("%w: file transfer: length or checksum of the file does not match (%d of %d octets)",
					iec104.ErrProtocol, len(data), ready.Length)
			}
			return data, nil
		case asdu.SectionReady:
			section = v
		default:
			return nil, unexpected(o, "section ready or last section")
		}
		if a.Negative || section.Qualifier&asdu.FileNegative != 0 {
			return nil, &iec104.NegativeError{ASDU: a}
		}
		call := asdu.FileCall{IOA: ioa, Name: name, Section: section.Section, Qualifier: asdu.SectionRequest}
		if err := f.send(call); err != nil {
			return nil, err
		}

		start := len(data)
	segments:
		for {
			_, o, err := f.next()
			if err != nil {
				return nil, err
			}
			switch v := o.(type) {
			case asdu.FileSegment:
				if uint32(len(data)+len(v.Data)) > ready.Length {
					return nil, fmt.Errorf("%w: file transfer: more data than the announced %d octets",
						iec104.ErrProtocol, ready.Length)
				}
				data = append(data, v.Data...)
			case asdu.FileLastSegment:
				if v.Qualifier != asdu.LastSectionNoDeactivation && v.Qualifier != asdu.LastSectionDeactivation {
					return nil, unexpected(o, "a segment or last segment")
				}
				good := v.Checksum == fileChecksum(data[start:]) && uint32(len(data)-start) == section.Length
				ack := asdu.FileAck{IOA: ioa, Name: name, Section: section.Section, Qualifier: asdu.AckSectionPositive}
				if !good {
					ack.Qualifier = asdu.AckSectionNegative
				}
				if err := f.send(ack); err != nil {
					return nil, err
				}
				if !good {
					return nil, fmt.Errorf("%w: file transfer: length or checksum of section %d does not match",
						iec104.ErrProtocol, section.Section)
				}
				break segments
			default:
				return nil, unexpected(o, "a segment or last segment")
			}
		}
	}
}

// PutFile sends a file to the controlled station: the file transfer
// procedure in control direction. ioa is the information object address of
// the file and name its name of file (NOF). Every argument after that is one
// section; a section is sent in segments of up to [asdu.MaxSegmentLength]
// octets. Without sections an empty file is sent.
//
// It announces the file, answers the station's calls for the file and for
// each section with the data and its checksum, and returns once the station
// has acknowledged the file.
//
// A station that refuses the file, or answers a section or the file with a
// negative acknowledgement, is reported as [*iec104.NegativeError]. The
// request timeout bounds every wait for the station, ctx the transfer as a
// whole. A transfer is never repeated by [WithRetry].
func (c *Client) PutFile(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA, name uint16, sections ...[]byte) error {
	total := 0
	for _, sec := range sections {
		total += len(sec)
	}
	if len(sections) > 254 || total > asdu.MaxFileLength {
		return fmt.Errorf("%w: file of %d sections and %d octets", asdu.ErrInvalidValue, len(sections), total)
	}
	req := asdu.New(asdu.CauseFileTransfer, ca, asdu.FileReady{IOA: ioa, Name: name, Length: uint32(total)})
	return c.run(ctx, req, false, func(context.Context) error {
		return c.putFile(ctx, req, ioa, name, sections)
	})
}

func (c *Client) putFile(ctx context.Context, req *asdu.ASDU, ioa asdu.IOA, name uint16, sections [][]byte) error {
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		return c.ofTransfer(req, a, ioa)
	})
	if err != nil {
		return err
	}
	defer c.end(x)
	f := &fileStep{c: c, x: x, ctx: ctx, ca: req.CommonAddr, ioa: ioa, name: name, calls: true}
	unexpected := func(o asdu.InformationObject, want string) error {
		return fmt.Errorf("%w: file transfer: got %T, want %s", iec104.ErrProtocol, o, want)
	}
	// call waits for the station to call the file or a section.
	call := func(qualifier, section uint8, want string) error {
		a, o, err := f.next()
		if err != nil {
			return err
		}
		switch v := o.(type) {
		case asdu.FileCall:
			if v.Qualifier&0x0f != qualifier || v.Section != section {
				return unexpected(o, want)
			}
			return nil
		case asdu.FileReady:
			// The station's own file ready with the negative bit refuses the file.
			if v.Qualifier&asdu.FileNegative != 0 {
				return &iec104.NegativeError{ASDU: a}
			}
		}
		return unexpected(o, want)
	}
	// acknowledged waits for the acknowledgement of a section or the file.
	acknowledged := func(positive uint8, want string) error {
		a, o, err := f.next()
		if err != nil {
			return err
		}
		ack, ok := o.(asdu.FileAck)
		if !ok {
			return unexpected(o, want)
		}
		if ack.Qualifier&0x0f != positive {
			return &iec104.NegativeError{ASDU: a}
		}
		return nil
	}

	if err := call(asdu.FileRequest, 0, "the call of the file"); err != nil {
		return err
	}
	var all uint8
	for i, data := range sections {
		nos := uint8(i + 1)
		ready := asdu.SectionReady{IOA: ioa, Name: name, Section: nos, Length: uint32(len(data))}
		if err := f.send(ready); err != nil {
			return err
		}
		if err := call(asdu.SectionRequest, nos, "the call of the section"); err != nil {
			return err
		}
		for rest := data; len(rest) > 0; {
			n := min(asdu.MaxSegmentLength, len(rest))
			if err := f.send(asdu.FileSegment{IOA: ioa, Name: name, Section: nos, Data: rest[:n]}); err != nil {
				return err
			}
			rest = rest[n:]
		}
		sum := fileChecksum(data)
		all += sum
		last := asdu.FileLastSegment{IOA: ioa, Name: name, Section: nos, Qualifier: asdu.LastSectionNoDeactivation, Checksum: sum}
		if err := f.send(last); err != nil {
			return err
		}
		if err := acknowledged(asdu.AckSectionPositive, "the acknowledgement of the section"); err != nil {
			return err
		}
	}
	last := asdu.FileLastSegment{IOA: ioa, Name: name, Section: uint8(len(sections) + 1),
		Qualifier: asdu.LastFileNoDeactivation, Checksum: all}
	if err := f.send(last); err != nil {
		return err
	}
	return acknowledged(asdu.AckFilePositive, "the acknowledgement of the file")
}

// ListFiles calls the directory of the controlled station (F_SC_NA_1 with
// cause "request") and returns its entries (F_DR_TA_1), collected until the
// entry the station marks as the last one ([asdu.FileLastOfDirectory]). ioa
// selects a directory; 0 is the station's default one.
//
// A station without a directory answers with the mirrored call, which is
// reported as [*iec104.NegativeError].
func (c *Client) ListFiles(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) ([]asdu.FileDirectoryEntry, error) {
	req := asdu.New(asdu.CauseRequest, ca, asdu.FileCall{IOA: ioa})
	var entries []asdu.FileDirectoryEntry
	err := c.run(ctx, req, true, func(ctx context.Context) (err error) {
		entries, err = c.listFiles(ctx, req)
		return err
	})
	return entries, err
}

func (c *Client) listFiles(ctx context.Context, req *asdu.ASDU) ([]asdu.FileDirectoryEntry, error) {
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		return a.Type == asdu.F_DR_TA_1 && a.Cause == asdu.CauseRequest && c.fromStation(req, a)
	})
	if err != nil {
		return nil, err
	}
	defer c.end(x)
	var entries []asdu.FileDirectoryEntry
	for {
		a, err := x.next(ctx)
		if err != nil {
			return entries, err
		}
		if a.Type == req.Type {
			// The mirrored call: a refusal, or a mirror that says nothing.
			if a.Negative || a.Cause.IsUnknown() {
				return entries, &iec104.NegativeError{ASDU: a}
			}
			continue
		}
		for _, o := range a.Objects {
			e, ok := o.(asdu.FileDirectoryEntry)
			if !ok {
				continue
			}
			entries = append(entries, e)
			if e.Status&asdu.FileLastOfDirectory != 0 {
				return entries, nil
			}
		}
	}
}
