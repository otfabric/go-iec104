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
		// The mirror of a call is the station's refusal; a positive mirror
		// is not part of the procedure and is skipped.
		if a.Type == asdu.F_SC_NA_1 {
			if err := rejected(a); err != nil {
				return nil, nil, err
			}
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

func (c *Client) getFile(ctx context.Context, req *asdu.ASDU, ioa asdu.IOA, name uint16) ([]byte, error) {
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		if !a.Type.IsFileTransfer() || !c.fromStation(req, a) {
			return false
		}
		o := a.First()
		return o != nil && o.Address() == ioa
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
