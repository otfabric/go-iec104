// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
)

// exchange collects the ASDUs that answer one request. IEC 60870-5-104 has
// no transaction identifier: answers are recognised by type identification,
// common address, information object address and cause of transmission.
type exchange struct {
	req   *asdu.ASDU
	match func(a *asdu.ASDU) bool

	mu    sync.Mutex
	items []*asdu.ASDU
	err   error
	sig   chan struct{}
}

func (x *exchange) deliver(a *asdu.ASDU) {
	x.mu.Lock()
	x.items = append(x.items, a)
	x.mu.Unlock()
	x.signal()
}

func (x *exchange) fail(err error) {
	x.mu.Lock()
	if x.err == nil {
		x.err = err
	}
	x.mu.Unlock()
	x.signal()
}

func (x *exchange) signal() {
	select {
	case x.sig <- struct{}{}:
	default:
	}
}

// next returns the next collected ASDU, waiting for one if necessary.
func (x *exchange) next(ctx context.Context) (*asdu.ASDU, error) {
	for {
		x.mu.Lock()
		if len(x.items) > 0 {
			a := x.items[0]
			x.items = x.items[1:]
			x.mu.Unlock()
			return a, nil
		}
		err := x.err
		x.mu.Unlock()
		if err != nil {
			return nil, err
		}
		select {
		case <-x.sig:
		case <-ctx.Done():
			return nil, fmt.Errorf("iec104: waiting for answer to %s: %w", x.req.Type, ctx.Err())
		}
	}
}

// sameRequest reports whether two requests would be answered by
// indistinguishable ASDUs.
func sameRequest(a, b *asdu.ASDU) bool {
	return a.Type == b.Type && a.CommonAddr == b.CommonAddr &&
		a.First().Address() == b.First().Address()
}

// mirrored reports whether a is the controlled station's mirror of req: a
// confirmation, termination or rejection.
func (c *Client) mirrored(req, a *asdu.ASDU) bool {
	if a.Type != req.Type {
		return false
	}
	if a.CommonAddr != req.CommonAddr && !c.opts.asduParams.IsBroadcast(req.CommonAddr) {
		return false
	}
	switch a.Cause {
	case asdu.CauseActivationCon, asdu.CauseDeactivationCon, asdu.CauseActivationTerm,
		asdu.CauseUnknownType, asdu.CauseUnknownCause, asdu.CauseUnknownCommonAddr, asdu.CauseUnknownIOA:
	default:
		return false
	}
	f := a.First()
	return f != nil && f.Address() == req.First().Address()
}

// fromStation reports whether a is monitor-direction data from the station
// (or stations) req addressed.
func (c *Client) fromStation(req, a *asdu.ASDU) bool {
	if a.Type.InControlDirection() {
		return false
	}
	return a.CommonAddr == req.CommonAddr || c.opts.asduParams.IsBroadcast(req.CommonAddr)
}

// begin registers an exchange for req, sends req and returns the exchange.
// also, when not nil, selects further ASDUs to collect besides the mirrors
// of req. The caller must call end.
func (c *Client) begin(ctx context.Context, req *asdu.ASDU, also func(a *asdu.ASDU) bool) (*exchange, error) {
	req.Originator = c.opts.originator
	raw, err := req.Encode(c.opts.asduParams)
	if err != nil {
		return nil, err
	}
	x := &exchange{req: req, sig: make(chan struct{}, 1)}
	x.match = func(a *asdu.ASDU) bool {
		return c.mirrored(req, a) || (also != nil && also(a))
	}

	c.mu.Lock()
	l := c.link
	switch {
	case c.closed:
		c.mu.Unlock()
		return nil, iec104.ErrClosed
	case l == nil:
		c.mu.Unlock()
		return nil, iec104.ErrNotConnected
	}
	for _, other := range c.exchanges {
		if sameRequest(other.req, req) {
			c.mu.Unlock()
			return nil, fmt.Errorf("%w: %s ca=%d ioa=%d", iec104.ErrBusy,
				req.Type, req.CommonAddr, req.First().Address())
		}
	}
	c.exchanges = append(c.exchanges, x)
	c.mu.Unlock()

	if err := l.Send(ctx, raw); err != nil {
		c.end(x)
		return nil, err
	}
	return x, nil
}

func (c *Client) end(x *exchange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, other := range c.exchanges {
		if other == x {
			c.exchanges = append(c.exchanges[:i], c.exchanges[i+1:]...)
			return
		}
	}
}

// rejected returns the error for a mirror that refuses the request, or nil.
func rejected(a *asdu.ASDU) error {
	if a.Negative || a.Cause.IsUnknown() {
		return &iec104.NegativeError{ASDU: a}
	}
	return nil
}

// confirmed sends req and waits for its confirmation.
func (c *Client) confirmed(ctx context.Context, req *asdu.ASDU) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	x, err := c.begin(ctx, req, nil)
	if err != nil {
		return err
	}
	defer c.end(x)
	a, err := x.next(ctx)
	if err != nil {
		return err
	}
	return rejected(a)
}

// Command sends a process command with cause "activation" and waits for the
// activation confirmation. obj must be one of [asdu.SingleCommand],
// [asdu.DoubleCommand], [asdu.StepCommand], [asdu.SetpointNormalized],
// [asdu.SetpointScaled], [asdu.SetpointFloat] or [asdu.BitstringCommand].
// A command whose Time is set is sent as the CP56Time2a variant.
//
// A negative confirmation or an "unknown ..." answer is returned as
// [*iec104.NegativeError].
//
// For select-before-operate call Command twice: first with Select set, then
// without. The activation termination some stations send after executing
// is not awaited; it reaches the [Handler].
func (c *Client) Command(ctx context.Context, ca asdu.CommonAddr, obj asdu.InformationObject) error {
	return c.command(ctx, asdu.CauseActivation, ca, obj)
}

// Deactivate cancels a previously selected command: it sends obj with cause
// "deactivation" and waits for the deactivation confirmation.
func (c *Client) Deactivate(ctx context.Context, ca asdu.CommonAddr, obj asdu.InformationObject) error {
	return c.command(ctx, asdu.CauseDeactivation, ca, obj)
}

func (c *Client) command(ctx context.Context, cause asdu.Cause, ca asdu.CommonAddr, obj asdu.InformationObject) error {
	if obj == nil {
		return fmt.Errorf("%w: nil command", asdu.ErrInvalidValue)
	}
	req := asdu.New(cause, ca, obj)
	if !req.Type.IsProcessCommand() {
		return fmt.Errorf("%w: %T is not a process command", asdu.ErrTypeMismatch, obj)
	}
	return c.confirmed(ctx, req)
}

// collect runs a request that the station answers with a confirmation, a
// stream of data and a termination, and returns the data.
func (c *Client) collect(ctx context.Context, req *asdu.ASDU, cause asdu.Cause) ([]*asdu.ASDU, error) {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		return a.Cause == cause && c.fromStation(req, a)
	})
	if err != nil {
		return nil, err
	}
	defer c.end(x)

	var data []*asdu.ASDU
	for {
		a, err := x.next(ctx)
		if err != nil {
			return data, err
		}
		if a.Type != req.Type {
			data = append(data, a)
			continue
		}
		if err := rejected(a); err != nil {
			return data, err
		}
		if a.Cause == asdu.CauseActivationTerm {
			return data, nil
		}
	}
}

// Interrogate runs an interrogation (C_IC_NA_1): it sends the command,
// waits for the confirmation and collects the ASDUs the station sends with
// the matching "interrogated by ..." cause until the activation
// termination arrives.
//
// qoi is [asdu.QOIStation] for a general interrogation or
// [asdu.QOIGroup](n) for one group. With ca set to [asdu.Broadcast] the
// answers of all stations are collected until the first termination.
//
// The collected ASDUs are also delivered to the [Handler]. A large station
// can take longer than the default request timeout: pass a context with a
// suitable deadline. On error the ASDUs collected so far are returned
// alongside it.
func (c *Client) Interrogate(ctx context.Context, ca asdu.CommonAddr, qoi asdu.QOI) ([]*asdu.ASDU, error) {
	req := asdu.New(asdu.CauseActivation, ca, asdu.Interrogation{Qualifier: qoi})
	return c.collect(ctx, req, qoi.Cause())
}

// CounterInterrogate runs a counter interrogation (C_CI_NA_1) and collects
// the integrated totals the station sends in answer, until the activation
// termination arrives. request is [asdu.CounterGeneral] or a counter group
// 1..4; freeze is one of the asdu.Freeze* qualifiers.
//
// It follows the same collection rules as [Client.Interrogate].
func (c *Client) CounterInterrogate(ctx context.Context, ca asdu.CommonAddr, request, freeze uint8) ([]*asdu.ASDU, error) {
	obj := asdu.CounterInterrogation{Request: request, Freeze: freeze}
	return c.collect(ctx, asdu.New(asdu.CauseActivation, ca, obj), obj.Cause())
}

// Read requests the current value of one information object (C_RD_NA_1)
// and returns the ASDU the station sends with cause "request" for that
// address. An unknown address is reported as [*iec104.NegativeError].
func (c *Client) Read(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) (*asdu.ASDU, error) {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	req := asdu.New(asdu.CauseRequest, ca, asdu.Read{IOA: ioa})
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		if a.Cause != asdu.CauseRequest || !c.fromStation(req, a) {
			return false
		}
		for _, o := range a.Objects {
			if o.Address() == ioa {
				return true
			}
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	defer c.end(x)
	for {
		a, err := x.next(ctx)
		if err != nil {
			return nil, err
		}
		if a.Type != req.Type {
			return a, nil
		}
		// A mirrored read command is a rejection; a positive mirror is not
		// defined by the standard and is skipped.
		if err := rejected(a); err != nil {
			return nil, err
		}
	}
}

// ClockSync sets the clock of the station to t (C_CS_NA_1) and waits for
// the confirmation. The time is sent in the zone of the ASDU parameters,
// UTC by default.
func (c *Client) ClockSync(ctx context.Context, ca asdu.CommonAddr, t time.Time) error {
	return c.confirmed(ctx, asdu.New(asdu.CauseActivation, ca, asdu.ClockSync{Time: asdu.At(t)}))
}

// TestCommand sends a test command with time tag (C_TS_TA_1) and waits for
// the confirmation. Unlike [Client.TestLink] it exercises the application
// layer of the station end to end.
func (c *Client) TestCommand(ctx context.Context, ca asdu.CommonAddr) error {
	c.mu.Lock()
	c.testSeq++
	seq := c.testSeq
	c.mu.Unlock()
	return c.confirmed(ctx, asdu.New(asdu.CauseActivation, ca,
		asdu.TestCommand{Counter: seq, Time: asdu.Now()}))
}

// ResetProcess sends a reset process command (C_RP_NA_1) and waits for the
// confirmation. qualifier is [asdu.ResetProcessGeneral] or
// [asdu.ResetPendingEvents].
func (c *Client) ResetProcess(ctx context.Context, ca asdu.CommonAddr, qualifier uint8) error {
	return c.confirmed(ctx, asdu.New(asdu.CauseActivation, ca, asdu.ResetProcess{Qualifier: qualifier}))
}
