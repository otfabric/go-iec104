// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
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
	// epoch is the started period of the link the request went out in; it
	// is very large until the request is sent, so that the end of an
	// earlier period leaves a request that is still on its way alone.
	epoch atomic.Uint64

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
	// A confirmation answers the request of its own kind: the confirmation
	// of a deactivation that was given up on must not pass for that of the
	// activation which followed it, nor the other way round.
	switch a.Cause {
	case asdu.CauseActivationCon, asdu.CauseActivationTerm:
		if req.Cause == asdu.CauseDeactivation {
			return false
		}
	case asdu.CauseDeactivationCon:
		if req.Cause != asdu.CauseDeactivation {
			return false
		}
	case asdu.CauseUnknownType, asdu.CauseUnknownCause, asdu.CauseUnknownCommonAddr, asdu.CauseUnknownIOA:
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

// processData is fromStation for a request that is answered with process
// data: an interrogation or a read. What belongs to file transfer does not
// answer it, though a directory carries the cause "request" as the answer
// to a read does, and may list a file at the address that is being read.
func (c *Client) processData(req, a *asdu.ASDU) bool {
	return !a.Type.IsFileTransfer() && c.fromStation(req, a)
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
	// The answer is delivered by the goroutine a callback runs on, and by
	// none while a state notification is being delivered ahead of it.
	if c.inCallback() {
		return nil, fmt.Errorf("%w: %s", iec104.ErrInHandler, req.Type)
	}
	x := &exchange{req: req, sig: make(chan struct{}, 1)}
	x.epoch.Store(math.MaxUint64)
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

	// The link stamps the exchange with the started period the request
	// goes out in, at the moment it does: the end of that period cannot
	// slip in between sending and stamping.
	if err := l.SendStamped(ctx, raw, &x.epoch); err != nil {
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

// retryable reports whether a failed attempt of an idempotent request is
// worth repeating: the cause is the connection or a missing answer, not the
// station's refusal, the caller or the request itself.
func retryable(parent context.Context, err error) bool {
	var neg *iec104.NegativeError
	switch {
	case parent.Err() != nil, errors.As(err, &neg),
		errors.Is(err, iec104.ErrClosed), errors.Is(err, iec104.ErrBusy):
		return false
	case errors.Is(err, iec104.ErrNotConnected), errors.Is(err, iec104.ErrNotStarted),
		errors.Is(err, iec104.ErrConnectionLost), errors.Is(err, iec104.ErrTimeout),
		errors.Is(err, iec104.ErrProtocol), errors.Is(err, context.DeadlineExceeded):
		return true
	}
	return false
}

// run executes one request: it bounds every attempt by the request timeout,
// repeats an idempotent request as configured by WithRetry, and reports to
// the metrics and the log. attempt performs a single try.
func (c *Client) run(ctx context.Context, req *asdu.ASDU, idempotent bool, attempt func(ctx context.Context) error) error {
	rm, _ := c.opts.metrics.(iec104.RequestMetrics)
	remote := c.remoteAddr()
	begin := time.Now()
	if rm != nil {
		rm.OnRequest(remote, req.Type, req.CommonAddr)
	}

	attempts := 1
	var delay, maxDelay time.Duration
	if r := c.opts.retry; r != nil && idempotent {
		attempts, delay, maxDelay = r.Attempts, r.Backoff, r.MaxBackoff
	}
	var err error
	for i := 1; ; i++ {
		actx, cancel := c.bound(ctx)
		err = attempt(actx)
		cancel()
		if err == nil || i >= attempts || !retryable(ctx, err) {
			break
		}
		c.log.WarnContext(ctx, "request failed, retrying", "type", req.Type.String(),
			"ca", req.CommonAddr, "attempt", i, "retry_in", delay.String(), "error", err)
		if rm != nil {
			rm.OnRetry(remote, req.Type, req.CommonAddr, i, err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-c.closeCh:
		}
		timer.Stop()
		if ctx.Err() != nil || c.isClosed() {
			break // the last error says why the request did not succeed
		}
		delay = min(delay*2, maxDelay)
	}

	elapsed := time.Since(begin)
	if rm != nil {
		rm.OnRequestDone(remote, req.Type, req.CommonAddr, elapsed, err)
	}
	if c.log.DebugEnabled() {
		kv := []any{"type", req.Type.String(), "ca", req.CommonAddr, "duration", elapsed.String()}
		if err != nil {
			kv = append(kv, "error", err)
		}
		c.log.DebugContext(ctx, "request", kv...)
	}
	return err
}

// confirmed sends req and waits for its confirmation.
func (c *Client) confirmed(ctx context.Context, req *asdu.ASDU, idempotent bool) error {
	return c.run(ctx, req, idempotent, func(ctx context.Context) error { return c.confirmedOnce(ctx, req) })
}

func (c *Client) confirmedOnce(ctx context.Context, req *asdu.ASDU) error {
	x, err := c.begin(ctx, req, nil)
	if err != nil {
		return err
	}
	defer c.end(x)
	for {
		a, err := x.next(ctx)
		if err != nil {
			return err
		}
		// A termination is not an answer to this request: it concludes an
		// earlier one for the same object, whose confirmation the caller
		// already has.
		if a.Cause == asdu.CauseActivationTerm {
			continue
		}
		return rejected(a)
	}
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
	return c.confirmed(ctx, req, false)
}

// collect runs a request that the station answers with a confirmation, a
// stream of data and a termination, and returns the data.
func (c *Client) collect(ctx context.Context, req *asdu.ASDU, cause asdu.Cause, idempotent bool) ([]*asdu.ASDU, error) {
	var data []*asdu.ASDU
	err := c.run(ctx, req, idempotent, func(ctx context.Context) (err error) {
		// A repeated attempt starts over: what a failed one collected is dropped.
		data, err = c.collectOnce(ctx, req, cause)
		return err
	})
	return data, err
}

func (c *Client) collectOnce(ctx context.Context, req *asdu.ASDU, cause asdu.Cause) ([]*asdu.ASDU, error) {
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		return a.Cause == cause && c.processData(req, a)
	})
	if err != nil {
		return nil, err
	}
	defer c.end(x)

	var data []*asdu.ASDU
	confirmed := false
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
		switch {
		case a.Cause != asdu.CauseActivationTerm:
			confirmed = true
		case confirmed:
			return data, nil
		}
		// A termination before the confirmation concludes an earlier
		// request of the same kind, not this one.
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
	return c.collect(ctx, req, qoi.Cause(), true)
}

// CounterInterrogate runs a counter interrogation (C_CI_NA_1) and collects
// the integrated totals the station sends in answer, until the activation
// termination arrives. request is [asdu.CounterGeneral] or a counter group
// 1..4; freeze is one of the asdu.Freeze* qualifiers.
//
// It follows the same collection rules as [Client.Interrogate].
func (c *Client) CounterInterrogate(ctx context.Context, ca asdu.CommonAddr, request, freeze uint8) ([]*asdu.ASDU, error) {
	obj := asdu.CounterInterrogation{Request: request, Freeze: freeze}
	// A freeze or reset changes the counters: only a plain read is repeated.
	return c.collect(ctx, asdu.New(asdu.CauseActivation, ca, obj), obj.Cause(), freeze == asdu.FreezeRead)
}

// Read requests the current value of one information object (C_RD_NA_1)
// and returns the ASDU the station sends with cause "request" for that
// address. An unknown address is reported as [*iec104.NegativeError].
func (c *Client) Read(ctx context.Context, ca asdu.CommonAddr, ioa asdu.IOA) (*asdu.ASDU, error) {
	req := asdu.New(asdu.CauseRequest, ca, asdu.Read{IOA: ioa})
	var answer *asdu.ASDU
	err := c.run(ctx, req, true, func(ctx context.Context) (err error) {
		answer, err = c.readOnce(ctx, req, ioa)
		return err
	})
	return answer, err
}

func (c *Client) readOnce(ctx context.Context, req *asdu.ASDU, ioa asdu.IOA) (*asdu.ASDU, error) {
	x, err := c.begin(ctx, req, func(a *asdu.ASDU) bool {
		if a.Cause != asdu.CauseRequest || !c.processData(req, a) {
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
	return c.confirmed(ctx, asdu.New(asdu.CauseActivation, ca, asdu.ClockSync{Time: asdu.At(t)}), false)
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
		asdu.TestCommand{Counter: seq, Time: asdu.Now()}), true)
}

// ResetProcess sends a reset process command (C_RP_NA_1) and waits for the
// confirmation. qualifier is [asdu.ResetProcessGeneral] or
// [asdu.ResetPendingEvents].
func (c *Client) ResetProcess(ctx context.Context, ca asdu.CommonAddr, qualifier uint8) error {
	return c.confirmed(ctx, asdu.New(asdu.CauseActivation, ca, asdu.ResetProcess{Qualifier: qualifier}), false)
}
