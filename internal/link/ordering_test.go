// SPDX-License-Identifier: MIT

package link

import (
	"context"
	"errors"
	"io"
	"testing"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/apci"
)

// The tests in this file reproduce the findings of an adversarial review of
// the state machines. Each failed when it was written.

// Finding 6 of the state machine review: a Send (or StartDT) that races a local Close can be picked by the loop
// in the same select as closeCh. The write then fails on the connection
// Close has already closed, and the caller gets ErrConnectionLost ("use of
// closed network connection") although the link's error is ErrClosed.
func TestOrderingSendRacingCloseReturnsLinkError(t *testing.T) {
	wrong := 0
	for i := 0; i < 400 && wrong == 0; i++ {
		l, p, _ := setup(t, Controlled, fastParams())
		go func() { _, _ = io.Copy(io.Discard, p.conn) }()
		p.send(apci.NewU(apci.StartDTAct))
		for !l.Started() {
		}
		errs := make(chan error, 1)
		go func() {
			for {
				if err := l.Send(context.Background(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}); err != nil {
					errs <- err
					return
				}
			}
		}()
		_ = l.Close()
		err := <-errs
		if !errors.Is(err, iec104.ErrClosed) {
			wrong++
			t.Errorf("iteration %d: Send returned %v, link error is %v", i, err, l.Err())
		}
	}
}
