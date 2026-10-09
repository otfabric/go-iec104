// SPDX-License-Identifier: MIT

package apci

const (
	// SeqModulus is the modulus of the send and receive sequence numbers.
	SeqModulus = 1 << 15

	// SeqMask masks a value to the 15-bit sequence number range.
	SeqMask = SeqModulus - 1
)

// SeqNext returns the sequence number following n.
func SeqNext(n uint16) uint16 {
	return (n + 1) & SeqMask
}

// SeqDiff returns how far a is ahead of b, modulo [SeqModulus]: the number
// of increments that turn b into a.
func SeqDiff(a, b uint16) int {
	return int((a - b) & SeqMask)
}

// SeqAcks reports whether a received N(R) of nr is a valid acknowledgement
// for a sender whose oldest unacknowledged frame is ack and whose next send
// sequence number is next, and how many frames it newly acknowledges.
//
// nr is valid when it lies in the closed range ack..next, modulo
// [SeqModulus].
func SeqAcks(nr, ack, next uint16) (n int, ok bool) {
	n = SeqDiff(nr, ack)
	if n > SeqDiff(next, ack) {
		return 0, false
	}
	return n, true
}
