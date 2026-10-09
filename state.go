// SPDX-License-Identifier: MIT

package iec104

// State is the state of a connection as seen by one station.
type State uint8

// Connection states.
const (
	// StateDisconnected means there is no transport connection.
	StateDisconnected State = iota
	// StateConnecting means the client is establishing or re-establishing
	// the transport connection.
	StateConnecting
	// StateStopped means the connection is established and data transfer
	// is stopped (STOPDT): only U and S frames are exchanged.
	StateStopped
	// StateStarted means data transfer is started (STARTDT): I frames
	// flow.
	StateStarted
)

// String returns "disconnected", "connecting", "stopped" or "started".
func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateStopped:
		return "stopped"
	case StateStarted:
		return "started"
	default:
		return "unknown"
	}
}
