// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// updateKeys are the encryption and authentication update keys of an
// association, 32 octets each.
type updateKeys struct {
	enc, auth []byte
}

func (u updateKeys) valid() bool { return len(u.enc) == 32 && len(u.auth) == 32 }

// deriveUpdateKeys is the key derivation of the Station Association: HKDF
// with the hash of the MAC algorithm, the ECDH shared secret as input key
// material, the controlling then the controlled station's random data as
// salt and no info, expanded to 64 octets: the encryption update key, then
// the authentication update key.
func deriveUpdateKeys(mal MACAlgorithm, priv *ecdh.PrivateKey, remote *ecdh.PublicKey, controllingRandom, controlledRandom []byte) (updateKeys, error) {
	secret, err := priv.ECDH(remote)
	if err != nil {
		return updateKeys{}, fmt.Errorf("%w: %w", ErrCertificate, err)
	}
	salt := append(append(make([]byte, 0, len(controllingRandom)+len(controlledRandom)), controllingRandom...), controlledRandom...)
	k := hkdf(mal.Hash, secret, salt, nil, 64)
	return updateKeys{enc: k[:32], auth: k[32:]}, nil
}

// sessionKeys are the control and monitor direction session keys.
type sessionKeys struct {
	control, monitor []byte
}

func (k sessionKeys) available() bool { return len(k.control) == 32 && len(k.monitor) == 32 }

// State is what one end of an association keeps over a restart: the
// association IDs and algorithms, the update keys, the remote certificate
// and the last session keys. Everything but the IDs and the certificate is
// secret: a [KeyStore] must protect it and must never log it.
//
// The session keys are kept only so that a controlled station can
// authenticate the Session Initiation Request that asks for new ones; they
// are not used for data after a restart.
type State struct {
	AIM               uint16 `json:"aim"`
	AIS               uint16 `json:"ais"`
	MAC               uint8  `json:"mal"`
	KeyWrap           uint8  `json:"kwa"`
	EncryptionKey     []byte `json:"encryptionUpdateKey,omitempty"`
	AuthenticationKey []byte `json:"authenticationUpdateKey,omitempty"`
	RemoteCertificate []byte `json:"remoteCertificate,omitempty"`
	ControlKey        []byte `json:"controlSessionKey,omitempty"`
	MonitorKey        []byte `json:"monitorSessionKey,omitempty"`
	DataProtection    uint8  `json:"dpa,omitempty"`
}

func (s State) clone() State {
	s.EncryptionKey = bytes.Clone(s.EncryptionKey)
	s.AuthenticationKey = bytes.Clone(s.AuthenticationKey)
	s.RemoteCertificate = bytes.Clone(s.RemoteCertificate)
	s.ControlKey = bytes.Clone(s.ControlKey)
	s.MonitorKey = bytes.Clone(s.MonitorKey)
	return s
}

// KeyStore keeps the [State] of one association. Load reports ok false when
// nothing is kept yet. Save is called after every change of the keys; an
// error is reported through [Config.OnEvent] and does not stop the
// association.
type KeyStore interface {
	Load() (s State, ok bool, err error)
	Save(State) error
}

// MemoryStore is a KeyStore in memory: the association survives a
// reconnect, not a restart of the process. The zero value is ready.
type MemoryStore struct {
	mu sync.Mutex
	st *State
}

// Load implements [KeyStore].
func (m *MemoryStore) Load() (State, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return State{}, false, nil
	}
	return m.st.clone(), true, nil
}

// Save implements [KeyStore].
func (m *MemoryStore) Save(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := s.clone()
	m.st = &c
	return nil
}

// FileStore is a KeyStore in a JSON file, written with mode 0600 through a
// temporary file and a rename. The keys are stored as they are: put the file
// where only the station's account can read it, on encrypted storage.
type FileStore struct {
	Path string
}

// Load implements [KeyStore].
func (f FileStore) Load() (State, bool, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, false, fmt.Errorf("sec: key store %s: %w", f.Path, err)
	}
	return s, true, nil
}

// Save implements [KeyStore].
func (f FileStore) Save(s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".keystore-*")
	if err != nil {
		return err
	}
	// Gone after the rename; left behind only when something failed.
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}
