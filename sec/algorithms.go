// SPDX-License-Identifier: MIT

package sec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
)

// MACAlgorithm is a truncated HMAC of IEC 62351-5: the MAL value of the
// Update Key Change Request, which also selects the hash of the key
// derivation, and a DPA value of the Session Key Change Request.
type MACAlgorithm struct {
	Name string
	Code uint8
	Hash func() hash.Hash
	Len  int // octets of the MAC kept, the leftmost
}

// The MAC algorithms. HMAC-SHA-256 is mandatory: truncated to 16 octets on
// TCP/IP, which is the default here, and to 8 on serial links. HMAC-SHA3-256
// (codes 7 and 8) is available when the module is built with Go 1.24 or
// later. BLAKE2s (codes 9 and 10) is not implemented.
var (
	HMACSHA256Serial = MACAlgorithm{"HMAC-SHA-256/8", 3, sha256.New, 8}
	HMACSHA256       = MACAlgorithm{"HMAC-SHA-256/16", 4, sha256.New, 16}
)

// Codes that are not MAC algorithms.
const (
	// KeyWrapAES256 is the KWA value of the AES-256 Key Wrap of RFC 3394,
	// the mandatory and only key wrap algorithm.
	KeyWrapAES256 uint8 = 2
	// AES256GCM is the DPA value of AEAD-AES-256-GCM for Secure Data.
	AES256GCM uint8 = 11
)

var macAlgorithms = map[uint8]MACAlgorithm{
	HMACSHA256Serial.Code: HMACSHA256Serial,
	HMACSHA256.Code:       HMACSHA256,
}

// MACByCode returns the MAC algorithm of a MAL or DPA value.
func MACByCode(code uint8) (MACAlgorithm, bool) {
	m, ok := macAlgorithms[code]
	return m, ok
}

// sum returns the truncated MAC of the concatenated parts.
func (a MACAlgorithm) sum(key []byte, parts ...[]byte) []byte {
	m := hmac.New(a.Hash, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:a.Len]
}

// verify compares a received MAC in constant time. A MAC of the wrong length
// never matches.
func (a MACAlgorithm) verify(key, got []byte, parts ...[]byte) bool {
	return len(got) == a.Len && subtle.ConstantTimeCompare(a.sum(key, parts...), got) == 1
}

// DataProtection is the algorithm that protects Secure Data: a MAC
// algorithm, or AEAD-AES-256-GCM.
type DataProtection struct {
	Code uint8
	MAC  *MACAlgorithm // nil for AES-256-GCM
}

// DataProtectionByCode returns the algorithm of a DPA value.
func DataProtectionByCode(code uint8) (DataProtection, bool) {
	if code == AES256GCM {
		return DataProtection{Code: code}, true
	}
	m, ok := macAlgorithms[code]
	if !ok {
		return DataProtection{}, false
	}
	return DataProtection{Code: code, MAC: &m}, true
}

// String names the algorithm.
func (d DataProtection) String() string {
	if d.MAC != nil {
		return d.MAC.Name
	}
	if d.Code == AES256GCM {
		return "AEAD-AES-256-GCM"
	}
	return fmt.Sprintf("DPA %d", d.Code)
}

// hkdf is RFC 5869 extract and expand.
func hkdf(h func() hash.Hash, secret, salt, info []byte, n int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	ext := hmac.New(h, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		exp := hmac.New(h, prk)
		exp.Write(t)
		exp.Write(info)
		exp.Write([]byte{i})
		t = exp.Sum(t[:0])
		out = append(out, t...)
	}
	return out[:n]
}

// The default initial value of RFC 3394.
var keyWrapIV = [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

// keyWrap is the AES key wrap of RFC 3394 with the default initial value.
func keyWrap(kek, plain []byte) ([]byte, error) {
	if len(plain) < 16 || len(plain)%8 != 0 {
		return nil, fmt.Errorf("%w: key data of %d octets to wrap", ErrConfig, len(plain))
	}
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plain) / 8
	out := make([]byte, 8+len(plain))
	copy(out[8:], plain)
	a := keyWrapIV
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], out[8*i:8*i+8])
			c.Encrypt(b[:], b[:])
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^uint64(n*j+i))
			copy(out[8*i:], b[8:])
		}
	}
	copy(out, a[:])
	return out, nil
}

// keyUnwrap reverses keyWrap and checks the initial value.
func keyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("%w: wrapped key data of %d octets", ErrAuthentication, len(wrapped))
	}
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	r := make([]byte, 8*n)
	copy(r, wrapped[8:])
	var a [8]byte
	copy(a[:], wrapped[:8])
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^uint64(n*j+i))
			copy(b[8:], r[8*(i-1):8*i])
			c.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[8*(i-1):], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], keyWrapIV[:]) != 1 {
		return nil, fmt.Errorf("%w: key unwrap integrity check", ErrAuthentication)
	}
	return r, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// gcmNonce is the AES-GCM nonce of Secure Data: the sequence number as
// transmitted, least significant octet first, padded with zeros to 12
// octets.
func gcmNonce(seq uint32) []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint32(n, seq)
	return n
}
