// SPDX-License-Identifier: MIT

//go:build go1.24

package sec

import (
	"crypto/sha3"
	"hash"
)

// HMAC-SHA3-256, optional in IEC 62351-5, needs crypto/sha3 (Go 1.24).
var (
	HMACSHA3_256Serial = MACAlgorithm{"HMAC-SHA3-256/8", 7, newSHA3, 8}
	HMACSHA3_256       = MACAlgorithm{"HMAC-SHA3-256/16", 8, newSHA3, 16}
)

func newSHA3() hash.Hash { return sha3.New256() }

func init() {
	macAlgorithms[HMACSHA3_256Serial.Code] = HMACSHA3_256Serial
	macAlgorithms[HMACSHA3_256.Code] = HMACSHA3_256
}
