// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/otfabric/go-iec104/asdu"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seq returns n octets b, b+1, ...
func seq(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b + byte(i)
	}
	return out
}

// The golden encodings were produced by github.com/cB-Sigma/iec60870 v0.3.0
// (sec.Encode, sec.ProtectSecureData, sec.AESKeyWrap, DeriveKeys) from the
// same field values: an independent encoder of the same formats.
var golden = []struct {
	dir Direction
	msg Message
	hex string
}{
	{Control, AssociationRequest{AIM: 7, Protocol: Version1, Certificate: seq(5, 0xc0)},
		"5101100534120700000010000500c0c1c2c3c4"},
	{Monitor, AssociationResponse{AIM: 7, AIS: 9, Certificate: seq(3, 0xc0), Random: seq(4, 0x10)},
		"52011005341207000900030004c0c1c210111213"},
	{Control, UpdateKeyChangeRequest{AIM: 7, AIS: 9, KeyWrap: 2, MAC: 4, Random: seq(4, 0x20), Tag: seq(16, 0x80)},
		"5301100534120700090002040420212223808182838485868788898a8b8c8d8e8f"},
	{Monitor, UpdateKeyChangeResponse{AIM: 7, AIS: 9, Tag: seq(16, 0x80)},
		"54011005341207000900808182838485868788898a8b8c8d8e8f"},
	{Monitor, SessionInitiationRequest{AIM: 7, AIS: 9, Random: seq(4, 0x30), Tag: seq(16, 0x80)},
		"55010f053412070009000430313233808182838485868788898a8b8c8d8e8f"},
	{Control, SessionRequest{AIM: 7, AIS: 9, Protocol: Version1, Random: seq(4, 0x40)},
		"56010f0534120700090010000440414243"},
	{Monitor, SessionResponse{AIM: 7, AIS: 9, Random: seq(4, 0x50), Tag: seq(16, 0x80)},
		"57010f053412070009000450515253808182838485868788898a8b8c8d8e8f"},
	{Control, SessionKeyChangeRequest{AIM: 7, AIS: 9, DataProtection: 11, Wrapped: seq(24, 0x60), Tag: seq(16, 0x80)},
		"58010f053412070009000b1800606162636465666768696a6b6c6d6e6f7071727374757677808182838485868788898a8b8c8d8e8f"},
	{Monitor, SessionKeyChangeResponse{AIM: 7, AIS: 9, Tag: seq(16, 0x80)},
		"59010f05341207000900808182838485868788898a8b8c8d8e8f"},
	{Control, SecureData{AIM: 7, AIS: 9, Sequence: 0x01020304, Payload: seq(6, 0x70)},
		"5b010e0534120700090004030201707172737475"},
}

func TestGoldenMessages(t *testing.T) {
	for _, g := range golden {
		want := unhex(t, g.hex)
		cause, _ := PermittedCause(g.msg.Type(), g.dir)
		got, err := Encode(Header{Cause: cause, Originator: 5, CommonAddr: 0x1234}, asdu.IEC104, g.msg)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: encode %x, %v\nwant          %x", g.msg.Type(), got, err, want)
		}
		h, m, err := Decode(want, asdu.IEC104, g.dir)
		if err != nil {
			t.Errorf("%s: decode: %v", g.msg.Type(), err)
			continue
		}
		if h.Cause != cause || h.CommonAddr != 0x1234 || h.Originator != 5 || h.Type != g.msg.Type() {
			t.Errorf("%s: header %+v", g.msg.Type(), h)
		}
		if !reflect.DeepEqual(m, g.msg) {
			t.Errorf("%s: decoded %+v, want %+v", g.msg.Type(), m, g.msg)
		}
		// Every message decodes only in its own direction.
		if _, _, err := Decode(want, asdu.IEC104, 1-g.dir); !errors.Is(err, ErrMessage) && g.msg.Type() != asdu.S_SD_NA_1 {
			t.Errorf("%s: decoded in the wrong direction: %v", g.msg.Type(), err)
		}
	}
}

func TestGoldenSecureData(t *testing.T) {
	key := seq(32, 0xa0)
	inner := []byte{45, 1, 6, 0, 0x34, 0x12, 0xd1, 0x07, 0, 1}
	for _, c := range []struct {
		code uint8
		hex  string
	}{
		{HMACSHA256.Code, "5b010e05341207000900030000000a002d0106003412d1070001dc5eae88cb43174be937f1fa055946fa"},
		{AES256GCM, "5b010e053412070009000300000005d3219e8b522bc7791cb6b560058ffc9dc3bc1913aba2ef0b0bd9c1"},
	} {
		dp, _ := DataProtectionByCode(c.code)
		got, err := protect(asdu.IEC104, Header{Originator: 5, CommonAddr: 0x1234}, SecureData{AIM: 7, AIS: 9, Sequence: 3}, inner, dp, key)
		want := unhex(t, c.hex)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %x, %v\nwant %x", dp, got, err, want)
		}
		_, m, err := Decode(want, asdu.IEC104, Control)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := open(want, asdu.IEC104, m.(SecureData), dp, key)
		if err != nil || !bytes.Equal(plain, inner) {
			t.Errorf("%s: open %x, %v", dp, plain, err)
		}
		bad := bytes.Clone(want)
		bad[len(bad)-1] ^= 1
		if _, err := open(bad, asdu.IEC104, SecureData{AIM: 7, AIS: 9, Sequence: 3, Payload: bad[14:]}, dp, key); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s: tampered: %v", dp, err)
		}
	}
}

func TestGoldenKeys(t *testing.T) {
	w, err := keyWrap(seq(32, 0xa0), seq(64, 0))
	want := unhex(t, "2a66928b5f5624880e0dc4ee135848d8ec22342fabf1d811bdf395c6445abf0f3219adda17539d27d8f5be42e52463fcc2cab286aec09e9506514a5a4f19fded74ab73a6f156cd60")
	if err != nil || !bytes.Equal(w, want) {
		t.Errorf("wrap %x, %v", w, err)
	}
	k := hkdf(sha256.New, seq(32, 1), append(seq(32, 0x40), seq(32, 0x60)...), nil, 64)
	if want := unhex(t, "dd1749f451b5a3aee7f2b2bd2e9396041c0851427b83032229615505416abd5256806cdfdf7b64ec194a3fa224c6d21346aad7501ec4881d3b22e591bbfee782"); !bytes.Equal(k, want) {
		t.Errorf("hkdf %x", k)
	}
}

// RFC 3394 section 4.6 (256-bit key data, 256-bit KEK) and RFC 5869 test
// case 1.
func TestRFCVectors(t *testing.T) {
	kek := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	data := unhex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	want := unhex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
	got, err := keyWrap(kek, data)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("wrap %X, %v", got, err)
	}
	back, err := keyUnwrap(kek, want)
	if err != nil || !bytes.Equal(back, data) {
		t.Errorf("unwrap %X, %v", back, err)
	}
	bad := bytes.Clone(want)
	bad[3] ^= 1
	if _, err := keyUnwrap(kek, bad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("unwrap tampered: %v", err)
	}
	for _, n := range []int{8, 15, 23} {
		if _, err := keyUnwrap(kek, make([]byte, n)); !errors.Is(err, ErrAuthentication) {
			t.Errorf("unwrap %d octets: %v", n, err)
		}
	}
	if _, err := keyWrap(kek, make([]byte, 12)); err == nil {
		t.Error("wrapped 12 octets")
	}
	if _, err := keyWrap(make([]byte, 7), make([]byte, 16)); err == nil {
		t.Error("wrapped with a 7-octet key")
	}

	okm := hkdf(sha256.New, unhex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), unhex(t, "000102030405060708090a0b0c"),
		unhex(t, "f0f1f2f3f4f5f6f7f8f9"), 42)
	if want := unhex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"); !bytes.Equal(okm, want) {
		t.Errorf("hkdf %x", okm)
	}
	// RFC 5869 test case 3: no salt.
	okm = hkdf(sha256.New, unhex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), nil, nil, 42)
	if want := unhex(t, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"); !bytes.Equal(okm, want) {
		t.Errorf("hkdf no salt %x", okm)
	}
}

func TestDecodeErrors(t *testing.T) {
	p := asdu.IEC104
	enc := func(d Direction, m Message) []byte {
		c, _ := PermittedCause(m.Type(), d)
		b, err := Encode(Header{Cause: c, CommonAddr: 1}, p, m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sq := enc(Control, SessionRequest{AIM: 1, AIS: 2, Protocol: Version1, Random: seq(8, 0)})
	si := enc(Monitor, SessionInitiationRequest{AIM: 1, AIS: 2, Random: seq(8, 0), Tag: seq(16, 0)})
	mod := func(b []byte, f func([]byte) []byte) []byte { return f(bytes.Clone(b)) }
	cases := map[string][]byte{
		"short header":     {86, 1, 15},
		"not security":     mod(sq, func(b []byte) []byte { b[0] = 45; return b }),
		"VSQ 2":            mod(sq, func(b []byte) []byte { b[1] = 2; return b }),
		"wrong cause":      mod(sq, func(b []byte) []byte { b[2] = 16; return b }),
		"truncated":        sq[:len(sq)-1],
		"trailing":         append(bytes.Clone(sq), 0),
		"SI random 3":      mod(si, func(b []byte) []byte { b[10] = 3; return b[:len(b)-5] }),
		"SI association 0": mod(si, func(b []byte) []byte { b[6], b[7] = 0, 0; return b }),
	}
	dirs := map[string]Direction{"SI random 3": Monitor, "SI association 0": Monitor}
	for name, b := range cases {
		if _, _, err := Decode(b, p, dirs[name]); !errors.Is(err, ErrMessage) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := Decode(sq, asdu.Params{CauseSize: 3, CommonAddrSize: 2}, Control); !errors.Is(err, ErrConfig) {
		t.Errorf("bad params: %v", err)
	}
	for _, m := range []Message{
		AssociationRequest{AIM: 1, Protocol: ProtocolInfo{Major: 16}},
		SessionRequest{AIM: 1, AIS: 1, Protocol: ProtocolInfo{Minor: 16}},
		AssociationRequest{AIM: 1, Certificate: make([]byte, 1<<16)},
		AssociationResponse{AIM: 1, Certificate: make([]byte, 1<<16)},
		AssociationResponse{AIM: 1, Random: make([]byte, 256)},
		UpdateKeyChangeRequest{Random: make([]byte, 256)},
		SessionInitiationRequest{AIM: 1, AIS: 1, Random: seq(3, 0)},
		SessionInitiationRequest{AIM: 0, AIS: 1, Random: seq(8, 0)},
		SessionRequest{Random: make([]byte, 256)},
		SessionResponse{Random: make([]byte, 256)},
		SessionKeyChangeRequest{Wrapped: make([]byte, 1<<16)},
	} {
		if _, err := Encode(Header{}, p, m); !errors.Is(err, ErrMessage) {
			t.Errorf("%s %+v: encoded: %v", m.Type(), m, err)
		}
	}
	// Narrow fields of IEC 60870-5-101.
	narrow := asdu.Params{CauseSize: 1, CommonAddrSize: 1}
	b, err := Encode(Header{Cause: asdu.CauseSessionKey, CommonAddr: 3, Test: true, Negative: true}, narrow, SessionRequest{AIM: 1, AIS: 2, Protocol: ProtocolInfo{Major: 1, Broadcast: true}, Random: seq(4, 0)})
	if err != nil || len(b) != 4+4+2+1+4 || b[2] != 0xcf {
		t.Fatalf("narrow: %x, %v", b, err)
	}
	h, m, err := Decode(b, narrow, Control)
	if err != nil || !h.Test || !h.Negative || !m.(SessionRequest).Protocol.Broadcast || h.CommonAddr != 3 {
		t.Errorf("narrow: %+v %+v %v", h, m, err)
	}
}

func TestNames(t *testing.T) {
	if Control.String() != "control" || Monitor.String() != "monitor" || Controlling.String() != "controlling" || Controlled.String() != "controlled" {
		t.Error("names")
	}
	if P256.String() != "secp256r1" || X25519.String() != "Curve25519" || Curve(9).String() != "curve(9)" {
		t.Error("curve names")
	}
	for _, s := range []string{"secp256r1", "P-256", "prime256v1", "x25519", "Curve25519"} {
		if _, err := ParseCurve(s); err != nil {
			t.Error(s, err)
		}
	}
	if _, err := ParseCurve("secp256k1"); !errors.Is(err, ErrConfig) {
		t.Error("secp256k1 accepted")
	}
	if Notice.String() != "notice" || Warning.String() != "warning" || Alarm.String() != "alarm" || Severity(0).String() != "none" {
		t.Error("severity names")
	}
	if StatKeyAuthenticationErrors.String() != "Key Authentication Errors" || NumStats.String() != "stat(29)" {
		t.Error("stat names")
	}
	if n, s, ok := StatKeyAuthenticationErrors.Event(); n != "KEY_AUTN_ERR" || s != Alarm || !ok {
		t.Error("stat event")
	}
	if _, _, ok := StatMessagesSent.Event(); ok {
		t.Error("plain counter with an event")
	}
	if _, _, ok := NumStats.Event(); ok {
		t.Error("NumStats with an event")
	}
	gcm, _ := DataProtectionByCode(AES256GCM)
	mac, _ := DataProtectionByCode(HMACSHA256.Code)
	if gcm.String() != "AEAD-AES-256-GCM" || mac.String() != "HMAC-SHA-256/16" || (DataProtection{Code: 99}).String() != "DPA 99" {
		t.Error("data protection names")
	}
	if _, ok := DataProtectionByCode(99); ok {
		t.Error("DPA 99")
	}
	if c, ok := PermittedCause(asdu.M_SP_NA_1, Control); ok || c != 0 {
		t.Error("cause of a non-security type")
	}
}

func TestSegments(t *testing.T) {
	p := asdu.IEC104
	head := []byte{81, 1, 16, 5, 0x34, 0x12}
	msg := append(bytes.Clone(head), seq(300, 0)...)
	segs, next, err := Segment(msg, p, 249, 62)
	// Lengths and ASC octets as github.com/cB-Sigma/iec60870 cuts them.
	if err != nil || len(segs) != 2 || len(segs[0]) != 249 || len(segs[1]) != 65 || segs[0][6] != 0x7e || segs[1][6] != 0xbf || next != 0 {
		t.Fatalf("segments %d, next %d, %v", len(segs), next, err)
	}
	if _, _, err := Segment(head[:3], p, 249, 0); !errors.Is(err, ErrMessage) {
		t.Error(err)
	}
	if _, _, err := Segment(msg, p, 7, 0); !errors.Is(err, ErrConfig) {
		t.Error(err)
	}
	if a := ParseASC(0xc5); !a.FIN || !a.FIR || a.Seq != 5 || a.Byte() != 0xc5 {
		t.Error("ASC")
	}

	var dropped int
	r := reassembler{p: p, discarded: func() { dropped++ }}
	expect := func(what string, seg []byte, done bool, drops int) {
		t.Helper()
		got := r.add(seg)
		if (got != nil) != done || dropped != drops {
			t.Errorf("%s: complete %v, dropped %d", what, got != nil, dropped)
		}
		if done && !bytes.Equal(got, msg) {
			t.Errorf("%s: reassembled %x", what, got)
		}
	}
	expect("first", segs[0], false, 0)
	expect("first again", segs[0], false, 0) // duplicate: ignored
	expect("last", segs[1], true, 0)
	expect("last alone", segs[1], false, 1)
	expect("short", head, false, 2)
	expect("first", segs[0], false, 2)
	expect("restart", segs[0][:len(segs[0])-1], false, 3) // FIR again: the series restarts
	other := bytes.Clone(segs[1])
	other[4] = 0x99 // another common address
	expect("other header", other, false, 4)
	expect("first", segs[0], false, 4)
	gap := bytes.Clone(segs[1])
	gap[6] = 0x82 // FIN, sequence 2: one missing
	expect("gap", gap, false, 5)
	expect("first", segs[0], false, 5)
	same := bytes.Clone(segs[0])
	same[6] = 0x3e // the same number, different content, no FIR
	same[10] ^= 1
	expect("same number", same, false, 6)
	single, _, _ := Segment(append(bytes.Clone(head), 1, 2, 3), p, 249, 9)
	expect("single", segs[0], false, 6)
	r.reset()
	if got := r.add(single[0]); !bytes.Equal(got, append(bytes.Clone(head), 1, 2, 3)) {
		t.Errorf("single: %x", got)
	}
}

func TestAssociationOf(t *testing.T) {
	narrow := asdu.Params{CauseSize: 1, CommonAddrSize: 1, IOASize: 2}
	for _, p := range []asdu.Params{asdu.IEC104, narrow} {
		whole, err := Encode(Header{Cause: asdu.CauseSessionKey, CommonAddr: 1}, p,
			SessionRequest{AIM: 0x1234, AIS: 9, Protocol: Version1, Random: seq(32, 0)})
		if err != nil {
			t.Fatal(err)
		}
		segs, _, err := Segment(whole, p, 20, 0)
		if err != nil || len(segs) < 2 {
			t.Fatalf("%d segments, %v", len(segs), err)
		}
		if aim, ok := AssociationOf(segs[0], p); !ok || aim != 0x1234 {
			t.Errorf("first segment: %#x, %v", aim, ok)
		}
		if _, ok := AssociationOf(segs[1], p); ok {
			t.Error("a later segment names an association")
		}
		if _, ok := AssociationOf(segs[0][:headerLen(p)+2], p); ok {
			t.Error("a short segment names an association")
		}
	}
	if aim, ok := AssociationOf(func() []byte {
		b, _ := Encode(Header{Cause: asdu.CauseSessionKey, CommonAddr: 1}, asdu.IEC104,
			SessionRequest{AIM: 3, AIS: 9, Protocol: Version1, Random: seq(32, 0)})
		s, _, _ := Segment(b, asdu.IEC104, 249, 0)
		return s[0]
	}(), asdu.Params{}); !ok || aim != 3 {
		t.Errorf("zero params: %d, %v", aim, ok)
	}
	plain := []byte{byte(asdu.C_IC_NA_1), 1, 6, 0, 1, 0, 0x40, 1, 0, 0, 0, 20}
	if _, ok := AssociationOf(plain, asdu.IEC104); ok {
		t.Error("an ASDU without security names an association")
	}
	if _, ok := AssociationOf(plain, asdu.Params{CauseSize: 3, CommonAddrSize: 2}); ok {
		t.Error("invalid params")
	}
}
