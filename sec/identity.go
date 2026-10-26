// SPDX-License-Identifier: MIT

package sec

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// Curve is the elliptic curve of a station's key pair. Both stations of an
// association use the same curve: the Station Association is an ECDH key
// agreement between the keys of their certificates.
//
// IEC 62351-5 also lists secp256k1, Curve448 and brainpoolP256r1. The Go
// standard library has none of them, and this module depends on nothing
// else, so they are not supported.
type Curve uint8

const (
	// P256 is secp256r1 (NIST P-256). A P-256 key can sign, so a station
	// with one can have a self-signed certificate.
	P256 Curve = iota + 1
	// X25519 is Curve25519. It serves key agreement only: the certificate
	// must be signed by a Central Authority.
	X25519
)

// String names the curve as IEC 62351-5 does.
func (c Curve) String() string {
	switch c {
	case P256:
		return "secp256r1"
	case X25519:
		return "Curve25519"
	}
	return fmt.Sprintf("curve(%d)", uint8(c))
}

// ParseCurve reads a curve name: secp256r1 (also p256, p-256, prime256v1) or
// curve25519 (also x25519).
func ParseCurve(s string) (Curve, error) {
	switch strings.ToLower(s) {
	case "secp256r1", "p256", "p-256", "prime256v1":
		return P256, nil
	case "curve25519", "x25519":
		return X25519, nil
	}
	return 0, fmt.Errorf("%w: curve %q, want secp256r1 or curve25519", ErrConfig, s)
}

// Identity is a station's key pair and its certificate.
type Identity struct {
	// Certificate is the station certificate. Its public key is the key
	// agreement key of the station.
	Certificate *x509.Certificate
	// Key is the private key: an *ecdsa.PrivateKey on P-256, or an
	// *ecdh.PrivateKey on X25519.
	Key crypto.PrivateKey
}

// curve returns the curve of the identity's certificate and checks that
// Key belongs to it.
func (id *Identity) check() (Curve, *ecdh.PrivateKey, error) {
	if id == nil || id.Certificate == nil || id.Key == nil {
		return 0, nil, fmt.Errorf("%w: identity needs a certificate and its private key", ErrConfig)
	}
	curve, pub, err := publicKey(id.Certificate)
	if err != nil {
		return 0, nil, err
	}
	var priv *ecdh.PrivateKey
	switch k := id.Key.(type) {
	case *ecdsa.PrivateKey:
		priv, err = k.ECDH()
	case *ecdh.PrivateKey:
		priv = k
	default:
		err = fmt.Errorf("%w: private key of type %T", ErrConfig, id.Key)
	}
	if err != nil {
		return 0, nil, err
	}
	if !priv.PublicKey().Equal(pub) {
		return 0, nil, fmt.Errorf("%w: the private key does not belong to the certificate", ErrConfig)
	}
	return curve, priv, nil
}

// publicKey returns the curve and key agreement key of a certificate.
func publicKey(c *x509.Certificate) (Curve, *ecdh.PublicKey, error) {
	key := c.PublicKey
	if key == nil {
		// crypto/x509 leaves PublicKey nil for an X25519 certificate, but
		// parses the key itself.
		key, _ = x509.ParsePKIXPublicKey(c.RawSubjectPublicKeyInfo)
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return 0, nil, fmt.Errorf("%w: EC key on %s, want secp256r1", ErrCertificate, k.Curve.Params().Name)
		}
		pub, err := k.ECDH()
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %w", ErrCertificate, err)
		}
		return P256, pub, nil
	case *ecdh.PublicKey:
		if k.Curve() == ecdh.X25519() {
			return X25519, k, nil
		}
	}
	return 0, nil, fmt.Errorf("%w: public key of type %T, want secp256r1 or Curve25519", ErrCertificate, key)
}

// Fingerprint returns the SHA-256 digest of a certificate's DER encoding,
// which [Trust.Fingerprints] lists.
func Fingerprint(c *x509.Certificate) [32]byte { return sha256.Sum256(c.Raw) }

// IdentityOptions describes a certificate for [NewIdentity].
type IdentityOptions struct {
	// Curve of the new key pair; P256 when zero.
	Curve Curve
	// Subject of the certificate.
	Subject pkix.Name
	// NotBefore and NotAfter bound the validity period; zero values give
	// now minus one minute and one year from now.
	NotBefore, NotAfter time.Time
	// Issuer signs the certificate: a Central Authority with a P-256 key.
	// Nil makes a self-signed certificate, which needs a P-256 key.
	Issuer *Identity
	// CA makes the certificate a Central Authority certificate that can
	// sign others.
	CA bool
}

// NewIdentity makes a key pair and a certificate for it, for provisioning
// and tests. Production keys are usually made where they are kept.
func NewIdentity(o IdentityOptions) (*Identity, error) {
	if o.Curve == 0 {
		o.Curve = P256
	}
	var (
		pub  any
		priv crypto.PrivateKey
	)
	switch o.Curve {
	case P256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub, priv = &k.PublicKey, k
	case X25519:
		if o.Issuer == nil {
			return nil, fmt.Errorf("%w: a Curve25519 certificate cannot be self-signed", ErrConfig)
		}
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pub, priv = k.PublicKey(), k
	default:
		return nil, fmt.Errorf("%w: %s", ErrConfig, o.Curve)
	}
	now := time.Now()
	if o.NotBefore.IsZero() {
		o.NotBefore = now.Add(-time.Minute)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = now.AddDate(1, 0, 0)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		Subject:      o.Subject,
		NotBefore:    o.NotBefore,
		NotAfter:     o.NotAfter,
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	if o.Curve == P256 {
		tmpl.KeyUsage |= x509.KeyUsageDigitalSignature
	}
	if o.CA {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parent, signer := tmpl, priv
	if o.Issuer != nil {
		parent, signer = o.Issuer.Certificate, o.Issuer.Key
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		return nil, fmt.Errorf("%w: the issuer needs a secp256r1 key", ErrConfig)
	}
	var der []byte
	if x, ok := pub.(*ecdh.PublicKey); ok {
		der, err = createX25519Certificate(tmpl, parent, x, signer.(*ecdsa.PrivateKey))
	} else {
		der, err = x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	}
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Identity{Certificate: cert, Key: priv}, nil
}

// createX25519Certificate issues a certificate for an X25519 key, which
// x509.CreateCertificate refuses: it makes the certificate for a stand-in
// P-256 key, puts the X25519 key into its to-be-signed part and signs that
// again.
func createX25519Certificate(tmpl, parent *x509.Certificate, pub *ecdh.PublicKey, signer *ecdsa.PrivateKey) ([]byte, error) {
	stand, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &stand.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(c.RawTBSCertificate, &seq); err != nil {
		return nil, err
	}
	var fields []byte
	for rest := seq.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, err
		}
		if bytes.Equal(f.FullBytes, c.RawSubjectPublicKeyInfo) {
			fields = append(fields, spki...)
		} else {
			fields = append(fields, f.FullBytes...)
		}
	}
	tbs, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: fields})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		return nil, err
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.Raw, &outer); err != nil {
		return nil, err
	}
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	return asn1.Marshal(outer)
}

// LoadIdentity reads a PEM certificate and its PEM private key (PKCS #8,
// or SEC 1 for P-256) from files.
func LoadIdentity(certFile, keyFile string) (*Identity, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ParseIdentity(certPEM, keyPEM)
}

// ParseIdentity reads a PEM certificate and its PEM private key.
func ParseIdentity(certPEM, keyPEM []byte) (*Identity, error) {
	certs, err := ParseCertificates(certPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificate", ErrConfig)
	}
	b, _ := pem.Decode(keyPEM)
	if b == nil {
		return nil, fmt.Errorf("%w: no PEM private key", ErrConfig)
	}
	var key crypto.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		key = k
	} else if k, err2 := x509.ParseECPrivateKey(b.Bytes); err2 == nil {
		key = k
	} else {
		return nil, fmt.Errorf("%w: private key: %w", ErrConfig, err)
	}
	id := &Identity{Certificate: certs[0], Key: key}
	if _, _, err := id.check(); err != nil {
		return nil, err
	}
	return id, nil
}

// ParseCertificates reads every certificate of PEM data.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out, nil
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCertificate, err)
		}
		out = append(out, c)
	}
}

// PEM returns the certificate and private key of the identity in PEM.
func (id *Identity) PEM() (certPEM, keyPEM []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.Certificate.Raw})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, nil
}

// Trust is what a station accepts as the other end of an association.
//
// A self-signed remote certificate is accepted when its fingerprint or its
// public key is listed. A certificate signed by one of the Central
// Authorities is accepted when Subjects is empty or lists its subject.
type Trust struct {
	// Fingerprints are SHA-256 digests of accepted self-signed
	// certificates (see [Fingerprint]).
	Fingerprints [][32]byte
	// PublicKeys are accepted self-signed certificates' public keys, as
	// carried in the certificate (the subjectPublicKey bit string).
	PublicKeys [][]byte
	// Authorities are the Central Authority certificates that may sign
	// remote station certificates.
	Authorities []*x509.Certificate
	// Subjects, when not empty, restricts the stations a Central Authority
	// vouches for to these subject names (DER, as in
	// x509.Certificate.RawSubject).
	Subjects [][]byte
}

// Pin returns a Trust that accepts exactly this self-signed identity.
func (id *Identity) Pin() Trust {
	return Trust{Fingerprints: [][32]byte{Fingerprint(id.Certificate)}}
}

// verify checks a remote station certificate (DER) for an association whose
// local key is on curve: same curve, within its validity period unless
// ignoreValidity, signed correctly, and authorized by t. notAuthorized tells
// a certificate that is valid but not accepted from one that is not valid.
func (t Trust) verify(der []byte, curve Curve, now time.Time, ignoreValidity bool) (c *x509.Certificate, pub *ecdh.PublicKey, notAuthorized bool, err error) {
	fail := func(na bool, format string, a ...any) (*x509.Certificate, *ecdh.PublicKey, bool, error) {
		return nil, nil, na, fmt.Errorf("%w: "+format, append([]any{ErrCertificate}, a...)...)
	}
	if len(der) == 0 {
		return fail(false, "no certificate")
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		return fail(false, "%v", err)
	}
	rc, pub, err := publicKey(c)
	if err != nil {
		return nil, nil, false, err
	}
	if rc != curve {
		return fail(false, "remote key on %s, ours on %s", rc, curve)
	}
	if !ignoreValidity && (now.Before(c.NotBefore) || now.After(c.NotAfter)) {
		return fail(false, "%q is outside its validity period", c.Subject)
	}
	// The authorities first: a station certificate whose subject equals its
	// issuer's (both empty, say) is not self-signed for that.
	var sigErr error
	for _, ca := range t.Authorities {
		if !bytes.Equal(ca.RawSubject, c.RawIssuer) {
			continue
		}
		// The signature alone: Central Authority certificates of some
		// implementations carry no basic constraints, which
		// x509.Certificate.CheckSignatureFrom would refuse.
		if err := ca.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			sigErr = err
			continue
		}
		if len(t.Subjects) > 0 {
			ok := false
			for _, s := range t.Subjects {
				ok = ok || bytes.Equal(s, c.RawSubject)
			}
			if !ok {
				return fail(true, "%q is not an authorized station", c.Subject)
			}
		}
		return c, pub, false, nil
	}
	if sigErr != nil {
		return fail(false, "%q: %v", c.Subject, sigErr)
	}
	if bytes.Equal(c.RawIssuer, c.RawSubject) {
		if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			return fail(false, "self-signed %q: %v", c.Subject, err)
		}
		fp := Fingerprint(c)
		spk := subjectPublicKey(c)
		for _, f := range t.Fingerprints {
			if f == fp {
				return c, pub, false, nil
			}
		}
		for _, k := range t.PublicKeys {
			if bytes.Equal(k, spk) {
				return c, pub, false, nil
			}
		}
		return fail(true, "self-signed %q is not trusted", c.Subject)
	}
	return fail(true, "%q is issued by %q, which is not a trusted authority", c.Subject, c.Issuer)
}

// subjectPublicKey returns the subjectPublicKey bit string of a certificate.
func subjectPublicKey(c *x509.Certificate) []byte {
	if _, pub, err := publicKey(c); err == nil {
		return pub.Bytes()
	}
	return nil
}
