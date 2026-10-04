// Package jose implements the minimal subset of JOSE (JSON Object Signing
// and Encryption) that an OAuth 2.1 authorization server needs: compact JWS
// signing and verification (RFC 7515), JWK/JWKS publication (RFC 7517), and
// JWK thumbprints (RFC 7638) used as stable key IDs.
//
// Only two signature algorithms are supported, both modern and both
// implementable directly on top of the Go standard library:
//
//   - ES256 (ECDSA over P-256 with SHA-256), the mandatory-to-implement
//     asymmetric JWS algorithm of RFC 7518, and
//   - EdDSA (Ed25519), per RFC 8037.
//
// The verifier accepts exactly the algorithm pinned to the server-side key
// record — never the algorithm named in a token header — which rules out
// alg=none and algorithm-confusion attacks by construction.
package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// Algorithm identifies a supported JWS signature algorithm.
type Algorithm string

// Supported JWS algorithms.
const (
	ES256 Algorithm = "ES256" // ECDSA using P-256 and SHA-256 (RFC 7518)
	EdDSA Algorithm = "EdDSA" // Ed25519 (RFC 8037)
)

var b64 = base64.RawURLEncoding

// SigningKey is a private key together with its pinned algorithm and its
// RFC 7638 thumbprint, which doubles as the JWS "kid".
type SigningKey struct {
	Alg Algorithm
	KID string

	ec *ecdsa.PrivateKey
	ed ed25519.PrivateKey
}

// PublicKey is the verification half of a SigningKey. The algorithm is part
// of the key record: verification never trusts the algorithm a token claims
// for itself.
type PublicKey struct {
	Alg Algorithm
	KID string

	ec *ecdsa.PublicKey
	ed ed25519.PublicKey
}

// GenerateKey creates a fresh signing key for the given algorithm.
func GenerateKey(alg Algorithm) (*SigningKey, error) {
	switch alg {
	case ES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		k := &SigningKey{Alg: ES256, ec: priv}
		k.KID = k.Public().Thumbprint()
		return k, nil
	case EdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		k := &SigningKey{Alg: EdDSA, ed: priv}
		k.KID = k.Public().Thumbprint()
		return k, nil
	default:
		return nil, fmt.Errorf("jose: unsupported algorithm %q", alg)
	}
}

// ParsePrivateKeyPEM loads a PKCS#8-encoded private key and infers the
// algorithm from the key type (P-256 → ES256, Ed25519 → EdDSA).
func ParsePrivateKeyPEM(data []byte) (*SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("jose: no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jose: parse PKCS#8 key: %w", err)
	}
	switch priv := parsed.(type) {
	case *ecdsa.PrivateKey:
		if priv.Curve != elliptic.P256() {
			return nil, fmt.Errorf("jose: unsupported curve %s (only P-256)", priv.Curve.Params().Name)
		}
		k := &SigningKey{Alg: ES256, ec: priv}
		k.KID = k.Public().Thumbprint()
		return k, nil
	case ed25519.PrivateKey:
		k := &SigningKey{Alg: EdDSA, ed: priv}
		k.KID = k.Public().Thumbprint()
		return k, nil
	default:
		return nil, fmt.Errorf("jose: unsupported private key type %T", parsed)
	}
}

// MarshalPrivateKeyPEM serializes the key as PKCS#8 PEM, e.g. for persisting
// a stable signing key across restarts.
func (k *SigningKey) MarshalPrivateKeyPEM() ([]byte, error) {
	var (
		der []byte
		err error
	)
	switch k.Alg {
	case ES256:
		der, err = x509.MarshalPKCS8PrivateKey(k.ec)
	case EdDSA:
		der, err = x509.MarshalPKCS8PrivateKey(k.ed)
	default:
		err = fmt.Errorf("jose: unsupported algorithm %q", k.Alg)
	}
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Public returns the verification half of the key.
func (k *SigningKey) Public() *PublicKey {
	pub := &PublicKey{Alg: k.Alg, KID: k.KID}
	switch k.Alg {
	case ES256:
		pub.ec = &k.ec.PublicKey
	case EdDSA:
		pub.ed = k.ed.Public().(ed25519.PublicKey)
	}
	return pub
}

// ecCoordinates returns the fixed-width big-endian X and Y coordinates.
func (p *PublicKey) ecCoordinates() (x, y []byte) {
	byteLen := (p.ec.Curve.Params().BitSize + 7) / 8
	x = make([]byte, byteLen)
	y = make([]byte, byteLen)
	p.ec.X.FillBytes(x)
	p.ec.Y.FillBytes(y)
	return x, y
}

// Thumbprint computes the RFC 7638 SHA-256 JWK thumbprint,
// base64url-encoded. It hashes the canonical JSON form of the key's required
// members in lexicographic order.
func (p *PublicKey) Thumbprint() string {
	var canonical string
	switch p.Alg {
	case ES256:
		x, y := p.ecCoordinates()
		canonical = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
			b64.EncodeToString(x), b64.EncodeToString(y))
	case EdDSA:
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`,
			b64.EncodeToString(p.ed))
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

// JWK is the public JSON Web Key representation published in the JWKS.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWK returns the public key in JWK form.
func (p *PublicKey) JWK() JWK {
	j := JWK{KID: p.KID, Use: "sig", Alg: string(p.Alg)}
	switch p.Alg {
	case ES256:
		x, y := p.ecCoordinates()
		j.Kty, j.Crv = "EC", "P-256"
		j.X, j.Y = b64.EncodeToString(x), b64.EncodeToString(y)
	case EdDSA:
		j.Kty, j.Crv = "OKP", "Ed25519"
		j.X = b64.EncodeToString(p.ed)
	}
	return j
}

// ParseJWK converts a published JWK back into a verification key, as a
// resource server does after fetching the authorization server's JWKS.
func ParseJWK(j JWK) (*PublicKey, error) {
	switch {
	case j.Kty == "EC" && j.Crv == "P-256":
		xb, err := b64.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("jose: invalid x coordinate: %w", err)
		}
		yb, err := b64.DecodeString(j.Y)
		if err != nil {
			return nil, fmt.Errorf("jose: invalid y coordinate: %w", err)
		}
		// Reject coordinates of the wrong width and points off the curve.
		if len(xb) != 32 || len(yb) != 32 {
			return nil, errors.New("jose: P-256 coordinates must be 32 bytes")
		}
		raw := append(append([]byte{4}, xb...), yb...)
		pubAny, err := parseECPoint(raw)
		if err != nil {
			return nil, err
		}
		return &PublicKey{Alg: ES256, KID: j.KID, ec: pubAny}, nil
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		xb, err := b64.DecodeString(j.X)
		if err != nil || len(xb) != ed25519.PublicKeySize {
			return nil, errors.New("jose: invalid Ed25519 public key")
		}
		return &PublicKey{Alg: EdDSA, KID: j.KID, ed: ed25519.PublicKey(xb)}, nil
	default:
		return nil, fmt.Errorf("jose: unsupported key type %s/%s", j.Kty, j.Crv)
	}
}

// parseECPoint validates an uncompressed SEC1 point via the standard
// library's on-curve checks.
func parseECPoint(raw []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), raw) //nolint:staticcheck // stdlib-only point validation
	if x == nil {
		return nil, errors.New("jose: point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// JWKS is the JSON Web Key Set document served at jwks_uri.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKS decodes a JWKS document.
func ParseJWKS(data []byte) (*JWKS, error) {
	var set JWKS
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jose: parse JWKS: %w", err)
	}
	return &set, nil
}
