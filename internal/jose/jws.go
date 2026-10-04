package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Header is the JOSE protected header of a compact JWS.
type Header struct {
	Alg Algorithm `json:"alg"`
	Typ string    `json:"typ,omitempty"`
	KID string    `json:"kid,omitempty"`
}

// ErrInvalidSignature is returned whenever a token's signature does not
// verify. The message is deliberately uniform to avoid leaking which check
// failed.
var ErrInvalidSignature = errors.New("jose: invalid signature")

// SignCompact produces a compact JWS (header.payload.signature) over payload
// with the given typ header (e.g. "at+jwt" per RFC 9068).
func SignCompact(key *SigningKey, typ string, payload []byte) (string, error) {
	headerJSON, err := json.Marshal(Header{Alg: key.Alg, Typ: typ, KID: key.KID})
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(payload)

	var sig []byte
	switch key.Alg {
	case ES256:
		sig, err = signES256(key.ec, []byte(signingInput))
	case EdDSA:
		sig = ed25519.Sign(key.ed, []byte(signingInput))
	default:
		err = fmt.Errorf("jose: unsupported algorithm %q", key.Alg)
	}
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// KeyResolver maps a key ID from a token header to a verification key.
// Returning false rejects the token.
type KeyResolver func(kid string) (*PublicKey, bool)

// VerifyCompact parses a compact JWS, resolves its kid through resolve, and
// verifies the signature using the algorithm pinned to the resolved key.
// A token whose header names a different algorithm than the key record is
// rejected — the header never selects the algorithm.
func VerifyCompact(token string, resolve KeyResolver) (Header, []byte, error) {
	var hdr Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, nil, errors.New("jose: token must have three segments")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, fmt.Errorf("jose: invalid header encoding: %w", err)
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return hdr, nil, fmt.Errorf("jose: invalid header: %w", err)
	}
	key, ok := resolve(hdr.KID)
	if !ok {
		return hdr, nil, ErrInvalidSignature
	}
	if hdr.Alg != key.Alg {
		return hdr, nil, ErrInvalidSignature
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return hdr, nil, ErrInvalidSignature
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	switch key.Alg {
	case ES256:
		if err := verifyES256(key.ec, signingInput, sig); err != nil {
			return hdr, nil, err
		}
	case EdDSA:
		if !ed25519.Verify(key.ed, signingInput, sig) {
			return hdr, nil, ErrInvalidSignature
		}
	default:
		return hdr, nil, ErrInvalidSignature
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return hdr, nil, fmt.Errorf("jose: invalid payload encoding: %w", err)
	}
	return hdr, payload, nil
}

// signES256 hashes the signing input with SHA-256 and encodes the ECDSA
// signature in the raw fixed-width R||S form JWS requires (RFC 7518 §3.4),
// not the ASN.1 DER form produced by crypto/ecdsa's SignASN1.
func signES256(priv *ecdsa.PrivateKey, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// verifyES256 checks a raw R||S signature, rejecting out-of-range scalars
// before handing off to the constant-time stdlib verifier.
func verifyES256(pub *ecdsa.PublicKey, input, sig []byte) error {
	if len(sig) != 64 {
		return ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := pub.Curve.Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return ErrInvalidSignature
	}
	digest := sha256.Sum256(input)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrInvalidSignature
	}
	return nil
}
