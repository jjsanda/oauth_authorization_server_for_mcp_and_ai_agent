package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// NewToken returns a URL-safe secret with 256 bits of entropy, used for
// authorization codes, refresh tokens, client secrets, and jti values.
// It panics if the operating system's entropy source fails, which is not a
// recoverable condition for an authorization server.
func NewToken() string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("oauth: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// HashSecret returns the SHA-256 digest under which a bearer secret is
// stored. Raw secrets never touch the store; a leaked database therefore
// contains nothing redeemable. SHA-256 without stretching is appropriate
// because every secret hashed here is server-generated with 256 bits of
// entropy — key-derivation functions exist to slow guessing of low-entropy
// human passwords, which these are not.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// SecretEqual compares a presented secret against a stored hash in constant
// time.
func SecretEqual(hash []byte, presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(hash, sum[:]) == 1
}
