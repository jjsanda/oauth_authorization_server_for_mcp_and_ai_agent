package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCE (RFC 7636) with the S256 method only. OAuth 2.1 requires PKCE for
// every authorization code flow, and this server additionally refuses the
// downgrade-prone "plain" method.

// VerifierValid reports whether v satisfies the RFC 7636 §4.1 grammar:
// 43–128 characters from the unreserved set ALPHA / DIGIT / "-" / "." /
// "_" / "~".
func VerifierValid(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range []byte(v) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// ChallengeS256 derives the S256 code challenge for a verifier:
// BASE64URL-ENCODE(SHA256(ASCII(verifier))) per RFC 7636 §4.2.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyS256 checks a presented code_verifier against the stored
// code_challenge in constant time.
func VerifyS256(challenge, verifier string) bool {
	if !VerifierValid(verifier) {
		return false
	}
	computed := ChallengeS256(verifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
