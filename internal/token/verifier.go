package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
)

// Verification failure reasons. All wrap ErrInvalidToken so callers can
// treat any of them as "present a fresh token" while logs stay precise.
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpired      = fmt.Errorf("%w: expired", ErrInvalidToken)
	ErrNotYetValid  = fmt.Errorf("%w: not yet valid", ErrInvalidToken)
	ErrIssuer       = fmt.Errorf("%w: unexpected issuer", ErrInvalidToken)
	ErrAudience     = fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	ErrTokenType    = fmt.Errorf("%w: not an access token", ErrInvalidToken)
	ErrSignature    = fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
)

// KeyResolver resolves a kid to a verification key. Implemented by
// jose.KeySet locally and by the resource server's cached JWKS client.
type KeyResolver interface {
	VerificationKey(kid string) (*jose.PublicKey, bool)
}

// DefaultLeeway absorbs modest clock skew between the authorization server
// and resource servers when checking exp/nbf/iat.
const DefaultLeeway = 30 * time.Second

// Verifier validates at+jwt access tokens.
type Verifier struct {
	// Issuer is the exact "iss" value required.
	Issuer string
	// Keys resolves the token's kid to a pinned-algorithm public key.
	Keys KeyResolver
	// Audience, when non-empty, must appear in the token's aud list — this
	// is how RFC 8707 audience restriction is enforced at the resource.
	Audience string
	// Leeway for clock skew; DefaultLeeway when zero.
	Leeway time.Duration
	// Now allows tests to pin the clock; time.Now when nil.
	Now func() time.Time
}

// Verify checks signature, typ, issuer, audience, and time claims, and
// returns the parsed claims on success.
func (v *Verifier) Verify(tok string) (*Claims, error) {
	hdr, payload, err := jose.VerifyCompact(tok, func(kid string) (*jose.PublicKey, bool) {
		return v.Keys.VerificationKey(kid)
	})
	if err != nil {
		// Keep the client-facing category uniform (ErrSignature) while
		// preserving the precise cause for server-side logs.
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	// RFC 9068 §4: reject anything not explicitly typed as an access token.
	if typ := strings.ToLower(hdr.Typ); typ != TypeAccessToken && typ != "application/"+TypeAccessToken {
		return nil, ErrTokenType
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	if claims.Issuer != v.Issuer {
		return nil, ErrIssuer
	}
	if v.Audience != "" && !claims.Audience.Contains(v.Audience) {
		return nil, ErrAudience
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	leeway := v.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	t := now()
	if t.After(time.Unix(claims.ExpiresAt, 0).Add(leeway)) {
		return nil, ErrExpired
	}
	if claims.NotBefore != 0 && t.Add(leeway).Before(time.Unix(claims.NotBefore, 0)) {
		return nil, ErrNotYetValid
	}
	if claims.IssuedAt != 0 && t.Add(leeway).Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	}
	return &claims, nil
}
