package token

import (
	"encoding/json"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
)

// TypeAccessToken is the JOSE "typ" header value RFC 9068 §2.1 assigns to
// OAuth access tokens, letting resource servers reject other token kinds
// (e.g. OpenID Connect ID tokens) outright.
const TypeAccessToken = "at+jwt"

// DefaultAccessTokenTTL is deliberately short; clients are expected to use
// refresh tokens rather than long-lived access tokens.
const DefaultAccessTokenTTL = 5 * time.Minute

// Issuer mints signed access tokens.
type Issuer struct {
	// Issuer is the value of the "iss" claim, the authorization server's
	// public URL.
	Issuer string
	// Keys provides the active signing key.
	Keys *jose.KeySet
	// TTL is the access token lifetime; DefaultAccessTokenTTL when zero.
	TTL time.Duration
	// Now allows tests to pin the clock; time.Now when nil.
	Now func() time.Time
}

// IssueParams describes one access token.
type IssueParams struct {
	Subject  string   // "user:<id>" or "client:<id>"
	ClientID string   // the client the token was issued to
	Audience []string // RFC 8707 resource identifiers
	Scope    []string
	ActorSub string        // non-empty only for token-exchange results
	TTL      time.Duration // optional per-token override
}

// Issue signs a new at+jwt access token and returns the compact JWS along
// with its claims (whose jti the caller records for introspection and
// revocation).
func (i *Issuer) Issue(p IssueParams) (string, *Claims, error) {
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	ttl := i.TTL
	if p.TTL != 0 {
		ttl = p.TTL
	}
	if ttl == 0 {
		ttl = DefaultAccessTokenTTL
	}
	iat := now().Unix()
	claims := &Claims{
		Issuer:    i.Issuer,
		Subject:   p.Subject,
		Audience:  Audience(p.Audience),
		ExpiresAt: iat + int64(ttl/time.Second),
		NotBefore: iat,
		IssuedAt:  iat,
		JTI:       oauth.NewToken(),
		ClientID:  p.ClientID,
		Scope:     oauth.FormatScope(p.Scope),
	}
	if p.ActorSub != "" {
		claims.Actor = &Actor{Subject: p.ActorSub}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	tok, err := jose.SignCompact(i.Keys.Active(), TypeAccessToken, payload)
	if err != nil {
		return "", nil, err
	}
	return tok, claims, nil
}
