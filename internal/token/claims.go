// Package token issues and verifies OAuth 2.0 access tokens in the JWT
// profile defined by RFC 9068 ("at+jwt"). Audience restriction follows
// RFC 8707: every token names the resource servers it may be presented to,
// and verification requires the verifier's own identifier to appear there.
package token

import (
	"encoding/json"
	"fmt"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
)

// Audience is the "aud" claim. RFC 7519 allows either a string or an array;
// this issuer always emits the array form so downstream parsers deal with a
// single canonical shape, while unmarshaling accepts both.
type Audience []string

// MarshalJSON always emits a JSON array.
func (a Audience) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(a))
}

// UnmarshalJSON accepts both the string and array forms of "aud".
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("aud must be a string or array of strings")
	}
	*a = Audience(many)
	return nil
}

// Contains reports whether the audience includes the given resource
// identifier.
func (a Audience) Contains(resource string) bool {
	for _, v := range a {
		if v == resource {
			return true
		}
	}
	return false
}

// Actor is the RFC 8693 §4.1 "act" claim identifying the party acting on
// behalf of the subject after a token exchange.
type Actor struct {
	Subject string `json:"sub"`
}

// Claims is the payload of an RFC 9068 JWT access token.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"`
	Actor     *Actor   `json:"act,omitempty"`
}

// Scopes returns the scope claim parsed into individual values.
func (c *Claims) Scopes() []string {
	return oauth.ParseScope(c.Scope)
}

// HasScope reports whether the token grants the given scope value.
func (c *Claims) HasScope(scope string) bool {
	return oauth.ScopeContains(c.Scopes(), scope)
}
