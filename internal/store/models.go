// Package store defines the persistence model of the authorization server:
// registered clients, demo users, one-time authorization codes, issued
// access-token records, and refresh-token families. Interfaces are kept
// narrow so alternative backends (e.g. SQL) can be added without touching
// protocol code; the in-memory implementation lives in the memory
// subpackage.
package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"time"
)

// Grant type identifiers used in client registrations and token requests.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantClientCredentials = "client_credentials"
	GrantRefreshToken      = "refresh_token"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: this is a public grant-type identifier, not a credential
)

// Token endpoint authentication methods (RFC 7591 §2).
const (
	AuthMethodBasic = "client_secret_basic"
	AuthMethodPost  = "client_secret_post"
	AuthMethodNone  = "none" // public client
)

// Client is a registered OAuth client, whether provisioned statically or via
// dynamic registration (RFC 7591).
type Client struct {
	ID                string
	SecretHash        []byte // SHA-256 of the server-generated secret; nil for public clients
	Name              string
	RedirectURIs      []string // matched exactly, never by prefix
	GrantTypes        []string
	TokenEndpointAuth string
	Scopes            []string // the most scope this client may ever be granted
	AllowedResources  []string // RFC 8707 resource identifiers this client may request
	CreatedAt         time.Time
	Dynamic           bool // true when created through /register
}

// Public reports whether the client authenticates with PKCE only.
func (c *Client) Public() bool { return c.TokenEndpointAuth == AuthMethodNone }

// AllowsGrant reports whether the client registered for the given grant type.
func (c *Client) AllowsGrant(grantType string) bool {
	for _, g := range c.GrantTypes {
		if g == grantType {
			return true
		}
	}
	return false
}

// AllowsRedirectURI performs the exact-string redirect URI match required to
// prevent open-redirect and code-interception attacks.
func (c *Client) AllowsRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AllowsResource reports whether the client may request tokens for the given
// RFC 8707 resource identifier.
func (c *Client) AllowsResource(resource string) bool {
	for _, r := range c.AllowedResources {
		if r == resource {
			return true
		}
	}
	return false
}

// Clone returns a deep copy so callers can never mutate stored state.
func (c *Client) Clone() *Client {
	cp := *c
	cp.SecretHash = append([]byte(nil), c.SecretHash...)
	cp.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	cp.GrantTypes = append([]string(nil), c.GrantTypes...)
	cp.Scopes = append([]string(nil), c.Scopes...)
	cp.AllowedResources = append([]string(nil), c.AllowedResources...)
	return &cp
}

// User is a resource owner. The only users in this system are demo fixtures
// whose passwords exist to make the login form walkable; production
// deployments would delegate authentication to an IdP or use a proper
// password KDF.
type User struct {
	ID           string
	Username     string
	Salt         []byte
	PasswordHash []byte // SHA-256(salt || password) — demo fixture, see docs/security.md
}

// NewUser builds a demo user with a salted password hash.
func NewUser(id, username, password string, salt []byte) *User {
	sum := sha256.Sum256(append(append([]byte(nil), salt...), []byte(password)...))
	return &User{ID: id, Username: username, Salt: salt, PasswordHash: sum[:]}
}

// PasswordMatches checks a login attempt in constant time.
func (u *User) PasswordMatches(password string) bool {
	sum := sha256.Sum256(append(append([]byte(nil), u.Salt...), []byte(password)...))
	return subtle.ConstantTimeCompare(u.PasswordHash, sum[:]) == 1
}

// AuthCode is a pending or redeemed authorization code. Only the SHA-256
// hash of the code is stored. Redeemed codes are retained until expiry so a
// replay can be detected and the tokens it minted revoked (RFC 6749 §4.1.2).
type AuthCode struct {
	CodeHash      []byte
	ClientID      string
	UserID        string
	RedirectURI   string
	Scope         []string
	Resources     []string
	CodeChallenge string // PKCE S256 challenge; always present
	ExpiresAt     time.Time
	Used          bool
	IssuedJTIs    []string // access tokens minted from this code, for replay revocation
	FamilyID      string   // refresh family minted from this code, for replay revocation
}

// Clone returns a deep copy.
func (a *AuthCode) Clone() *AuthCode {
	cp := *a
	cp.CodeHash = append([]byte(nil), a.CodeHash...)
	cp.Scope = append([]string(nil), a.Scope...)
	cp.Resources = append([]string(nil), a.Resources...)
	cp.IssuedJTIs = append([]string(nil), a.IssuedJTIs...)
	return &cp
}

// AccessTokenRecord tracks an issued JWT access token by its jti so that
// introspection (RFC 7662) and revocation (RFC 7009) work even though the
// token itself is stateless.
type AccessTokenRecord struct {
	JTI       string
	ClientID  string
	Subject   string
	Scope     []string
	Audience  []string
	ExpiresAt time.Time
	Revoked   bool
	FamilyID  string // owning refresh family, "" for client-credentials tokens
}

// Clone returns a deep copy.
func (t *AccessTokenRecord) Clone() *AccessTokenRecord {
	cp := *t
	cp.Scope = append([]string(nil), t.Scope...)
	cp.Audience = append([]string(nil), t.Audience...)
	return &cp
}

// RefreshTokenFamily implements refresh token rotation (OAuth 2.1 §4.3.1,
// draft-ietf-oauth-security-topics): every refresh produces a new member and
// retires the previous one. Presenting a retired member is proof of token
// theft and revokes the entire family.
type RefreshTokenFamily struct {
	ID             string
	ClientID       string
	UserID         string
	Scope          []string // ceiling: refreshed tokens may only narrow this
	Resources      []string
	Members        []RefreshTokenMember // append-only history
	CurrentHash    []byte               // the single redeemable member
	Generation     int
	Revoked        bool
	RevokedReason  string // "reuse_detected", "revoked_by_client", "auth_code_replayed"
	IdleExpiry     time.Time
	AbsoluteExpiry time.Time
}

// Reasons a refresh token family can be revoked.
const (
	RevokedReasonReuse    = "reuse_detected"
	RevokedReasonClient   = "revoked_by_client"
	RevokedReasonAuthCode = "auth_code_replayed"
)

// RefreshTokenMember is one generation of a family.
type RefreshTokenMember struct {
	Hash       []byte
	Generation int
	IssuedAt   time.Time
}

// Clone returns a deep copy.
func (f *RefreshTokenFamily) Clone() *RefreshTokenFamily {
	cp := *f
	cp.Scope = append([]string(nil), f.Scope...)
	cp.Resources = append([]string(nil), f.Resources...)
	cp.CurrentHash = append([]byte(nil), f.CurrentHash...)
	cp.Members = make([]RefreshTokenMember, len(f.Members))
	for i, m := range f.Members {
		cp.Members[i] = RefreshTokenMember{
			Hash:       append([]byte(nil), m.Hash...),
			Generation: m.Generation,
			IssuedAt:   m.IssuedAt,
		}
	}
	return &cp
}
