package store

import "time"

// ClientStore persists OAuth client registrations.
type ClientStore interface {
	GetClient(id string) (*Client, bool)
	PutClient(c *Client)
}

// UserStore persists resource owners.
type UserStore interface {
	GetUser(id string) (*User, bool)
	GetUserByUsername(username string) (*User, bool)
	PutUser(u *User)
}

// ConsumeResult classifies an authorization-code redemption attempt.
type ConsumeResult int

// Possible outcomes of AuthCodeStore.ConsumeAuthCode.
const (
	ConsumeOK       ConsumeResult = iota // first redemption, code now marked used
	ConsumeReplayed                      // code was already redeemed — attack indicator
	ConsumeNotFound                      // unknown or expired code
)

// AuthCodeStore persists one-time authorization codes, keyed by the SHA-256
// hash of the code value.
type AuthCodeStore interface {
	PutAuthCode(c *AuthCode)
	// ConsumeAuthCode atomically looks up and marks the code used. On
	// ConsumeReplayed the returned snapshot carries the JTIs and family
	// minted at first use so the caller can revoke them.
	ConsumeAuthCode(codeHash []byte) (*AuthCode, ConsumeResult)
	// RecordIssued attaches the artifacts minted from a redeemed code, so a
	// later replay can revoke them.
	RecordIssued(codeHash []byte, jtis []string, familyID string)
}

// TokenStore tracks issued access tokens by jti for introspection and
// revocation.
type TokenStore interface {
	PutToken(t *AccessTokenRecord)
	GetToken(jti string) (*AccessTokenRecord, bool)
	// RevokeToken marks one token revoked; reports whether it existed.
	RevokeToken(jti string) bool
	// RevokeFamilyTokens revokes every access token minted through the given
	// refresh family and returns how many were affected.
	RevokeFamilyTokens(familyID string) int
}

// RedeemStatus classifies a refresh-token redemption attempt.
type RedeemStatus int

// Possible outcomes of RefreshFamilyStore.Redeem.
const (
	RedeemOK       RedeemStatus = iota // rotated: newHash is now the only redeemable member
	RedeemReused                       // a superseded member was presented — family revoked
	RedeemNotFound                     // no family knows this hash
	RedeemDead                         // family revoked or expired
)

// RefreshFamilyStore persists refresh-token families and performs the
// rotation state machine atomically.
type RefreshFamilyStore interface {
	PutFamily(f *RefreshTokenFamily)
	GetFamily(id string) (*RefreshTokenFamily, bool)
	// Redeem processes presentation of the refresh token whose SHA-256 is
	// tokenHash, atomically:
	//   - current member of a live family → append a member with newHash,
	//     advance the generation, extend the idle expiry, return RedeemOK;
	//   - superseded member → revoke the family (reuse detected), return
	//     RedeemReused;
	//   - revoked or expired family → RedeemDead;
	//   - unknown hash → RedeemNotFound.
	// The returned snapshot reflects the state after the transition.
	Redeem(tokenHash, newHash []byte, now time.Time, idleTTL time.Duration) (*RefreshTokenFamily, RedeemStatus)
	// RevokeFamily marks a family revoked with the given reason; reports
	// whether the family existed. Used by RFC 7009 revocation and by
	// auth-code replay handling.
	RevokeFamily(id, reason string) bool
	// FindFamilyByTokenHash resolves a presented refresh token to its family
	// without mutating state (used by introspection and revocation).
	FindFamilyByTokenHash(tokenHash []byte) (*RefreshTokenFamily, bool)
}

// Store aggregates everything the authorization server needs.
type Store interface {
	ClientStore
	UserStore
	AuthCodeStore
	TokenStore
	RefreshFamilyStore
}
