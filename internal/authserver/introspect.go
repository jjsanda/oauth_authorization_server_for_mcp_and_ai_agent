package authserver

import (
	"net/http"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// introspectionResponse is the RFC 7662 §2.2 document. Only "active" is
// present for tokens that are unknown, expired, revoked — or that the caller
// is not authorized to learn about (the spec's anti-fishing rule).
type introspectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
}

// handleIntrospect implements RFC 7662. Callers must authenticate as a
// confidential client; a caller only learns about tokens it is entitled to
// see — its own, or tokens audienced to a resource it is registered for.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRequest, "malformed form body"))
		return
	}
	caller, oerr := s.authenticateClient(r)
	if oerr != nil {
		oauth.WriteError(w, oerr)
		return
	}
	if caller.Public() {
		// A public client cannot keep a secret, so it cannot be trusted
		// with introspection (RFC 7662 §2.1).
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidClient,
			"public clients may not introspect tokens"))
		return
	}
	presented := r.PostForm.Get("token")
	if presented == "" {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRequest, "token is required"))
		return
	}

	// Try as a JWT access token first, then as a refresh token; the
	// token_type_hint only changes ordering, not the outcome (RFC 7662 §2.1).
	if resp, ok := s.introspectAccessToken(presented, caller); ok {
		writeIntrospection(w, resp)
		return
	}
	if resp, ok := s.introspectRefreshToken(presented, caller); ok {
		writeIntrospection(w, resp)
		return
	}
	writeIntrospection(w, introspectionResponse{Active: false})
}

func writeIntrospection(w http.ResponseWriter, resp introspectionResponse) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// mayInspect decides whether caller is entitled to see this token's state:
// it must be the client the token was issued to, or be registered for one
// of the token's audiences (the resource-server case).
func mayInspect(caller *store.Client, tokenClientID string, audience []string) bool {
	if tokenClientID == caller.ID {
		return true
	}
	for _, aud := range audience {
		if caller.AllowsResource(aud) {
			return true
		}
	}
	return false
}

func (s *Server) introspectAccessToken(presented string, caller *store.Client) (introspectionResponse, bool) {
	claims, err := s.localVerifier().Verify(presented)
	if err != nil {
		return introspectionResponse{}, false
	}
	rec, ok := s.store.GetToken(claims.JTI)
	if !ok {
		// Signed by us but unknown — treat as not an access token.
		return introspectionResponse{}, false
	}
	if !mayInspect(caller, rec.ClientID, rec.Audience) {
		return introspectionResponse{Active: false}, true
	}
	if rec.Revoked || time.Now().After(rec.ExpiresAt) {
		return introspectionResponse{Active: false}, true
	}
	return introspectionResponse{
		Active:    true,
		Scope:     oauth.FormatScope(rec.Scope),
		ClientID:  rec.ClientID,
		Subject:   rec.Subject,
		Audience:  rec.Audience,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		TokenType: "Bearer",
		JTI:       rec.JTI,
		Issuer:    s.cfg.Issuer,
	}, true
}

func (s *Server) introspectRefreshToken(presented string, caller *store.Client) (introspectionResponse, bool) {
	hash := oauth.HashSecret(presented)
	family, ok := s.store.FindFamilyByTokenHash(hash)
	if !ok {
		return introspectionResponse{}, false
	}
	if !mayInspect(caller, family.ClientID, family.Resources) {
		return introspectionResponse{Active: false}, true
	}
	now := time.Now()
	active := !family.Revoked &&
		now.Before(family.AbsoluteExpiry) &&
		now.Before(family.IdleExpiry) &&
		string(hash) == string(family.CurrentHash)
	if !active {
		return introspectionResponse{Active: false}, true
	}
	return introspectionResponse{
		Active:    true,
		Scope:     oauth.FormatScope(family.Scope),
		ClientID:  family.ClientID,
		Subject:   "user:" + family.UserID,
		Audience:  family.Resources,
		ExpiresAt: family.AbsoluteExpiry.Unix(),
		TokenType: "refresh_token",
		Issuer:    s.cfg.Issuer,
	}, true
}

// localVerifier verifies our own tokens: signature, issuer, and time checks
// but no audience restriction, since introspection concerns tokens for any
// resource.
func (s *Server) localVerifier() *token.Verifier {
	return &token.Verifier{Issuer: s.cfg.Issuer, Keys: s.keys}
}
