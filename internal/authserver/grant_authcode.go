package authserver

import (
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// grantAuthorizationCode redeems a one-time authorization code (RFC 6749
// §4.1.3) with mandatory PKCE verification. A replayed code is treated as an
// attack: everything minted from its first redemption is revoked.
func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, client *store.Client) error {
	if !client.AllowsGrant(store.GrantAuthorizationCode) {
		return oauth.NewError(oauth.ErrUnauthorizedClient,
			"client is not registered for the authorization_code grant")
	}
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	redirectURI := r.PostForm.Get("redirect_uri")
	if code == "" || verifier == "" || redirectURI == "" {
		return oauth.NewError(oauth.ErrInvalidRequest,
			"code, code_verifier and redirect_uri are required")
	}

	codeHash := oauth.HashSecret(code)
	ac, result := s.store.ConsumeAuthCode(codeHash)
	switch result {
	case store.ConsumeNotFound:
		return oauth.NewError(oauth.ErrInvalidGrant, "authorization code is invalid or expired")
	case store.ConsumeReplayed:
		// Second redemption of the same code. Revoke every artifact the
		// first redemption produced (RFC 6749 §4.1.2 SHOULD; here: does).
		for _, jti := range ac.IssuedJTIs {
			s.store.RevokeToken(jti)
		}
		if ac.FamilyID != "" {
			s.store.RevokeFamily(ac.FamilyID, store.RevokedReasonAuthCode)
			s.store.RevokeFamilyTokens(ac.FamilyID)
		}
		s.log.WarnContext(r.Context(), "authorization code replay detected",
			slog.String("client_id", client.ID),
			slog.String("original_client_id", ac.ClientID),
			slog.Int("revoked_tokens", len(ac.IssuedJTIs)))
		return oauth.NewError(oauth.ErrInvalidGrant, "authorization code is invalid or expired")
	}

	// Binding checks: the code must be redeemed by the client it was issued
	// to, over the redirect URI it was issued for, with the PKCE verifier
	// matching the challenge from /authorize.
	if ac.ClientID != client.ID {
		return oauth.NewError(oauth.ErrInvalidGrant, "authorization code was issued to a different client")
	}
	if ac.RedirectURI != redirectURI {
		return oauth.NewError(oauth.ErrInvalidGrant, "redirect_uri does not match the authorization request")
	}
	if !oauth.VerifyS256(ac.CodeChallenge, verifier) {
		return oauth.NewError(oauth.ErrInvalidGrant, "PKCE verification failed")
	}

	// RFC 8707 §2.2: the token request may narrow the granted resources but
	// never add ones the user did not consent to.
	resources := ac.Resources
	if requested := r.PostForm["resource"]; len(requested) > 0 {
		narrowed, oerr := resolveResources(requested, client)
		if oerr != nil {
			return oerr
		}
		for _, res := range narrowed {
			if !contains(ac.Resources, res) {
				return oauth.NewError(oauth.ErrInvalidTarget,
					"resource %q was not part of the authorization grant", res)
			}
		}
		resources = narrowed
	}

	subject := "user:" + ac.UserID
	tok, claims, err := s.issuer.Issue(token.IssueParams{
		Subject:  subject,
		ClientID: client.ID,
		Audience: resources,
		Scope:    ac.Scope,
	})
	if err != nil {
		return err
	}

	refreshToken, family := s.newRefreshFamily(client.ID, ac.UserID, ac.Scope, resources)
	s.store.PutToken(&store.AccessTokenRecord{
		JTI:       claims.JTI,
		ClientID:  client.ID,
		Subject:   subject,
		Scope:     ac.Scope,
		Audience:  resources,
		ExpiresAt: timeFromUnix(claims.ExpiresAt),
		FamilyID:  family.ID,
	})
	s.store.RecordIssued(codeHash, []string{claims.JTI}, family.ID)

	writeTokenResponse(w, tokenResponse{
		AccessToken:  tok,
		TokenType:    "Bearer",
		ExpiresIn:    claims.ExpiresAt - claims.IssuedAt,
		Scope:        oauth.FormatScope(ac.Scope),
		RefreshToken: refreshToken,
	})
	return nil
}

// newRefreshFamily starts a rotation family and returns its first token.
func (s *Server) newRefreshFamily(clientID, userID string, scope, resources []string) (string, *store.RefreshTokenFamily) {
	refreshToken := oauth.NewToken()
	now := time.Now()
	family := &store.RefreshTokenFamily{
		ID:        oauth.NewToken(),
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		Resources: resources,
		Members: []store.RefreshTokenMember{{
			Hash:       oauth.HashSecret(refreshToken),
			Generation: 1,
			IssuedAt:   now,
		}},
		CurrentHash:    oauth.HashSecret(refreshToken),
		Generation:     1,
		IdleExpiry:     now.Add(s.cfg.RefreshIdleTTL),
		AbsoluteExpiry: now.Add(s.cfg.RefreshAbsoluteTTL),
	}
	s.store.PutFamily(family)
	return refreshToken, family
}

func contains(list []string, v string) bool {
	return slices.Contains(list, v)
}
