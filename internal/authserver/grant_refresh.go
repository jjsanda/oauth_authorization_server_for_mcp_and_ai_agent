package authserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// grantRefreshToken implements refresh with rotation (OAuth 2.1 §4.3): every
// redemption retires the presented token and issues a new one in the same
// family. Presenting a retired token is treated as theft: the store revokes
// the family and all of its access tokens atomically, and both the original
// holder and the thief lose access.
func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request, client *store.Client) error {
	if !client.AllowsGrant(store.GrantRefreshToken) {
		return oauth.NewError(oauth.ErrUnauthorizedClient,
			"client is not registered for the refresh_token grant")
	}
	presented := r.PostForm.Get("refresh_token")
	if presented == "" {
		return oauth.NewError(oauth.ErrInvalidRequest, "refresh_token is required")
	}
	presentedHash := oauth.HashSecret(presented)

	// Ownership check before any state transition: a different client
	// presenting a (stolen) refresh token must not trigger a rotation.
	owner, ok := s.store.FindFamilyByTokenHash(presentedHash)
	if !ok {
		return oauth.NewError(oauth.ErrInvalidGrant, "refresh token is invalid or expired")
	}
	if owner.ClientID != client.ID {
		s.log.WarnContext(r.Context(), "refresh token presented by wrong client",
			slog.String("presenting_client", client.ID),
			slog.String("owning_client", owner.ClientID))
		return oauth.NewError(oauth.ErrInvalidGrant, "refresh token is invalid or expired")
	}

	// Validate scope and resources against the family snapshot BEFORE
	// rotating. Rotating first and rejecting afterwards would retire the
	// presented token on a malformed request, so the client's next
	// legitimate refresh would look like a replay and needlessly revoke the
	// whole family. Scope and resources may only narrow the original grant.
	scopes, oerr := resolveScope(r.PostForm.Get("scope"), owner.Scope)
	if oerr != nil {
		return oerr
	}
	resources := owner.Resources
	if requested := r.PostForm["resource"]; len(requested) > 0 {
		narrowed, oerr := resolveResources(requested, client)
		if oerr != nil {
			return oerr
		}
		for _, res := range narrowed {
			if !contains(owner.Resources, res) {
				return oauth.NewError(oauth.ErrInvalidTarget,
					"resource %q was not part of the original grant", res)
			}
		}
		resources = narrowed
	}

	next := oauth.NewToken()
	family, status := s.store.Redeem(presentedHash, oauth.HashSecret(next), time.Now(), s.cfg.RefreshIdleTTL)
	switch status {
	case store.RedeemOK:
		// fall through to issuance
	case store.RedeemReused:
		s.log.WarnContext(r.Context(), "refresh token reuse detected — family revoked",
			slog.String("client_id", client.ID),
			slog.String("family_id", family.ID),
			slog.Int("generation", family.Generation))
		return oauth.NewError(oauth.ErrInvalidGrant, "refresh token is invalid or expired")
	default:
		return oauth.NewError(oauth.ErrInvalidGrant, "refresh token is invalid or expired")
	}

	subject := "user:" + family.UserID
	tok, claims, err := s.issuer.Issue(token.IssueParams{
		Subject:  subject,
		ClientID: client.ID,
		Audience: resources,
		Scope:    scopes,
	})
	if err != nil {
		return err
	}
	s.store.PutToken(&store.AccessTokenRecord{
		JTI:       claims.JTI,
		ClientID:  client.ID,
		Subject:   subject,
		Scope:     scopes,
		Audience:  resources,
		ExpiresAt: timeFromUnix(claims.ExpiresAt),
		FamilyID:  family.ID,
	})

	writeTokenResponse(w, tokenResponse{
		AccessToken:  tok,
		TokenType:    "Bearer",
		ExpiresIn:    claims.ExpiresAt - claims.IssuedAt,
		Scope:        oauth.FormatScope(scopes),
		RefreshToken: next,
	})
	return nil
}
