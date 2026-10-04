package authserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// RFC 8693 token type identifiers.
const (
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // G101: this is a public token-type identifier, not a credential
)

// grantTokenExchange implements RFC 8693 delegation: a confidential client
// presents a valid access token and receives a new one for a different,
// explicitly named audience. The new token keeps the original subject and
// records the exchanging client in the act claim, so the downstream service
// sees both who the request is for and who is making it.
//
// This is the alternative to the token-passthrough anti-pattern: the
// original token never leaves its audience, privileges can only narrow, and
// the delegation chain is visible and auditable.
func (s *Server) grantTokenExchange(w http.ResponseWriter, r *http.Request, client *store.Client) error {
	if !client.AllowsGrant(store.GrantTokenExchange) {
		return oauth.NewError(oauth.ErrUnauthorizedClient,
			"client is not registered for the token-exchange grant")
	}
	if client.Public() {
		return oauth.NewError(oauth.ErrUnauthorizedClient,
			"token exchange requires a confidential client")
	}

	if st := r.PostForm.Get("subject_token_type"); st != tokenTypeAccessToken {
		return oauth.NewError(oauth.ErrInvalidRequest,
			"subject_token_type must be %s", tokenTypeAccessToken)
	}
	if rt := r.PostForm.Get("requested_token_type"); rt != "" && rt != tokenTypeAccessToken {
		return oauth.NewError(oauth.ErrInvalidRequest,
			"only %s can be issued", tokenTypeAccessToken)
	}
	if r.PostForm.Get("actor_token") != "" {
		return oauth.NewError(oauth.ErrInvalidRequest,
			"actor_token is not supported: the authenticated client is the actor")
	}

	subjectToken := r.PostForm.Get("subject_token")
	if subjectToken == "" {
		return oauth.NewError(oauth.ErrInvalidRequest, "subject_token is required")
	}
	claims, err := s.localVerifier().Verify(subjectToken)
	if err != nil {
		return oauth.NewError(oauth.ErrInvalidGrant, "subject_token is not a valid access token")
	}
	rec, ok := s.store.GetToken(claims.JTI)
	if !ok || rec.Revoked || time.Now().After(rec.ExpiresAt) {
		return oauth.NewError(oauth.ErrInvalidGrant, "subject_token has been revoked or expired")
	}

	// The exchanging client must be entitled to the subject token: either it
	// is the client the token was issued to, or it is (registered for) one of
	// the token's audiences — the resource-server-initiated exchange. Without
	// this check any client registered for the exchange grant could retarget
	// a user token it merely came into contact with, which is exactly the
	// confused-deputy escalation token exchange is meant to prevent.
	if !clientEntitledToSubject(client, claims) {
		return oauth.NewError(oauth.ErrInvalidGrant,
			"client is not entitled to exchange this token")
	}

	// The new audience must be explicit and allowed for the exchanging
	// client; there is no implicit inheritance of the subject token's
	// audience.
	resources, oerr := resolveResources(r.PostForm["resource"], client)
	if oerr != nil {
		return oerr
	}

	// Privileges only narrow: the exchanged token's scope is bounded by both
	// the subject token's scope and what the exchanging client may ever hold.
	ceiling := intersectScopes(claims.Scopes(), client.Scopes)
	scopes, oerr := resolveScope(r.PostForm.Get("scope"), ceiling)
	if oerr != nil {
		return oerr
	}

	actor := "client:" + client.ID
	tok, newClaims, err := s.issuer.Issue(token.IssueParams{
		Subject:  claims.Subject, // the original subject is preserved
		ClientID: client.ID,
		Audience: resources,
		Scope:    scopes,
		ActorSub: actor,
	})
	if err != nil {
		return err
	}
	// The exchanged token inherits the subject token's refresh family (when
	// there is one), so a family revocation — e.g. after refresh token theft
	// — also cascades to everything exchanged from its access tokens.
	s.store.PutToken(&store.AccessTokenRecord{
		JTI:       newClaims.JTI,
		ClientID:  client.ID,
		Subject:   claims.Subject,
		Scope:     scopes,
		Audience:  resources,
		ExpiresAt: timeFromUnix(newClaims.ExpiresAt),
		FamilyID:  rec.FamilyID,
	})
	s.log.InfoContext(r.Context(), "token exchanged",
		slog.String("actor", actor),
		slog.String("subject", claims.Subject),
		slog.Any("new_audience", resources),
		slog.String("subject_jti", claims.JTI),
		slog.String("new_jti", newClaims.JTI))

	// RFC 8693 §2.2.1: no refresh token on exchange responses.
	writeTokenResponse(w, tokenResponse{
		AccessToken:     tok,
		TokenType:       "Bearer",
		ExpiresIn:       newClaims.ExpiresAt - newClaims.IssuedAt,
		Scope:           oauth.FormatScope(scopes),
		IssuedTokenType: tokenTypeAccessToken,
	})
	return nil
}

// clientEntitledToSubject reports whether client may exchange the given
// subject token: it must be the client the token was issued to, or be
// registered for one of the token's audiences (a resource server exchanging
// a token that was presented to it).
func clientEntitledToSubject(client *store.Client, claims *token.Claims) bool {
	if claims.ClientID == client.ID {
		return true
	}
	for _, aud := range claims.Audience {
		if client.AllowsResource(aud) {
			return true
		}
	}
	return false
}

// intersectScopes returns the scopes present in both lists, preserving the
// order of the first.
func intersectScopes(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if inB[s] {
			out = append(out, s)
		}
	}
	return out
}
