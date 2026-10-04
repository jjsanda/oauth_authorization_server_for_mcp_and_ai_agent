package authserver

import (
	"net/http"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// grantClientCredentials implements RFC 6749 §4.4 for machine-to-machine
// clients. No refresh token is issued: the client can simply authenticate
// again (OAuth 2.1 §4.3.3).
func (s *Server) grantClientCredentials(w http.ResponseWriter, r *http.Request, client *store.Client) error {
	if client.Public() {
		return oauth.NewError(oauth.ErrUnauthorizedClient,
			"public clients cannot use the client_credentials grant")
	}
	if !client.AllowsGrant(store.GrantClientCredentials) {
		return oauth.NewError(oauth.ErrUnauthorizedClient,
			"client is not registered for the client_credentials grant")
	}
	resources, oerr := resolveResources(r.PostForm["resource"], client)
	if oerr != nil {
		return oerr
	}
	scopes, oerr := resolveScope(r.PostForm.Get("scope"), client.Scopes)
	if oerr != nil {
		return oerr
	}

	subject := "client:" + client.ID
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
	})

	writeTokenResponse(w, tokenResponse{
		AccessToken: tok,
		TokenType:   "Bearer",
		ExpiresIn:   claims.ExpiresAt - claims.IssuedAt,
		Scope:       oauth.FormatScope(scopes),
	})
	return nil
}
