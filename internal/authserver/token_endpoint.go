package authserver

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

func timeFromUnix(sec int64) time.Time { return time.Unix(sec, 0) }

// tokenResponse is the RFC 6749 §5.1 success document, extended with the
// RFC 8693 issued_token_type member for token-exchange responses.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

func writeTokenResponse(w http.ResponseWriter, resp tokenResponse) {
	// RFC 6749 §5.1: token responses must not be cached anywhere.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

// handleToken dispatches POST /token by grant_type after authenticating the
// client.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRequest, "malformed form body"))
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		s.logGrant(r, "", "unknown", err)
		oauth.WriteError(w, err)
		return
	}

	grantType := r.PostForm.Get("grant_type")
	var oerr error
	switch grantType {
	case store.GrantClientCredentials:
		oerr = s.grantClientCredentials(w, r, client)
	case store.GrantAuthorizationCode:
		oerr = s.grantAuthorizationCode(w, r, client)
	case store.GrantRefreshToken:
		oerr = s.grantRefreshToken(w, r, client)
	case store.GrantTokenExchange:
		oerr = s.grantTokenExchange(w, r, client)
	case "":
		oerr = oauth.NewError(oauth.ErrInvalidRequest, "grant_type is required")
	default:
		oerr = oauth.NewError(oauth.ErrUnsupportedGrantType, "grant type %q is not supported", grantType)
	}
	s.logGrant(r, client.ID, grantType, oerr)
	if oerr != nil {
		oauth.WriteError(w, oerr)
	}
}

// logGrant emits one structured, auditable line per token-endpoint decision.
func (s *Server) logGrant(r *http.Request, clientID, grantType string, err error) {
	attrs := []any{
		slog.String("endpoint", "token"),
		slog.String("grant_type", grantType),
		slog.String("client_id", clientID),
	}
	if err != nil {
		oe := oauth.AsError(err)
		s.log.WarnContext(r.Context(), "grant denied", append(attrs,
			slog.String("outcome", "denied"),
			slog.String("error", oe.Code),
			slog.String("detail", oe.Description))...)
		return
	}
	s.log.InfoContext(r.Context(), "grant issued", append(attrs, slog.String("outcome", "granted"))...)
}

// authenticateClient implements token-endpoint client authentication for
// client_secret_basic, client_secret_post, and public ("none") clients.
// The client must use exactly the method it registered with, and never more
// than one method per request (RFC 6749 §2.3).
func (s *Server) authenticateClient(r *http.Request) (*store.Client, *oauth.Error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	formID := r.PostForm.Get("client_id")
	formSecret := r.PostForm.Get("client_secret")

	// RFC 6749 §2.3: a client must not use more than one authentication
	// mechanism. Reject Basic combined with either a form secret or a form
	// client_id.
	if hasBasic && (formSecret != "" || formID != "") {
		return nil, oauth.NewError(oauth.ErrInvalidRequest, "multiple client authentication methods used")
	}

	var clientID, secret, method string
	switch {
	case hasBasic:
		// RFC 6749 §2.3.1: Basic credentials are form-urlencoded before
		// being base64-encoded.
		var err error
		clientID, err = url.QueryUnescape(basicID)
		if err != nil {
			return nil, oauth.NewError(oauth.ErrInvalidClient, "malformed basic credentials")
		}
		secret, err = url.QueryUnescape(basicSecret)
		if err != nil {
			return nil, oauth.NewError(oauth.ErrInvalidClient, "malformed basic credentials")
		}
		method = store.AuthMethodBasic
	case formSecret != "":
		clientID, secret = formID, formSecret
		method = store.AuthMethodPost
	case formID != "":
		clientID, method = formID, store.AuthMethodNone
	default:
		return nil, oauth.NewError(oauth.ErrInvalidClient, "no client authentication provided")
	}

	client, ok := s.store.GetClient(clientID)
	if !ok {
		return nil, oauth.NewError(oauth.ErrInvalidClient, "unknown client")
	}
	if client.TokenEndpointAuth != method {
		return nil, oauth.NewError(oauth.ErrInvalidClient,
			"client must authenticate with %s", client.TokenEndpointAuth)
	}
	if !client.Public() && !oauth.SecretEqual(client.SecretHash, secret) {
		return nil, oauth.NewError(oauth.ErrInvalidClient, "client authentication failed")
	}
	return client, nil
}

// resolveResources validates the RFC 8707 resource parameters of a token
// request. This server takes the strict stance the MCP authorization spec
// requires: every token must name at least one resource, each must be a
// syntactically valid resource identifier, and the client must be allowed to
// request it. Tokens therefore can never be redeemed at a server they were
// not minted for.
func resolveResources(values []string, client *store.Client) ([]string, *oauth.Error) {
	if len(values) == 0 {
		return nil, oauth.NewError(oauth.ErrInvalidTarget,
			"a resource parameter is required (RFC 8707)")
	}
	seen := make(map[string]bool)
	var out []string
	for _, v := range values {
		u, err := url.Parse(v)
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			return nil, oauth.NewError(oauth.ErrInvalidTarget,
				"resource must be an absolute URI without a fragment")
		}
		if !client.AllowsResource(v) {
			return nil, oauth.NewError(oauth.ErrInvalidTarget,
				"client is not allowed to request tokens for %q", v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

// resolveScope applies the RFC 6749 §3.3 scope rules: an omitted scope
// defaults to the ceiling; a requested scope must be a subset of it.
func resolveScope(requested string, ceiling []string) ([]string, *oauth.Error) {
	if requested == "" {
		return ceiling, nil
	}
	scopes := oauth.ParseScope(requested)
	if !oauth.ScopeIsSubset(scopes, ceiling) {
		return nil, oauth.NewError(oauth.ErrInvalidScope,
			"requested scope exceeds what the client may be granted")
	}
	return scopes, nil
}
