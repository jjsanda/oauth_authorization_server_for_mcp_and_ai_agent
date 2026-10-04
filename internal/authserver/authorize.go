package authserver

import (
	"net/http"
	"net/url"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// handleAuthorize validates an RFC 6749 §4.1.1 authorization request with
// the OAuth 2.1 hardenings: response_type=code only, PKCE with S256
// mandatory, exact redirect_uri matching, and RFC 8707 resource indicators
// required.
//
// Error handling follows §4.1.2.1 precisely: when the client identity or
// redirect URI cannot be trusted, the user gets a local error page and is
// never redirected; all later errors redirect back to the validated
// redirect_uri with error/state parameters.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	client, ok := s.store.GetClient(q.Get("client_id"))
	if !ok {
		s.renderErrorPage(w, http.StatusBadRequest, "Unknown application",
			"The application that sent you here is not registered with this authorization server.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !client.AllowsRedirectURI(redirectURI) {
		// Redirecting to an unregistered URI is how authorization codes get
		// stolen; show a dead-end page instead.
		s.renderErrorPage(w, http.StatusBadRequest, "Invalid redirect address",
			"The application supplied a return address that does not match its registration.")
		return
	}

	state := q.Get("state")
	fail := func(code, description string) {
		s.redirectAuthorizeError(w, r, redirectURI, state, code, description)
	}

	if q.Get("response_type") != "code" {
		fail(oauth.ErrUnsupportedResponseType, "only response_type=code is supported")
		return
	}
	if !client.AllowsGrant(store.GrantAuthorizationCode) {
		fail(oauth.ErrUnauthorizedClient, "client is not registered for the authorization_code grant")
		return
	}

	// PKCE is mandatory and S256-only (OAuth 2.1 §4.1.1, RFC 7636).
	challenge := q.Get("code_challenge")
	switch {
	case challenge == "":
		fail(oauth.ErrInvalidRequest, "PKCE is required: missing code_challenge")
		return
	case q.Get("code_challenge_method") != "S256":
		fail(oauth.ErrInvalidRequest, "code_challenge_method must be S256")
		return
	case !validChallenge(challenge):
		fail(oauth.ErrInvalidRequest, "malformed code_challenge")
		return
	}

	scopes, oerr := resolveScope(q.Get("scope"), client.Scopes)
	if oerr != nil {
		fail(oerr.Code, oerr.Description)
		return
	}
	resources, oerr := resolveResources(q["resource"], client)
	if oerr != nil {
		fail(oerr.Code, oerr.Description)
		return
	}

	reqID := s.pending.put(&pendingAuthorization{
		ClientID:      client.ID,
		ClientName:    client.Name,
		RedirectURI:   redirectURI,
		Scope:         scopes,
		Resources:     resources,
		State:         state,
		CodeChallenge: challenge,
	})

	if _, ok := s.sessions.fromRequest(r); ok {
		http.Redirect(w, r, "/consent?req="+url.QueryEscape(reqID), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login?req="+url.QueryEscape(reqID), http.StatusFound)
}

// validChallenge checks the S256 code_challenge shape: 43 base64url
// characters (the encoding of a SHA-256 digest).
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for _, ch := range []byte(c) {
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

// redirectAuthorizeError sends the §4.1.2.1 error response to the already
// validated redirect URI.
func (s *Server) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, "Invalid redirect address", "The return address could not be parsed.")
		return
	}
	qs := u.Query()
	qs.Set("error", code)
	qs.Set("error_description", description)
	if state != "" {
		qs.Set("state", state)
	}
	qs.Set("iss", s.cfg.Issuer) // RFC 9207
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redirectAuthorizeCode sends the success response: code, state, and the
// RFC 9207 iss parameter that lets clients detect authorization server mix-ups.
func (s *Server) redirectAuthorizeCode(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, "Internal error", "The return address could not be parsed.")
		return
	}
	qs := u.Query()
	qs.Set("code", code)
	if state != "" {
		qs.Set("state", state)
	}
	qs.Set("iss", s.cfg.Issuer)
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
