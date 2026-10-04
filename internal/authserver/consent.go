package authserver

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

type consentPageData struct {
	Title      string
	ReqID      string
	CSRF       string
	ClientName string
	Username   string
	Scopes     []string
	Resources  []string
}

// handleConsentPage shows what the client is asking for. The form carries a
// CSRF token bound to the login session so consent cannot be forged
// cross-site.
func (s *Server) handleConsentPage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.fromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login?req="+url.QueryEscape(r.URL.Query().Get("req")), http.StatusFound)
		return
	}
	req, ok := s.pending.get(r.URL.Query().Get("req"))
	if !ok {
		s.renderErrorPage(w, http.StatusBadRequest, "Request expired",
			"This authorization request is no longer valid. Start again from the application.")
		return
	}
	user, ok := s.store.GetUser(sess.UserID)
	if !ok {
		// The session outlived its user record; treat as an expired session.
		http.Redirect(w, r, "/login?req="+url.QueryEscape(req.ID), http.StatusFound)
		return
	}
	name := req.ClientName
	if name == "" {
		name = req.ClientID
	}
	s.renderPage(w, http.StatusOK, "consent", consentPageData{
		Title:      "Authorize " + name,
		ReqID:      req.ID,
		CSRF:       sess.CSRF,
		ClientName: name,
		Username:   user.Username,
		Scopes:     req.Scope,
		Resources:  req.Resources,
	})
}

// handleConsentSubmit turns an approval into a one-time authorization code
// bound to the user, client, redirect URI, scope, resources, and PKCE
// challenge of the pending request.
func (s *Server) handleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.fromRequest(r)
	if !ok {
		s.renderErrorPage(w, http.StatusForbidden, "Not signed in", "Your session has expired. Start again from the application.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, "Malformed request", "The submitted form could not be read.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(sess.CSRF)) != 1 {
		s.renderErrorPage(w, http.StatusForbidden, "Invalid request", "The consent form could not be validated. Start again from the application.")
		return
	}
	// Consume: each authorization request yields at most one decision.
	req, ok := s.pending.consume(r.PostForm.Get("req"))
	if !ok {
		s.renderErrorPage(w, http.StatusBadRequest, "Request expired",
			"This authorization request is no longer valid. Start again from the application.")
		return
	}

	if r.PostForm.Get("action") != "approve" {
		s.log.InfoContext(r.Context(), "consent denied",
			slog.String("client_id", req.ClientID), slog.String("user_id", sess.UserID))
		s.redirectAuthorizeError(w, r, req.RedirectURI, req.State,
			oauth.ErrAccessDenied, "the resource owner denied the request")
		return
	}

	code := oauth.NewToken()
	s.store.PutAuthCode(&store.AuthCode{
		CodeHash:      oauth.HashSecret(code),
		ClientID:      req.ClientID,
		UserID:        sess.UserID,
		RedirectURI:   req.RedirectURI,
		Scope:         req.Scope,
		Resources:     req.Resources,
		CodeChallenge: req.CodeChallenge,
		ExpiresAt:     time.Now().Add(s.cfg.AuthCodeTTL),
	})
	s.log.InfoContext(r.Context(), "consent granted",
		slog.String("client_id", req.ClientID),
		slog.String("user_id", sess.UserID),
		slog.Any("scope", req.Scope),
		slog.Any("resources", req.Resources))
	s.redirectAuthorizeCode(w, r, req.RedirectURI, req.State, code)
}
