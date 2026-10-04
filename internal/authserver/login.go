package authserver

import (
	"log/slog"
	"net/http"
	"net/url"
)

type loginPageData struct {
	Title string
	ReqID string
	CSRF  string
	Error string
}

// handleLoginPage shows the sign-in form for a pending authorization
// request. Login is deliberately session-scoped and cookie-based; the
// original OAuth parameters stay parked server-side and never pass through
// the browser form.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	reqID := r.URL.Query().Get("req")
	if _, ok := s.pending.get(reqID); !ok {
		s.renderErrorPage(w, http.StatusBadRequest, "Request expired",
			"This sign-in link is no longer valid. Start again from the application.")
		return
	}
	nonce, cookie := s.sessions.loginGuard()
	http.SetCookie(w, cookie)
	s.renderPage(w, http.StatusOK, "login", loginPageData{Title: "Sign in", ReqID: reqID, CSRF: nonce})
}

// handleLoginSubmit verifies credentials and establishes the session.
// Failed attempts re-render the form with a uniform error message that does
// not reveal whether the username exists.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, "Malformed request", "The submitted form could not be read.")
		return
	}
	reqID := r.PostForm.Get("req")
	if _, ok := s.pending.get(reqID); !ok {
		s.renderErrorPage(w, http.StatusBadRequest, "Request expired",
			"This sign-in attempt is no longer valid. Start again from the application.")
		return
	}
	// Reject a login POST that did not originate from our own login page
	// (login CSRF / session fixation).
	if !s.sessions.verifyLoginGuard(r, r.PostForm.Get("csrf")) {
		s.renderErrorPage(w, http.StatusForbidden, "Invalid request",
			"This sign-in attempt could not be validated. Start again from the application.")
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	user, found := s.store.GetUserByUsername(username)
	if !found || !user.PasswordMatches(password) {
		s.log.WarnContext(r.Context(), "login failed", slog.String("username", username))
		nonce, cookie := s.sessions.loginGuard()
		http.SetCookie(w, cookie)
		s.renderPage(w, http.StatusUnauthorized, "login", loginPageData{
			Title: "Sign in", ReqID: reqID, CSRF: nonce, Error: "Incorrect username or password.",
		})
		return
	}

	_, cookie := s.sessions.create(user.ID)
	http.SetCookie(w, cookie)
	s.log.InfoContext(r.Context(), "login succeeded", slog.String("user_id", user.ID))
	http.Redirect(w, r, "/consent?req="+url.QueryEscape(reqID), http.StatusFound)
}
