package authserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
)

const (
	sessionCookieName    = "as_session"
	loginGuardCookieName = "as_login"
)

// session is a logged-in browser session. State lives server-side; the
// cookie carries only an HMAC-signed random ID, so it can neither be forged
// nor decoded.
type session struct {
	ID        string
	UserID    string
	CSRF      string // per-session token embedded in login/consent forms
	ExpiresAt time.Time
}

type sessionManager struct {
	key    []byte // HMAC key, generated at startup; sessions do not survive restarts
	ttl    time.Duration
	secure bool // set the Secure cookie attribute (issuer served over https)

	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionManager(ttl time.Duration, secure bool) *sessionManager {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("authserver: crypto/rand unavailable: " + err.Error())
	}
	return &sessionManager{key: key, ttl: ttl, secure: secure, sessions: make(map[string]*session)}
}

func (m *sessionManager) sign(id string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// create starts a session for a user and returns it with its cookie.
func (m *sessionManager) create(userID string) (*session, *http.Cookie) {
	now := time.Now()
	s := &session{
		ID:        oauth.NewToken(),
		UserID:    userID,
		CSRF:      oauth.NewToken(),
		ExpiresAt: now.Add(m.ttl),
	}
	m.mu.Lock()
	// Opportunistically evict expired sessions so abandoned logins do not
	// accumulate for the life of the process.
	for id, sess := range m.sessions {
		if now.After(sess.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
	m.sessions[s.ID] = s
	m.mu.Unlock()
	return s, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.ID + "." + m.sign(s.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl / time.Second),
	}
}

// loginGuard issues a pre-login CSRF token: a random nonce returned both as
// an HttpOnly cookie and for embedding in the login form. Because an attacker
// cannot set this cookie in the victim's browser, requiring the form value to
// match the cookie defeats login CSRF (forcing a victim to submit the
// attacker's credentials).
func (m *sessionManager) loginGuard() (nonce string, cookie *http.Cookie) {
	nonce = oauth.NewToken()
	return nonce, &http.Cookie{
		Name:     loginGuardCookieName,
		Value:    nonce + "." + m.sign(nonce),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl / time.Second),
	}
}

// verifyLoginGuard checks that the login form's CSRF value matches the signed
// pre-login cookie.
func (m *sessionManager) verifyLoginGuard(r *http.Request, formValue string) bool {
	c, err := r.Cookie(loginGuardCookieName)
	if err != nil {
		return false
	}
	nonce, sig, found := strings.Cut(c.Value, ".")
	if !found || !hmac.Equal([]byte(sig), []byte(m.sign(nonce))) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(nonce), []byte(formValue)) == 1
}

// fromRequest resolves and validates the session cookie.
func (m *sessionManager) fromRequest(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	id, sig, found := strings.Cut(c.Value, ".")
	if !found || !hmac.Equal([]byte(sig), []byte(m.sign(id))) {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || time.Now().After(s.ExpiresAt) {
		delete(m.sessions, id)
		return nil, false
	}
	return s, true
}
