// Package authserver implements an OAuth 2.1 authorization server:
// authorization code with mandatory PKCE, client credentials, refresh token
// rotation, and RFC 8693 token exchange, together with server metadata
// (RFC 8414), dynamic client registration (RFC 7591), token introspection
// (RFC 7662), and revocation (RFC 7009). Access tokens are RFC 9068 JWTs
// audience-restricted with RFC 8707 resource indicators.
package authserver

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/httpx"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// Config carries the deployment-specific knobs of the authorization server.
type Config struct {
	// Issuer is the server's public base URL and the "iss" claim of every
	// token it signs.
	Issuer string
	// Scopes is the full set of scopes this deployment knows about,
	// advertised in the server metadata.
	Scopes []string
	// Resources is the registry of RFC 8707 resource identifiers this
	// deployment fronts. Dynamically registered clients may only be
	// provisioned for resources in this list.
	Resources []string
	// AccessTokenTTL bounds access token lifetime (default 5m).
	AccessTokenTTL time.Duration
	// AuthCodeTTL bounds authorization code lifetime (default 60s).
	AuthCodeTTL time.Duration
	// RefreshIdleTTL is how long a refresh token generation stays
	// redeemable without being used (default 8h, extended on each rotation).
	RefreshIdleTTL time.Duration
	// RefreshAbsoluteTTL caps a refresh family's total lifetime regardless
	// of activity (default 30 days).
	RefreshAbsoluteTTL time.Duration
	// SessionTTL bounds the browser login session (default 1h).
	SessionTTL time.Duration
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.AccessTokenTTL == 0 {
		out.AccessTokenTTL = token.DefaultAccessTokenTTL
	}
	if out.AuthCodeTTL == 0 {
		out.AuthCodeTTL = 60 * time.Second
	}
	if out.RefreshIdleTTL == 0 {
		out.RefreshIdleTTL = 8 * time.Hour
	}
	if out.RefreshAbsoluteTTL == 0 {
		out.RefreshAbsoluteTTL = 30 * 24 * time.Hour
	}
	if out.SessionTTL == 0 {
		out.SessionTTL = time.Hour
	}
	if len(out.Scopes) == 0 {
		out.Scopes = []string{"tools:read", "tools:invoke", "reports:read"}
	}
	return out
}

// Server is the authorization server. Wire it into an *http.Server (or an
// httptest.Server) via Routes.
type Server struct {
	cfg    Config
	store  store.Store
	keys   *jose.KeySet
	issuer *token.Issuer
	log    *slog.Logger

	sessions *sessionManager
	pending  *pendingAuthorizations
}

// New assembles a Server around a store and signing key set.
func New(cfg Config, st store.Store, keys *jose.KeySet, log *slog.Logger) *Server {
	cfg = cfg.withDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:   cfg,
		store: st,
		keys:  keys,
		issuer: &token.Issuer{
			Issuer: cfg.Issuer,
			Keys:   keys,
			TTL:    cfg.AccessTokenTTL,
		},
		log: log,
		// Mark session cookies Secure whenever the issuer is served over
		// https, so they are never sent in cleartext in a real deployment
		// (the localhost demo runs over http).
		sessions: newSessionManager(cfg.SessionTTL, strings.HasPrefix(cfg.Issuer, "https://")),
		pending:  newPendingAuthorizations(10 * time.Minute),
	}
}

// Routes returns the full handler tree with middleware applied.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("GET /consent", s.handleConsentPage)
	mux.HandleFunc("POST /consent", s.handleConsentSubmit)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("POST /revoke", s.handleRevoke)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return httpx.Chain(mux,
		httpx.Recover,
		httpx.RequestID,
		httpx.WithLogger(s.log),
		httpx.AccessLog,
		httpx.SecureHeaders,
	)
}
