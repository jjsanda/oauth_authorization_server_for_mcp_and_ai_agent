// Package resourceserver implements an OAuth 2.0 protected resource that
// follows the Model Context Protocol authorization pattern: it publishes
// RFC 9728 protected-resource metadata so clients can discover its
// authorization server, validates RFC 9068 JWT access tokens locally against
// the authorization server's JWKS, enforces RFC 8707 audience restriction,
// and serves a small set of JSON-RPC 2.0 tools.
package resourceserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/httpx"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// Config carries one resource server instance's identity and policy. The
// same binary runs as "tools-api" and "reports-api" in the demo deployment,
// differing only in this configuration.
type Config struct {
	// Resource is this server's RFC 8707 resource identifier — the value
	// access tokens must carry in their aud claim.
	Resource string
	// Issuer is the sole authorization server whose tokens are accepted.
	Issuer string
	// ScopeList is the scope required to list tools.
	ScopeList string
	// ScopeCall is the scope required to invoke a tool.
	ScopeCall string
	// ScopesSupported is advertised in the protected-resource metadata.
	ScopesSupported []string
	// JWKSRefreshTTL is how long fetched keys are trusted before a lazy
	// refresh (default 5m).
	JWKSRefreshTTL time.Duration
	// JWKSMinRefreshInterval rate-limits refreshes triggered by unknown
	// kids so unverifiable garbage tokens cannot make this server hammer
	// the authorization server (default 10s).
	JWKSMinRefreshInterval time.Duration
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.ScopeList == "" {
		out.ScopeList = "tools:read"
	}
	if out.ScopeCall == "" {
		out.ScopeCall = "tools:invoke"
	}
	if len(out.ScopesSupported) == 0 {
		out.ScopesSupported = []string{out.ScopeList, out.ScopeCall}
	}
	if out.JWKSRefreshTTL == 0 {
		out.JWKSRefreshTTL = 5 * time.Minute
	}
	if out.JWKSMinRefreshInterval == 0 {
		out.JWKSMinRefreshInterval = 10 * time.Second
	}
	return out
}

// Server is one protected resource instance.
type Server struct {
	cfg      Config
	verifier *token.Verifier
	log      *slog.Logger
}

// New assembles a resource server that discovers and caches the
// authorization server's keys via its RFC 8414 metadata.
func New(cfg Config, log *slog.Logger) *Server {
	cfg = cfg.withDefaults()
	if log == nil {
		log = slog.Default()
	}
	keys := newJWKSClient(cfg.Issuer, cfg.JWKSRefreshTTL, cfg.JWKSMinRefreshInterval, log)
	return &Server{
		cfg: cfg,
		verifier: &token.Verifier{
			Issuer:   cfg.Issuer,
			Keys:     keys,
			Audience: cfg.Resource,
		},
		log: log,
	}
}

// Routes returns the handler tree with middleware applied.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleMetadata)
	mux.Handle("POST /mcp", s.requireAuth(http.HandlerFunc(s.handleRPC)))
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
