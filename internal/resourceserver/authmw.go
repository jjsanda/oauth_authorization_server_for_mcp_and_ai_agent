package resourceserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

type claimsKey struct{}

// ClaimsFrom returns the verified token claims stored by requireAuth.
func ClaimsFrom(ctx context.Context) *token.Claims {
	c, _ := ctx.Value(claimsKey{}).(*token.Claims)
	return c
}

// metadataURL is where this server's RFC 9728 document lives; 401 responses
// point clients here so they can discover the authorization server — the
// exact mechanism the MCP authorization spec builds on.
func (s *Server) metadataURL() string {
	return s.cfg.Resource + "/.well-known/oauth-protected-resource"
}

// challenge writes a 401 with an RFC 6750 §3 Bearer challenge carrying the
// RFC 9728 resource_metadata pointer. errCode is empty when the request
// simply lacked credentials (the spec forbids an error code in that case).
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, errCode, description string) {
	value := fmt.Sprintf("Bearer resource_metadata=%q", s.metadataURL())
	if errCode != "" {
		value += fmt.Sprintf(", error=%q, error_description=%q", errCode, description)
	}
	w.Header().Set("WWW-Authenticate", value)
	s.log.InfoContext(r.Context(), "request rejected",
		slog.String("outcome", "unauthorized"),
		slog.String("error", errCode))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// requireAuth extracts and verifies the bearer token, enforcing issuer,
// signature, expiry, and — critically — that this server's identifier is in
// the token's audience, so a token minted for another resource server can
// never be redeemed here (RFC 8707).
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			s.challenge(w, r, "", "")
			return
		}
		scheme, raw, found := strings.Cut(auth, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || raw == "" {
			s.challenge(w, r, "invalid_request", "authorization header must be a bearer token")
			return
		}
		claims, err := s.verifier.Verify(raw)
		if err != nil {
			// The uniform error string avoids oracle behavior; details go to
			// the server log only.
			s.log.WarnContext(r.Context(), "token rejected", slog.String("reason", err.Error()))
			s.challenge(w, r, "invalid_token", "token verification failed")
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireScope enforces a scope on an already-authenticated request,
// answering 403 insufficient_scope with the needed scope per RFC 6750 §3.1.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope string) bool {
	claims := ClaimsFrom(r.Context())
	if claims != nil && claims.HasScope(scope) {
		return true
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		"Bearer resource_metadata=%q, error=%q, scope=%q", s.metadataURL(), "insufficient_scope", scope))
	s.log.InfoContext(r.Context(), "request rejected",
		slog.String("outcome", "forbidden"),
		slog.String("missing_scope", scope))
	http.Error(w, "insufficient scope", http.StatusForbidden)
	return false
}
