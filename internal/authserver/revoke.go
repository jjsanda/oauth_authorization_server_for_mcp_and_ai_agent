package authserver

import (
	"log/slog"
	"net/http"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// handleRevoke implements RFC 7009. Revoking a refresh token kills its whole
// rotation family and every access token minted through it. Per §2.2 the
// endpoint answers 200 even for unknown tokens and for tokens belonging to
// other clients (after doing nothing), so it cannot be used as an oracle.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRequest, "malformed form body"))
		return
	}
	caller, oerr := s.authenticateClient(r)
	if oerr != nil {
		oauth.WriteError(w, oerr)
		return
	}
	presented := r.PostForm.Get("token")
	if presented == "" {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRequest, "token is required"))
		return
	}

	switch {
	case s.revokeAccessToken(r, presented, caller):
	case s.revokeRefreshToken(r, presented, caller):
	default:
		// Unknown token: nothing to do, still 200.
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) revokeAccessToken(r *http.Request, presented string, caller *store.Client) bool {
	claims, err := s.localVerifier().Verify(presented)
	if err != nil {
		return false
	}
	rec, ok := s.store.GetToken(claims.JTI)
	if !ok {
		return false
	}
	if rec.ClientID != caller.ID {
		// Not the caller's token: pretend success, change nothing.
		s.log.WarnContext(r.Context(), "revocation of foreign token ignored",
			slog.String("caller", caller.ID), slog.String("token_client", rec.ClientID))
		return true
	}
	s.store.RevokeToken(claims.JTI)
	s.log.InfoContext(r.Context(), "access token revoked",
		slog.String("client_id", caller.ID), slog.String("jti", claims.JTI))
	return true
}

func (s *Server) revokeRefreshToken(r *http.Request, presented string, caller *store.Client) bool {
	family, ok := s.store.FindFamilyByTokenHash(oauth.HashSecret(presented))
	if !ok {
		return false
	}
	if family.ClientID != caller.ID {
		s.log.WarnContext(r.Context(), "revocation of foreign refresh token ignored",
			slog.String("caller", caller.ID), slog.String("token_client", family.ClientID))
		return true
	}
	s.store.RevokeFamily(family.ID, store.RevokedReasonClient)
	n := s.store.RevokeFamilyTokens(family.ID)
	s.log.InfoContext(r.Context(), "refresh token family revoked",
		slog.String("client_id", caller.ID),
		slog.String("family_id", family.ID),
		slog.Int("access_tokens_revoked", n))
	return true
}
