package authserver

import (
	"encoding/json"
	"net/http"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// serverMetadata is the RFC 8414 authorization server metadata document.
type serverMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	AuthorizationResponseIssSupported bool     `json:"authorization_response_iss_parameter_supported"`
	ServiceDocumentation              string   `json:"service_documentation,omitempty"`
}

// handleMetadata serves RFC 8414 discovery. Clients (including the demo
// agent) find every other endpoint through this document.
func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	iss := s.cfg.Issuer
	doc := serverMetadata{
		Issuer:                 iss,
		AuthorizationEndpoint:  iss + "/authorize",
		TokenEndpoint:          iss + "/token",
		JWKSURI:                iss + "/.well-known/jwks.json",
		RegistrationEndpoint:   iss + "/register",
		IntrospectionEndpoint:  iss + "/introspect",
		RevocationEndpoint:     iss + "/revoke",
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported: []string{
			store.GrantAuthorizationCode,
			store.GrantClientCredentials,
			store.GrantRefreshToken,
			store.GrantTokenExchange,
		},
		// S256 only: OAuth 2.1 requires PKCE and this server refuses the
		// downgrade-prone "plain" method.
		CodeChallengeMethodsSupported: []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{
			store.AuthMethodBasic,
			store.AuthMethodPost,
			store.AuthMethodNone,
		},
		ScopesSupported: s.cfg.Scopes,
		// RFC 9207: authorization responses carry an iss parameter.
		AuthorizationResponseIssSupported: true,
	}
	writeJSON(w, http.StatusOK, doc)
}

// handleJWKS publishes the verification keys (RFC 7517). Retired keys stay
// listed until tokens signed with them have expired.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	body, err := s.keys.JWKS()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	// Small positive cache: resource servers refresh on unknown kid anyway.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
