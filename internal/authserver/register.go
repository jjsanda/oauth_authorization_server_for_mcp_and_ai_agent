package authserver

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// registrationRequest is the RFC 7591 client metadata this server accepts.
// "resources" is an extension member (RFC 7591 §2 allows them) declaring
// which RFC 8707 resource identifiers the client intends to request tokens
// for; it must stay within this deployment's registry.
type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	Resources               []string `json:"resources"`
}

// registrationResponse echoes the registered metadata plus the issued
// credentials (RFC 7591 §3.2.1).
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	Resources               []string `json:"resources"`
}

var supportedGrantTypes = map[string]bool{
	store.GrantAuthorizationCode: true,
	store.GrantClientCredentials: true,
	store.GrantRefreshToken:      true,
	store.GrantTokenExchange:     true,
}

var supportedAuthMethods = map[string]bool{
	store.AuthMethodBasic: true,
	store.AuthMethodPost:  true,
	store.AuthMethodNone:  true,
}

// handleRegister implements open dynamic client registration (RFC 7591).
// Registration is anonymous by design here — the MCP pattern expects agents
// to self-register — and every registered client is still constrained by
// scope, resource, and grant validation on each later request. A production
// deployment would additionally gate this endpoint with initial access
// tokens or software statements.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidClientMetadata, "request body must be a JSON client metadata document"))
		return
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{store.GrantAuthorizationCode}
	}
	for _, gt := range req.GrantTypes {
		if !supportedGrantTypes[gt] {
			oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidClientMetadata, "unsupported grant type %q", gt))
			return
		}
	}

	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = store.AuthMethodBasic
	}
	if !supportedAuthMethods[req.TokenEndpointAuthMethod] {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidClientMetadata,
			"unsupported token_endpoint_auth_method %q", req.TokenEndpointAuthMethod))
		return
	}

	needsRedirects := false
	for _, gt := range req.GrantTypes {
		if gt == store.GrantAuthorizationCode {
			needsRedirects = true
		}
	}
	if needsRedirects && len(req.RedirectURIs) == 0 {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRedirectURI,
			"redirect_uris is required for the authorization_code grant"))
		return
	}
	for _, uri := range req.RedirectURIs {
		if reason := invalidRedirectURI(uri); reason != "" {
			oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidRedirectURI, "%s: %s", uri, reason))
			return
		}
	}

	scopes, oerr := resolveScope(req.Scope, s.cfg.Scopes)
	if oerr != nil {
		oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidClientMetadata, "%s", oerr.Description))
		return
	}

	resources := req.Resources
	if len(resources) == 0 {
		resources = s.cfg.Resources
	}
	for _, res := range resources {
		if !contains(s.cfg.Resources, res) {
			oauth.WriteError(w, oauth.NewError(oauth.ErrInvalidClientMetadata,
				"resource %q is not served by this authorization server", res))
			return
		}
	}

	client := &store.Client{
		ID:                oauth.NewToken(),
		Name:              req.ClientName,
		RedirectURIs:      req.RedirectURIs,
		GrantTypes:        req.GrantTypes,
		TokenEndpointAuth: req.TokenEndpointAuthMethod,
		Scopes:            scopes,
		AllowedResources:  resources,
		CreatedAt:         time.Now(),
		Dynamic:           true,
	}
	var secret string
	if req.TokenEndpointAuthMethod != store.AuthMethodNone {
		secret = oauth.NewToken()
		client.SecretHash = oauth.HashSecret(secret)
	}
	s.store.PutClient(client)
	s.log.InfoContext(r.Context(), "client registered",
		slog.String("client_id", client.ID),
		slog.String("client_name", client.Name),
		slog.Bool("public", client.Public()),
		slog.Any("grant_types", client.GrantTypes))

	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                client.ID,
		ClientSecret:            secret,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0, // does not expire
		ClientName:              client.Name,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		TokenEndpointAuthMethod: client.TokenEndpointAuth,
		Scope:                   oauth.FormatScope(client.Scopes),
		Resources:               client.AllowedResources,
	})
}

// invalidRedirectURI enforces RFC 8252 §7.3 / OAuth 2.1 redirect rules:
// absolute URI, no fragment, and https except for loopback hosts.
func invalidRedirectURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return "must be an absolute URI"
	}
	if u.Fragment != "" {
		return "must not contain a fragment"
	}
	switch u.Scheme {
	case "https":
		return ""
	case "http":
		host := u.Hostname()
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			return "" // native-app loopback redirect (RFC 8252)
		}
		return "http is only allowed for loopback addresses"
	default:
		// Private-use schemes for native apps would be validated here;
		// this deployment supports loopback redirects instead.
		return "unsupported scheme"
	}
}
