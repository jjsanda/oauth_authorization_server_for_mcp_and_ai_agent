// Package agent implements an autonomous OAuth 2.1 client in the shape of an
// AI agent connecting to MCP-style tool servers: it starts with nothing but
// a resource URL, discovers the authorization server from the resource's 401
// challenge (RFC 9728), registers itself (RFC 7591), obtains
// audience-restricted tokens (RFC 8707) via authorization code + PKCE or
// client credentials, calls protected tools, exchanges tokens for downstream
// resources (RFC 8693), and demonstrates refresh rotation with reuse
// detection.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ProtectedResourceMetadata is the RFC 9728 document served by a resource
// server.
type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// ServerMetadata is the RFC 8414 authorization server metadata document.
type ServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	IntrospectionEndpoint         string   `json:"introspection_endpoint"`
	RevocationEndpoint            string   `json:"revocation_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

var resourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// ProbeResource sends an unauthenticated request to the resource's MCP
// endpoint and extracts the RFC 9728 metadata URL from the 401 challenge.
func ProbeResource(ctx context.Context, hc *http.Client, resource string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resource+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("probing %s: %w", resource, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("expected 401 from unauthenticated probe, got %s", resp.Status)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	m := resourceMetadataRe.FindStringSubmatch(challenge)
	if m == nil {
		return "", fmt.Errorf("401 challenge carries no resource_metadata: %q", challenge)
	}
	return m[1], nil
}

// FetchProtectedResourceMetadata retrieves and validates the RFC 9728
// document.
func FetchProtectedResourceMetadata(ctx context.Context, hc *http.Client, metadataURL, expectedResource string) (*ProtectedResourceMetadata, error) {
	var doc ProtectedResourceMetadata
	if err := getJSON(ctx, hc, metadataURL, &doc); err != nil {
		return nil, err
	}
	if doc.Resource != expectedResource {
		return nil, fmt.Errorf("metadata resource %q does not match %q", doc.Resource, expectedResource)
	}
	if len(doc.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("resource metadata names no authorization servers")
	}
	return &doc, nil
}

// FetchServerMetadata retrieves the RFC 8414 document for an issuer and
// verifies the issuer claim matches (§3.3).
func FetchServerMetadata(ctx context.Context, hc *http.Client, issuer string) (*ServerMetadata, error) {
	var doc ServerMetadata
	if err := getJSON(ctx, hc, issuer+"/.well-known/oauth-authorization-server", &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("issuer mismatch: metadata says %q, expected %q", doc.Issuer, issuer)
	}
	return &doc, nil
}

func getJSON(ctx context.Context, hc *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("GET %s: parsing body: %w", url, err)
	}
	return nil
}
