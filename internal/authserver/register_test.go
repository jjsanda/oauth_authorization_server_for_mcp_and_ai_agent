package authserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

func register(t *testing.T, s *testServer, meta map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(meta)
	resp, err := http.Post(s.ts.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestDynamicRegistrationConfidentialClient(t *testing.T) {
	s := newTestServer(t)
	resp, body := register(t, s, map[string]any{
		"client_name": "CI Robot",
		"grant_types": []string{store.GrantClientCredentials},
		"scope":       "tools:read",
		"resources":   []string{testResource},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d body = %v", resp.StatusCode, body)
	}
	clientID, _ := body["client_id"].(string)
	secret, _ := body["client_secret"].(string)
	if clientID == "" || secret == "" {
		t.Fatalf("missing credentials in %v", body)
	}
	if body["client_secret_expires_at"] != float64(0) {
		t.Errorf("client_secret_expires_at = %v", body["client_secret_expires_at"])
	}

	// The fresh credentials must work at the token endpoint immediately.
	tokResp, tokBody := s.postToken(t, url.Values{
		"grant_type": {store.GrantClientCredentials},
		"resource":   {testResource},
	}, clientID, secret)
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("token with registered client: %d %v", tokResp.StatusCode, tokBody)
	}
}

func TestDynamicRegistrationPublicClient(t *testing.T) {
	s := newTestServer(t)
	resp, body := register(t, s, map[string]any{
		"client_name":                "Agent CLI",
		"redirect_uris":              []string{"http://127.0.0.1:0/callback", "http://localhost:8123/cb"},
		"grant_types":                []string{store.GrantAuthorizationCode, store.GrantRefreshToken},
		"token_endpoint_auth_method": "none",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d body = %v", resp.StatusCode, body)
	}
	if _, hasSecret := body["client_secret"]; hasSecret {
		t.Error("public client must not receive a secret")
	}
	// Defaults applied: all server scopes and resources.
	if body["scope"] == "" || body["resources"] == nil {
		t.Errorf("defaults not applied: %v", body)
	}
}

func TestDynamicRegistrationRejectsBadMetadata(t *testing.T) {
	s := newTestServer(t)
	tests := []struct {
		name      string
		meta      map[string]any
		wantError string
	}{
		{
			"authorization_code without redirect_uris",
			map[string]any{"grant_types": []string{store.GrantAuthorizationCode}},
			oauth.ErrInvalidRedirectURI,
		},
		{
			"non-loopback http redirect",
			map[string]any{"redirect_uris": []string{"http://app.example/cb"}},
			oauth.ErrInvalidRedirectURI,
		},
		{
			"redirect with fragment",
			map[string]any{"redirect_uris": []string{"https://app.example/cb#frag"}},
			oauth.ErrInvalidRedirectURI,
		},
		{
			"unsupported grant type",
			map[string]any{"grant_types": []string{"implicit"}, "redirect_uris": []string{"https://app.example/cb"}},
			oauth.ErrInvalidClientMetadata,
		},
		{
			"unknown auth method",
			map[string]any{"token_endpoint_auth_method": "private_key_jwt", "redirect_uris": []string{"https://a.example/cb"}},
			oauth.ErrInvalidClientMetadata,
		},
		{
			"scope outside registry",
			map[string]any{"scope": "admin:everything", "redirect_uris": []string{"https://a.example/cb"}},
			oauth.ErrInvalidClientMetadata,
		},
		{
			"resource outside registry",
			map[string]any{"resources": []string{"http://foreign.example"}, "redirect_uris": []string{"https://a.example/cb"}},
			oauth.ErrInvalidClientMetadata,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := register(t, s, tc.meta)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if body["error"] != tc.wantError {
				t.Errorf("error = %v, want %s", body["error"], tc.wantError)
			}
		})
	}
}
