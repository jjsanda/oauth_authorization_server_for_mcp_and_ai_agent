package authserver

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// The demo-m2m client is registered for both demo resources, so it may
// introspect user tokens audienced to them (the resource-server role).

func TestIntrospectionOfAccessAndRefreshTokens(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)

	at := s.introspect(t, grant["access_token"].(string))
	if at["active"] != true {
		t.Fatalf("access token inactive: %v", at)
	}
	if at["sub"] != "user:u-alice" || at["client_id"] != webClientID || at["token_type"] != "Bearer" {
		t.Errorf("introspection = %v", at)
	}

	rt := s.introspect(t, grant["refresh_token"].(string))
	if rt["active"] != true || rt["token_type"] != "refresh_token" {
		t.Errorf("refresh introspection = %v", rt)
	}

	garbage := s.introspect(t, "completely-unknown-token")
	if garbage["active"] != false || len(garbage) != 1 {
		t.Errorf("unknown token introspection must be exactly {active:false}: %v", garbage)
	}
}

func TestIntrospectionRequiresConfidentialClient(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)

	// No credentials at all.
	resp, _ := s.postForm(t, "/introspect", url.Values{"token": {grant["access_token"].(string)}}, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated introspection: %d, want 401", resp.StatusCode)
	}

	// A public client (web-app) must be refused too.
	resp, body := s.postForm(t, "/introspect", url.Values{
		"token":     {grant["access_token"].(string)},
		"client_id": {webClientID},
	}, "", "")
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != oauth.ErrInvalidClient {
		t.Errorf("public-client introspection: %d %v", resp.StatusCode, body)
	}
}

func TestIntrospectionHidesForeignAudienceTokens(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)

	// Register a confidential client with no resource overlap.
	outsider, outsiderSecret := "outsider", oauth.NewToken()
	s.st.PutClient(&store.Client{
		ID:                outsider,
		SecretHash:        oauth.HashSecret(outsiderSecret),
		GrantTypes:        []string{store.GrantClientCredentials},
		TokenEndpointAuth: store.AuthMethodBasic,
		Scopes:            []string{"tools:read"},
		AllowedResources:  []string{"http://elsewhere.example"},
	})
	resp, body := s.postForm(t, "/introspect",
		url.Values{"token": {grant["access_token"].(string)}}, outsider, outsiderSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body["active"] != false || len(body) != 1 {
		t.Errorf("token state leaked to unrelated client: %v", body)
	}
}

func TestRevocationOfAccessToken(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	at := grant["access_token"].(string)

	// The web-app (public client) revokes its own access token.
	resp, _ := s.postForm(t, "/revoke", url.Values{
		"token":     {at},
		"client_id": {webClientID},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	if got := s.introspect(t, at); got["active"] != false {
		t.Errorf("token still active after revocation: %v", got)
	}
}

func TestRevocationOfRefreshTokenKillsFamily(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	at := grant["access_token"].(string)
	rt := grant["refresh_token"].(string)

	resp, _ := s.postForm(t, "/revoke", url.Values{
		"token":     {rt},
		"client_id": {webClientID},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}

	// Refresh token dead.
	if got := s.introspect(t, rt); got["active"] != false {
		t.Errorf("refresh token still active: %v", got)
	}
	// Its access tokens dead as well.
	if got := s.introspect(t, at); got["active"] != false {
		t.Errorf("family access token still active: %v", got)
	}
	// And the grant cannot be used again.
	tokResp, body := s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt},
	}, "", "")
	if tokResp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
		t.Errorf("revoked family still refreshes: %d %v", tokResp.StatusCode, body)
	}
}

func TestRevocationIgnoresForeignTokensSilently(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	at := grant["access_token"].(string)

	// demo-m2m tries to revoke the web-app's token: 200, but no effect.
	resp, _ := s.postForm(t, "/revoke", url.Values{"token": {at}}, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no oracle)", resp.StatusCode)
	}
	if got := s.introspect(t, at); got["active"] != true {
		t.Error("foreign client managed to revoke a token it does not own")
	}
}

func TestRevocationOfUnknownTokenStill200(t *testing.T) {
	s := newTestServer(t)
	resp, _ := s.postForm(t, "/revoke", url.Values{"token": {"who-knows"}}, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
