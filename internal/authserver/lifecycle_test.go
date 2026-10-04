package authserver

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// obtainUserGrant runs the full browser flow and returns the token response
// (access + refresh token) for the seeded web-app client.
func obtainUserGrant(t *testing.T, s *testServer) map[string]any {
	t.Helper()
	browser := newBrowser(t)
	cb := walkToCode(t, s, browser, authorizeURL(s.ts.URL, nil))
	resp, body := s.postToken(t, url.Values{
		"grant_type":    {store.GrantAuthorizationCode},
		"client_id":     {webClientID},
		"code":          {cb.Get("code")},
		"code_verifier": {pkceVerifier},
		"redirect_uri":  {webRedirectURI},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: %d %v", resp.StatusCode, body)
	}
	return body
}

func (s *testServer) introspect(t *testing.T, tok string) map[string]any {
	t.Helper()
	resp, body := s.postForm(t, "/introspect", url.Values{"token": {tok}}, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status = %d %v", resp.StatusCode, body)
	}
	return body
}

func TestRefreshRotationLifecycle(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	rt1 := grant["refresh_token"].(string)

	// Rotation 1: rt1 → rt2.
	resp, body := s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt1},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh failed: %d %v", resp.StatusCode, body)
	}
	rt2 := body["refresh_token"].(string)
	if rt2 == rt1 {
		t.Fatal("refresh token was not rotated")
	}
	at2 := body["access_token"].(string)

	// The rotated access token verifies with the user's subject.
	v := &token.Verifier{Issuer: s.iss, Keys: s.keys, Audience: testResource}
	claims, err := v.Verify(at2)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user:u-alice" {
		t.Errorf("subject = %s", claims.Subject)
	}

	// Replaying rt1 (now retired) must kill the family…
	resp, body = s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt1},
	}, "", "")
	if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
		t.Fatalf("replay: %d %v", resp.StatusCode, body)
	}
	// …making rt2 dead too…
	resp, body = s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt2},
	}, "", "")
	if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
		t.Errorf("post-reuse refresh: %d %v", resp.StatusCode, body)
	}
	// …and revoking the family's access tokens.
	rec, ok := s.st.GetToken(claims.JTI)
	if !ok || !rec.Revoked {
		t.Error("family access token not revoked after reuse detection")
	}
}

func TestRefreshScopeNarrowingRules(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	rt := grant["refresh_token"].(string)

	// Narrowing is allowed.
	resp, body := s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt},
		"scope":         {"tools:read"},
	}, "", "")
	if resp.StatusCode != http.StatusOK || body["scope"] != "tools:read" {
		t.Fatalf("narrowing refresh: %d %v", resp.StatusCode, body)
	}
	rt = body["refresh_token"].(string)

	// Widening is not: the family ceiling stays what the user consented to.
	resp, body = s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt},
		"scope":         {"tools:read tools:invoke reports:read"},
	}, "", "")
	if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidScope {
		t.Errorf("widening refresh: %d %v", resp.StatusCode, body)
	}

	// A rejected refresh must NOT have rotated the token: the same refresh
	// token still works afterwards (rejecting validation before rotation).
	resp, body = s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh token was burned by a rejected request: %d %v", resp.StatusCode, body)
	}
}

func TestRefreshRejectsWrongClient(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	rt := grant["refresh_token"].(string)

	// A different client — registered for the refresh grant — presents the
	// web-app's refresh token with its own valid credentials.
	thiefSecret := oauth.NewToken()
	s.st.PutClient(&store.Client{
		ID:                "thief",
		SecretHash:        oauth.HashSecret(thiefSecret),
		GrantTypes:        []string{store.GrantRefreshToken},
		TokenEndpointAuth: store.AuthMethodBasic,
		Scopes:            []string{"tools:read"},
		AllowedResources:  []string{testResource},
	})
	resp, body := s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"refresh_token": {rt},
	}, "thief", thiefSecret)
	if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
		t.Fatalf("wrong-client refresh: %d %v", resp.StatusCode, body)
	}
	// The token must still work for its rightful owner (no rotation happened).
	resp, _ = s.postToken(t, url.Values{
		"grant_type":    {store.GrantRefreshToken},
		"client_id":     {webClientID},
		"refresh_token": {rt},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("legitimate refresh after foreign attempt failed: %d", resp.StatusCode)
	}
}

func TestTokenExchangeDelegation(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	subjectToken := grant["access_token"].(string)

	// demo-m2m (confidential) exchanges the user's tools-api token for a
	// reports-api token.
	resp, body := s.postToken(t, url.Values{
		"grant_type":         {store.GrantTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {tokenTypeAccessToken},
		"resource":           {testSecondResource},
		"scope":              {"tools:read"},
	}, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange failed: %d %v", resp.StatusCode, body)
	}
	if body["issued_token_type"] != tokenTypeAccessToken {
		t.Errorf("issued_token_type = %v", body["issued_token_type"])
	}
	if _, hasRefresh := body["refresh_token"]; hasRefresh {
		t.Error("exchange must not issue a refresh token")
	}

	v := &token.Verifier{Issuer: s.iss, Keys: s.keys, Audience: testSecondResource}
	claims, err := v.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user:u-alice" {
		t.Errorf("subject not preserved: %s", claims.Subject)
	}
	if claims.Actor == nil || claims.Actor.Subject != "client:"+DemoM2MClientID {
		t.Errorf("act = %+v", claims.Actor)
	}
	// The exchanged token must NOT be valid at the original audience.
	vOrig := &token.Verifier{Issuer: s.iss, Keys: s.keys, Audience: testResource}
	if _, err := vOrig.Verify(body["access_token"].(string)); err == nil {
		t.Error("exchanged token still valid at original audience")
	}
}

func TestTokenExchangeRefusals(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	grant := obtainUserGrant(t, s)
	subjectToken := grant["access_token"].(string)

	base := url.Values{
		"grant_type":         {store.GrantTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {tokenTypeAccessToken},
		"resource":           {testSecondResource},
	}

	t.Run("public client refused", func(t *testing.T) {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		form.Set("client_id", webClientID)
		resp, body := s.postToken(t, form, "", "")
		if resp.StatusCode != 400 || body["error"] != oauth.ErrUnauthorizedClient {
			t.Errorf("%d %v", resp.StatusCode, body)
		}
	})

	t.Run("scope widening refused", func(t *testing.T) {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		form.Set("scope", "tools:read tools:invoke reports:read")
		// subject token has tools:read tools:invoke only.
		resp, body := s.postToken(t, form, DemoM2MClientID, DemoM2MClientSecret)
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidScope {
			t.Errorf("%d %v", resp.StatusCode, body)
		}
	})

	t.Run("client not entitled to subject token refused", func(t *testing.T) {
		// A confidential client registered for the exchange grant and for a
		// resource, but NOT for the subject token's audience, must not be
		// able to retarget a token it merely came into contact with.
		outsiderSecret := oauth.NewToken()
		s.st.PutClient(&store.Client{
			ID:                "exchange-outsider",
			SecretHash:        oauth.HashSecret(outsiderSecret),
			GrantTypes:        []string{store.GrantTokenExchange},
			TokenEndpointAuth: store.AuthMethodBasic,
			Scopes:            []string{"reports:read"},
			AllowedResources:  []string{testSecondResource},
		})
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		// subject token is audienced to testResource; outsider is only
		// registered for testSecondResource and is not the token's client.
		resp, body := s.postToken(t, form, "exchange-outsider", outsiderSecret)
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
			t.Errorf("%d %v", resp.StatusCode, body)
		}
	})

	t.Run("garbage subject token refused", func(t *testing.T) {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		form.Set("subject_token", "not-a-jwt")
		resp, body := s.postToken(t, form, DemoM2MClientID, DemoM2MClientSecret)
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
			t.Errorf("%d %v", resp.StatusCode, body)
		}
	})

	t.Run("revoked subject token refused", func(t *testing.T) {
		v := &token.Verifier{Issuer: s.iss, Keys: s.keys}
		claims, _ := v.Verify(subjectToken)
		s.st.RevokeToken(claims.JTI)
		resp, body := s.postToken(t, base, DemoM2MClientID, DemoM2MClientSecret)
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
			t.Errorf("%d %v", resp.StatusCode, body)
		}
	})
}
