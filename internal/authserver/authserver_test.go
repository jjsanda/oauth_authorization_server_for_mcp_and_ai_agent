package authserver

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store/memory"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

const (
	testResource       = "http://localhost:9100"
	testSecondResource = "http://localhost:9200"
)

// testServer wires a Server against an in-memory store with the demo seed.
type testServer struct {
	*Server
	st  *memory.Store
	ts  *httptest.Server
	iss string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	keys, err := jose.NewKeySet(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := New(Config{
		Issuer:    "http://as.test",
		Resources: []string{testResource, testSecondResource},
	}, st, keys, log)
	SeedDemo(st, []string{testResource, testSecondResource}, nil)
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return &testServer{Server: srv, st: st, ts: ts, iss: "http://as.test"}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// postToken sends a form to /token with optional basic auth.
func (s *testServer) postToken(t *testing.T, form url.Values, basicUser, basicPass string) (*http.Response, map[string]any) {
	t.Helper()
	return s.postForm(t, "/token", form, basicUser, basicPass)
}

// postForm sends a form to any endpoint with optional basic auth.
func (s *testServer) postForm(t *testing.T, path string, form url.Values, basicUser, basicPass string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.ts.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicPass))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestMetadataDocument(t *testing.T) {
	s := newTestServer(t)
	resp, err := http.Get(s.ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != s.iss {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	for _, field := range []string{
		"authorization_endpoint", "token_endpoint", "jwks_uri",
		"registration_endpoint", "introspection_endpoint", "revocation_endpoint",
	} {
		if doc[field] == nil {
			t.Errorf("metadata missing %s", field)
		}
	}
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256] only", methods)
	}
}

func TestJWKSServesActiveKey(t *testing.T) {
	s := newTestServer(t)
	resp, err := http.Get(s.ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KID != s.keys.Active().KID {
		t.Errorf("JWKS = %+v", set)
	}
}

func TestClientCredentialsHappyPath(t *testing.T) {
	s := newTestServer(t)
	form := url.Values{
		"grant_type": {store.GrantClientCredentials},
		"resource":   {testResource},
		"scope":      {"tools:read tools:invoke"},
	}
	resp, body := s.postToken(t, form, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	if _, hasRefresh := body["refresh_token"]; hasRefresh {
		t.Error("client_credentials must not issue a refresh token")
	}

	// The issued JWT must verify and carry the requested audience/scope.
	v := &token.Verifier{Issuer: s.iss, Keys: s.keys, Audience: testResource}
	claims, err := v.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
	if claims.Subject != "client:"+DemoM2MClientID || claims.ClientID != DemoM2MClientID {
		t.Errorf("claims = %+v", claims)
	}
	if !claims.HasScope("tools:invoke") {
		t.Error("scope missing")
	}
	// And it must be introspectable via its record.
	if _, ok := s.st.GetToken(claims.JTI); !ok {
		t.Error("no AccessTokenRecord stored for issued token")
	}
}

func TestClientCredentialsMultipleResources(t *testing.T) {
	s := newTestServer(t)
	form := url.Values{
		"grant_type": {store.GrantClientCredentials},
		"resource":   {testResource, testSecondResource},
	}
	resp, body := s.postToken(t, form, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, body)
	}
	v := &token.Verifier{Issuer: s.iss, Keys: s.keys, Audience: testSecondResource}
	if _, err := v.Verify(body["access_token"].(string)); err != nil {
		t.Errorf("token missing second audience: %v", err)
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	s := newTestServer(t)
	tests := []struct {
		name       string
		form       url.Values
		user, pass string
		wantStatus int
		wantError  string
	}{
		{
			name:       "wrong client secret",
			form:       url.Values{"grant_type": {store.GrantClientCredentials}, "resource": {testResource}},
			user:       DemoM2MClientID,
			pass:       "wrong-secret",
			wantStatus: 401,
			wantError:  oauth.ErrInvalidClient,
		},
		{
			name:       "unknown client",
			form:       url.Values{"grant_type": {store.GrantClientCredentials}, "resource": {testResource}},
			user:       "ghost",
			pass:       "whatever",
			wantStatus: 401,
			wantError:  oauth.ErrInvalidClient,
		},
		{
			name:       "missing resource parameter",
			form:       url.Values{"grant_type": {store.GrantClientCredentials}},
			user:       DemoM2MClientID,
			pass:       DemoM2MClientSecret,
			wantStatus: 400,
			wantError:  oauth.ErrInvalidTarget,
		},
		{
			name: "resource not allowed for client",
			form: url.Values{
				"grant_type": {store.GrantClientCredentials},
				"resource":   {"http://unregistered.example"},
			},
			user:       DemoM2MClientID,
			pass:       DemoM2MClientSecret,
			wantStatus: 400,
			wantError:  oauth.ErrInvalidTarget,
		},
		{
			name: "relative resource URI",
			form: url.Values{
				"grant_type": {store.GrantClientCredentials},
				"resource":   {"/api"},
			},
			user:       DemoM2MClientID,
			pass:       DemoM2MClientSecret,
			wantStatus: 400,
			wantError:  oauth.ErrInvalidTarget,
		},
		{
			name: "scope wider than registration",
			form: url.Values{
				"grant_type": {store.GrantClientCredentials},
				"resource":   {testResource},
				"scope":      {"tools:read admin:everything"},
			},
			user:       DemoM2MClientID,
			pass:       DemoM2MClientSecret,
			wantStatus: 400,
			wantError:  oauth.ErrInvalidScope,
		},
		{
			name:       "unsupported grant type",
			form:       url.Values{"grant_type": {"password"}, "resource": {testResource}},
			user:       DemoM2MClientID,
			pass:       DemoM2MClientSecret,
			wantStatus: 400,
			wantError:  oauth.ErrUnsupportedGrantType,
		},
		{
			name:       "missing grant type",
			form:       url.Values{"resource": {testResource}},
			user:       DemoM2MClientID,
			pass:       DemoM2MClientSecret,
			wantStatus: 400,
			wantError:  oauth.ErrInvalidRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := s.postToken(t, tc.form, tc.user, tc.pass)
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %v)", resp.StatusCode, tc.wantStatus, body)
			}
			if body["error"] != tc.wantError {
				t.Errorf("error = %v, want %s", body["error"], tc.wantError)
			}
			if tc.wantStatus == 401 {
				if www := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(www, "Basic") {
					t.Errorf("WWW-Authenticate = %q", www)
				}
			}
		})
	}
}

func TestClientAuthRejectsMixedMethods(t *testing.T) {
	s := newTestServer(t)
	form := url.Values{
		"grant_type":    {store.GrantClientCredentials},
		"resource":      {testResource},
		"client_id":     {DemoM2MClientID},
		"client_secret": {DemoM2MClientSecret},
	}
	// Both Basic and form credentials → invalid_request per RFC 6749 §2.3.
	resp, body := s.postToken(t, form, DemoM2MClientID, DemoM2MClientSecret)
	if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidRequest {
		t.Errorf("status=%d error=%v, want 400 invalid_request", resp.StatusCode, body["error"])
	}
}

func TestClientAuthRejectsWrongMethod(t *testing.T) {
	s := newTestServer(t)
	// demo-m2m registered client_secret_basic; posting the secret in the
	// body must be rejected.
	form := url.Values{
		"grant_type":    {store.GrantClientCredentials},
		"resource":      {testResource},
		"client_id":     {DemoM2MClientID},
		"client_secret": {DemoM2MClientSecret},
	}
	resp, body := s.postToken(t, form, "", "")
	if resp.StatusCode != 401 || body["error"] != oauth.ErrInvalidClient {
		t.Errorf("status=%d error=%v, want 401 invalid_client", resp.StatusCode, body["error"])
	}
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)
	resp, err := http.Get(s.ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
}
