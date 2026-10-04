package resourceserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

// fakeAS is a minimal authorization server: RFC 8414 metadata, a JWKS, and
// an issuer to mint arbitrary tokens for the resource server under test.
type fakeAS struct {
	ts     *httptest.Server
	keys   *jose.KeySet
	issuer *token.Issuer
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	keys, err := jose.NewKeySet(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAS{keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   f.ts.URL,
			"jwks_uri": f.ts.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		body, _ := keys.JWKS()
		_, _ = w.Write(body)
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	f.issuer = &token.Issuer{Issuer: f.ts.URL, Keys: keys}
	return f
}

func (f *fakeAS) mint(t *testing.T, audience, scope string) string {
	t.Helper()
	tok, _, err := f.issuer.Issue(token.IssueParams{
		Subject:  "user:alice",
		ClientID: "test-client",
		Audience: []string{audience},
		Scope:    strings.Fields(scope),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type rsFixture struct {
	as *fakeAS
	ts *httptest.Server
}

func newFixture(t *testing.T) *rsFixture {
	t.Helper()
	as := newFakeAS(t)
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))

	var srv *Server
	// The resource identifier must equal the public URL, which httptest
	// only assigns at start; bootstrap with a placeholder handler.
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.Routes().ServeHTTP(w, r)
	}))
	t.Cleanup(outer.Close)
	srv = New(Config{
		Resource:               outer.URL,
		Issuer:                 as.ts.URL,
		JWKSMinRefreshInterval: -1, // disable rate limiting in tests
	}, log)
	return &rsFixture{as: as, ts: outer}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func (f *rsFixture) rpc(t *testing.T, bearer, method string, params any) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp, decoded
}

func TestUnauthenticatedRequestGetsDiscoveryChallenge(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.rpc(t, "", "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	www := resp.Header.Get("WWW-Authenticate")
	wantMeta := f.ts.URL + "/.well-known/oauth-protected-resource"
	if !strings.Contains(www, `resource_metadata="`+wantMeta+`"`) {
		t.Errorf("WWW-Authenticate = %q, want resource_metadata pointing at %s", www, wantMeta)
	}
	// A missing token gets a bare challenge — no error code (RFC 6750 §3.1).
	if strings.Contains(www, "error=") {
		t.Errorf("challenge for missing credentials must not carry an error code: %q", www)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc protectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != f.ts.URL {
		t.Errorf("resource = %s", doc.Resource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != f.as.ts.URL {
		t.Errorf("authorization_servers = %v", doc.AuthorizationServers)
	}
	if len(doc.BearerMethodsSupported) != 1 || doc.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported = %v", doc.BearerMethodsSupported)
	}
}

func TestToolsListAndCall(t *testing.T) {
	f := newFixture(t)
	tok := f.as.mint(t, f.ts.URL, "tools:read tools:invoke")

	resp, body := f.rpc(t, tok, "tools/list", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status = %d", resp.StatusCode)
	}
	tools := body["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Errorf("tool count = %d, want 3", len(tools))
	}

	resp, body = f.rpc(t, tok, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]string{"message": "hello"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call status = %d", resp.StatusCode)
	}
	if msg := body["result"].(map[string]any)["message"]; msg != "hello" {
		t.Errorf("echo = %v", msg)
	}

	_, body = f.rpc(t, tok, "tools/call", map[string]any{"name": "whoami"})
	result := body["result"].(map[string]any)
	if result["subject"] != "user:alice" || result["client_id"] != "test-client" {
		t.Errorf("whoami = %v", result)
	}
	if _, hasActor := result["actor"]; hasActor {
		t.Error("actor present without token exchange")
	}
}

func TestWhoamiExposesActorAfterExchange(t *testing.T) {
	f := newFixture(t)
	tok, _, err := f.as.issuer.Issue(token.IssueParams{
		Subject:  "user:alice",
		ClientID: "downstream",
		Audience: []string{f.ts.URL},
		Scope:    []string{"tools:invoke"},
		ActorSub: "client:agent-cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := f.rpc(t, tok, "tools/call", map[string]any{"name": "whoami"})
	result := body["result"].(map[string]any)
	if result["actor"] != "client:agent-cli" {
		t.Errorf("actor = %v, want client:agent-cli", result["actor"])
	}
}

// TestCrossAudienceTokenRejected is the core RFC 8707 guarantee: a token
// minted for another resource server must not be accepted here.
func TestCrossAudienceTokenRejected(t *testing.T) {
	f := newFixture(t)
	foreign := f.as.mint(t, "http://some-other-rs.example", "tools:read tools:invoke")
	resp, _ := f.rpc(t, foreign, "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for cross-audience token", resp.StatusCode)
	}
	if www := resp.Header.Get("WWW-Authenticate"); !strings.Contains(www, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q", www)
	}
}

func TestInsufficientScope(t *testing.T) {
	f := newFixture(t)
	readOnly := f.as.mint(t, f.ts.URL, "tools:read")
	resp, _ := f.rpc(t, readOnly, "tools/call", map[string]any{"name": "time"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	www := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(www, `error="insufficient_scope"`) || !strings.Contains(www, `scope="tools:invoke"`) {
		t.Errorf("WWW-Authenticate = %q", www)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	f := newFixture(t)
	old := f.as.issuer.Now
	f.as.issuer.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	stale := f.as.mint(t, f.ts.URL, "tools:read")
	f.as.issuer.Now = old

	resp, _ := f.rpc(t, stale, "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for expired token", resp.StatusCode)
	}
}

func TestGarbageTokenRejected(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.rpc(t, "not.a.jwt", "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestKeyRotationPickedUpViaUnknownKid: after the AS rotates its signing
// key, tokens signed with the new key carry an unknown kid, which must
// trigger a JWKS refresh instead of a rejection.
func TestKeyRotationPickedUpViaUnknownKid(t *testing.T) {
	f := newFixture(t)

	// Prime the RS key cache with the pre-rotation JWKS.
	tok := f.as.mint(t, f.ts.URL, "tools:read tools:invoke")
	if resp, _ := f.rpc(t, tok, "tools/list", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-rotation request failed: %d", resp.StatusCode)
	}

	if err := f.as.keys.Rotate(); err != nil {
		t.Fatal(err)
	}
	fresh := f.as.mint(t, f.ts.URL, "tools:read tools:invoke")
	resp, _ := f.rpc(t, fresh, "tools/list", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("post-rotation token rejected: %d — unknown-kid refresh not working", resp.StatusCode)
	}

	// And tokens from before the rotation must still verify (retired key
	// stays in the JWKS).
	if resp, _ := f.rpc(t, tok, "tools/list", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("pre-rotation token rejected after rotation: %d", resp.StatusCode)
	}
}

func TestRPCEnvelopeErrors(t *testing.T) {
	f := newFixture(t)
	tok := f.as.mint(t, f.ts.URL, "tools:read tools:invoke")

	resp, body := f.rpc(t, tok, "no/such/method", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	errObj := body["error"].(map[string]any)
	if int(errObj["code"].(float64)) != rpcMethodNotFound {
		t.Errorf("error = %v", errObj)
	}

	_, body = f.rpc(t, tok, "tools/call", map[string]any{"name": "no-such-tool"})
	errObj = body["error"].(map[string]any)
	if int(errObj["code"].(float64)) != rpcMethodNotFound {
		t.Errorf("unknown tool error = %v", errObj)
	}
}
