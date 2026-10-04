package authserver

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/token"
)

const (
	webClientID    = "web-app"
	webRedirectURI = "http://127.0.0.1:7777/callback"
	pkceVerifier   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
)

func seedWebClient(s *testServer) {
	s.st.PutClient(&store.Client{
		ID:                webClientID,
		Name:              "Demo Web App",
		RedirectURIs:      []string{webRedirectURI},
		GrantTypes:        []string{store.GrantAuthorizationCode, store.GrantRefreshToken},
		TokenEndpointAuth: store.AuthMethodNone, // public client, PKCE only
		Scopes:            []string{"tools:read", "tools:invoke"},
		AllowedResources:  []string{testResource, testSecondResource},
	})
}

// browser is a cookie-keeping client that never follows redirects, so tests
// can inspect each hop of the flow.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func authorizeURL(base string, params map[string]string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {webClientID},
		"redirect_uri":          {webRedirectURI},
		"scope":                 {"tools:read tools:invoke"},
		"state":                 {"xyz-state"},
		"code_challenge":        {oauth.ChallengeS256(pkceVerifier)},
		"code_challenge_method": {"S256"},
		"resource":              {testResource},
	}
	for k, v := range params {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return base + "/authorize?" + q.Encode()
}

var reqIDRe = regexp.MustCompile(`req=([A-Za-z0-9_-]+)`)

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// fetchLoginCSRF GETs the login page (setting the login-guard cookie in the
// browser's jar) and returns the embedded CSRF token.
func fetchLoginCSRF(t *testing.T, browser *http.Client, base, reqID string) string {
	t.Helper()
	resp, err := browser.Get(base + "/login?req=" + reqID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no CSRF token on login page:\n%s", page)
	}
	return string(m[1])
}

// walkToCode drives browser through authorize → login → consent and returns
// the authorization code and the state/iss params from the final redirect.
func walkToCode(t *testing.T, s *testServer, browser *http.Client, authorizeTarget string) url.Values {
	t.Helper()

	// Step 1: /authorize parks the request and bounces to /login.
	resp, err := browser.Get(authorizeTarget)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?req=") {
		t.Fatalf("authorize redirected to %q, want /login", loc)
	}
	reqID := reqIDRe.FindStringSubmatch(loc)[1]

	// Step 2: fetch the login page for the login-CSRF cookie and token.
	loginCSRF := fetchLoginCSRF(t, browser, s.ts.URL, reqID)

	// Step 3: submit credentials.
	resp, err = browser.PostForm(s.ts.URL+"/login", url.Values{
		"req": {reqID}, "csrf": {loginCSRF}, "username": {"alice"}, "password": {"password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/consent") {
		t.Fatalf("login: status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Step 3: fetch the consent page to obtain the CSRF token.
	resp, err = browser.Get(s.ts.URL + "/consent?req=" + reqID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrfMatch := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(page)
	if csrfMatch == nil {
		t.Fatalf("no CSRF token on consent page:\n%s", page)
	}

	// Step 4: approve.
	resp, err = browser.PostForm(s.ts.URL+"/consent", url.Values{
		"req": {reqID}, "csrf": {string(csrfMatch[1])}, "action": {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("consent status = %d", resp.StatusCode)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cb.String(), webRedirectURI) {
		t.Fatalf("final redirect went to %q", cb.String())
	}
	return cb.Query()
}

func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	cb := walkToCode(t, s, browser, authorizeURL(s.ts.URL, nil))
	if cb.Get("state") != "xyz-state" {
		t.Errorf("state = %q", cb.Get("state"))
	}
	if cb.Get("iss") != s.iss {
		t.Errorf("iss = %q, want %s (RFC 9207)", cb.Get("iss"), s.iss)
	}
	code := cb.Get("code")
	if code == "" {
		t.Fatalf("no code in callback: %v", cb)
	}

	// Redeem the code (public client: client_id + PKCE, no secret).
	resp, body := s.postToken(t, url.Values{
		"grant_type":    {store.GrantAuthorizationCode},
		"client_id":     {webClientID},
		"code":          {code},
		"code_verifier": {pkceVerifier},
		"redirect_uri":  {webRedirectURI},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d body = %v", resp.StatusCode, body)
	}
	if body["refresh_token"] == nil {
		t.Error("no refresh token issued for user grant")
	}
	v := &token.Verifier{Issuer: s.iss, Keys: s.keys, Audience: testResource}
	claims, err := v.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user:u-alice" {
		t.Errorf("subject = %s", claims.Subject)
	}

	// Replaying the same code must fail and revoke the first token.
	resp2, body2 := s.postToken(t, url.Values{
		"grant_type":    {store.GrantAuthorizationCode},
		"client_id":     {webClientID},
		"code":          {code},
		"code_verifier": {pkceVerifier},
		"redirect_uri":  {webRedirectURI},
	}, "", "")
	if resp2.StatusCode != 400 || body2["error"] != oauth.ErrInvalidGrant {
		t.Errorf("replay: status=%d error=%v", resp2.StatusCode, body2["error"])
	}
	rec, ok := s.st.GetToken(claims.JTI)
	if !ok || !rec.Revoked {
		t.Error("access token from first redemption not revoked after code replay")
	}
}

func TestAuthorizeRejectsUntrustedClientLocally(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	for name, params := range map[string]map[string]string{
		"unknown client":        {"client_id": "ghost"},
		"unregistered redirect": {"redirect_uri": "https://evil.example/steal"},
		"missing redirect":      {"redirect_uri": ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := browser.Get(authorizeURL(s.ts.URL, params))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			// Must render a local error page, never redirect.
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Errorf("redirected to %q — must never redirect on untrusted client/redirect_uri", loc)
			}
		})
	}
}

func TestAuthorizeRedirectsProtocolErrors(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	tests := []struct {
		name      string
		params    map[string]string
		wantError string
	}{
		{"missing pkce", map[string]string{"code_challenge": ""}, oauth.ErrInvalidRequest},
		{"plain pkce", map[string]string{"code_challenge_method": "plain"}, oauth.ErrInvalidRequest},
		{"malformed challenge", map[string]string{"code_challenge": "too-short"}, oauth.ErrInvalidRequest},
		{"bad response type", map[string]string{"response_type": "token"}, oauth.ErrUnsupportedResponseType},
		{"scope too wide", map[string]string{"scope": "tools:read admin"}, oauth.ErrInvalidScope},
		{"missing resource", map[string]string{"resource": ""}, oauth.ErrInvalidTarget},
		{"foreign resource", map[string]string{"resource": "http://unknown.example"}, oauth.ErrInvalidTarget},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := browser.Get(authorizeURL(s.ts.URL, tc.params))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want 302", resp.StatusCode)
			}
			cb, _ := url.Parse(resp.Header.Get("Location"))
			if !strings.HasPrefix(cb.String(), webRedirectURI) {
				t.Fatalf("redirected to %q, want registered redirect_uri", cb.String())
			}
			q := cb.Query()
			if q.Get("error") != tc.wantError {
				t.Errorf("error = %q, want %q (%s)", q.Get("error"), tc.wantError, q.Get("error_description"))
			}
			if q.Get("state") != "xyz-state" {
				t.Errorf("state not echoed: %q", q.Get("state"))
			}
		})
	}
}

func TestTokenRequestBindingFailures(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	// A second client to test cross-client redemption.
	s.st.PutClient(&store.Client{
		ID:                "other-app",
		RedirectURIs:      []string{webRedirectURI},
		GrantTypes:        []string{store.GrantAuthorizationCode},
		TokenEndpointAuth: store.AuthMethodNone,
		Scopes:            []string{"tools:read"},
		AllowedResources:  []string{testResource},
	})

	newCode := func(t *testing.T) string {
		browser := newBrowser(t)
		return walkToCode(t, s, browser, authorizeURL(s.ts.URL, nil)).Get("code")
	}

	t.Run("wrong verifier", func(t *testing.T) {
		resp, body := s.postToken(t, url.Values{
			"grant_type":    {store.GrantAuthorizationCode},
			"client_id":     {webClientID},
			"code":          {newCode(t)},
			"code_verifier": {strings.Repeat("wrong-verifier-", 3) + "padding"},
			"redirect_uri":  {webRedirectURI},
		}, "", "")
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
			t.Errorf("status=%d error=%v", resp.StatusCode, body["error"])
		}
	})

	t.Run("wrong redirect_uri", func(t *testing.T) {
		resp, body := s.postToken(t, url.Values{
			"grant_type":    {store.GrantAuthorizationCode},
			"client_id":     {webClientID},
			"code":          {newCode(t)},
			"code_verifier": {pkceVerifier},
			"redirect_uri":  {"http://127.0.0.1:7777/other"},
		}, "", "")
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
			t.Errorf("status=%d error=%v", resp.StatusCode, body["error"])
		}
	})

	t.Run("different client redeems", func(t *testing.T) {
		resp, body := s.postToken(t, url.Values{
			"grant_type":    {store.GrantAuthorizationCode},
			"client_id":     {"other-app"},
			"code":          {newCode(t)},
			"code_verifier": {pkceVerifier},
			"redirect_uri":  {webRedirectURI},
		}, "", "")
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidGrant {
			t.Errorf("status=%d error=%v", resp.StatusCode, body["error"])
		}
	})

	t.Run("resource narrowing cannot widen", func(t *testing.T) {
		resp, body := s.postToken(t, url.Values{
			"grant_type":    {store.GrantAuthorizationCode},
			"client_id":     {webClientID},
			"code":          {newCode(t)},
			"code_verifier": {pkceVerifier},
			"redirect_uri":  {webRedirectURI},
			// consented resource was testResource only.
			"resource": {testSecondResource},
		}, "", "")
		if resp.StatusCode != 400 || body["error"] != oauth.ErrInvalidTarget {
			t.Errorf("status=%d error=%v", resp.StatusCode, body["error"])
		}
	})
}

func TestConsentDenyRedirectsAccessDenied(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	resp, _ := browser.Get(authorizeURL(s.ts.URL, nil))
	resp.Body.Close()
	reqID := reqIDRe.FindStringSubmatch(resp.Header.Get("Location"))[1]

	loginCSRF := fetchLoginCSRF(t, browser, s.ts.URL, reqID)
	resp, _ = browser.PostForm(s.ts.URL+"/login", url.Values{
		"req": {reqID}, "csrf": {loginCSRF}, "username": {"alice"}, "password": {"password"},
	})
	resp.Body.Close()

	resp, _ = browser.Get(s.ts.URL + "/consent?req=" + reqID)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := csrfRe.FindSubmatch(page)[1]

	resp, _ = browser.PostForm(s.ts.URL+"/consent", url.Values{
		"req": {reqID}, "csrf": {string(csrf)}, "action": {"deny"},
	})
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if cb.Query().Get("error") != oauth.ErrAccessDenied {
		t.Errorf("error = %q, want access_denied", cb.Query().Get("error"))
	}
}

func TestConsentRejectsBadCSRF(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	resp, _ := browser.Get(authorizeURL(s.ts.URL, nil))
	resp.Body.Close()
	reqID := reqIDRe.FindStringSubmatch(resp.Header.Get("Location"))[1]
	loginCSRF := fetchLoginCSRF(t, browser, s.ts.URL, reqID)
	resp, _ = browser.PostForm(s.ts.URL+"/login", url.Values{
		"req": {reqID}, "csrf": {loginCSRF}, "username": {"alice"}, "password": {"password"},
	})
	resp.Body.Close()

	resp, err := browser.PostForm(s.ts.URL+"/consent", url.Values{
		"req": {reqID}, "csrf": {"forged"}, "action": {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on CSRF mismatch", resp.StatusCode)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	resp, _ := browser.Get(authorizeURL(s.ts.URL, nil))
	resp.Body.Close()
	reqID := reqIDRe.FindStringSubmatch(resp.Header.Get("Location"))[1]

	loginCSRF := fetchLoginCSRF(t, browser, s.ts.URL, reqID)
	resp, _ = browser.PostForm(s.ts.URL+"/login", url.Values{
		"req": {reqID}, "csrf": {loginCSRF}, "username": {"alice"}, "password": {"not-the-password"},
	})
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(string(page), "Incorrect username or password") {
		t.Error("expected uniform error message on login page")
	}
}

// TestLoginRejectsWithoutGuard proves the login-CSRF defense: a credentials
// POST that did not originate from a fetched login page (no guard cookie, or
// a mismatched token) is refused, so an attacker cannot force a victim's
// browser to log in as the attacker.
func TestLoginRejectsWithoutGuard(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	resp, _ := browser.Get(authorizeURL(s.ts.URL, nil))
	resp.Body.Close()
	reqID := reqIDRe.FindStringSubmatch(resp.Header.Get("Location"))[1]

	// POST straight to /login without ever GETting the page (no guard cookie).
	resp, err := browser.PostForm(s.ts.URL+"/login", url.Values{
		"req": {reqID}, "csrf": {"anything"}, "username": {"alice"}, "password": {"password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 without a valid login guard", resp.StatusCode)
	}

	// With the cookie set but a wrong token, still rejected.
	fetchLoginCSRF(t, browser, s.ts.URL, reqID) // sets the guard cookie
	resp, err = browser.PostForm(s.ts.URL+"/login", url.Values{
		"req": {reqID}, "csrf": {"wrong-token"}, "username": {"alice"}, "password": {"password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 with a mismatched login guard token", resp.StatusCode)
	}
}

func TestSessionSkipsLoginOnSecondAuthorization(t *testing.T) {
	s := newTestServer(t)
	seedWebClient(s)
	browser := newBrowser(t)

	// First round establishes the session.
	walkToCode(t, s, browser, authorizeURL(s.ts.URL, nil))

	// Second authorize with the same browser jumps straight to consent.
	resp, err := browser.Get(authorizeURL(s.ts.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/consent") {
		t.Errorf("second authorize redirected to %q, want /consent (session reuse)", loc)
	}
}
