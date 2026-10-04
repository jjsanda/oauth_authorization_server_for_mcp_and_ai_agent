package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

// driveHeadless walks the authorization endpoint's login and consent pages
// programmatically — the same HTTP conversation a human has in a browser,
// driven by a cookie jar instead. This is what makes the full authorization
// code flow runnable in CI.
func driveHeadless(ctx context.Context, authorizeURL, username, password string) (*url.URL, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	// Never follow redirects automatically: each hop is inspected, and the
	// final hop (to the loopback callback) must not be followed at all.
	browser := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Hop 1: /authorize parks the request and redirects to /login.
	resp, err := get(ctx, browser, authorizeURL)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("authorize returned %s, expected a redirect", resp.Status)
	}
	base, _ := url.Parse(authorizeURL)
	loginURL, err := base.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	// The authorization response may short-circuit straight back to the
	// client (error case) — surface that instead of trying to log in.
	if loginURL.Query().Get("error") != "" {
		return loginURL, nil
	}
	reqID := loginURL.Query().Get("req")
	if reqID == "" {
		return nil, fmt.Errorf("authorize redirected to %q without a pending request id", loginURL)
	}

	// Hop 2: fetch the login page to obtain the login-CSRF cookie and token,
	// exactly as a browser following the redirect would.
	resp, err = get(ctx, browser, base.ResolveReference(loginURL).String())
	if err != nil {
		return nil, err
	}
	loginPage, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	loginCSRF := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(loginPage)
	if loginCSRF == nil {
		return nil, fmt.Errorf("login page carries no CSRF token (status %s)", resp.Status)
	}

	// Hop 3: submit credentials.
	resp, err = postForm(ctx, browser, base.ResolveReference(&url.URL{Path: "/login"}).String(), url.Values{
		"req": {reqID}, "csrf": {string(loginCSRF[1])}, "username": {username}, "password": {password},
	})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("login returned %s — check the demo credentials", resp.Status)
	}

	// Hop 4: read the consent page and pick up the CSRF token.
	resp, err = get(ctx, browser, base.ResolveReference(&url.URL{Path: "/consent", RawQuery: "req=" + url.QueryEscape(reqID)}).String())
	if err != nil {
		return nil, err
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(page)
	if csrf == nil {
		return nil, fmt.Errorf("consent page carries no CSRF token (status %s)", resp.Status)
	}

	// Hop 4: approve. The response redirects to the client's callback.
	resp, err = postForm(ctx, browser, base.ResolveReference(&url.URL{Path: "/consent"}).String(), url.Values{
		"req": {reqID}, "csrf": {string(csrf[1])}, "action": {"approve"},
	})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("consent returned %s, expected a redirect", resp.Status)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("parsing callback redirect: %w", err)
	}
	return cb, nil
}

func get(ctx context.Context, hc *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return hc.Do(req)
}

func postForm(ctx context.Context, hc *http.Client, target string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return hc.Do(req)
}
