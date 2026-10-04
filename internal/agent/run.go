package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
)

// Mode selects how the agent obtains its first token.
type Mode string

// Supported agent modes.
const (
	// ModeHeadless runs the full authorization-code flow with a scripted
	// login (demo user) — used by CI and the compose demo.
	ModeHeadless Mode = "headless"
	// ModeAuthCode prints the authorization URL and waits for a human to
	// approve in a browser; the loopback listener receives the callback.
	ModeAuthCode Mode = "auth-code"
	// ModeClientCredentials skips user involvement entirely (M2M).
	ModeClientCredentials Mode = "client-credentials"
)

// Options configures a scenario run.
type Options struct {
	// Resource is the MCP server the agent wants to use. Everything else is
	// discovered from it.
	Resource string
	Mode     Mode
	// ExchangeFor, when set, demonstrates RFC 8693: the agent's token is
	// exchanged for one audienced to this second resource.
	ExchangeFor string
	// DemoRefreshReplay, when set, rotates the refresh token and then
	// deliberately replays the retired one to show the family revocation.
	DemoRefreshReplay bool
	// Username and Password drive the scripted login in headless mode.
	Username, Password string
	// Out receives the narrated steps (default io.Discard).
	Out io.Writer
	// HTTP is the transport to use (default: a client with a timeout).
	HTTP *http.Client
}

type runner struct {
	out  io.Writer
	hc   *http.Client
	step int
}

func (r *runner) stepf(format string, args ...any) {
	r.step++
	fmt.Fprintf(r.out, "\n[%2d] %s\n", r.step, fmt.Sprintf(format, args...))
}

func (r *runner) notef(format string, args ...any) {
	fmt.Fprintf(r.out, "     %s\n", fmt.Sprintf(format, args...))
}

// Run executes the scenario and returns the first failed assertion. A nil
// return means every step behaved exactly as the protocol requires — the
// compose demo and the e2e suite both rely on that.
func Run(ctx context.Context, opts Options) error {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.HTTP == nil {
		opts.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.Mode == "" {
		opts.Mode = ModeHeadless
	}
	if opts.Username == "" {
		opts.Username, opts.Password = "alice", "password"
	}
	r := &runner{out: opts.Out, hc: opts.HTTP}

	// ── Discovery ────────────────────────────────────────────────────────
	r.stepf("Probe %s without credentials", opts.Resource)
	metaURL, err := ProbeResource(ctx, r.hc, opts.Resource)
	if err != nil {
		return err
	}
	r.notef("401 challenge points at %s (RFC 9728)", metaURL)

	prMeta, err := FetchProtectedResourceMetadata(ctx, r.hc, metaURL, opts.Resource)
	if err != nil {
		return err
	}
	issuer := prMeta.AuthorizationServers[0]
	r.stepf("Discover the authorization server: %s", issuer)
	asMeta, err := FetchServerMetadata(ctx, r.hc, issuer)
	if err != nil {
		return err
	}
	r.notef("token endpoint     %s", asMeta.TokenEndpoint)
	r.notef("PKCE methods       %s", strings.Join(asMeta.CodeChallengeMethodsSupported, ", "))

	// The scope and resource set this run will ask the user (or policy) for.
	scopes := prMeta.ScopesSupported
	resources := []string{opts.Resource}
	var exchangeScopes []string
	if opts.ExchangeFor != "" {
		exchangeMetaURL, err := ProbeResource(ctx, r.hc, opts.ExchangeFor)
		if err != nil {
			return fmt.Errorf("probing exchange target: %w", err)
		}
		exchangePR, err := FetchProtectedResourceMetadata(ctx, r.hc, exchangeMetaURL, opts.ExchangeFor)
		if err != nil {
			return err
		}
		exchangeScopes = exchangePR.ScopesSupported
		scopes = append(append([]string(nil), scopes...), exchangeScopes...)
		resources = append(resources, opts.ExchangeFor)
	}

	// ── Registration ─────────────────────────────────────────────────────
	r.stepf("Register this agent dynamically (RFC 7591)")
	grantTypes := []string{"authorization_code", "refresh_token",
		"urn:ietf:params:oauth:grant-type:token-exchange"}
	if opts.Mode == ModeClientCredentials {
		grantTypes = []string{"client_credentials",
			"urn:ietf:params:oauth:grant-type:token-exchange"}
	}
	var loopback *loopbackListener
	metadata := map[string]any{
		"client_name":                "mcp-agent-cli",
		"grant_types":                grantTypes,
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      strings.Join(scopes, " "),
		"resources":                  resources,
	}
	if opts.Mode != ModeClientCredentials {
		var err error
		loopback, err = newLoopbackListener()
		if err != nil {
			return err
		}
		defer loopback.close()
		metadata["redirect_uris"] = []string{loopback.URL}
	}
	reg, err := RegisterClient(ctx, r.hc, asMeta.RegistrationEndpoint, metadata)
	if err != nil {
		return err
	}
	r.notef("client_id %s (confidential)", reg.ClientID)

	// ── First token ──────────────────────────────────────────────────────
	var tok *TokenResponse
	switch opts.Mode {
	case ModeClientCredentials:
		r.stepf("Request a token: client_credentials, audience-limited to %s (RFC 8707)", opts.Resource)
		tok, err = RequestToken(ctx, r.hc, asMeta.TokenEndpoint, url.Values{
			"grant_type": {"client_credentials"},
			"resource":   {opts.Resource},
		}, reg.ClientID, reg.ClientSecret)
		if err != nil {
			return err
		}

	case ModeHeadless, ModeAuthCode:
		pkce := newPKCE()
		state := newState()
		authorizeURL := buildAuthorizeURL(asMeta.AuthorizationEndpoint, reg.ClientID,
			loopback.URL, strings.Join(scopes, " "), state, pkce.Challenge, []string{opts.Resource})

		var code string
		if opts.Mode == ModeHeadless {
			r.stepf("Authorization code + PKCE with scripted login as %q", opts.Username)
			cb, err := driveHeadless(ctx, authorizeURL, opts.Username, opts.Password)
			if err != nil {
				return err
			}
			// Deliver the callback to the loopback listener exactly as a
			// browser would, then let the listener validate state and iss.
			cbResp, err := get(ctx, r.hc, cb.String())
			if err != nil {
				return fmt.Errorf("delivering callback: %w", err)
			}
			cbResp.Body.Close()
		} else {
			r.stepf("Open this URL in a browser to approve access:")
			r.notef("%s", authorizeURL)
			r.notef("waiting for the callback on %s …", loopback.URL)
		}
		code, err = loopback.wait(ctx, state, issuer)
		if err != nil {
			return err
		}
		r.notef("received one-time code; state and iss verified (RFC 9207)")

		r.stepf("Redeem the code with the PKCE verifier")
		tok, err = RequestToken(ctx, r.hc, asMeta.TokenEndpoint, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"code_verifier": {pkce.Verifier},
			"redirect_uri":  {loopback.URL},
		}, reg.ClientID, reg.ClientSecret)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown mode %q", opts.Mode)
	}
	if claims, err := decodeClaims(tok.AccessToken); err == nil {
		r.notef("access token: sub=%v aud=%v scope=%q (expires in %ds)",
			claims["sub"], claims["aud"], tok.Scope, tok.ExpiresIn)
	}

	// ── Use the tool server ──────────────────────────────────────────────
	r.stepf("Call the protected tools on %s", opts.Resource)
	list, err := callMCP(ctx, r.hc, opts.Resource, tok.AccessToken, "tools/list", nil)
	if err != nil {
		return err
	}
	if list.Status != http.StatusOK {
		return fmt.Errorf("tools/list returned %d with a valid token", list.Status)
	}
	whoami, err := callMCP(ctx, r.hc, opts.Resource, tok.AccessToken, "tools/call", map[string]any{"name": "whoami"})
	if err != nil {
		return err
	}
	if whoami.Status != http.StatusOK {
		return fmt.Errorf("tools/call whoami returned %d", whoami.Status)
	}
	r.notef("whoami → subject=%v client_id=%v", whoami.Result["subject"], whoami.Result["client_id"])

	// ── Audience restriction & token exchange ────────────────────────────
	if opts.ExchangeFor != "" {
		r.stepf("Try the SAME token against %s (different audience)", opts.ExchangeFor)
		foreign, err := callMCP(ctx, r.hc, opts.ExchangeFor, tok.AccessToken, "tools/list", nil)
		if err != nil {
			return err
		}
		if foreign.Status != http.StatusUnauthorized {
			return fmt.Errorf("cross-audience call returned %d, want 401 — RFC 8707 broken", foreign.Status)
		}
		r.notef("rejected with 401: tokens do not cross resource servers")

		r.stepf("Exchange the token for a %s-audienced one (RFC 8693)", opts.ExchangeFor)
		exchanged, err := RequestToken(ctx, r.hc, asMeta.TokenEndpoint, url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {tok.AccessToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"resource":           {opts.ExchangeFor},
			"scope":              {strings.Join(exchangeScopes, " ")},
		}, reg.ClientID, reg.ClientSecret)
		if err != nil {
			return err
		}
		if exchanged.RefreshToken != "" {
			return errors.New("exchange response carried a refresh token — it must not")
		}
		downstream, err := callMCP(ctx, r.hc, opts.ExchangeFor, exchanged.AccessToken, "tools/call", map[string]any{"name": "whoami"})
		if err != nil {
			return err
		}
		if downstream.Status != http.StatusOK {
			return fmt.Errorf("exchanged token rejected by %s: %d", opts.ExchangeFor, downstream.Status)
		}
		if downstream.Result["actor"] == nil {
			return errors.New("downstream whoami shows no act claim — delegation not recorded")
		}
		r.notef("whoami → subject=%v actor=%v (delegation is visible downstream)",
			downstream.Result["subject"], downstream.Result["actor"])
	}

	// ── Refresh rotation & reuse detection ───────────────────────────────
	if opts.DemoRefreshReplay {
		if tok.RefreshToken == "" {
			r.stepf("Skipping refresh demo: the %s grant issues no refresh token", opts.Mode)
		} else {
			if err := r.demoRefreshReplay(ctx, asMeta, reg, tok); err != nil {
				return err
			}
		}
	}

	fmt.Fprintf(r.out, "\nAll steps completed successfully.\n")
	return nil
}

func (r *runner) demoRefreshReplay(ctx context.Context, asMeta *ServerMetadata, reg *Registration, tok *TokenResponse) error {
	r.stepf("Rotate the refresh token")
	oldRefresh := tok.RefreshToken
	fresh, err := RequestToken(ctx, r.hc, asMeta.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefresh},
	}, reg.ClientID, reg.ClientSecret)
	if err != nil {
		return err
	}
	if fresh.RefreshToken == "" || fresh.RefreshToken == oldRefresh {
		return errors.New("refresh did not rotate the token")
	}
	r.notef("new access + refresh token issued; previous refresh token retired")

	r.stepf("Replay the RETIRED refresh token (simulated theft)")
	_, err = RequestToken(ctx, r.hc, asMeta.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefresh},
	}, reg.ClientID, reg.ClientSecret)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != oauth.ErrInvalidGrant {
		return fmt.Errorf("replay should fail with invalid_grant, got %v", err)
	}
	r.notef("rejected with invalid_grant — reuse detected")

	r.stepf("Verify the whole family is dead, including the NEWEST token")
	_, err = RequestToken(ctx, r.hc, asMeta.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {fresh.RefreshToken},
	}, reg.ClientID, reg.ClientSecret)
	if !errors.As(err, &te) || te.Code != oauth.ErrInvalidGrant {
		return fmt.Errorf("newest refresh token should be dead after reuse, got %v", err)
	}
	r.notef("newest refresh token also rejected: the theft burned the grant for everyone")

	// Confirm via introspection that the rotated access token was revoked.
	r.stepf("Introspect the rotated access token (RFC 7662)")
	form := url.Values{"token": {fresh.AccessToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMeta.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(reg.ClientID), url.QueryEscape(reg.ClientSecret))
	resp, err := r.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var intro struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&intro); err != nil {
		return err
	}
	if intro.Active {
		return errors.New("access token still active after family revocation")
	}
	r.notef("active=false — the access tokens minted through the family are revoked too")
	return nil
}
