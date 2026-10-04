// Package e2e wires the authorization server, two resource servers, and the
// agent client together in-process and runs the complete protocol story:
// discovery → dynamic registration → authorization code + PKCE (scripted
// login) → audience-restricted tool call → cross-audience rejection → token
// exchange → refresh rotation → reuse detection → family revocation.
package e2e

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/agent"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/authserver"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/resourceserver"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store/memory"
)

// stack is a fully wired in-process deployment.
type stack struct {
	as      *httptest.Server
	tools   *httptest.Server
	reports *httptest.Server
}

func newStack(t *testing.T, alg jose.Algorithm) *stack {
	t.Helper()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	keys, err := jose.NewKeySet(alg)
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()

	// The servers need to know their own public URLs, which httptest only
	// assigns at start; bootstrap each behind an indirection.
	var asrv *authserver.Server
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asrv.Routes().ServeHTTP(w, r)
	}))
	t.Cleanup(as.Close)

	var toolsSrv, reportsSrv *resourceserver.Server
	tools := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toolsSrv.Routes().ServeHTTP(w, r)
	}))
	t.Cleanup(tools.Close)
	reports := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportsSrv.Routes().ServeHTTP(w, r)
	}))
	t.Cleanup(reports.Close)

	asrv = authserver.New(authserver.Config{
		Issuer:    as.URL,
		Resources: []string{tools.URL, reports.URL},
	}, st, keys, log)
	authserver.SeedDemo(st, []string{tools.URL, reports.URL}, nil)

	toolsSrv = resourceserver.New(resourceserver.Config{
		Resource:               tools.URL,
		Issuer:                 as.URL,
		ScopeList:              "tools:read",
		ScopeCall:              "tools:invoke",
		JWKSMinRefreshInterval: -1, // disable rate limiting in tests
	}, log)
	reportsSrv = resourceserver.New(resourceserver.Config{
		Resource:               reports.URL,
		Issuer:                 as.URL,
		ScopeList:              "reports:read",
		ScopeCall:              "reports:read",
		ScopesSupported:        []string{"reports:read"},
		JWKSMinRefreshInterval: -1, // disable rate limiting in tests
	}, log)

	return &stack{as: as, tools: tools, reports: reports}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// TestFullStoryHeadless is the complete narrative the README promises,
// executed against real HTTP servers.
func TestFullStoryHeadless(t *testing.T) {
	s := newStack(t, jose.ES256)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var narration bytes.Buffer
	err := agent.Run(ctx, agent.Options{
		Resource:          s.tools.URL,
		Mode:              agent.ModeHeadless,
		ExchangeFor:       s.reports.URL,
		DemoRefreshReplay: true,
		Out:               &narration,
	})
	t.Logf("agent narration:%s", narration.String())
	if err != nil {
		t.Fatalf("scenario failed: %v", err)
	}

	// Assert the story hit its landmark steps.
	for _, landmark := range []string{
		"401 challenge points at",      // RFC 9728 discovery
		"client_id",                    // RFC 7591 registration
		"state and iss verified",       // RFC 9207 + CSRF protection
		"tokens do not cross resource", // RFC 8707 audience restriction
		"delegation is visible",        // RFC 8693 act claim downstream
		"reuse detected",               // rotation reuse detection
		"the theft burned the grant",   // family revocation
		"active=false",                 // RFC 7662 confirms revocation
		"All steps completed successfully",
	} {
		if !strings.Contains(narration.String(), landmark) {
			t.Errorf("narration missing landmark %q", landmark)
		}
	}
}

// TestFullStoryClientCredentials runs the machine-to-machine variant,
// including exchange of a client-credentials token, under EdDSA signing to
// cover the second algorithm end-to-end.
func TestFullStoryClientCredentials(t *testing.T) {
	s := newStack(t, jose.EdDSA)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var narration bytes.Buffer
	err := agent.Run(ctx, agent.Options{
		Resource:          s.tools.URL,
		Mode:              agent.ModeClientCredentials,
		ExchangeFor:       s.reports.URL,
		DemoRefreshReplay: true, // no refresh token in CC mode; the agent must skip gracefully
		Out:               &narration,
	})
	t.Logf("agent narration:%s", narration.String())
	if err != nil {
		t.Fatalf("scenario failed: %v", err)
	}
	if !strings.Contains(narration.String(), "issues no refresh token") {
		t.Error("agent should note that client_credentials has no refresh token")
	}
}
