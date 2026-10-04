package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
)

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// pkcePair is a fresh PKCE verifier and its S256 challenge (RFC 7636).
type pkcePair struct {
	Verifier  string
	Challenge string
}

func newPKCE() pkcePair {
	var buf [48]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("agent: crypto/rand unavailable: " + err.Error())
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf[:]) // 64 chars
	return pkcePair{Verifier: verifier, Challenge: oauth.ChallengeS256(verifier)}
}

func newState() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("agent: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// buildAuthorizeURL assembles the RFC 6749 §4.1.1 request with PKCE and
// resource indicators.
func buildAuthorizeURL(authzEndpoint, clientID, redirectURI, scope, state, challenge string, resources []string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	for _, r := range resources {
		q.Add("resource", r)
	}
	return authzEndpoint + "?" + q.Encode()
}

// callbackResult is what arrives at the loopback redirect.
type callbackResult struct {
	Code  string
	State string
	Iss   string
	Err   string
	Desc  string
}

// loopbackListener is the RFC 8252 §7.3 native-app redirect target: an
// ephemeral HTTP server on 127.0.0.1 with an OS-assigned port.
type loopbackListener struct {
	URL    string
	server *http.Server
	result chan callbackResult
}

func newLoopbackListener() (*loopbackListener, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &loopbackListener{
		URL:    fmt.Sprintf("http://%s/callback", ln.Addr().String()),
		result: make(chan callbackResult, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		select {
		case l.result <- callbackResult{
			Code:  q.Get("code"),
			State: q.Get("state"),
			Iss:   q.Get("iss"),
			Err:   q.Get("error"),
			Desc:  q.Get("error_description"),
		}:
		default: // duplicate callback; ignore
		}
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		_, _ = w.Write([]byte("<!DOCTYPE html><title>Done</title><body style=\"font-family:system-ui\">" +
			"<p>Authorization complete — you can return to the terminal.</p></body>"))
	})
	l.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = l.server.Serve(ln) }()
	return l, nil
}

// wait blocks until the callback arrives or ctx expires, then validates
// state (CSRF) and iss (RFC 9207 mix-up defense).
func (l *loopbackListener) wait(ctx context.Context, expectedState, expectedIss string) (string, error) {
	defer l.close()
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("waiting for authorization callback: %w", ctx.Err())
	case res := <-l.result:
		if res.Err != "" {
			return "", fmt.Errorf("authorization denied: %s: %s", res.Err, res.Desc)
		}
		if res.State != expectedState {
			return "", fmt.Errorf("state mismatch: possible CSRF, refusing the code")
		}
		if res.Iss != expectedIss {
			return "", fmt.Errorf("iss mismatch: expected %q got %q (RFC 9207)", expectedIss, res.Iss)
		}
		if res.Code == "" {
			return "", fmt.Errorf("callback carried no authorization code")
		}
		return res.Code, nil
	}
}

func (l *loopbackListener) close() {
	_ = l.server.Close()
}
