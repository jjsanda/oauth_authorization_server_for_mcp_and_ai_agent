package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TokenResponse is an RFC 6749 §5.1 (and RFC 8693 §2.2.1) success document.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token"`
	IssuedTokenType string `json:"issued_token_type"`
}

// TokenError is an RFC 6749 §5.2 error document, kept distinct so scenario
// steps can assert on specific protocol errors.
type TokenError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

// Error implements the error interface.
func (e *TokenError) Error() string {
	return fmt.Sprintf("token endpoint: %d %s: %s", e.Status, e.Code, e.Description)
}

// RequestToken posts a grant to the token endpoint. Confidential clients
// authenticate with client_secret_basic; public clients send client_id in
// the form. A protocol error is returned as *TokenError.
func RequestToken(ctx context.Context, hc *http.Client, endpoint string, form url.Values, clientID, clientSecret string) (*TokenResponse, error) {
	// Copy so we never mutate the caller's map.
	body := url.Values{}
	for k, v := range form {
		body[k] = v
	}
	form = body
	if clientSecret == "" {
		form.Set("client_id", clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		// RFC 6749 §2.3.1: credentials are form-urlencoded inside Basic auth.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		te := &TokenError{Status: resp.StatusCode}
		if err := json.Unmarshal(raw, te); err != nil || te.Code == "" {
			return nil, fmt.Errorf("token request failed: %s: %s", resp.Status, raw)
		}
		return nil, te
	}
	var tr TokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, fmt.Errorf("unexpected token_type %q", tr.TokenType)
	}
	return &tr, nil
}

// decodeClaims extracts a JWT's payload without verifying it — the agent is
// not the token's audience; it decodes purely to narrate what it received.
func decodeClaims(jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT")
	}
	payload, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
