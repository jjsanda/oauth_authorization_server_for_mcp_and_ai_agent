package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Registration is the credential set returned by RFC 7591 dynamic
// registration.
type Registration struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	GrantTypes   []string `json:"grant_types"`
	Scope        string   `json:"scope"`
	Resources    []string `json:"resources"`
}

// RegisterClient posts client metadata to the registration endpoint.
func RegisterClient(ctx context.Context, hc *http.Client, endpoint string, metadata map[string]any) (*Registration, error) {
	body, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registering client: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed: %s: %s", resp.Status, raw)
	}
	var reg Registration
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("parsing registration response: %w", err)
	}
	if reg.ClientID == "" {
		return nil, fmt.Errorf("registration response carries no client_id")
	}
	return &reg, nil
}
