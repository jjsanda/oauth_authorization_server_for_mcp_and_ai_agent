package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// rpcEnvelope is a JSON-RPC 2.0 response envelope.
type rpcEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// CallResult carries an MCP call's HTTP status and decoded result.
type CallResult struct {
	Status int
	Result map[string]any
}

// callMCP performs one JSON-RPC request against a resource server with the
// given bearer token ("" for none).
func callMCP(ctx context.Context, hc *http.Client, resource, bearer, method string, params any) (*CallResult, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resource+"/mcp", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling %s on %s: %w", method, resource, err)
	}
	defer resp.Body.Close()

	out := &CallResult{Status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		return out, nil
	}
	var envelope rpcEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decoding %s response: %w", method, err)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("%s failed: %d %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	if len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, &out.Result); err != nil {
			return nil, fmt.Errorf("decoding %s result: %w", method, err)
		}
	}
	return out, nil
}
