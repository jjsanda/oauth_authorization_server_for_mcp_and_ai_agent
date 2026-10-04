package resourceserver

import (
	"encoding/json"
	"net/http"
	"time"
)

// A deliberately small JSON-RPC 2.0 surface in the shape MCP servers expose:
// tools/list enumerates the available tools, tools/call invokes one. The
// tools themselves are trivial — the point of this server is the
// authorization boundary in front of them.

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// JSON-RPC 2.0 error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

type toolDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

var toolCatalog = []toolDescriptor{
	{Name: "echo", Description: "Returns the provided message unchanged."},
	{Name: "time", Description: "Returns the server's current time in RFC 3339 format."},
	{Name: "whoami", Description: "Returns the identity and authorization context of the caller as seen by this server."},
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	resp.JSONRPC = "2.0"
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRPC dispatches tools/list and tools/call with per-method scopes.
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, rpcResponse{Error: &rpcError{Code: rpcParseError, Message: "invalid JSON"}})
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, rpcResponse{ID: req.ID, Error: &rpcError{Code: rpcInvalidRequest, Message: "not a JSON-RPC 2.0 request"}})
		return
	}

	switch req.Method {
	case "tools/list":
		if !s.requireScope(w, r, s.cfg.ScopeList) {
			return
		}
		writeRPC(w, rpcResponse{ID: req.ID, Result: map[string]any{"tools": toolCatalog}})
	case "tools/call":
		if !s.requireScope(w, r, s.cfg.ScopeCall) {
			return
		}
		s.handleToolCall(w, r, req)
	default:
		writeRPC(w, rpcResponse{ID: req.ID, Error: &rpcError{Code: rpcMethodNotFound, Message: "unknown method " + req.Method}})
	}
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeRPC(w, rpcResponse{ID: req.ID, Error: &rpcError{Code: rpcInvalidParams, Message: "params must include a tool name"}})
		return
	}

	switch params.Name {
	case "echo":
		var args struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			writeRPC(w, rpcResponse{ID: req.ID, Error: &rpcError{Code: rpcInvalidParams, Message: "echo requires a message argument"}})
			return
		}
		writeRPC(w, rpcResponse{ID: req.ID, Result: map[string]any{"message": args.Message}})
	case "time":
		writeRPC(w, rpcResponse{ID: req.ID, Result: map[string]any{"time": time.Now().Format(time.RFC3339)}})
	case "whoami":
		claims := ClaimsFrom(r.Context())
		result := map[string]any{
			"resource":  s.cfg.Resource,
			"subject":   claims.Subject,
			"client_id": claims.ClientID,
			"scope":     claims.Scope,
		}
		if claims.Actor != nil {
			// Present after a token exchange: the subject is the user, the
			// actor is the service acting on their behalf.
			result["actor"] = claims.Actor.Subject
		}
		writeRPC(w, rpcResponse{ID: req.ID, Result: result})
	default:
		writeRPC(w, rpcResponse{ID: req.ID, Error: &rpcError{Code: rpcMethodNotFound, Message: "unknown tool " + params.Name}})
	}
}
