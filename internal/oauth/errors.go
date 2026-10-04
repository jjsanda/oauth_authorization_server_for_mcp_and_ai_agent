// Package oauth holds protocol vocabulary shared by the authorization
// server, resource server, and client: error codes and the RFC 6749 §5.2
// error response format, PKCE (RFC 7636), scope handling, and generation and
// hashing of high-entropy secrets.
package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// OAuth error codes (RFC 6749 §4.1.2.1 and §5.2, RFC 8707 §2, RFC 7591 §3.2.2).
const (
	ErrInvalidRequest          = "invalid_request"
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrInvalidScope            = "invalid_scope"
	ErrInvalidTarget           = "invalid_target"
	ErrAccessDenied            = "access_denied"
	ErrServerError             = "server_error"
	ErrInvalidClientMetadata   = "invalid_client_metadata"
	ErrInvalidRedirectURI      = "invalid_redirect_uri"
)

// Error is a protocol error that can be rendered as an RFC 6749 §5.2 JSON
// error response.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// NewError builds a protocol error with a formatted description.
func NewError(code, format string, args ...any) *Error {
	return &Error{Code: code, Description: fmt.Sprintf(format, args...)}
}

// AsError coerces any error into an *Error, mapping unexpected failures to
// server_error without leaking internals to the client.
func AsError(err error) *Error {
	if oe, ok := err.(*Error); ok {
		return oe
	}
	return &Error{Code: ErrServerError, Description: "internal error"}
}

// statusFor maps an error code to the HTTP status RFC 6749 §5.2 assigns it.
func statusFor(code string) int {
	switch code {
	case ErrInvalidClient:
		return http.StatusUnauthorized
	case ErrServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// WriteError renders err as an RFC 6749 §5.2 JSON error response. For
// invalid_client it responds 401 with a WWW-Authenticate challenge as the
// spec requires when client authentication was attempted via the
// Authorization header.
func WriteError(w http.ResponseWriter, err error) {
	oe := AsError(err)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if oe.Code == ErrInvalidClient {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth-token-endpoint", charset="UTF-8"`)
	}
	w.WriteHeader(statusFor(oe.Code))
	_ = json.NewEncoder(w).Encode(oe)
}
