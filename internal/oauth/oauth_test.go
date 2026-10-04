package oauth

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPKCERFC7636Vector uses the worked example from RFC 7636 appendix B.
func TestPKCERFC7636Vector(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := ChallengeS256(verifier); got != challenge {
		t.Errorf("ChallengeS256 = %s, want %s", got, challenge)
	}
	if !VerifyS256(challenge, verifier) {
		t.Error("VerifyS256 rejected the RFC 7636 vector")
	}
	if VerifyS256(challenge, verifier[:len(verifier)-1]+"X") {
		t.Error("VerifyS256 accepted a wrong verifier")
	}
}

func TestVerifierValid(t *testing.T) {
	tests := []struct {
		name string
		v    string
		want bool
	}{
		{"min length", strings.Repeat("a", 43), true},
		{"max length", strings.Repeat("a", 128), true},
		{"too short", strings.Repeat("a", 42), false},
		{"too long", strings.Repeat("a", 129), false},
		{"unreserved punctuation", strings.Repeat("a", 39) + "-._~", true},
		{"illegal char", strings.Repeat("a", 42) + "!", false},
		{"illegal space", strings.Repeat("a", 42) + " ", false},
	}
	for _, tc := range tests {
		if got := VerifierValid(tc.v); got != tc.want {
			t.Errorf("%s: VerifierValid = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScopeParseFormat(t *testing.T) {
	got := ParseScope("  tools:read tools:invoke  tools:read ")
	if len(got) != 2 || got[0] != "tools:read" || got[1] != "tools:invoke" {
		t.Errorf("ParseScope = %v", got)
	}
	if ParseScope("") != nil {
		t.Error("ParseScope(\"\") should be nil")
	}
	if s := FormatScope(got); s != "tools:read tools:invoke" {
		t.Errorf("FormatScope = %q", s)
	}
}

func TestScopeIsSubset(t *testing.T) {
	super := []string{"tools:read", "tools:invoke"}
	if !ScopeIsSubset([]string{"tools:read"}, super) {
		t.Error("subset rejected")
	}
	if !ScopeIsSubset(nil, super) {
		t.Error("empty set is a subset of anything")
	}
	if ScopeIsSubset([]string{"tools:read", "admin"}, super) {
		t.Error("widening accepted")
	}
}

func TestSecretHashing(t *testing.T) {
	s := NewToken()
	if len(s) != 43 { // 32 bytes base64url unpadded
		t.Errorf("NewToken length = %d, want 43", len(s))
	}
	h := HashSecret(s)
	if !SecretEqual(h, s) {
		t.Error("SecretEqual rejected the original secret")
	}
	if SecretEqual(h, s+"x") {
		t.Error("SecretEqual accepted a different secret")
	}
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok := NewToken()
		if seen[tok] {
			t.Fatal("NewToken returned a duplicate")
		}
		seen[tok] = true
	}
}

func TestWriteErrorInvalidClient(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, NewError(ErrInvalidClient, "client authentication failed"))
	if rec.Code != 401 {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want Basic challenge", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	var body Error
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != ErrInvalidClient {
		t.Errorf("error code = %s", body.Code)
	}
}

func TestWriteErrorMapsUnknownErrorsToServerError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, errors.New("database on fire"))
	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "database") {
		t.Error("internal error details leaked to client")
	}
}

func TestWriteErrorBadRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, NewError(ErrInvalidTarget, "unknown resource %q", "http://evil.example"))
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
