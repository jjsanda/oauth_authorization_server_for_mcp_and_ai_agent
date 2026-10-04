package token

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
)

const (
	testIssuer   = "https://as.example"
	testResource = "https://rs.example"
)

func newIssuer(t *testing.T) (*Issuer, *jose.KeySet) {
	t.Helper()
	ks, err := jose.NewKeySet(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	return &Issuer{Issuer: testIssuer, Keys: ks}, ks
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	iss, ks := newIssuer(t)
	tok, claims, err := iss.Issue(IssueParams{
		Subject:  "user:alice",
		ClientID: "client-1",
		Audience: []string{testResource},
		Scope:    []string{"tools:read", "tools:invoke"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Issuer: testIssuer, Keys: ks, Audience: testResource}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "user:alice" || got.ClientID != "client-1" {
		t.Errorf("claims = %+v", got)
	}
	if got.JTI == "" || got.JTI != claims.JTI {
		t.Error("jti missing or mismatched")
	}
	if !got.HasScope("tools:invoke") || got.HasScope("admin") {
		t.Error("scope handling broken")
	}
	if got.Actor != nil {
		t.Error("unexpected act claim")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	iss, ks := newIssuer(t)
	tok, _, _ := iss.Issue(IssueParams{Subject: "user:alice", Audience: []string{testResource}})
	v := &Verifier{Issuer: testIssuer, Keys: ks, Audience: "https://other.example"}
	if _, err := v.Verify(tok); !errors.Is(err, ErrAudience) {
		t.Errorf("err = %v, want ErrAudience", err)
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	iss, ks := newIssuer(t)
	tok, _, _ := iss.Issue(IssueParams{Subject: "user:alice", Audience: []string{testResource}})
	v := &Verifier{Issuer: "https://impostor.example", Keys: ks, Audience: testResource}
	if _, err := v.Verify(tok); !errors.Is(err, ErrIssuer) {
		t.Errorf("err = %v, want ErrIssuer", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	iss, ks := newIssuer(t)
	tok, _, _ := iss.Issue(IssueParams{Subject: "user:alice", Audience: []string{testResource}})
	future := func() time.Time { return time.Now().Add(DefaultAccessTokenTTL + time.Minute) }
	v := &Verifier{Issuer: testIssuer, Keys: ks, Audience: testResource, Now: future}
	if _, err := v.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyLeewayAbsorbsSmallSkew(t *testing.T) {
	iss, ks := newIssuer(t)
	tok, claims, _ := iss.Issue(IssueParams{Subject: "user:alice", Audience: []string{testResource}})
	// 10 seconds past expiry is inside the 30s leeway.
	justPast := func() time.Time { return time.Unix(claims.ExpiresAt, 0).Add(10 * time.Second) }
	v := &Verifier{Issuer: testIssuer, Keys: ks, Audience: testResource, Now: justPast}
	if _, err := v.Verify(tok); err != nil {
		t.Errorf("token inside leeway rejected: %v", err)
	}
}

// TestVerifyRejectsNonAccessTokenTyp ensures ID tokens or other JWTs signed
// by the same server cannot be replayed as access tokens (RFC 9068 §4).
func TestVerifyRejectsNonAccessTokenTyp(t *testing.T) {
	_, ks := newIssuer(t)
	payload, _ := json.Marshal(Claims{
		Issuer: testIssuer, Subject: "user:alice",
		Audience:  Audience{testResource},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	tok, err := jose.SignCompact(ks.Active(), "JWT", payload)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Issuer: testIssuer, Keys: ks, Audience: testResource}
	if _, err := v.Verify(tok); !errors.Is(err, ErrTokenType) {
		t.Errorf("err = %v, want ErrTokenType", err)
	}
}

func TestActClaimRoundTrip(t *testing.T) {
	iss, ks := newIssuer(t)
	tok, _, _ := iss.Issue(IssueParams{
		Subject:  "user:alice",
		ClientID: "downstream",
		Audience: []string{testResource},
		ActorSub: "client:agent-cli",
	})
	v := &Verifier{Issuer: testIssuer, Keys: ks, Audience: testResource}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Actor == nil || got.Actor.Subject != "client:agent-cli" {
		t.Errorf("act = %+v, want sub=client:agent-cli", got.Actor)
	}
}

func TestAudienceUnmarshalAcceptsStringAndArray(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"aud":"https://one.example"}`), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "https://one.example" {
		t.Errorf("string aud = %v", c.Audience)
	}
	if err := json.Unmarshal([]byte(`{"aud":["a","b"]}`), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Audience) != 2 {
		t.Errorf("array aud = %v", c.Audience)
	}
}

func TestAudienceMarshalAlwaysArray(t *testing.T) {
	out, err := json.Marshal(Claims{Audience: Audience{"https://one.example"}})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(out, &raw)
	if raw["aud"][0] != '[' {
		t.Errorf("aud marshaled as %s, want array form", raw["aud"])
	}
}
