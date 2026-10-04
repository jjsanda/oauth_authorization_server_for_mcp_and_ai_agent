package jose

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{ES256, EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			payload := []byte(`{"sub":"user:alice"}`)
			tok, err := SignCompact(key, "at+jwt", payload)
			if err != nil {
				t.Fatalf("SignCompact: %v", err)
			}
			hdr, got, err := VerifyCompact(tok, singleKey(key.Public()))
			if err != nil {
				t.Fatalf("VerifyCompact: %v", err)
			}
			if hdr.Alg != alg || hdr.Typ != "at+jwt" || hdr.KID != key.KID {
				t.Errorf("header = %+v", hdr)
			}
			if string(got) != string(payload) {
				t.Errorf("payload = %s, want %s", got, payload)
			}
		})
	}
}

func singleKey(pub *PublicKey) KeyResolver {
	return func(kid string) (*PublicKey, bool) {
		if kid == pub.KID {
			return pub, true
		}
		return nil, false
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key, _ := GenerateKey(ES256)
	tok, _ := SignCompact(key, "at+jwt", []byte(`{"scope":"tools:read"}`))
	parts := strings.Split(tok, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"scope":"tools:read admin"}`))
	tampered := parts[0] + "." + forged + "." + parts[2]
	if _, _, err := VerifyCompact(tampered, singleKey(key.Public())); err == nil {
		t.Fatal("tampered token verified")
	}
}

func TestVerifyRejectsUnknownKID(t *testing.T) {
	key, _ := GenerateKey(ES256)
	other, _ := GenerateKey(ES256)
	tok, _ := SignCompact(key, "at+jwt", []byte(`{}`))
	if _, _, err := VerifyCompact(tok, singleKey(other.Public())); err == nil {
		t.Fatal("token with unknown kid verified")
	}
}

// TestVerifyRejectsAlgorithmMismatch pins the algorithm to the key record:
// a token whose header names a different algorithm than the stored key must
// fail even if the kid matches.
func TestVerifyRejectsAlgorithmMismatch(t *testing.T) {
	key, _ := GenerateKey(ES256)
	tok, _ := SignCompact(key, "at+jwt", []byte(`{}`))
	pub := key.Public()
	pub.Alg = EdDSA // simulate a key record pinned to a different algorithm
	if _, _, err := VerifyCompact(tok, singleKey(pub)); err == nil {
		t.Fatal("algorithm mismatch accepted")
	}
}

func TestVerifyRejectsNoneAlgorithm(t *testing.T) {
	key, _ := GenerateKey(ES256)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + key.KID + `"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user:alice"}`))
	if _, _, err := VerifyCompact(header+"."+payload+".", singleKey(key.Public())); err == nil {
		t.Fatal("alg=none accepted")
	}
}

// TestES256SignatureIsRawP1363 guards the classic JWS pitfall: ECDSA
// signatures must be the fixed 64-byte R||S concatenation (RFC 7518 §3.4),
// not ASN.1 DER. A DER signature starts with 0x30 and has variable length.
func TestES256SignatureIsRawP1363(t *testing.T) {
	key, _ := GenerateKey(ES256)
	tok, _ := SignCompact(key, "at+jwt", []byte(`{}`))
	sig, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("ES256 signature length = %d, want 64 (raw R||S)", len(sig))
	}
}

func TestES256VerifyRejectsWrongLengthSignature(t *testing.T) {
	key, _ := GenerateKey(ES256)
	tok, _ := SignCompact(key, "at+jwt", []byte(`{}`))
	parts := strings.Split(tok, ".")
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 63))
	if _, _, err := VerifyCompact(parts[0]+"."+parts[1]+"."+short, singleKey(key.Public())); err == nil {
		t.Fatal("63-byte signature accepted")
	}
}

// TestEd25519ThumbprintRFC8037Vector uses the JWK thumbprint example from
// RFC 8037 appendix A.3.
func TestEd25519ThumbprintRFC8037Vector(t *testing.T) {
	xb, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	pub := &PublicKey{Alg: EdDSA, ed: ed25519.PublicKey(xb)}
	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	if got := pub.Thumbprint(); got != want {
		t.Errorf("Thumbprint() = %s, want %s", got, want)
	}
}

func TestKeySetRotation(t *testing.T) {
	ks, err := NewKeySet(ES256)
	if err != nil {
		t.Fatal(err)
	}
	oldKID := ks.Active().KID
	tok, _ := SignCompact(ks.Active(), "at+jwt", []byte(`{}`))

	if err := ks.Rotate(); err != nil {
		t.Fatal(err)
	}
	if ks.Active().KID == oldKID {
		t.Fatal("rotation kept the same key")
	}
	// Tokens signed before rotation must keep verifying via the retired key.
	if _, _, err := VerifyCompact(tok, ks.VerificationKey); err != nil {
		t.Errorf("pre-rotation token no longer verifies: %v", err)
	}
	jwksJSON, err := ks.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseJWKS(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys after one rotation, want 2", len(set.Keys))
	}
	if set.Keys[0].KID != ks.Active().KID {
		t.Error("active key is not listed first in JWKS")
	}
}

// TestJWKPublishParseVerify exercises the full resource-server path: publish
// a JWKS, parse it on the other side, and verify a token with the parsed key.
func TestJWKPublishParseVerify(t *testing.T) {
	for _, alg := range []Algorithm{ES256, EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			key, _ := GenerateKey(alg)
			tok, _ := SignCompact(key, "at+jwt", []byte(`{"ok":true}`))

			raw, _ := json.Marshal(JWKS{Keys: []JWK{key.Public().JWK()}})
			set, err := ParseJWKS(raw)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseJWK(set.Keys[0])
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Thumbprint() != key.KID {
				t.Error("thumbprint changed across publish/parse")
			}
			if _, _, err := VerifyCompact(tok, singleKey(parsed)); err != nil {
				t.Errorf("verification with parsed JWK failed: %v", err)
			}
		})
	}
}

func TestParseJWKRejectsOffCurvePoint(t *testing.T) {
	key, _ := GenerateKey(ES256)
	j := key.Public().JWK()
	j.Y = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // not on curve
	if _, err := ParseJWK(j); err == nil {
		t.Fatal("off-curve point accepted")
	}
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{ES256, EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			key, _ := GenerateKey(alg)
			pemBytes, err := key.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := ParsePrivateKeyPEM(pemBytes)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.KID != key.KID || loaded.Alg != key.Alg {
				t.Errorf("loaded key differs: kid %s vs %s", loaded.KID, key.KID)
			}
		})
	}
}
