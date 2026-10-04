package jose

import (
	"encoding/json"
	"sync"
)

// KeySet holds the authorization server's signing keys: one active key used
// for new signatures plus zero or more retired keys that remain published in
// the JWKS so that tokens issued before a rotation keep verifying until they
// expire.
type KeySet struct {
	mu      sync.RWMutex
	active  *SigningKey
	retired []*SigningKey
}

// NewKeySet creates a key set with a freshly generated active key.
func NewKeySet(alg Algorithm) (*KeySet, error) {
	key, err := GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	return &KeySet{active: key}, nil
}

// NewKeySetWithKey creates a key set around an existing key (e.g. one loaded
// from a PEM file so the issuer survives restarts).
func NewKeySetWithKey(key *SigningKey) *KeySet {
	return &KeySet{active: key}
}

// Active returns the current signing key.
func (ks *KeySet) Active() *SigningKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.active
}

// Rotate generates a new active key and keeps the previous one available for
// verification.
func (ks *KeySet) Rotate() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	next, err := GenerateKey(ks.active.Alg)
	if err != nil {
		return err
	}
	ks.retired = append(ks.retired, ks.active)
	ks.active = next
	return nil
}

// VerificationKey resolves a kid to a public key, searching the active key
// first and then retired keys.
func (ks *KeySet) VerificationKey(kid string) (*PublicKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.active.KID == kid {
		return ks.active.Public(), true
	}
	for _, k := range ks.retired {
		if k.KID == kid {
			return k.Public(), true
		}
	}
	return nil, false
}

// JWKS renders the public JSON Web Key Set (active key first).
func (ks *KeySet) JWKS() ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	set := JWKS{Keys: []JWK{ks.active.Public().JWK()}}
	for _, k := range ks.retired {
		set.Keys = append(set.Keys, k.Public().JWK())
	}
	return json.Marshal(set)
}
