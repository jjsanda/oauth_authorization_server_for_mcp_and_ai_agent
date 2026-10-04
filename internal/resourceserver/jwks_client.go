package resourceserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
)

// jwksClient resolves token kids to verification keys fetched from the
// authorization server. The jwks_uri itself is discovered through the
// server's RFC 8414 metadata rather than assumed.
//
// Refresh strategy: keys are cached for refreshTTL and lazily re-fetched on
// expiry, and an unknown kid triggers an immediate refresh (this is how a
// resource server picks up key rotation without restarts) — but never more
// often than minRefreshInterval, so a flood of garbage tokens with made-up
// kids cannot turn this server into a DoS amplifier against the
// authorization server. Fetches are single-flight: concurrent requests wait
// for one network call instead of issuing their own.
type jwksClient struct {
	issuer             string
	refreshTTL         time.Duration
	minRefreshInterval time.Duration
	http               *http.Client
	log                *slog.Logger

	fetchMu sync.Mutex // serializes network fetches (single-flight)

	mu          sync.RWMutex // guards the fields below
	keys        map[string]*jose.PublicKey
	lastFetch   time.Time
	lastAttempt time.Time
}

func newJWKSClient(issuer string, refreshTTL, minRefreshInterval time.Duration, log *slog.Logger) *jwksClient {
	return &jwksClient{
		issuer:             issuer,
		refreshTTL:         refreshTTL,
		minRefreshInterval: minRefreshInterval,
		http:               &http.Client{Timeout: 5 * time.Second},
		log:                log,
		keys:               make(map[string]*jose.PublicKey),
	}
}

// VerificationKey implements token.KeyResolver.
func (c *jwksClient) VerificationKey(kid string) (*jose.PublicKey, bool) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	fresh := time.Since(c.lastFetch) < c.refreshTTL
	c.mu.RUnlock()
	if ok && fresh {
		return key, true
	}

	// Cache miss or stale cache: refresh (single-flight, rate-limited).
	c.refresh()

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keys[kid]
	return key, ok
}

// refresh fetches the JWKS unless another goroutine just did or the rate
// limit applies.
func (c *jwksClient) refresh() {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	// A negative interval disables rate limiting (used in tests). Otherwise
	// skip if the previous attempt was too recent.
	if c.minRefreshInterval >= 0 {
		c.mu.RLock()
		sinceAttempt := time.Since(c.lastAttempt)
		hadAttempt := !c.lastAttempt.IsZero()
		c.mu.RUnlock()
		if hadAttempt && sinceAttempt < c.minRefreshInterval {
			return
		}
	}

	keys, err := c.fetch()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastAttempt = time.Now()
	if err != nil {
		// Keep serving the previous keys; transient AS unavailability must
		// not take down token verification for still-cached kids.
		c.log.Warn("jwks refresh failed", slog.String("issuer", c.issuer), slog.String("error", err.Error()))
		return
	}
	c.keys = keys
	c.lastFetch = time.Now()
}

// fetch discovers jwks_uri via RFC 8414 metadata and downloads the key set.
func (c *jwksClient) fetch() (map[string]*jose.PublicKey, error) {
	metaURL := c.issuer + "/.well-known/oauth-authorization-server"
	resp, err := c.http.Get(metaURL)
	if err != nil {
		return nil, fmt.Errorf("fetch AS metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AS metadata: %s returned %s", metaURL, resp.Status)
	}
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("parse AS metadata: %w", err)
	}
	// RFC 8414 §3.3: the issuer in the metadata must match the issuer the
	// metadata was resolved for.
	if meta.Issuer != c.issuer {
		return nil, fmt.Errorf("metadata issuer %q does not match expected %q", meta.Issuer, c.issuer)
	}

	jresp, err := c.http.Get(meta.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer jresp.Body.Close()
	if jresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS: %s returned %s", meta.JWKSURI, jresp.Status)
	}
	var set jose.JWKS
	if err := json.NewDecoder(jresp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := make(map[string]*jose.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		key, err := jose.ParseJWK(jwk)
		if err != nil {
			// Skip unusable entries rather than rejecting the whole set.
			c.log.Warn("skipping unparseable JWK", slog.String("kid", jwk.KID), slog.String("error", err.Error()))
			continue
		}
		// Index by the RFC 7638 thumbprint computed from the key material,
		// not by the advertised "kid". This authorization server always uses
		// thumbprint key IDs (and tokens carry them), so a JWKS that labels a
		// substituted key with a legitimate kid is ignored rather than
		// trusted.
		keys[key.Thumbprint()] = key
	}
	return keys, nil
}
