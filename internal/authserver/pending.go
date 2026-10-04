package authserver

import (
	"sync"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
)

// pendingAuthorization is a validated /authorize request parked while the
// user logs in and consents. Keeping it server-side under an opaque ID means
// the original parameters never round-trip through the browser and cannot be
// tampered with between steps.
type pendingAuthorization struct {
	ID            string
	ClientID      string
	ClientName    string
	RedirectURI   string
	Scope         []string
	Resources     []string
	State         string
	CodeChallenge string
	ExpiresAt     time.Time
}

type pendingAuthorizations struct {
	ttl time.Duration

	mu   sync.Mutex
	reqs map[string]*pendingAuthorization
}

func newPendingAuthorizations(ttl time.Duration) *pendingAuthorizations {
	return &pendingAuthorizations{ttl: ttl, reqs: make(map[string]*pendingAuthorization)}
}

// put parks a request and returns its opaque ID.
func (p *pendingAuthorizations) put(req *pendingAuthorization) string {
	req.ID = oauth.NewToken()
	req.ExpiresAt = time.Now().Add(p.ttl)
	p.mu.Lock()
	defer p.mu.Unlock()
	// Opportunistically drop expired entries; the map stays tiny.
	for id, r := range p.reqs {
		if time.Now().After(r.ExpiresAt) {
			delete(p.reqs, id)
		}
	}
	p.reqs[req.ID] = req
	return req.ID
}

// get returns a live pending request without consuming it.
func (p *pendingAuthorizations) get(id string) (*pendingAuthorization, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.reqs[id]
	if !ok || time.Now().After(r.ExpiresAt) {
		return nil, false
	}
	return r, true
}

// consume removes and returns a pending request; each authorization request
// can produce at most one code.
func (p *pendingAuthorizations) consume(id string) (*pendingAuthorization, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.reqs[id]
	if !ok || time.Now().After(r.ExpiresAt) {
		return nil, false
	}
	delete(p.reqs, id)
	return r, true
}
