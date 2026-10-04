// Package memory provides the in-memory store.Store implementation used by
// the demo deployment and the test suite. All state transitions that the
// protocol requires to be atomic (one-time code redemption, refresh token
// rotation) happen under a single mutex.
package memory

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// Store is a mutex-guarded in-memory implementation of store.Store.
type Store struct {
	mu sync.Mutex

	clients   map[string]*store.Client
	users     map[string]*store.User
	usernames map[string]string // username → user ID

	authCodes map[string]*store.AuthCode // hex(codeHash) → code

	tokens map[string]*store.AccessTokenRecord // jti → record

	families     map[string]*store.RefreshTokenFamily // family ID → family
	refreshIndex map[string]string                    // hex(member hash) → family ID
}

// New creates an empty store.
func New() *Store {
	return &Store{
		clients:      make(map[string]*store.Client),
		users:        make(map[string]*store.User),
		usernames:    make(map[string]string),
		authCodes:    make(map[string]*store.AuthCode),
		tokens:       make(map[string]*store.AccessTokenRecord),
		families:     make(map[string]*store.RefreshTokenFamily),
		refreshIndex: make(map[string]string),
	}
}

var _ store.Store = (*Store)(nil)

func key(hash []byte) string { return hex.EncodeToString(hash) }

// GetClient implements store.ClientStore.
func (s *Store) GetClient(id string) (*store.Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, false
	}
	return c.Clone(), true
}

// PutClient implements store.ClientStore.
func (s *Store) PutClient(c *store.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c.Clone()
}

// GetUser implements store.UserStore.
func (s *Store) GetUser(id string) (*store.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// GetUserByUsername implements store.UserStore.
func (s *Store) GetUserByUsername(username string) (*store.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.usernames[username]
	if !ok {
		return nil, false
	}
	cp := *s.users[id]
	return &cp, true
}

// PutUser implements store.UserStore.
func (s *Store) PutUser(u *store.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *u
	s.users[u.ID] = &cp
	s.usernames[u.Username] = u.ID
}

// PutAuthCode implements store.AuthCodeStore.
func (s *Store) PutAuthCode(c *store.AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[key(c.CodeHash)] = c.Clone()
}

// ConsumeAuthCode implements store.AuthCodeStore.
func (s *Store) ConsumeAuthCode(codeHash []byte) (*store.AuthCode, store.ConsumeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.authCodes[key(codeHash)]
	if !ok || time.Now().After(c.ExpiresAt) {
		return nil, store.ConsumeNotFound
	}
	if c.Used {
		return c.Clone(), store.ConsumeReplayed
	}
	c.Used = true
	return c.Clone(), store.ConsumeOK
}

// RecordIssued implements store.AuthCodeStore.
func (s *Store) RecordIssued(codeHash []byte, jtis []string, familyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.authCodes[key(codeHash)]; ok {
		c.IssuedJTIs = append(c.IssuedJTIs, jtis...)
		c.FamilyID = familyID
	}
}

// PutToken implements store.TokenStore.
func (s *Store) PutToken(t *store.AccessTokenRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.JTI] = t.Clone()
}

// GetToken implements store.TokenStore.
func (s *Store) GetToken(jti string) (*store.AccessTokenRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[jti]
	if !ok {
		return nil, false
	}
	return t.Clone(), true
}

// RevokeToken implements store.TokenStore.
func (s *Store) RevokeToken(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[jti]
	if !ok {
		return false
	}
	t.Revoked = true
	return true
}

// RevokeFamilyTokens implements store.TokenStore.
func (s *Store) RevokeFamilyTokens(familyID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeFamilyTokensLocked(familyID)
}

func (s *Store) revokeFamilyTokensLocked(familyID string) int {
	if familyID == "" {
		return 0
	}
	n := 0
	for _, t := range s.tokens {
		if t.FamilyID == familyID && !t.Revoked {
			t.Revoked = true
			n++
		}
	}
	return n
}

// PutFamily implements store.RefreshFamilyStore.
func (s *Store) PutFamily(f *store.RefreshTokenFamily) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.families[f.ID] = f.Clone()
	for _, m := range f.Members {
		s.refreshIndex[key(m.Hash)] = f.ID
	}
}

// GetFamily implements store.RefreshFamilyStore.
func (s *Store) GetFamily(id string) (*store.RefreshTokenFamily, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.families[id]
	if !ok {
		return nil, false
	}
	return f.Clone(), true
}

// Redeem implements store.RefreshFamilyStore. See the interface contract for
// the state machine; everything below happens atomically.
func (s *Store) Redeem(tokenHash, newHash []byte, now time.Time, idleTTL time.Duration) (*store.RefreshTokenFamily, store.RedeemStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()

	famID, ok := s.refreshIndex[key(tokenHash)]
	if !ok {
		return nil, store.RedeemNotFound
	}
	f := s.families[famID]

	if f.Revoked || now.After(f.AbsoluteExpiry) || now.After(f.IdleExpiry) {
		return f.Clone(), store.RedeemDead
	}

	if key(tokenHash) != key(f.CurrentHash) {
		// A superseded generation was presented: someone is replaying an old
		// refresh token. Kill the family and everything it issued.
		f.Revoked = true
		f.RevokedReason = store.RevokedReasonReuse
		s.revokeFamilyTokensLocked(f.ID)
		return f.Clone(), store.RedeemReused
	}

	f.Generation++
	member := store.RefreshTokenMember{
		Hash:       append([]byte(nil), newHash...),
		Generation: f.Generation,
		IssuedAt:   now,
	}
	f.Members = append(f.Members, member)
	f.CurrentHash = member.Hash
	f.IdleExpiry = now.Add(idleTTL)
	s.refreshIndex[key(newHash)] = f.ID
	return f.Clone(), store.RedeemOK
}

// RevokeFamily implements store.RefreshFamilyStore.
func (s *Store) RevokeFamily(id, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.families[id]
	if !ok {
		return false
	}
	if !f.Revoked {
		f.Revoked = true
		f.RevokedReason = reason
	}
	return true
}

// FindFamilyByTokenHash implements store.RefreshFamilyStore.
func (s *Store) FindFamilyByTokenHash(tokenHash []byte) (*store.RefreshTokenFamily, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	famID, ok := s.refreshIndex[key(tokenHash)]
	if !ok {
		return nil, false
	}
	return s.families[famID].Clone(), true
}

// StartJanitor launches a background sweep that drops expired authorization
// codes, access-token records, and refresh families, keeping the demo
// process from growing without bound. It stops when ctx is canceled.
func (s *Store) StartJanitor(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.sweep(now)
			}
		}
	}()
}

func (s *Store) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.authCodes {
		// Keep redeemed codes a little past expiry so replays of a
		// just-expired code are still detected as replays.
		if now.After(c.ExpiresAt.Add(5 * time.Minute)) {
			delete(s.authCodes, k)
		}
	}
	for jti, t := range s.tokens {
		if now.After(t.ExpiresAt.Add(time.Hour)) {
			delete(s.tokens, jti)
		}
	}
	for id, f := range s.families {
		if now.After(f.AbsoluteExpiry.Add(time.Hour)) || now.After(f.IdleExpiry.Add(24*time.Hour)) {
			for _, m := range f.Members {
				delete(s.refreshIndex, key(m.Hash))
			}
			delete(s.families, id)
		}
	}
}
