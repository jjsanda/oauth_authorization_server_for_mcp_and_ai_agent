package memory

import (
	"sync"
	"testing"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

func TestClientRoundTripAndIsolation(t *testing.T) {
	s := New()
	c := &store.Client{ID: "c1", Name: "Test", RedirectURIs: []string{"https://app.example/cb"}}
	s.PutClient(c)

	got, ok := s.GetClient("c1")
	if !ok || got.Name != "Test" {
		t.Fatalf("GetClient = %+v, %v", got, ok)
	}
	// Mutating the returned copy must not leak into the store.
	got.RedirectURIs[0] = "https://evil.example"
	again, _ := s.GetClient("c1")
	if again.RedirectURIs[0] != "https://app.example/cb" {
		t.Error("stored client mutated through returned pointer")
	}
}

func TestUserLookupAndPassword(t *testing.T) {
	s := New()
	u := store.NewUser("u1", "alice", "password", []byte("salt"))
	s.PutUser(u)
	got, ok := s.GetUserByUsername("alice")
	if !ok || got.ID != "u1" {
		t.Fatalf("GetUserByUsername = %+v, %v", got, ok)
	}
	if !got.PasswordMatches("password") || got.PasswordMatches("wrong") {
		t.Error("password verification broken")
	}
}

func newCode(hash []byte, ttl time.Duration) *store.AuthCode {
	return &store.AuthCode{
		CodeHash:      hash,
		ClientID:      "c1",
		UserID:        "u1",
		RedirectURI:   "https://app.example/cb",
		Scope:         []string{"tools:read"},
		CodeChallenge: "challenge",
		ExpiresAt:     time.Now().Add(ttl),
	}
}

func TestConsumeAuthCodeOnceThenReplay(t *testing.T) {
	s := New()
	hash := oauth.HashSecret("the-code")
	s.PutAuthCode(newCode(hash, time.Minute))

	first, res := s.ConsumeAuthCode(hash)
	if res != store.ConsumeOK || first == nil {
		t.Fatalf("first consume = %v", res)
	}
	s.RecordIssued(hash, []string{"jti-1"}, "fam-1")

	replay, res := s.ConsumeAuthCode(hash)
	if res != store.ConsumeReplayed {
		t.Fatalf("second consume = %v, want ConsumeReplayed", res)
	}
	if len(replay.IssuedJTIs) != 1 || replay.IssuedJTIs[0] != "jti-1" || replay.FamilyID != "fam-1" {
		t.Errorf("replay snapshot missing issued artifacts: %+v", replay)
	}
}

func TestConsumeAuthCodeExpired(t *testing.T) {
	s := New()
	hash := oauth.HashSecret("old-code")
	s.PutAuthCode(newCode(hash, -time.Second))
	if _, res := s.ConsumeAuthCode(hash); res != store.ConsumeNotFound {
		t.Errorf("expired consume = %v, want ConsumeNotFound", res)
	}
}

// TestConsumeAuthCodeConcurrent proves single-use holds under contention:
// exactly one of N concurrent redeemers wins.
func TestConsumeAuthCodeConcurrent(t *testing.T) {
	s := New()
	hash := oauth.HashSecret("contended-code")
	s.PutAuthCode(newCode(hash, time.Minute))

	const n = 32
	var wg sync.WaitGroup
	results := make([]store.ConsumeResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = s.ConsumeAuthCode(hash)
		}(i)
	}
	wg.Wait()
	oks := 0
	for _, r := range results {
		if r == store.ConsumeOK {
			oks++
		}
	}
	if oks != 1 {
		t.Errorf("%d concurrent consumers succeeded, want exactly 1", oks)
	}
}

func newFamily(id string, currentHash []byte) *store.RefreshTokenFamily {
	now := time.Now()
	return &store.RefreshTokenFamily{
		ID:             id,
		ClientID:       "c1",
		UserID:         "u1",
		Scope:          []string{"tools:read"},
		Resources:      []string{"https://rs.example"},
		Members:        []store.RefreshTokenMember{{Hash: currentHash, Generation: 1, IssuedAt: now}},
		CurrentHash:    currentHash,
		Generation:     1,
		IdleExpiry:     now.Add(8 * time.Hour),
		AbsoluteExpiry: now.Add(30 * 24 * time.Hour),
	}
}

func TestRedeemRotatesAndDetectsReuse(t *testing.T) {
	s := New()
	gen1 := oauth.HashSecret("refresh-gen1")
	gen2 := oauth.HashSecret("refresh-gen2")
	gen3 := oauth.HashSecret("refresh-gen3")
	s.PutFamily(newFamily("fam-1", gen1))
	s.PutToken(&store.AccessTokenRecord{JTI: "jti-1", FamilyID: "fam-1", ExpiresAt: time.Now().Add(time.Hour)})

	// Normal rotation: gen1 → gen2.
	f, status := s.Redeem(gen1, gen2, time.Now(), 8*time.Hour)
	if status != store.RedeemOK || f.Generation != 2 {
		t.Fatalf("rotation: status=%v gen=%d", status, f.Generation)
	}

	// gen2 is now current and redeems fine.
	if _, status := s.Redeem(gen2, gen3, time.Now(), 8*time.Hour); status != store.RedeemOK {
		t.Fatalf("second rotation failed: %v", status)
	}

	// Replaying gen1 (superseded) must kill the family...
	f, status = s.Redeem(gen1, oauth.HashSecret("x"), time.Now(), 8*time.Hour)
	if status != store.RedeemReused {
		t.Fatalf("replay status = %v, want RedeemReused", status)
	}
	if !f.Revoked || f.RevokedReason != store.RevokedReasonReuse {
		t.Errorf("family not revoked on reuse: %+v", f)
	}
	// ...revoke the family's access tokens...
	tok, _ := s.GetToken("jti-1")
	if !tok.Revoked {
		t.Error("family access token survived reuse detection")
	}
	// ...and leave even the newest member unredeemable.
	if _, status := s.Redeem(gen3, oauth.HashSecret("y"), time.Now(), 8*time.Hour); status != store.RedeemDead {
		t.Errorf("post-revocation redeem = %v, want RedeemDead", status)
	}
}

func TestRedeemUnknownAndExpired(t *testing.T) {
	s := New()
	if _, status := s.Redeem(oauth.HashSecret("nope"), oauth.HashSecret("new"), time.Now(), time.Hour); status != store.RedeemNotFound {
		t.Errorf("unknown hash = %v, want RedeemNotFound", status)
	}

	hash := oauth.HashSecret("stale")
	f := newFamily("fam-idle", hash)
	f.IdleExpiry = time.Now().Add(-time.Minute)
	s.PutFamily(f)
	if _, status := s.Redeem(hash, oauth.HashSecret("new"), time.Now(), time.Hour); status != store.RedeemDead {
		t.Errorf("idle-expired family = %v, want RedeemDead", status)
	}

	hash2 := oauth.HashSecret("ancient")
	f2 := newFamily("fam-abs", hash2)
	f2.AbsoluteExpiry = time.Now().Add(-time.Minute)
	s.PutFamily(f2)
	if _, status := s.Redeem(hash2, oauth.HashSecret("new"), time.Now(), time.Hour); status != store.RedeemDead {
		t.Errorf("absolutely-expired family = %v, want RedeemDead", status)
	}
}

// TestRedeemConcurrent: under contention on the same current member, exactly
// one caller rotates; the rest see reuse (their presented member is retired
// the moment the winner rotates) or a dead family thereafter.
func TestRedeemConcurrent(t *testing.T) {
	s := New()
	cur := oauth.HashSecret("contended-refresh")
	s.PutFamily(newFamily("fam-c", cur))

	const n = 16
	var wg sync.WaitGroup
	statuses := make([]store.RedeemStatus, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, statuses[i] = s.Redeem(cur, oauth.HashSecret(oauth.NewToken()), time.Now(), time.Hour)
		}(i)
	}
	wg.Wait()
	oks := 0
	for _, st := range statuses {
		if st == store.RedeemOK {
			oks++
		}
	}
	if oks != 1 {
		t.Errorf("%d concurrent redeemers rotated, want exactly 1", oks)
	}
}

func TestRevokeFamilyAndTokens(t *testing.T) {
	s := New()
	hash := oauth.HashSecret("r1")
	s.PutFamily(newFamily("fam-r", hash))
	s.PutToken(&store.AccessTokenRecord{JTI: "a", FamilyID: "fam-r", ExpiresAt: time.Now().Add(time.Hour)})
	s.PutToken(&store.AccessTokenRecord{JTI: "b", FamilyID: "other", ExpiresAt: time.Now().Add(time.Hour)})

	if !s.RevokeFamily("fam-r", store.RevokedReasonClient) {
		t.Fatal("RevokeFamily returned false")
	}
	if n := s.RevokeFamilyTokens("fam-r"); n != 1 {
		t.Errorf("revoked %d tokens, want 1", n)
	}
	other, _ := s.GetToken("b")
	if other.Revoked {
		t.Error("unrelated token revoked")
	}
	f, _ := s.FindFamilyByTokenHash(hash)
	if !f.Revoked || f.RevokedReason != store.RevokedReasonClient {
		t.Errorf("family state = %+v", f)
	}
}

func TestSweepRemovesExpiredState(t *testing.T) {
	s := New()
	old := time.Now().Add(-48 * time.Hour)

	codeHash := oauth.HashSecret("dead-code")
	c := newCode(codeHash, time.Minute)
	c.ExpiresAt = old
	s.PutAuthCode(c)

	s.PutToken(&store.AccessTokenRecord{JTI: "dead", ExpiresAt: old})

	famHash := oauth.HashSecret("dead-refresh")
	f := newFamily("fam-dead", famHash)
	f.AbsoluteExpiry = old
	f.IdleExpiry = old
	s.PutFamily(f)

	s.sweep(time.Now())

	if _, res := s.ConsumeAuthCode(codeHash); res != store.ConsumeNotFound {
		t.Error("expired code survived sweep")
	}
	if _, ok := s.GetToken("dead"); ok {
		t.Error("expired token survived sweep")
	}
	if _, ok := s.GetFamily("fam-dead"); ok {
		t.Error("expired family survived sweep")
	}
	if _, ok := s.FindFamilyByTokenHash(famHash); ok {
		t.Error("refresh index entry survived sweep")
	}
}
