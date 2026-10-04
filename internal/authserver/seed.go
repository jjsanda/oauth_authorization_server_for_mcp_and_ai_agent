package authserver

import (
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/oauth"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store"
)

// Demo fixtures. These exist so the flows are walkable out of the box; a
// real deployment would provision clients through /register (or config) and
// delegate user authentication to an identity provider.
const (
	DemoM2MClientID = "demo-m2m"
	// DemoM2MClientSecret is intentionally fixed and documented — it is the
	// credential the curl examples and docker-compose demo use.
	DemoM2MClientSecret = "demo-m2m-secret-Kt5v9pQ2wX7zR4mN" //nolint:gosec // G101: deliberate demo fixture, documented in the README
)

// SeedDemo provisions two demo users and one confidential machine-to-machine
// client that may request tokens for the given resource identifiers.
func SeedDemo(st store.Store, resources []string, scopes []string) {
	if len(scopes) == 0 {
		scopes = []string{"tools:read", "tools:invoke", "reports:read"}
	}
	st.PutUser(store.NewUser("u-alice", "alice", "password", []byte("demo-salt-alice")))
	st.PutUser(store.NewUser("u-bob", "bob", "password", []byte("demo-salt-bob")))

	st.PutClient(&store.Client{
		ID:                DemoM2MClientID,
		SecretHash:        oauth.HashSecret(DemoM2MClientSecret),
		Name:              "Demo M2M Service",
		GrantTypes:        []string{store.GrantClientCredentials, store.GrantTokenExchange},
		TokenEndpointAuth: store.AuthMethodBasic,
		Scopes:            scopes,
		AllowedResources:  resources,
		CreatedAt:         time.Now(),
	})
}
