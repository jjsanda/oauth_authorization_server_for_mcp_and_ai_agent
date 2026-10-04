# Security design

This document explains the security decisions in this codebase threat by
threat: what the attack is, what this implementation does about it, and where
the code and its tests live. It follows the structure of the
[OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
and the OAuth 2.1 consolidation.

## Token forgery and algorithm confusion

**Threat.** Classic JWT attacks don't break the cryptography — they talk the
verifier out of using it: `alg: none` tokens, or an RS256/HS256 confusion
where an attacker signs with the *public* key as an HMAC secret.

**Design.** The verifier ([`internal/jose/jws.go`](../internal/jose/jws.go))
resolves the token's `kid` to a server-side key record and takes the
algorithm *from that record*. The header's `alg` is only ever compared for
equality; it never selects code. `alg: none` and cross-algorithm tokens are
structurally impossible, not just rejected — there is no code path that
verifies with a header-chosen algorithm. Symmetric algorithms are not
implemented at all.

Two signature algorithms exist, both modern:

- **ES256** (default): the mandatory-to-implement asymmetric JWS algorithm.
  Hand-implementing it forces handling a classic pitfall — JWS requires the
  raw 64-byte `R‖S` (IEEE P-1363) signature encoding, not the ASN.1 DER that
  `crypto/ecdsa` produces by default. A regression test pins this, and
  verification rejects out-of-range scalars before calling the stdlib.
- **EdDSA** (Ed25519): deterministic, fast, no nonce-reuse failure mode.

RS256 is deliberately absent: large keys, PKCS#1 v1.5 legacy, and nothing in
this system needs it.

**Tests.** `TestVerifyRejectsNoneAlgorithm`,
`TestVerifyRejectsAlgorithmMismatch`, `TestES256SignatureIsRawP1363`, and
`TestJWKPublishParseVerify` (round-trips a published key through parsing and
verification for both algorithms).

## Token substitution across services

**Threat.** A resource server (or an attacker who compromised one) redeems a
token it received at a *different* resource server — the "confused deputy"
version of token theft, and the reason the MCP specification forbids token
passthrough.

**Design.** RFC 8707 resource indicators are **mandatory**: every grant must
name at least one registered resource, or it fails with `invalid_target`
([`internal/authserver/token_endpoint.go`](../internal/authserver/token_endpoint.go)).
The `aud` claim is always emitted as an array
([`internal/token/claims.go`](../internal/token/claims.go)), and each resource
server requires its own identifier in that array
([`internal/resourceserver/authmw.go`](../internal/resourceserver/authmw.go)).
Access tokens are typed `at+jwt` (RFC 9068) so an ID token or any other JWT
signed by the same issuer can never pass as an access token.

Crossing to another service is done properly with RFC 8693 token exchange
([`internal/authserver/grant_exchange.go`](../internal/authserver/grant_exchange.go)):
the exchanging client must be entitled to the subject token (it is the token's
own client, or a resource the token is audienced to), the subject is
preserved, the audience is explicitly re-targeted, the scope may only narrow —
bounded by both the subject token and the exchanging client's own
registration — no refresh token is issued, and the exchanging client is
recorded in the `act` claim so the downstream service sees the delegation
chain.

**Tests.** `TestCrossAudienceTokenRejected`, `TestTokenExchangeDelegation`,
`TestVerifyRejectsNonAccessTokenTyp`, and the agent's step 7/8 assertions.

## Authorization code interception

**Threat.** Codes travel through the browser and OS; anything from a
malicious app registering the same redirect to a leaked redirect log can
capture one.

**Design.**

- **PKCE is required, S256 only** ([`internal/oauth/pkce.go`](../internal/oauth/pkce.go)).
  The downgrade-prone `plain` method is rejected, verifier grammar (43–128
  chars, unreserved set) is enforced, and the comparison is constant-time.
  An intercepted code is useless without the in-memory verifier.
- **Codes are one-time, short-lived, and stored hashed** — 256-bit random,
  60-second TTL, consumed atomically under the store mutex
  ([`internal/store/memory`](../internal/store/memory/memory.go)).
- **Replay is treated as an attack, not a retry**: redeeming a code twice
  revokes every token and the refresh family that the first redemption
  produced (RFC 6749 §4.1.2's SHOULD, implemented as a hard rule) —
  [`internal/authserver/grant_authcode.go`](../internal/authserver/grant_authcode.go).
- **Binding checks**: the code is bound to the client that requested it, the
  exact redirect URI, and the PKCE challenge; all three are re-verified at
  redemption.

**Tests.** `TestAuthorizationCodeFlowEndToEnd` (replay revocation),
`TestTokenRequestBindingFailures`, `TestConsumeAuthCodeConcurrent` (exactly
one winner under contention), RFC 7636 appendix B vector.

## Open redirects and redirect manipulation

**Threat.** If the authorization endpoint redirects errors to an
attacker-supplied URI, it becomes a laundering service for phishing links; if
redirect URIs match loosely, codes leak to lookalike paths.

**Design.** Redirect URIs match by **exact string comparison** — no prefix,
no wildcard, no path normalization
([`store.Client.AllowsRedirectURI`](../internal/store/models.go)). When the
`client_id` or `redirect_uri` cannot be validated, `/authorize` renders a
local error page and **never** redirects
([`internal/authserver/authorize.go`](../internal/authserver/authorize.go)).
Registration enforces RFC 8252 rules: `https` for real hosts, plain `http`
only for loopback addresses, fragments rejected
([`internal/authserver/register.go`](../internal/authserver/register.go)).
Authorization responses carry the RFC 9207 `iss` parameter, and the demo
agent verifies it, closing mix-up attacks where a second authorization server
answers for the first.

**Tests.** `TestAuthorizeRejectsUntrustedClientLocally`,
`TestDynamicRegistrationRejectsBadMetadata`, agent `iss`/`state` checks.

## Credential storage

**Threat.** A leaked database yields redeemable secrets.

**Design.** No bearer secret is ever stored in the clear. Authorization
codes, refresh tokens, and client secrets are stored as **SHA-256 digests**
and compared with `crypto/subtle`
([`internal/oauth/random.go`](../internal/oauth/random.go)).

A deliberate decision worth spelling out: these hashes use plain SHA-256,
**not** bcrypt/argon2. Key-stretching KDFs exist to slow down guessing of
*low-entropy human passwords*. Every secret hashed here is server-generated
with 256 bits of entropy; stretching a 2²⁵⁶ space is pure overhead with no
security gain. The demo *user* passwords are labeled fixtures behind a salted
hash — a real deployment federates login to an IdP or uses a memory-hard KDF,
as [the README's production notes](../README.md#non-goals-and-production-notes)
state.

## Refresh token theft

**Threat.** Refresh tokens are the longest-lived secrets a client holds. A
stolen one silently mints access tokens for as long as it lives.

**Design.** Rotation with family-wide reuse detection
([`internal/store/memory/memory.go`](../internal/store/memory/memory.go),
[`internal/authserver/grant_refresh.go`](../internal/authserver/grant_refresh.go)):

- Every refresh retires the presented token and issues the next generation;
  exactly one generation is redeemable at any time.
- Presenting a **retired** generation is proof of theft (either the thief or
  the legitimate client is replaying). The family is revoked atomically,
  along with **every access token it minted** — including tokens produced by
  RFC 8693 exchanges from those access tokens, which inherit the family.
- Ownership is verified *before* any state transition, so a different client
  presenting a stolen refresh token (with its own valid credentials) cannot
  rotate or burn someone else's grant.
- Families carry an 8-hour idle cap and a 30-day absolute cap.

**Tests.** `TestRedeemRotatesAndDetectsReuse`, `TestRefreshRotationLifecycle`,
`TestRefreshRejectsWrongClient`, `TestRedeemConcurrent`, agent steps 9–12.

## Cross-site request forgery on login and consent

**Threat.** A malicious page submits the consent form in the victim's
session, approving access the user never saw.

**Design.** Consent approval requires a CSRF token generated per login
session and compared in constant time
([`internal/authserver/consent.go`](../internal/authserver/consent.go)). The
login form is likewise protected against login CSRF / session fixation by a
signed double-submit token: the login page sets an `HttpOnly` guard cookie and
embeds a matching value in the form, and the POST is rejected unless the two
agree — an attacker cannot set that cookie in the victim's browser, so cannot
force a login ([`internal/authserver/login.go`](../internal/authserver/login.go)).
Session and guard cookies are `HttpOnly`, `SameSite=Lax`, `Secure` when the
issuer is served over https, and HMAC-signed with a server-side session record
— the cookie is an unforgeable reference, not data
([`internal/authserver/session.go`](../internal/authserver/session.go)).
The original authorization parameters never round-trip through the browser:
they are parked server-side under an opaque single-use ID
([`internal/authserver/pending.go`](../internal/authserver/pending.go)), so
neither the user nor a proxy can tamper with scope or redirect target between
steps. On the client side, the agent's `state` parameter closes the mirror
image of this attack (an attacker's code being bound to the victim's session).

**Tests.** `TestConsentRejectsBadCSRF`, `TestLoginRejectsWithoutGuard`,
`TestSessionSkipsLoginOnSecondAuthorization`, agent state verification.

## Information disclosure through auxiliary endpoints

**Threat.** Introspection and revocation endpoints make convenient oracles:
"is this stolen token still good?", "does this token exist?".

**Design.** Introspection (RFC 7662) requires an authenticated
**confidential** client, and a caller only learns about tokens it is entitled
to see — its own, or tokens audienced to a resource it is registered for;
everything else returns a bare `{"active": false}`
([`internal/authserver/introspect.go`](../internal/authserver/introspect.go)).
Revocation (RFC 7009) returns 200 for unknown tokens and for tokens owned by
other clients (after doing nothing), so success/failure cannot be used to
probe ([`internal/authserver/revoke.go`](../internal/authserver/revoke.go)).
Login failures produce one uniform message regardless of whether the username
exists. Resource servers log the precise verification failure but answer
clients with a uniform `invalid_token`.

**Tests.** `TestIntrospectionHidesForeignAudienceTokens`,
`TestRevocationIgnoresForeignTokensSilently`, `TestLoginRejectsBadCredentials`.

## Key management

**Threat.** Key rotation that breaks outstanding tokens gets postponed
forever; a JWKS endpoint that re-fetches on demand becomes a DoS amplifier.

**Design.** The key set keeps retired keys published until their tokens
expire ([`internal/jose/keyset.go`](../internal/jose/keyset.go)); key IDs are
RFC 7638 thumbprints, so they are stable and collision-free by construction.
Resource servers cache the JWKS, refresh it lazily on TTL expiry or on an
unknown `kid` (which is how a rotation propagates with zero downtime), fetch
single-flight, and rate-limit refreshes so a flood of garbage tokens with
invented kids cannot make the resource server hammer the authorization server
([`internal/resourceserver/jwks_client.go`](../internal/resourceserver/jwks_client.go)).

**Tests.** `TestKeySetRotation`, `TestKeyRotationPickedUpViaUnknownKid`.

## Transport and browser hardening

- Token responses carry `Cache-Control: no-store` + `Pragma: no-cache`
  (RFC 6749 §5.1).
- HTML pages are served with a strict CSP (`default-src 'none'`, inline
  styles only, `form-action 'self'`, `frame-ancestors 'none'`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and
  `X-Frame-Options: DENY` ([`internal/httpx/middleware.go`](../internal/httpx/middleware.go)).
- Bearer tokens are accepted **only** in the `Authorization` header — never
  in query strings (they end up in access logs) or form bodies.
- Servers run with read/write/idle timeouts and drain gracefully on SIGTERM
  ([`internal/httpx/server.go`](../internal/httpx/server.go)).
- Time-based claims are verified with a ±30s leeway; `iat` values in the
  future are rejected ([`internal/token/verifier.go`](../internal/token/verifier.go)).

## Auditability

Every authorization decision — grant issued, grant denied (with the protocol
error), login success/failure, consent, code replay, refresh reuse,
revocation — is one structured `log/slog` line with a request ID, client ID,
grant type, and outcome. The reuse-detection and replay events are explicitly
tagged so they can be alerted on; in an incident, the family history
(generations with issue timestamps) reconstructs the timeline of a theft.

## Known limitations

Honest boundaries of the current implementation:

- **Bearer tokens, not sender-constrained.** DPoP (RFC 9449) is the natural
  next step; the verifier and issuer are structured so a confirmation claim
  can be added without redesign.
- **Strict refresh rotation has no replay-grace window.** Two legitimate
  refreshes racing on the same token (a client retry, or parallel requests)
  will have the second treated as reuse and revoke the family. This is the
  standard rotation trade-off — availability sacrificed for unambiguous theft
  detection; a short grace window would soften it.
- **No rate limiting** on `/login`, `/token`, or `/register` — a production
  gateway concern that in-process token buckets would only approximate.
- **Open dynamic registration** matches the MCP agent pattern but must be
  gated (initial access tokens, RFC 7591 software statements) in production.
- **Sessions and state are in-memory** — restarts log everyone out and
  invalidate outstanding codes (and, with the default ephemeral signing key,
  outstanding JWTs too; configure `AUTH_SIGNING_KEY_FILE` to survive
  restarts). Acceptable for a demo, interface-isolated for replacement.
