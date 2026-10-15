# Identity login

How an administrator proves who they are: SP-initiated OIDC with the authorization code flow and PKCE, SP-initiated SAML with the HTTP-POST binding, break-glass local accounts with a generated password and TOTP, the first-start administrator, external-principal links and identity-provider administration. Every successful login ends in the server-side session of [identity sessions](identity-sessions.md); the browser never receives a token from an identity provider.

Authorities: BE-01, BE-02, BE-09 and BE-17 in [decisions](../decisions.md), [backend design](../design/backend.md) sections 1.1 and 6, [console design](../design/console.md) sections 2 and 3.2, [API foundation](api-foundation.md) and [the implementation plan](../plans/identity-sessions.md). Operations, schemas and fixtures are in [`schemas/openapi/v1/`](../../schemas/openapi/v1/openapi.yaml).

## 1. Boundary and authority

The `identity` module owns providers, principal links, link requests, break-glass accounts, pre-login records, the SAML replay cache and sessions. Users, principal links, enabled state, break-glass credentials, provider trust and role grants are authority under BE-12 (backend design section 6.1): a database writer who could insert a link or enable a user would own the console. The login engines therefore read them only through an `identity.AuthorityReader` interface.

| Part | State |
|---|---|
| OIDC and SAML protocol engines, TOTP, generated credentials, return paths, cookies, pre-login records, decision order, login and enrollment handlers against store and authority interfaces | Implementable now with in-memory stores and a fixture authority reader |
| End-to-end tests against the real binary with test OIDC and SAML providers | Implementable now under the `ricevanta_testauthority` build tag, which release verification rejects |
| PostgreSQL stores for pre-login records, link requests, replay cache, accounts and sessions | Blocked on the PostgreSQL platform slice |
| Production `AuthorityReader`, provider and link administration, break-glass lifecycle, first start | Blocked on BE-12 (committed projection, read lease, approval consumption and the recovery manifest) |
| Alerting on break-glass use through notifier connectors | Blocked on the `notifier` connector contract (EXT-05); the audit record exists without it |

The server needs its public console origin for redirect URIs, SAML endpoints and origin checks. The server configuration gains `api.public_origin`: an `https` origin with no path, query or fragment, required when the `api` role serves `/api/v1`. It extends the BE-15 configuration schema in the plan.

## 2. Shared login mechanics

### 2.1 Pre-login records and cookies

Starting a login or re-authentication creates a pre-login record: a 256-bit random cookie value, whose SHA-256 is the record key; the purpose (`login` or `reauth`); the provider uid; for re-authentication the session uid and the purpose binding (`general` or `approval:<uid>`); the return path; for OIDC the 256-bit `state`, the 256-bit `nonce` and the PKCE verifier from 32 random octets ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) section 4.1), encrypted under the identity integrity key; for SAML the request ID; the creation time; and an expiry 10 minutes later. The first callback consumes the record whatever the outcome, so a code, state or assertion can be presented once. A second start in the same browser overwrites the cookie, and the earlier tab's callback then fails as `state_mismatch`. At most 10,000 unexpired records exist; `jobs` deletes expired records hourly.

| Cookie | Attributes | Purpose |
|---|---|---|
| `__Host-rv_login` | `Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax` | OIDC; `Lax` lets it travel on the provider's top-level `GET` to the callback |
| `__Host-rv_saml` | `Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None` | SAML; the identity provider's form `POST` is cross-site, and only `None` cookies travel on it |
| `__Host-rv_enroll` | `Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Strict` | Binds the two break-glass enrollment steps (section 6.4) |

The `__Host-` prefix requires `Secure`, `Path=/` and no `Domain` ([RFC 6265bis-22](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) section 4.1.3.2), which blocks injection from sibling hosts. A pre-login cookie is cleared with `Max-Age=0` when its record is consumed. The exact strings, in `net/http` `Cookie.String` attribute order, are fixtures in `sessions.json`.

### 2.2 Return paths

`return_to` must match `^/[A-Za-z0-9._~/-]{0,511}$`, contain no empty, `.` or `..` segment, and not be or lie under `/api`, `/agent`, `/ext`, `/assets`, `/brand`, `/mdm`, `/scep`, `/acme`, `/healthz`, `/readyz`, `/login` or `/__test__`. Anything else becomes `/`. No query or fragment survives; the console restores view state from `sessionStorage`. The `303` `Location` is that path, which the browser resolves against the callback's own origin, so no callback is an open redirect. `return-paths.json` fixes the vectors.

### 2.3 Navigation outcomes and limits

Start, callback and assertion-consumer endpoints are browser navigations and always answer `303`: to the provider, to the return path on success, or to `/login?error=<code>` with a code from `LoginErrorCode` in the document. Start endpoints refuse `Sec-Fetch-Site: cross-site` or `same-site` with `cross_site_start` ([Fetch Metadata](https://www.w3.org/TR/fetch-metadata/), W3C Working Draft, section 4.1); a typed URL (`none`) is allowed. The callback and consumer accept cross-site navigations by design and rely on the pre-login record instead.

| Endpoint group | Limit per source address |
|---|---|
| Start and callback, OIDC and SAML | 20 per minute, burst 10 |
| `loginLocal`, `reauthenticateLocal` | 10 per minute, burst 5 |
| Enrollment and first start | 5 per minute, burst 3 |

Every attempt writes an administrative audit record with the provider, outcome code, source and user agent, never a code, token, assertion, password or TOTP value (`design/events.md` section 6).

### 2.4 Principal resolution and link requests

A validated authentication yields a principal key: OIDC provider uid, exact `iss` and `sub`; SAML provider uid, issuer, persistent `NameID` format and `NameID` (backend design section 1.1). OpenID Connect Core 1.0 section 5.7 makes `iss` with `sub` the only guaranteed unique identifier and forbids using `email` or `preferred_username` as one ([OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)); SAML Core section 8.3.7 defines persistent identifiers as pseudo-random values with no correspondence to the user name ([SAML core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)).

A key with a link resolves to its internal user. A key without one creates or refreshes a link request holding the key, the claimed display name and email for the reviewer, and first and last seen times, then answers `link_pending`. A request expires after 7 days; at most 100 open requests exist per provider, beyond which the answer is `rate_limited`. Turning a request into a link is the protected `createPrincipalLink` operation (section 5). Claims never create, merge or match users, and claim-to-group mapping is not part of this slice (section 10).

## 3. OIDC

### 3.1 Provider configuration

An OIDC provider stores the issuer (`https`, no query or fragment), client id, client authentication method (`client_secret_basic` or `client_secret_post`), the client secret under envelope encryption (backend design section 6), extra scopes (`profile`, `email`) and the allowed ID token algorithms from `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512` and `EdDSA`. Configuration fetches the discovery document with `go-oidc` `NewProvider`, which fails unless the discovered issuer matches exactly ([go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)). The provider must list `code` in `response_types_supported` and `S256` in `code_challenge_methods_supported`; [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) section 2.1.1 recommends PKCE for confidential clients, and Ricevanta requires it. `authorization_response_iss_parameter_supported` is recorded ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) section 3). The redirect URI is `https://<public origin>/api/v1/auth/oidc/<provider_uid>/callback`, distinct per provider as RFC 9700 section 4.4.2.2 requires of clients with several issuers.

### 3.2 Authorization request

`startOidcLogin` creates the pre-login record and redirects to the authorization endpoint with `response_type=code`, `client_id`, the exact redirect URI, `scope=openid` plus the configured extras, `state`, `nonce`, `code_challenge` (`S256`, RFC 7636 section 4.2) and `code_challenge_method=S256`. Re-authentication adds `prompt=login` and `max_age=0`: with `prompt=login` the provider "MUST reauthenticate the End-User even if the End-User is already authenticated" (OpenID Connect Core section 3.1.2.3), and with `max_age` the ID token "MUST include an auth_time Claim Value" (section 3.1.2.1). The default `query` response mode is used; `form_post` would be a cross-site `POST`.

### 3.3 Callback

`completeOidcLogin` applies these steps in order; `login.json` fixes the outcome of each:

1. The `__Host-rv_login` cookie must name an existing, unconsumed record for this provider path, else `state_mismatch`; an expired record is `expired`. The record is consumed now.
2. `state` must equal the stored value (constant-time), else `state_mismatch`. RFC 9700 section 4.7.1 lists `state`, PKCE and `nonce` as request-forgery defences; Ricevanta uses all three.
3. A disabled provider is `provider_disabled`; an `error` parameter is `provider_error`.
4. `iss`: present and different from the issuer, or absent when the provider advertises support, is `invalid_response` (RFC 9207 section 2.4).
5. Without `code`, `invalid_response`. The token request uses the stored verifier, a 10-second timeout and a 64 KiB response limit; a 4xx answer is `provider_error`, a network failure or 5xx is `unavailable`.
6. The ID token passes `go-oidc` `Verify` with the client id and the allowed algorithms (signature from the provider's JWKS, `iss`, `aud`, `exp`). Ricevanta then checks what `go-oidc` leaves to the caller: `nonce` equals the stored nonce, which "Verify does NOT do" (go-oidc documentation); `azp` equals the client id when present and is present when `aud` has more than one value; `iat` is no more than 60 seconds ahead and no more than 10 minutes old. Any failure is `invalid_response`. The access token and userinfo endpoint are not used.
7. Re-authentication only: `auth_time` must be present and no earlier than the record's creation minus 60 seconds, else `reauth_stale`; the bound session must still be valid, else `session_required`.
8. Principal resolution (section 2.4): `link_pending` or `rate_limited` for unlinked keys; a disabled user is `user_disabled`; a re-authentication whose principal resolves to another user is `reauth_user_mismatch`.
9. Login creates a session; re-authentication updates and rotates the bound one ([identity sessions](identity-sessions.md) sections 2 and 5). Both answer `303` to the return path and clear the pre-login cookie. The response sets `__Host-rv_session` although it answers a cross-site navigation: a top-level navigation may set a cookie with any `SameSite` value (RFC 6265bis-22 section 5.7, step 18.3).

## 4. SAML

### 4.1 Provider configuration

A SAML provider is configured by importing the identity provider's metadata, at most 256 KiB: its entity ID, the `SingleSignOnService` location for the HTTP-Redirect binding, one to four signing certificates and `WantAuthnRequestsSigned`. Metadata is never fetched at login time. The server generates one RSA-3072 service-provider key per provider under envelope encryption and publishes its certificate, the entity ID `https://<public origin>/api/v1/auth/saml/<provider_uid>/metadata` and the consumer URL `https://<public origin>/api/v1/auth/saml/<provider_uid>/acs` through `getSamlServiceProviderMetadata`. The key signs authentication requests when the identity provider requires it and decrypts encrypted assertions when the identity provider sends them. The clock skew is 60 seconds by default and at most 180.

The library is `github.com/russellhaering/gosaml2` v0.12.0 with `goxmldsig` v1.6.1, `beevik/etree` and `mattermost/xml-roundtrip-validator` (section 9).

### 4.2 Authentication request

`startSamlLogin` sends an `AuthnRequest` over the HTTP-Redirect binding with a fresh `ID` of `_` plus 40 hexadecimal characters, `Destination` the SSO location, `AssertionConsumerServiceURL` the consumer URL, `ProtocolBinding` HTTP-POST, `Issuer` the service-provider entity ID and `NameIDPolicy` persistent with `AllowCreate="true"`. Re-authentication sets `ForceAuthn="true"`, which obliges the identity provider to "authenticate the presenter directly rather than rely on a previous security context" (SAML Core section 3.4.1). No `RelayState` is sent; the pre-login record holds the return path. IdP-initiated responses are refused because they carry no request to bind (BE-09).

### 4.3 Assertion consumer service

`completeSamlLogin` accepts `application/x-www-form-urlencoded` with `SAMLResponse` up to 262,000 characters and ignores `RelayState`. Steps, fixed by `login.json`:

1. The `__Host-rv_saml` cookie must name an unconsumed record for this provider path (`state_mismatch`, `expired`); the record is consumed. The response's `InResponseTo` must equal the stored request ID, so unsolicited responses fail as `state_mismatch`.
2. A disabled provider is `provider_disabled`.
3. The response `Destination` must be present and equal the consumer URL; the HTTP-POST binding requires the recipient to verify it for signed messages ([SAML bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) section 3.5.5.2). `gosaml2` checks `Destination` only when present, so the absence check is Ricevanta's.
4. A non-success status is `provider_error`.
5. The issuer must equal the configured entity ID; the response must hold exactly one assertion, because `gosaml2` evaluates only the first; that assertion must carry its own valid signature from a configured certificate. The Web Browser SSO profile requires assertions delivered by HTTP-POST to be signed ([SAML profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) section 4.1.4.5); a signature over the response alone does not satisfy Ricevanta. Verify the library field that reports assertion-level validation during implementation.
6. The assertion needs a bearer `SubjectConfirmation` whose data names the consumer URL as `Recipient` and an unexpired `NotOnOrAfter` at most one hour ahead; valid `Conditions` times; an `AudienceRestriction` containing the service-provider entity ID; an `AuthnStatement`; and a persistent `NameID` of at most 256 characters (profiles section 4.1.4.2 and 4.1.4.3). `gosaml2` reports audience and time failures only as `WarningInfo` flags, so any set flag fails. Every failure is `invalid_response`.
7. Replay: the assertion ID is recorded with its `NotOnOrAfter` in a unique-keyed cache, and a second use is `invalid_response`, as profiles section 4.1.4.5 requires.
8. Re-authentication only: `AuthnInstant` no earlier than the record's creation minus the skew, else `reauth_stale`; then steps 7 to 9 of section 3.3 apply unchanged.

## 5. Identity providers and principal links

`createIdentityProvider`, `updateIdentityProvider` and `deleteIdentityProvider` change an authentication authority, and `createPrincipalLink` and `deletePrincipalLink` change who an external principal is. All five are identity-authority actions (BE-02, console design section 3.2): they need recent authentication, answer `202` with an approval request, and are approved only by a different enabled user with a direct `identity.authority.approve` assignment whose decision re-authentication is bound to the request and uses a method outside the affected set ([identity sessions](identity-sessions.md) section 6). The affected set of a provider change is that provider; of a link change, the link's provider and the target user's current methods. The request binds the before and after resource hashes, the provider uid, the principal key and the target user uid. Applying a provider update that changes its issuer, client, certificates or endpoints, or deleting it, revokes every session authenticated through it and every link request it holds. Write-only fields (client secret, imported metadata) are hashed into the binding by SHA-256 fingerprint, never stored in the request. The catalogue names are in [API foundation](api-foundation.md) section 8. Execution is gated on BE-12.

## 6. Break-glass accounts

### 6.1 Credentials

A break-glass account is a local account bound to one internal user (BE-01). Its credentials are generated, never chosen: a password of 24 RFC 4648 base32 characters (120 bits), compared case-insensitively after removing spaces and hyphens, and a TOTP seed of 20 random bytes. [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html) section 5.1 asks for keys as long as the HMAC output, 20 bytes for SHA-1. Because the password is 120 random bits, the stored verifier is `HMAC-SHA-256(K_local, account_uid || normalized password)`, not a slow password hash: offline guessing of a 120-bit secret is infeasible, and the key keeps a database writer from installing a verifier for a password of its choice. The seed is stored under envelope encryption. The console renders the seed as text and as a QR matrix of `0` and `1` rows that the server encodes with `rsc.io/qr`, drawn as SVG rectangles, so no `data:` image or new console dependency is needed.

### 6.2 TOTP

Codes are 6 digits over HMAC-SHA-1 with 30-second steps from the Unix epoch (RFC 6238 section 4.1). The verifier accepts the current and the previous step only, following "at most one time step is allowed as the network delay" (section 5.2), and stores the last accepted step per account with a conditional update, so a code is never accepted twice: "The verifier MUST NOT accept the second attempt of the OTP" (section 5.2). `totp.json` carries the appendix B SHA-1 vectors truncated to 6 digits and the window and replay decisions.

### 6.3 Login

`loginLocal` takes user name, password and TOTP code as JSON under the `origin` request guard. In order: per-source rate limit; strict decoding; account lookup, computing a verifier for a fixed dummy account when the name is unknown so that both paths do the same work; constant-time password comparison; the account's TOTP throttle; TOTP verification; account `active` and user enabled. Every failure in these steps answers the same `401 invalid_credentials`. After three consecutive TOTP failures with a correct password, further TOTP checks for that account wait 30 seconds, doubling to at most 15 minutes, and are answered `429` until then; this throttle starts only after a correct password, so a guesser without the password cannot lock out the holder, and the first such failure is a critical audit event and notifier alert because someone holds the password. Success creates a `break_glass` session, revokes any other session of the account, writes a critical audit event and raises a notifier alert (section 1 states the connector dependency).

### 6.4 Enrollment

Creating, resetting or replacing the factor of an account is an identity-authority request. After it is applied, its requester claims a one-time enrollment code with `claimBreakGlassEnrollmentCode`: 26 base32 characters (130 bits), stored as an HMAC, valid for 24 hours, claimable once and only with recent authentication. The requester is the person who seals the credentials for storage. `startBreakGlassEnrollment` exchanges the code for freshly generated credentials, shown once (a new password for create and reset, a new seed for all three), and sets `__Host-rv_enroll`; calling it again within the code's lifetime replaces the pending credentials. `completeBreakGlassEnrollment` requires that cookie and a valid code from the new seed, then activates the new credentials atomically, consumes the enrollment code, revokes the account's sessions and audits the event. Completion creates no session.

### 6.5 Lifecycle

Accounts are `pending_enrollment`, `active` or `disabled`. Enable, disable, reset, factor replacement and deletion are identity-authority requests (catalogue rule `identity_authority`). Disabling or deleting an account revokes its sessions when applied. A break-glass session uses the shorter timeouts and the persistent banner of [identity sessions](identity-sessions.md) section 3.

## 7. First start

`completeFirstStartSetup` consumes the one-time setup token: 256 random bits written by `ricevanta-server` to a file readable only by the server user, whose path, never value, is logged (console design section 2.1). Before the endpoint opens, the offline recovery quorum manifest must be verified and the authority journal genesis written (backend design section 6.1). The request names the first administrator's user name and display name; the server creates the internal user with the built-in administrator role and a direct `identity.authority.approve` assignment, creates a break-glass account in `pending_enrollment`, deletes the token file, and returns enrollment credentials and the enrollment cookie as section 6.4 does. The token grants nothing after this call. The operation is gated on BE-12.

## 8. Security trace

Path: browser navigation → start (record, cookie) → provider authentication → callback or consumer (record consumed, protocol checks) → principal link → authority reader → session. Break-glass: JSON login → verifier and TOTP → authority reader → session.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Nothing: agent enrollment tokens are not login credentials anywhere in this flow |
| Compromised agent host | Network access to public login options and SAML metadata; no credential that resolves to an administrator |
| Compromised console session | Within the session, it can start re-authentication but must pass the provider or present the password and a fresh TOTP code; it can request provider, link and break-glass changes, which wait for a different approver with bound, unaffected re-authentication; if it requested a break-glass change, it can claim that enrollment code after approval |
| Rogue extension publisher | Console module frames lack top-level navigation and the bridge excludes authentication and identity-authority operations (EXT-04), so a module cannot start or complete a login |
| Network position between agent and server | Not on this channel. Between browser, server and provider, TLS protects codes and assertions; a party able to obtain a publicly trusted certificate for the provider's host could serve forged discovery and keys to the server, so OIDC trust rests on the Web PKI unless the operator pins the provider's CA (section 10) |
| Database writer without signing keys | Cannot install a break-glass verifier or enrollment code without the identity integrity key, and cannot read PKCE verifiers or seeds without the envelope key; can insert a principal link, enable a user or roll back `totp_last_step`, which is why the production authority reader waits for BE-12 |
| Server restored from backup | Expired pre-login records stay expired; the SAML replay cache loses entries newer than the backup, bounded by the one-hour confirmation window; restored break-glass verifiers and links are authority that BE-12's epoch transition invalidates, and the HMAC keys bind the recovery epoch ([identity sessions](identity-sessions.md) section 8) |
| Compromised identity provider | Can authenticate any principal of that provider, so can log in as its linked users; cannot approve identity-authority changes, because the approver must re-authenticate through another provider or a break-glass account |

## 9. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: three request-forgery defences in OIDC, InResponseTo, Destination and replay binding in SAML, single-use pre-login records and per-provider endpoints remove login request forgery and mix-up; generated break-glass secrets make online and offline guessing pointless and let the account delay apply only after a correct password; identity-authority protection keeps a compromised provider from extending its own reach.

Trade-offs: one pre-login cookie per protocol means parallel logins in two tabs of one browser fail one of them; generated passwords must be stored by the holder rather than remembered; IdP-initiated SAML is unsupported; logout ends only the Ricevanta session, and the provider's session may log the user in again silently, which `prompt=login` and `ForceAuthn` counter for re-authentication.

Dependencies: `github.com/coreos/go-oidc/v3` v3.21.0 with `github.com/go-jose/go-jose/v4` and `golang.org/x/oauth2`; `github.com/russellhaering/gosaml2` v0.12.0, `github.com/russellhaering/goxmldsig` v1.6.1, `github.com/beevik/etree`, `github.com/jonboulle/clockwork` and `github.com/mattermost/xml-roundtrip-validator`; `rsc.io/qr`; Go standard library `crypto/hmac`, `crypto/sha1`, `crypto/hkdf`. Rows are in [licensing](../licensing.md). `gosaml2` and `goxmldsig` released in August 2026; `crewjam/saml`'s latest release is April 2025 and pulls `golang-jwt` and `x/crypto`, so the activity check of backend design section 2 selects `gosaml2` (module proxy data).

Limits: OIDC trust in the provider's discovery and keys rests on the Web PKI by default; SAML trust rests on imported certificates and changes only through a protected update; the source-address limits share a bucket behind a load balancer (API foundation section 7); break-glass alerts exist only as critical audit events until the notifier connector contract exists.

Alternatives considered: one callback for all providers (rejected: RFC 9700 mix-up defence needs distinct redirect URIs); `form_post` response mode (rejected: a cross-site `POST` needs a `SameSite=None` cookie for no benefit); signed AuthnRequests always (not chosen: many providers do not need them, and the key is available when they do); operator-chosen break-glass passwords with Argon2id (rejected: a memorized password is guessable and the hash needs a new dependency, while a generated secret needs neither); automatic link creation from email or directory attributes (rejected: BE-01 forbids mutable identifiers); `crewjam/saml` (not chosen: less recent releases and a larger dependency set).

## 10. Unresolved questions

- Which claim or directory attribute maps a provider principal to a SCIM or LDAP user without a manual link request, and how are group claims mapped (analysis section 3, Identity)? Until settled, every link goes through `createPrincipalLink`.
- Should an OIDC provider support an operator-pinned CA bundle for discovery, JWKS and token endpoints? The default trusts the system roots.
- Does the owner accept an unfenced authority reader for a labelled v0.1.x alpha, or does console login wait for BE-12? This design keeps production login behind BE-12.
