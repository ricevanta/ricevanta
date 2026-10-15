# Identity sessions

What a console login produces and how every later request is checked: the server-side session and its cookie, idle and absolute lifetimes, revocation, the credential, resource-isolation and request-forgery guards, re-authentication windows and their binding to approval decisions, API tokens, and the keys that protect these records. Login itself is in [identity login](identity-login.md).

Authorities: BE-01, BE-02, BE-09, BE-12 and BE-17 in [decisions](../decisions.md), [console design](../design/console.md) sections 2 and 3.2, [backend design](../design/backend.md) sections 1.1, 6 and 6.1, [API foundation](api-foundation.md) and [the implementation plan](../plans/identity-sessions.md).

## 1. Boundary

The `identity` module owns sessions, API tokens and the identity integrity key; `authz` owns effective permissions and approval requests; `transport` runs the request guards of section 4 before any handler. Session and token mechanics, the guards, re-authentication checks and decision preconditions are implementable now against store and authority interfaces. PostgreSQL storage waits for the PostgreSQL platform slice. Anything that reads or consumes authority in production (the authority reader behind each request, token issuance, approval decisions) waits for BE-12, as [identity login](identity-login.md) section 1 states.

## 2. Sessions and the cookie

A session token is 32 bytes from `crypto/rand`, sent as 43 base64url characters in `__Host-rv_session` with `Path=/; HttpOnly; Secure; SameSite=Strict` and no `Max-Age`, so it ends with the browser session; the server's lifetimes govern regardless. OWASP asks for at least 64 bits of entropy and recommends the `__Host-` prefix for session identifiers ([session management cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), verify). The server stores the SHA-256 of the token, never the token.

| Field | Content |
|---|---|
| `session_uid` | Public UUIDv7 used by session lists and revocation; it is not a credential |
| `token_hash` | SHA-256 of the current token; unique |
| `user_uid`, `kind` | Internal user; `sso` or `break_glass` |
| Authentication | Method (`oidc`, `saml`, `local`), provider or break-glass account uid, principal link uid, first authentication time |
| Re-authentication | Time, method, purpose binding (`general` or `approval:<uid>`) and whether the binding was consumed |
| Lifetimes | Creation, last activity, idle timeout, absolute expiry |
| `recovery_epoch` | BE-12 epoch at creation |
| Audit context | Source address and user agent (at most 256 bytes), for the session list and audit only |
| Revocation | Time and reason |
| `mac` | HMAC-SHA-256 under the session key (section 8) over every field above except last activity and revocation |

Each request looks the token up by hash, verifies the MAC, requires the current epoch, no revocation and both lifetimes (section 3), then asks the authority reader whether the user is enabled and, for SSO, whether the principal link still exists. A token is replaced at login and at every re-authentication by updating the same row, so the previous cookie stops working at once; other tabs share the browser's cookie jar and pick up the new value. The cookie is cleared with `Max-Age=0` at logout. A login from a cross-site navigation sets the `Strict` cookie, which a top-level navigation may do (RFC 6265bis-22 section 5.7), but the first console document request after that navigation does not carry it; the console shell is static and its same-origin API calls carry the cookie (console design section 2.2).

`getSession` returns the session, effective permissions, the CSRF token, locale, server version, timeouts, the recovery quorum and whether configurable approval policies are disabled (console design section 3.1). The CSRF token is `base64url(HMAC-SHA-256(K_csrf, token_hash))`, 43 characters: it changes with every token rotation, needs no storage, and reveals nothing about the token.

## 3. Lifetimes, activity and revocation

| Kind | Idle | Absolute | Configurable range |
|---|---|---|---|
| `sso` | 15 minutes | 8 hours | Idle 5 to 60 minutes; absolute 1 to 12 hours; idle below absolute |
| `break_glass` | 5 minutes | 1 hour | Idle 2 to 15 minutes; absolute 15 minutes to 4 hours; idle below absolute |

The defaults and ranges are BE-09's; changing them is a protected `platform.settings.update` in a later settings slice, and until then the defaults apply. Absolute expiry counts from the first authentication and re-authentication never extends it. A session is `revoked`, `absolute_expired`, `idle_expired` or valid, checked in that order, and expiry applies at the exact boundary second; `sessions.json` fixes the vectors.

Idle time counts operator-initiated requests only. Requests with `X-Ricevanta-Background: 1` and the change stream never extend a session; a client that omits the header only shortens its own idle window. The stored last activity advances only when at least 30 seconds have passed since the stored value, which bounds writes to one per session per 30 seconds and makes idle expiry precise to 30 seconds. The console warns two minutes before idle expiry, and continuing sends `getSession` without the background marker (WCAG 2.2.1, console design section 2.4).

A user holds at most 10 `sso` sessions; the eleventh login revokes the oldest and audits it. A break-glass account holds one session; a new login revokes the previous one. Revocation is immediate and audited, and happens on `logout`, `revokeSession`, `revokeUserSessions`, user disable, deletion of the link or account the session authenticated through, an applied change to the provider it used (identity login section 5), a break-glass reset, disable or deletion, and every BE-12 epoch transition (section 8). An open change stream ends within its next 2-second tick ([change stream](change-stream.md) section 6). A role change needs no revocation: permissions are resolved per request, and the change stream tells the console to refetch `getSession`.

## 4. Request guards

The guard runs before the handler and decides in this order; `http-guards.json` fixes 52 decisions and `models.py` states them executably:

1. An operation that accepts credentials refuses a request carrying both a session cookie and a bearer token: `credentials_ambiguous`.
2. Resource isolation: `Sec-Fetch-Site: cross-site` or `same-site` is refused (`csrf_rejected`, or the `cross_site_start` redirect for start navigations) except on the OIDC callback and the SAML consumer, which are cross-site by design. An unsafe method with `Sec-Fetch-Site: none` is refused. Fetch Metadata defines these values and lets servers reject requests before they reach the application ([Fetch Metadata](https://www.w3.org/TR/fetch-metadata/) sections 1 and 4.1).
3. Credentials: a bearer token is accepted only where the binding lists `token` and only when valid; otherwise the session cookie must be valid, else `unauthenticated` (or the `session_required` redirect for re-authentication navigations).
4. Origin: unsafe requests in the `synchronizer` and `origin` classes, other than token requests, need `Origin` equal to the configured public origin. The Fetch Standard appends `Origin` to every request whose method is neither `GET` nor `HEAD`, and replaces it with `null` under a `no-referrer` policy only when the request mode is not `cors` ([Fetch](https://fetch.spec.whatwg.org/) section 3.2, "append a request `Origin` header"). The console's `fetch` calls use `cors` mode, so its `Referrer-Policy: no-referrer` header leaves `Origin` intact, while a form post would send `null`; the console's `form-action 'none'` forbids forms anyway (console foundation section 4).
5. Body media type: `application/json` with at most `charset=utf-8`, or form encoding for the SAML consumer, else `unsupported_media_type`. Because `application/json` is not a CORS-safelisted content type (Fetch section 2.2.2), a cross-origin page cannot send it without a preflight, and the server answers no preflight.
6. Synchronizer token: unsafe session requests need `X-Ricevanta-CSRF` equal to the session's CSRF token, compared in constant time, else `csrf_rejected`. Token-authenticated requests skip it because browsers never attach a bearer token by themselves.

| Class | Used by | Checks |
|---|---|---|
| `synchronizer` | Unsafe session operations | Steps 1 to 6 |
| `origin` | `loginLocal`, enrollment, first start | Steps 2, 4 and 5; no session exists yet |
| `navigation` | Login and re-authentication starts | Step 2 with `none` allowed; step 3 for re-authentication |
| `navigation_callback` | OIDC callback | Pre-login record checks of identity login section 3.3 |
| `cross_site_post` | SAML consumer | Step 5 with form encoding; record checks of identity login section 4.3 |
| `none` | Safe reads | Steps 1 to 3 |

The cookie's `SameSite=Strict` is a further layer: RFC 6265bis-22 section 5.6.7.1 says `Lax` "provides reasonable defense in depth against CSRF attacks that rely on unsafe HTTP methods" but "does not offer a robust defense against CSRF as a general category of attack", and OWASP treats Origin verification as the mandatory fallback for Fetch Metadata and `SameSite` as defence in depth only ([CSRF prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), verify). Login request forgery is covered by the pre-login records and the `origin` class rather than a pre-session token.

## 5. Re-authentication

An operation with `reauth: recent` needs a re-authentication or first authentication within the last 600 seconds; `reauth: bound` additionally needs the purpose `approval:<request_uid>` of the request being decided and an unconsumed binding (BE-09). Otherwise the answer is `401 reauth_required` with the window, the binding and the methods the user may use, which excludes methods in the request's affected set (section 6).

The console starts re-authentication with `startOidcReauthentication` or `startSamlReauthentication` (top-level navigations; the pre-login record stores the session, purpose and return path) or `reauthenticateLocal` with the break-glass password and a fresh TOTP code. The principal must resolve to the session's own user. Success records the method, the purpose binding and a time equal to the provider's `auth_time` or `AuthnInstant`, clamped to the callback time, then rotates the token. The operator submits the original action again; nothing is replayed automatically (console design section 2.5). A `bound` re-authentication is consumed by the decision it was bound to and cannot serve a second one.

## 6. Approval decisions

A protected request answers `202` with an approval request whose `binding_hash` covers the action, the exact before and after hashes and the frozen targets (BE-02, permission catalogue section 4). Deciding it requires, rechecked in the decision transaction:

- a session credential, the synchronizer guard and `reauth: recent` for `approveApprovalRequest`, `rejectApprovalRequest` and `rejectIdentityAuthorityRequest`, or `reauth: bound` for `approveIdentityAuthorityRequest`;
- a decider who is not the requester, and for identity-authority requests not a target user of the change;
- current eligibility: the access policy's approver group with `authz.approvals.approve` or `.reject`, or a direct `identity.authority.approve` assignment that no role, group or token can carry;
- for identity authority, a re-authentication method outside the affected set: the providers and break-glass accounts whose trust, links or credentials the change touches (backend design section 1.1);
- a `binding_hash` in the body equal to the request's current hash, a pending and unexpired request, and a comment of 1 to 2,000 characters; any difference is `approval_stale`.

The decision records the decider, the method and the time. API tokens never decide, because every decision operation accepts only the session. Recording the decision, consuming it once and dispatching the approved action are BE-12 obligations; the operations are gated on BE-12 and answer `501` until then.

## 7. API tokens

An API token is `rvt_` followed by 43 base64url characters (256 bits), shown once by `createApiToken`, stored as `HMAC-SHA-256(K_token, secret)` with a MAC over its owner, permissions, scopes and expiry. The list shows the first 6 characters after the prefix. Creation needs a session with recent re-authentication; the permissions and device-group scopes must be a subset of the creator's current effective grants, `identity.authority.approve` and connector-only permissions excluded, and at use the token's effective grant is that subset intersected with the owner's current grants. Expiry defaults to 90 days and may not exceed 365. Revocation and owner disable stop a token at once. The last-use time advances at most once a minute. The header form is exactly `Authorization: Bearer rvt_…`; any other scheme or malformed value is `unauthenticated`. Token issuance creates a grant and is gated on BE-12.

## 8. Keys and integrity

The identity integrity key is a 256-bit data key under envelope encryption (backend design section 6), unwrapped by the `api` role only. HKDF-SHA-256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html); Go `crypto/hkdf`) derives each purpose key with the installation uid as salt and the info string `ricevanta/identity/v1/<purpose>` followed by the 8-byte big-endian recovery epoch, for the purposes `session-mac`, `csrf`, `api-token`, `local-verifier`, `enrollment-code` and `prelogin-aead` (AES-256-GCM for PKCE verifiers and pending enrollment secrets). Binding the epoch means a BE-12 epoch transition invalidates every session, CSRF token, API token, break-glass verifier and enrollment code of the earlier epoch; the transition's authority repair set must therefore issue fresh break-glass enrollment codes through the offline ceremony. Until BE-12 exists the epoch is 1. Rotating the key outside an epoch transition is a compromise-recovery step with the same effect.

A database writer without the key cannot create a usable session, token, verifier or enrollment code, because the MACs and keyed hashes fail. It can delete records (denial of service), undo a revocation by clearing its columns, extend idle time up to the absolute expiry, or change authority rows the session depends on. Those are the BE-12 obligations that keep the production authority reader blocked.

## 9. Security trace

Path: login → token in `__Host-` cookie → per-request guard, token hash lookup, MAC and epoch check, authority reader, `authz` resolution → re-authentication for gated actions → decision preconditions.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Nothing: it is not a session or API credential |
| Compromised agent host | No session, cookie or token; `/api/v1` treats it as an unauthenticated client |
| Compromised console session, outside its re-authentication window | A stolen cookie (malware on the operator's host) or same-origin script acts as the operator for ordinary reads and writes until idle or absolute expiry or revocation; it cannot create API tokens, decide approvals, or request identity-authority, role or access-policy changes without passing the provider or the break-glass factors; requested protected actions wait for a different approver |
| Compromised console session, inside its re-authentication window | Additionally, for the rest of the 10 minutes, it can create an API token within the operator's grants and approve or reject other operators' access-policy requests; it can never approve its own request, and an identity-authority approval needs a re-authentication bound to that exact request, so it can approve at most a request the operator re-authenticated for, and only through an unaffected method |
| Rogue extension publisher | Console modules run in opaque-origin frames without the cookie or CSRF token, and the bridge excludes token creation, approval decisions and identity authority (EXT-04) |
| Network position between agent and server | Not this channel. Between browser and server, TLS and HSTS protect the cookie; `__Host-` prevents a sibling host from setting or shadowing it |
| Database writer without signing keys | Section 8: no forged sessions, tokens or verifiers; revocations can be undone and authority rows changed until BE-12 |
| Server restored from backup | Sessions and tokens revoked after the backup reappear until an epoch transition or their expiry; under BE-12 restore requires an epoch transition, which invalidates all of them (section 8) |

## 10. Console browser window

The console browsers are Chrome and Edge 154 and 155, Firefox 156, 157 and 153 ESR on macOS ARM64, Windows x64 and Linux x64, and Safari 27 on macOS ARM64 ([platform support](../platform-support.md#browser-coverage)). The guards need `__Host-` cookies, `SameSite`, `Origin` on unsafe `fetch` requests and `Sec-Fetch-Site`; MDN's compatibility data lists `Sec-Fetch-Site` from Chrome and Edge 76, Firefox 90 and Safari 16.4 ([browser-compat-data](https://github.com/mdn/browser-compat-data/blob/main/http/headers/Sec-Fetch-Site.json), verify). A browser without Fetch Metadata still meets the guard through steps 4 to 6. Whether every browser in the window sends the `SameSite=None` SAML cookie and the `Lax` OIDC cookie on the provider's top-level return, under its tracking-protection defaults, is a qualification case in the end-to-end tests, not an assumption; a browser that fails it blocks the release for that login method.

## 11. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: server-side sessions make revocation immediate; keyed MACs keep a database writer from minting credentials; three independent request-forgery layers; fresh authentication bound to the exact identity-authority request limits what a hijacked session can approve; tokens can request but never approve.

Trade-offs: a lookup and MAC check per request; the 30-second activity granularity; generated break-glass secrets and epoch-bound keys mean re-enrollment after recovery; one shared cookie jar means every tab of a browser is one session.

Dependencies: Go standard library (`crypto/rand`, `crypto/hmac`, `crypto/sha256`, `crypto/hkdf`, `crypto/aes`, `crypto/cipher`); envelope encryption and the master key from the secrets slice (backend design section 6), which does not exist yet; the PostgreSQL platform slice; BE-12 for the production authority reader and decisions.

Limits: a stolen cookie works from any host until expiry or revocation, because sessions are not bound to a device key; idle precision is 30 seconds; until BE-12, a database writer can undo revocations and a restore can revive sessions within their absolute lifetime.

Alternatives considered: tokens in browser storage (rejected by BE-09: readable by any injected script); self-contained signed session cookies (rejected: revocation needs server state anyway); double-submit cookies (not chosen: the synchronizer token needs no extra cookie and survives subdomain cookie injection); device-bound session credentials (not chosen: not available across the console browser window, verify); a slow password hash for break-glass (rejected: generated 120-bit secrets need none, identity login section 6.1).

## 12. Unresolved questions

- Should a later release bind sessions to a device-held key once every console browser in the window supports a standard mechanism?
- Which settings slice owns the timeout configuration and its protected update, and does it also own the per-installation session limit of 10?
