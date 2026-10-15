# Identity sessions

A login produces a server-side session. Every request checks its credential, expiry and committed authority; sensitive actions also require verified recent authentication. Login protocols live in [identity login](identity-login.md), HTTP rules in [API foundation](api-foundation.md), and stream lifetime in [change stream](change-stream.md).

Authorities: BE-01, BE-02, BE-09, BE-12 and BE-17 in [decisions](../decisions.md), [console design](../design/console.md) sections 2 and 3.2, and [backend design](../design/backend.md) sections 1.1 and 6. This design needs independent review and an implementation plan before production code starts.

## 1. Boundary and production gate

`identity` owns sessions, API tokens, authentication evidence and integrity keys. `authz` resolves grants and owns approval requests. `transport` applies the guards before handlers. Pure models and isolated test stores can exercise these contracts; PostgreSQL storage needs the platform slice.

Every production operation depends on BE-12. [Authority journal protocol](authority-journal-protocol.md) sections 5, 6 and 10 leave cross-store ordering, reducers, audit replay and publication unproved. An authority-reader interface, a MAC or a database transaction does not solve that gate. These specs state its identity obligations, not a qualified implementation. The BE-15 runtime continues to refuse identity configuration and serve no administration routes until the gates and implementation plan pass independent review. No database-only or fixed-epoch production fallback is allowed.

## 2. Session record and cookie

Generate 32 random bytes and encode them as 43 canonical unpadded base64url characters. Send `__Host-rv_session` with `Path=/; HttpOnly; Secure; SameSite=Strict`, no Domain and no Max-Age. Browser-session cookies can survive browser session restoration; the server deadlines always govern (verify browser restoration behavior). OWASP recommends at least 64 bits and the `__Host-` prefix ([session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), verify). Store only the SHA-256 of the decoded random bytes.

| Field | Contract |
|---|---|
| `session_uid`, `user_uid` | Immutable public UUIDv7 identifiers, never credentials |
| `token_hash`, `credential_generation`, `generation` | Current digest, rotation generation and record generation; neither is reused |
| `kind` | `sso` or `break_glass` |
| Authentication provenance | Initial method, provider/link or local account uid and authority generations; verified authentication time when available |
| Re-authentication evidence | Method and dependency generations, verified time, purpose `general` or `approval:<uid>`, request hash and epoch for bound evidence, one-use evidence uid |
| Lifetimes | Creation, last activity, idle timeout and absolute expiry |
| `recovery_epoch` | Epoch at creation, never relabelled |
| Audit context | TCP source address and user agent truncated to 256 Unicode characters; display-only |
| Deny | Revoked time and reason |
| `mac` | Section 8 MAC over every security field, including activity and deny state |

Each request checks the hash lookup, MAC, epoch, current generation, deny state and lifetimes, then the user's enabled state and authentication dependencies through the committed projection. The closure includes initial and retained re-authentication methods. Deleting or changing any of those dependencies ends the session even when the last re-authentication used another method.

Login creates a new uid and revokes the browser's presented current session, if any, in the same authority operation. Re-authentication rotates the token on the existing uid by compare-and-swap of its credential generation; exactly one concurrent rotation succeeds. A loser returns `conflict` without setting or clearing cookies. Callbacks bind the original credential generation and cannot revive a logged-out session. An old token stops authorizing new requests; already admitted work still needs its action's commit fence. Logout clears the cookie with Max-Age=0 and records a durable deny.

A top-level callback may set the Strict cookie ([RFC 6265bis-22](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) section 5.7). The redirected console document may lack it; that static shell requires none and same-origin API fetches carry it. Cookie attribute strings are fixed in `fixtures/sessions.json`.

`getSession` returns the effective grants, CSRF token, locale, server version, timeout state, recovery epoch, recovery quorum and approval-policy warning state. Local login and re-authentication return the same shape. Lists return only `SessionSummary`, never CSRF or credential digests. CSRF is base64url of HMAC-SHA-256 under `K_csrf` over the 32 raw token-hash bytes. Rotation changes it. The console holds it in memory only, drops protected caches on permission changes, and clears resource caches and session storage on logout, unauthenticated responses or a changed user/epoch. A stale-CSRF failure refreshes session state and requires an explicit resubmission; it never automatically repeats a mutation.

## 3. Lifetimes, activity and revocation

| Kind | Idle default | Absolute default | Allowed configuration |
|---|---|---|---|
| `sso` | 15 minutes | 8 hours | Idle 5 to 60 minutes; absolute 1 to 12 hours |
| `break_glass` | 5 minutes | 1 hour | Idle 2 to 15 minutes; absolute 15 minutes to 4 hours |

Idle must be less than absolute. The future settings slice owns protected `platform.settings.update`; defaults apply until it exists. Limits are copied into each session; tightening settings revokes affected sessions, widening applies only to new sessions. Re-authentication never extends absolute expiry. Check `revoked`, then `now >= absolute_expires_at`, then `now >= last_activity + idle_timeout`, in that order.

Only successful authenticated operator requests advance activity. `X-Ricevanta-Background: 1`, denied requests and the change stream never renew it. Omitting the marker can keep a stolen session alive until absolute expiry: this is a client convention, not evidence of human presence. Check expiry before renewal; advance activity only after 30 seconds since its stored value, conditionally with a new MAC and record generation; activity alone does not change the credential generation or close a stream. This can expire a session up to 30 seconds early relative to the last interaction. The console warns two minutes before expiry and Continue calls `getSession` without the marker (WCAG 2.2.1, console design section 2.4).

Cap SSO sessions at 10 per user; the next login revokes the oldest by `(created_at, session_uid)` in the same authority operation. Cap local sessions at one per account. Local re-authentication of an SSO session also enforces that account cap. These caps are fixed in this contract.

Revocation is a monotonic deny. Triggers include logout, explicit session revocation, user disable, removed authentication links, provider changes, break-glass reset/disable/deletion and every recovery epoch transition. New requests require current authority; streams end within the independently enforced five-second read lease. Immediate refusal at mutation and external-effect boundaries remains a BE-12 proof obligation, not a property of notifications. Role changes re-resolve grants per request and invalidate the console cache without requiring a new login.

`logout` is a subject exemption. `listSessions` needs `identity.sessions.read`; `revokeSession` and `revokeUserSessions` need `identity.sessions.revoke`. Urgent revocation requires neither approval nor fresh authentication. Unknown uids return `not_found`; a known ended session returns `204`. Revoke-all counts newly revoked sessions and does not revoke API tokens; user disable revokes both. Session lists show active sessions only, in `(created_at, session_uid)` ascending keyset order.

## 4. Request guards

`http-guards.json` and `models.py` fix guard precedence. Before these steps reject duplicate Authorization, Origin or Fetch Metadata fields, duplicate named cookies, comma-joined header values and unknown Fetch Metadata values as `validation_failed`. Cookie/bearer values must decode canonically to 32 bytes. A malformed present Authorization value never falls back to the cookie. Protocol routes reject Authorization and use only their named protocol credential; ordinary cookies do not authenticate them.

1. Credential-accepting routes refuse both a session cookie and Authorization as `credentials_ambiguous`.
2. Refuse `Sec-Fetch-Site: cross-site` or `same-site` as `csrf_rejected`, except provider callbacks. Start navigations redirect with `cross_site_start`. Unsafe origin/synchronizer routes also refuse `none`. The [Fetch Metadata specification](https://www.w3.org/TR/fetch-metadata/) sections 1 and 4.1 define the values.
3. Accept a bearer credential only on a token-enabled binding; otherwise require a valid session. Failure is `unauthenticated`, or `session_required` for re-authentication navigation.
4. Unsafe origin/synchronizer requests without bearer authentication require Origin equal to the configured public origin. Absence and `null` fail. Never infer it from Host, forwarded headers or a suffix match. The console uses fetch mode `cors`: the [Fetch Standard](https://fetch.spec.whatwg.org/) section 3.2 specifies Origin handling with no-referrer; form posts may instead send `null`, and console forms use fetch under `form-action 'none'`.
5. A body needs `application/json`, optionally one `charset=utf-8` parameter; only SAML accepts `application/x-www-form-urlencoded`. Other media return `unsupported_media_type`. Fetch section 2.2.2 excludes JSON from CORS-safelisted types; this API enables no CORS preflight.
6. Unsafe session requests require constant-time equality with `X-Ricevanta-CSRF`. Bearer authentication skips Origin and synchronizer checks, because the browser does not attach that header automatically; resource-isolation checks still apply.

| Class | Operations | Checks |
|---|---|---|
| `synchronizer` | Unsafe session operations | All six |
| `origin` | Local login, enrollment, setup | Isolation, Origin, media and protocol proof |
| `navigation` | Login and re-authentication starts | Isolation; session for re-authentication; typed navigation `none` allowed |
| `navigation_callback` | OIDC callback | Pre-login proof and identity-login section 3.3 |
| `cross_site_post` | SAML consumer | Form media, pre-login proof and identity-login section 4.3 |
| `none` | Safe reads | Ambiguity, isolation and credentials |

Missing Fetch Metadata does not bypass Origin/CSRF on unsafe requests. Safe data reads still need authentication and send no CORS grants with same-origin resource policy. SameSite is defence in depth: RFC 6265bis-22 section 5.6.7.1 and [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) (verify) explain why it cannot replace the other checks.

## 5. Verified freshness and bound evidence

`reauth: recent` requires verified evidence with `0 <= now - authenticated_at < 600` seconds. Session issuance is not authentication freshness. Initial local login supplies fresh evidence; initial SSO supplies it only from a validated `auth_time` or `AuthnInstant`, never `iat` or callback time. Missing/older evidence permits ordinary login but sensitive actions require explicit re-authentication. Reject timestamps ahead by more than the provider skew; within skew clamp to callback time.

`reauth: bound` also requires purpose `approval:<request_uid>`, the exact current binding hash, epoch and an unconsumed evidence uid. Otherwise return `reauth_required` with the allowed methods; identity-authority approval excludes the affected set. With no unaffected method the only repair path is the exact offline-quorum ceremony, never a weaker online fallback.

OIDC re-authentication uses `prompt=login`, `max_age=0` and verified `auth_time`; SAML uses ForceAuthn and verified AuthnInstant (identity login). At start resolve the request and verify current decision eligibility, freeze its hash and affected dependency closure, and bind the credential generation. Recheck at callback and decision. The resulting principal must be the same internal user.

Local re-authentication supplies `account_uid`, password and a new TOTP code. The account must be active and belong to that same internal user. This lets an SSO user with an explicitly linked local account use an unaffected method. It sets kind `break_glass` and the warning banner, and shortens idle and absolute limits to the lesser of existing limits and the local limits measured from original session creation. If that deadline has passed, end the session and require a new local login. Later SSO re-authentication never widens those limits.

Success rotates the credential and records method, dependency generations, verified time and purpose. A bound record can satisfy a recent check but not a different bound decision. The user explicitly resubmits the action; no automatic replay occurs. Evidence consumption is a BE-12 irreversible effect.

## 6. Approval decisions and visibility

A protected request binds its operation, requester, exact before/after revisions and hashes, frozen targets, policy generation and epoch. The paged inspection contract is in API foundation section 8. Identity requests expire after 72 hours; access policies may choose a shorter lifetime. Recheck these conditions at decision and immediately before application:

- Session, synchronizer guard, recent authentication for ordinary decisions or authority rejection, bound evidence for authority approval.
- Decider differs from requester and, for identity authority, from every target user.
- Ordinary decision: current approver-group membership and `authz.approvals.approve` or `.reject`. Authority decision: current direct `identity.authority.approve`, never acquired through a role, mapping, group or token.
- Authority approval: authenticated method outside the affected providers, links, mappings, recovery paths and accounts. Rejection grants nothing and may use any current recent method.
- Pending unexpired request; body `binding_hash` equals current request hash; required comment has 1 to 2,000 characters. Changed dependencies, eligibility, request revisions or epoch make it `approval_stale`.

Generic approve/reject routes accept only `access_policy`; authority routes accept only `identity_authority`. A mismatch is `approval_stale` even when the caller has both permissions. Record decider, comment, evidence uid, method and time; approval and bound-evidence consumption are one authority operation. `approved` means awaiting application, not permission to omit the fence. Application rechecks requester rights and decider eligibility and consumes the approval once. A repeated identical decision by the same decider returns the recorded result after current read authorization; a different decision returns `approval_stale`. Unknown application outcomes remain pending recovery, never retried as a fresh action.

`mine` lists requests made by the user. `awaiting` lists pending requests the interactive user can currently decide, excluding self/target requests. `all` needs `authz.approvals.read`. A token may read its owner's requests or use its effective queue-read permission, but cannot select interactive decision eligibility; `awaiting` is `permission_denied`. Detail and target pages apply the same subject checks or queue-read permission; outside that set return `not_found`. Secrets never appear in approval views. Domain payloads require their own read grants; a missing required inspection view blocks a decision. API tokens never approve or reject.

## 7. API tokens

Generate `rvt_` plus 43 canonical base64url characters from 32 random bytes. Show the secret once, store an HMAC lookup digest and a separate record MAC. Display only prefix `rvt_` plus six characters. `createApiToken` needs a session, `identity.tokens.create` and recent authentication; owner is always the caller.

`expires_at` is optional, defaulting to issuance plus 90 days. A supplied expiry must be strictly future and at most 365 days ahead. Cap active tokens at 100 per user; the next creation returns `conflict`. Reject duplicate permission names even with different scopes, unknown/retired names, direct/connector grants, decision permissions and permissions whose only operations require a session. Requested grants must be covered by the creator's current grants.

Organization permissions omit `device_groups`. For a device permission, omission snapshots the creator's current scope; a supplied list must be nonempty, distinct, existing and wholly covered. At use intersect that immutable token ceiling with the owner's current grants. Later grants cannot widen it; deleted groups grant nothing. Disable/revocation is a durable deny. Display-only last-use time advances at most once a minute and cannot extend expiry.

`identity.tokens.read` lists own tokens; `owner=all` needs `.manage`. Revoke chooses `.revoke` for an authoritative owner equal to the caller, otherwise `.manage`. Unknown/invisible uids return `not_found`; a visible revoked token returns `204`. Token-authenticated management uses only the token/owner intersection. Lists order by `(created_at, token_uid)`, include revocation metadata and disclose neither lookup digest nor MAC. A lost creation response requires revocation and fresh creation. Issuance and all token authority depend on BE-12.

## 8. Keys, replay protection and restore

The 256-bit identity integrity data key is envelope-encrypted and available only to `api` (backend design section 6). HKDF-SHA-256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html); Go `crypto/hkdf`) derives 32-byte purpose keys: salt is the installation UUID's 16 bytes; info is UTF-8 `ricevanta/identity/v1/<purpose>` followed by the eight-byte big-endian epoch. Purposes are `session-mac`, `csrf`, `api-token-lookup`, `api-token-mac`, `local-verifier`, `enrollment-code`, `record-mac` and `prelogin-aead`.

MAC input is UTF-8 `ricevanta/identity-record/v1\n` plus [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) bytes of `{installation_uid, recovery_epoch, kind, uid, generation, fields}`. Epoch and generation are positive unsigned decimal strings. `fields` contains every security field except the MAC; never concatenate variable-length fields without framing. AES-256-GCM uses `prelogin-aead`, a fresh 12-byte random nonce and the same identity tuple without `fields` as associated data. The MAC binds ciphertext digests. Exact journal item schemas and reducers remain a BE-12 gate, not an invented runtime format.

| Record | Fields that must be authenticated and checked against current authority |
|---|---|
| Session | Token hash, initial and fresh-authentication dependencies, evidence, expiry, activity, deny and generation |
| API token | Lookup digest, owner, immutable grant ceiling, expiry, deny and generation |
| Pre-login | Cookie hash, provider revision, purpose, credential generation, state/nonce, return path, ciphertext digest, expiry and consumption |
| Enrollment | Account, approved request, credential generation, code/cookie digests, pending ciphertext, expiry, attempt budget and consumption |
| Local account | User link, verifier, seed ciphertext, credential generation, enabled state, TOTP step floor and throttle |

API-token lookup HMAC input is its decoded random bytes. Local verifier input is JCS `{account_uid, password}` after ASCII normalization; enrollment-code input is its exact ASCII form. Distinct purpose keys separate uses. Verify MAC and current authority before decrypting. The committed key inventory pins key id and wrapped-key digest, so a database writer cannot substitute a chosen key. Master-key rewrapping preserves the integrity key. Replacing it requires an offline epoch transition.

A MAC prevents forgery, not replay of an older valid record. The committed projection must cover generations, denies, pre-login/SAML/enrollment/setup consumption, TOTP floors and throttles, fresh-evidence consumption and every grant dependency. Derive the complete dependency closure from that projection, not the set of rows PostgreSQL returns. Missing, extra, mismatched or older rows fail closed. Activity renewals are authority writes too; omitting them for performance would weaken the database-writer model. Independent head freshness and BE-12 fencing remain required even when every MAC matches.

Restore starts sealed and requires the live head, complete key inventory and exact offline-quorum epoch transition. All old sessions, tokens, pre-login records, replay contexts, enrollment codes and pending factors become invalid. Old local verifiers cannot be relabelled: the repair set supplies fresh break-glass enrollment. No old credential becomes usable because its wall-clock expiry is still future.

Use one trusted UTC sample per decision and monotonic live timers. Future activity/evidence beyond allowed skew fails; backwards clock movement beyond skew seals identity until trusted time and authority reconcile. Browser time is display-only. Required qualification covers skew, clock jumps, duplicate callbacks, concurrent rotation, logout races, TOTP reuse across replicas, stale-record replay, dependency deletion, lost responses, stream lease expiry and sealed restore. Fixture models do not prove the journal or clock mechanisms.

## 9. Security trace

Path: verified login proof -> committed session generation -> HttpOnly cookie -> request guard -> digest/MAC/epoch/current projection -> effective grants -> fresh evidence -> approval -> fenced one-use application. Tokens follow the same path with an immutable grant ceiling; recovery uses the offline quorum instead of online credentials.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Agent enrollment tokens authenticate no operation here. A stolen local enrollment code has the narrower authority stated in identity login section 6.4 |
| Compromised agent host | No administrator credential; public login metadata only. If it is also the operator's browser host, use the session-compromise row |
| Compromised console session outside freshness window | Ordinary authorized reads/writes until absolute expiry or deny; can defeat idle expiry by making requests. Cannot create tokens or decide approvals without fresh evidence |
| Compromised console session inside freshness window | Can create a token within allowed grants and decide other users' ordinary requests for the remaining window. Cannot approve its own request. Exact bound evidence permits stealing the one authority decision the operator authenticated for, not another request; same-origin malicious code can alter displayed context, so binding is not a trusted display |
| Rogue extension publisher | No session/CSRF material or identity operations through the bridge. Opaque-origin isolation and egress remain separate EXT-04 qualification gates, not proof supplied here |
| Network position between agent and server | No identity credential on that channel. Browser/provider connections require TLS; HSTS and `__Host-` limit downgrade/cookie injection, but do not defend a compromised browser or trusted TLS endpoint |
| Database writer without signing keys | Can delete/replay bytes and deny service; cannot forge MACs. Replayed generations, denies, TOTP floors and dependency substitutions are refused only with the required current projection and BE-12 fence; production remains blocked until proved |
| Server restored from backup | Sealed serving; offline reconciliation and a new epoch invalidate every old online credential and consumed proof. No timer or database-selected head unseals it |

## 10. Browser qualification

Use the [platform support browser window](../platform-support.md#browser-coverage) on macOS ARM64, Windows x64 and Linux x64, with Safari on macOS. Do not maintain a second version list here. Required mechanisms are `__Host-`, SameSite, Origin and Fetch Metadata. MDN [compatibility data](https://github.com/mdn/browser-compat-data/blob/main/http/headers/Sec-Fetch-Site.json) lists introduction versions (verify); missing Metadata still requires Origin and CSRF on writes. Qualify Lax OIDC and None SAML cookies under each browser's default tracking protection, same-origin fetch after cross-site return, rotation races and the console CSP. A failed required login method blocks that browser's release qualification.

## 11. Benefits, trade-offs, dependencies, limits and alternatives

Benefits: server-side records permit deny checks; separate keyed digests and MACs resist forged database records; exact request binding narrows authority approval; token ceilings prevent later grant growth from widening an issued token.

Trade-offs: MAC and current-authority work per request; activity renewals and proof consumption increase journal traffic; one cookie jar shares rotation across tabs; recovery requires fresh local enrollment. These costs need qualification, not a database-only shortcut.

Dependencies: Go standard library `crypto/rand`, `crypto/hmac`, `crypto/sha256`, `crypto/hkdf`, `crypto/aes`, `crypto/cipher`; PostgreSQL platform and envelope-encryption slices; BE-12. No new runtime library is introduced here.

Limits: bearer cookies are not device-bound; a copied cookie works until denial or absolute expiry. A recently compromised session can mint longer-lived tokens within its grants. CSP does not prevent authorized same-origin malicious code from acting as the user. The unresolved BE-12 protocol blocks production guarantees.

Alternatives: browser-storage tokens expose credentials to script; self-contained cookies still need revocation state; double-submit cookies add cookie state without improving this synchronizer design. Device-bound credentials require a separate browser qualification (verify availability across the window). Generated 120-bit local passwords use keyed verifiers instead of a slow memorized-password hash, as identity login section 6.1 explains.

## 12. Unresolved questions

- Which independently reviewed BE-12 gate and typed identity reducers prove current-generation checks and one-use consumption across stalled replicas and restored databases?
- Which qualified clock-health mechanism establishes the skew and rollback assumptions for the deployed replica set?
