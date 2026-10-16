# API foundation

`/api/v1` is described by one hand-written OpenAPI 3.1 document, [`schemas/openapi/v1/openapi.yaml`](../../schemas/openapi/v1/openapi.yaml), and every operation in it follows the rules below: strict JSON, RFC 9457 problem details, keyset pagination, `ETag` concurrency, `Idempotency-Key` for requests that create approval requests, and an authorization binding that names the exact permission catalogue entry. The console client is generated from the document. This specification is the contract for the administration API; it does not by itself implement an operation.

Authorities: BE-05, BE-08 and BE-16 in [decisions](../decisions.md), [architecture](../architecture.md) section 3.3, [backend design](../design/backend.md) section 2, [console design](../design/console.md) section 1.2. Identity and session operations are specified in [identity login](identity-login.md) and [identity sessions](identity-sessions.md); `/api/v1/changes` in [change stream](change-stream.md). The permission names come from the [permission catalogue](permission-catalogue.md).

## 1. Boundary and dependencies

Included: the document skeleton with the identity, session, approval-decision and change-stream operations; the shared components (problem details, pagination, identifiers, timestamps, approval request); the `x-ricevanta-*` extensions; the vendored OpenAPI 3.1 meta-schemas; the validator, its reference models and fixtures; the Go request pipeline that enforces these rules; the generated console client.

Excluded: domain operations of other areas (devices, alerts, policies and the rest of console design section 5), which each domain slice adds to the same document under these rules; the connector contracts under `schemas/openapi/connectors/`, which stay separate documents (EXT-05); GitOps resource schemas.

The `api` role and its listener come from the server runtime slice (BE-15, [server runtime](server-runtime.md)): one root handler, reserved prefixes that never fall back to the console document, per-handler read and write deadlines and `/api/v1/*` answering `404` while no operation exists. This document defines a future route table, not a change to the current runtime. BE-15 keeps its `404` and startup refusal until reviewed integration registers complete handlers. There are no advertised `501` stubs. Persistent stores (idempotency records, sessions, change watermarks) need the PostgreSQL platform slice, which does not exist yet; until it does, only isolated models/harnesses may use test stores. No production-handler implementation plan exists for these four specs yet; a reviewed plan precedes production work. [Contract validation](../plans/contract-validation.md) covers offline validation and catalogue integration only.

## 2. Document and versioning

- One YAML file, at most 1 MiB, exactly one document, UTF-8, with no anchors, aliases, explicit tags, duplicate keys or non-string keys. [RFC 9512](https://www.rfc-editor.org/rfc/rfc9512.html) registers `application/yaml` and warns about alias expansion (section 4.2); refusing anchors removes that class instead of bounding it. The server serves the embedded bytes unchanged as `getOpenApiDocument` with `Content-Type: application/yaml`.
- `openapi: 3.1.2`. OpenAPI 3.1.2 ([specification](https://spec.openapis.org/oas/v3.1.2.html)) states that tooling should treat 3.1 patch versions alike; pinning the exact patch keeps the validator and its vendored schema in step. The validator checks the document against the OpenAPI Initiative's published `schema-base/2026-08-03` and `dialect/2024-11-10` schemas, vendored with their digests and the Apache-2.0 license in [`schemas/openapi/upstream/`](../../schemas/openapi/upstream/lock.json). The specification calls that JSON Schema informational and itself authoritative; the profile rules in this document carry what the schema cannot.
- `info.version` is `1.<revision>`. The revision increments with every change to the document and never decreases. The product version (SH-04) is not the API version.
- Changes within v1 are additive: new operations, new optional request fields, new response fields and new response enumeration values. Clients ignore unknown response members and treat an unknown enumeration value as an unrecognized state. Removing or renaming an operation, path, parameter, field or request enumeration value, tightening a request constraint, or changing a status code or meaning needs `/api/v2`. Request objects are closed (`additionalProperties: false`); response objects are open, so additions do not break generated clients.

## 3. Paths, operations and JSON

| Element | Rule |
|---|---|
| Path | `/api/v1/` followed by lowercase kebab-case segments or `{snake_case}` parameters; every path parameter is a required lowercase UUIDv7 (`Uid`, [core primitives](core-primitives.md)) |
| Action | A state change that is not a create, replace or delete is `POST` to a verb segment, for example `/sessions/{session_uid}/revoke` |
| operationId | `^[a-z][a-zA-Z0-9]{2,63}$`, unique and case-sensitive per OpenAPI 3.1.2 section 4.8.10.1; the names the console design lists are binding requirements on new operations |
| Request media | `application/json` with optional `charset=utf-8` and nothing else; the SAML assertion consumer service alone accepts `application/x-www-form-urlencoded` |
| Response media | `application/json`; errors `application/problem+json`; the change stream `text/event-stream`; the document `application/yaml`; SAML metadata `application/samlmetadata+xml` (the SAML 2.0 metadata registration, verify) |
| Body limit | Every operation with a body declares `x-ricevanta-max-body-bytes`, at most 1 MiB; a larger declared or streamed body is answered `413` before parsing |
| Field names | `snake_case`; times are RFC 3339 UTC with `Z` and at most nine fractional digits; this profile rejects leap-second `:60` encodings; hashes are `sha256:<hex>` |

The server decodes JSON strictly: invalid UTF-8, duplicate member names at any depth, unknown members, trailing data, nesting deeper than 32, integers outside the declared range and strings longer than declared are `validation_failed`. Unpaired surrogate escapes and non-finite numbers also fail; schema formats and semantic constraints must be checked, not treated as annotations. Go's `encoding/json` accepts duplicate names and replaces invalid UTF-8 ([documentation](https://pkg.go.dev/encoding/json)), so the pipeline tokenizes first, as the permission catalogue parser already does. Every request string has `maxLength`, every request array `maxItems`, every request integer both bounds and every request object `additionalProperties: false`; the validator rejects a request schema that lacks one.

Decode path and query values once, reject invalid escapes, duplicate/unknown query parameters and encoded path separators. The only repeated query parameter is `topic`. Callback parameters have their declared limits; an invalid `return_to` value falls back to `/` before applying its schema, as identity login specifies. Headers named as credentials or guards are single-valued. Bodyless operations reject declared/chunked content with `413`, using BE-15's immediate read deadline before returning. Body operations have a ten-second total read deadline and enforce their limit while streaming; responses retain BE-15's ten-second progress/write bounds, with the earlier hard connection cutoff for streams in change-stream section 6. Raw URLs, query strings, Authorization, Cookie, Set-Cookie and request bodies never enter access logs; use the operation id and server request id.

## 4. Errors

Every error body is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) problem with `application/problem+json`. `type` is an absolute URI from the closed table below (section 3.1.1 recommends absolute URIs); `about:blank` is never sent. `title` is the type suffix with underscores replaced by spaces and its first character uppercased (for example `Precondition failed`); the console shows its own localized text for the type. `instance`, when present, is `urn:uuid:<request_id>`. `detail` never contains request values, resource data, secrets or stack traces (section 5). Clients ignore unknown members (section 3.2).

| Type (`https://ricevanta.io/problems/…`) | Status | Meaning and extension members |
|---|---|---|
| `validation_failed` | 400 | Malformed or invalid request; `errors[]` holds at most 64 `{pointer, code}` items, `pointer` an RFC 6901 pointer or `#<parameter>` |
| `unauthenticated` | 401 | No usable credential; `WWW-Authenticate: Bearer realm="ricevanta"` |
| `reauth_required` | 401 | Recent or bound authentication missing; `reauth` names `max_age_seconds` 600, the binding and the allowed methods; `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="600"` after [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html) section 3 |
| `invalid_credentials` | 401 | Break-glass login or re-authentication failed; never says which factor |
| `permission_denied` | 403 | Authenticated but not permitted; `permission` names one missing catalogue name |
| `csrf_rejected` | 403 | Request-forgery or resource-isolation check failed ([identity sessions](identity-sessions.md) section 4) |
| `credentials_ambiguous` | 400 | Session cookie and bearer token in one request |
| `not_found` | 404 | Unknown resource, or a resource outside the caller's scope |
| `method_not_allowed` | 405 | With `Allow` |
| `conflict` | 409 | State conflict, for example a duplicate name |
| `approval_stale` | 409 | Decision on a request whose binding hash, targets or eligibility changed |
| `idempotency_in_progress` | 409 | Same `Idempotency-Key` still executing |
| `precondition_failed` | 412 | `If-Match` does not match the current `ETag` |
| `payload_too_large` | 413 | Body above the operation limit |
| `unsupported_media_type` | 415 | Body media type outside section 3 |
| `idempotency_key_reused` | 422 | Same key with a different request digest |
| `precondition_required` | 428 | `If-Match` missing on a versioned write ([RFC 6585](https://www.rfc-editor.org/rfc/rfc6585.html) section 3) |
| `rate_limited` | 429 | `Retry-After` and `retry_after_seconds` (RFC 6585 section 4) |
| `internal_error` | 500 | Unexpected failure; the request id is the only correlation |
| `unavailable` | 503 | Dependency down; `Retry-After` |
| `recovery_sealed` | 503 | Serving sealed by BE-12 recovery; `Retry-After` |

Every problem carries `request_id`, the server-generated UUIDv7 that also appears in the `X-Request-Id` response header and the audit record. Navigation endpoints of the login flows answer with `303` redirects to `/login?error=<code>` instead of JSON, because a browser navigation cannot render a problem body usefully ([identity login](identity-login.md) section 2).

## 5. Pagination

List operations use keyset pagination: `page_size` 1 to 500, default 50; an opaque `page_token` of at most 512 base64url characters; responses `{items, next_page_token?, total: {count, exact}}` with `count` exact up to 10,000 and `exact: false` beyond (console design section 4). A token encodes a format version, the operation id, a SHA-256 digest of the normalized filter and sort parameters, and the last row's sort key. It is not secret and not signed: the server rejects a token whose operation or digest differs from the request as `validation_failed`, and authorization and scope apply to every page, so an edited token can only select another position in rows the caller may already read. This slice fixes ascending `(created_at, uid)` order, with `first_seen_at` for link requests and `(resource_kind, uid)` for approval targets. No client-selected sort is accepted. The token is canonical base64url of compact sorted-key UTF-8 JSON `[1, operationId, filter_sha256_hex, last_key]`; reject duplicate keys, wrong tuple arity/types and any key inconsistent with the fixed order. Normalize omitted query defaults, exclude page size/token, and sort multi-value filters before hashing. Reapply current scope to rows and counts on every page; changing authority can cause omissions or repeats, so this is not a snapshot export. `total.count` is min(actual count, 10000), with `exact` true through 10000 and false beyond.

## 6. Concurrency and idempotency

Versioned resources carry a strong `ETag` `"r<revision>"`. `PUT`, `PATCH` and `DELETE` on them require `If-Match` with that value: absent is `428 precondition_required`, different is `412 precondition_failed`, and a weak validator, wildcard or list is rejected.

Every unsafe operation declares `x-ricevanta-concurrency: if_match` or `not_versioned`; all `PUT`, `PATCH` and `DELETE` operations in this profile use `if_match`. Revision-changing POST actions on existing local accounts also use `if_match`. Rule `R24` requires exactly one operation-level `If-Match` header for that class, `required: true`, with the exact canonical schema in `components.parameters.IfMatch`; the validator pins that schema independently, so weakening the shared definition fails too.

Path-level parameters are excluded from this profile. The current eight versioned operation IDs are pinned in the validator; changing their classification requires a contract review. New unsafe operations must choose a class explicitly. The console shows the server version beside the operator's edit on `412` (console design section 1.2).

Every operation that answers `202` with an approval request requires `Idempotency-Key`, 16 to 64 characters of `[A-Za-z0-9_-]`; other unsafe operations declare `x-ricevanta-idempotency: not_supported`. The header follows the expired IETF draft [draft-ietf-httpapi-idempotency-key-header-07](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) in name and purpose only; Ricevanta fixes its own rules. The server stores `(epoch, principal uid, operationId, key)` with SHA-256 of JCS `[method, concrete_path, normalized_query, if_match_or_null, body_or_null]`, and the final status/body for 24 hours. Normalize JSON after strict decoding; secret request fields contribute only keyed fingerprints to the persisted digest input, and their recoverable after-images remain envelope-encrypted. Never store a request plaintext or one-time response secret in this table. Atomic reservation picks one executor; uncertain outcomes reconcile by operation uid before a retry can run, never by an expired lock alone. After authenticating and rechecking current permissions, visibility and freshness, a retry with the same digest returns the stored response; a different digest is `422 idempotency_key_reused`; a retry while the first request executes is `409 idempotency_in_progress`. Responses that carry a one-time secret (`createApiToken`, `claimBreakGlassEnrollmentCode`, break-glass enrollment) are `not_supported`, because storing the response would store the secret; a lost response means revoking and recreating. Idempotency records are not authority: approval requests also deduplicate on their binding hash while pending, approved or unresolved in recovery, and BE-12 consumption remains the only replay guard for protected execution. A conclusively stale, expired or rejected request with no applied effect permits an explicit new proposal with a new request uid and Idempotency-Key; it never revives the old approval or evidence. An uncertain effect must reconcile before that binding can be proposed again. A restored database stays sealed; the new epoch rejects old credentials and excludes old idempotency records. A newly authenticated explicit retry may create a new proposal, but requires fresh approval and cannot revive a consumed action. Store/MAC tampering is never authority to create, approve or apply work. Sign the status/body digest with the identity record key and bind its operation uid and epoch; a mismatch fails closed rather than returning attacker-controlled response content.

## 7. Credentials, request identity and response headers

An operation accepts the credentials its binding lists: the session cookie `__Host-rv_session` (with the synchronizer token on unsafe methods) or a bearer API token `rvt_…` in `Authorization`. A request carrying both is `credentials_ambiguous`. OpenAPI security requirements mirror the binding: `{session, csrf}` for unsafe session operations, `{session}` for safe ones, `{token}` where tokens are accepted, `[]` for public and protocol operations. The meaning of each credential, the CSRF rules and fresh authentication are in [identity sessions](identity-sessions.md).

The server generates a UUIDv7 request id for every request and returns it in `X-Request-Id`. A client `X-Request-Id` matching `^[A-Za-z0-9-]{1,64}$` is logged as `client_request_id`; it never becomes the server id. Every `/api/v1` response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin` and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. No `Access-Control-*` header is ever sent: the console is same-origin (architecture section 3.1), so a cross-origin browser request that needs a preflight fails, and `OPTIONS` is `405`.

Rate limits are token buckets keyed by principal for authenticated requests, 50 requests per second with a burst of 200 per principal by default; buckets are per replica, so the deployment ceiling is multiplied by replica count, and by source address for public and protocol operations at the per-operation values in [identity login](identity-login.md). Until a trusted-proxy configuration exists (BE-15 logs only the TCP peer), the source is the TCP peer, so requests behind one load balancer share a bucket; section 12 records that limit.

## 8. Authorization binding and route table

Every operation carries `x-ricevanta-authorization`, validated by [`extensions.schema.json`](../../schemas/openapi/v1/extensions.schema.json):

| Field | Values | Meaning |
|---|---|---|
| `principal` | `public`, `protocol`, `subject`, `permission` | Who may call: anyone; a protocol credential named in `protocol` (OIDC callback, SAML response, break-glass login, enrollment code, enrollment-challenge cookie, setup token); the authenticated subject acting on its own resources; or a holder of the listed permissions |
| `credentials` | `session`, `token` | Accepted credentials for `subject` and `permission` |
| `permissions` | `{name, uses, selector?}` | Each `name` must be an active catalogue entry whose `uses` contains this exact string; entries without `selector` are all required; among entries with selectors exactly one branch applies, chosen by the server from the request as the operation's description states |
| `reauth` | `none`, `recent`, `bound` | Fresh authentication: none, within 10 minutes, or within 10 minutes and bound to the approval request being decided |
| `csrf` | `none`, `synchronizer`, `origin`, `navigation`, `navigation_callback`, `cross_site_post` | The request-guard class of [identity sessions](identity-sessions.md) section 4 |

`x-ricevanta-gates: [BE-12]` is required on every operation in this revision, including public provider discovery and protocol callbacks, because they read or create identity authority. It is a build/startup admission dependency, not a `501` handler. Before integration BE-15 serves reserved-prefix `404`; a configured production API whose gate is unavailable refuses startup. Once admitted, transient dependency loss answers `unavailable` or `recovery_sealed`; login navigations use the bounded `unavailable` redirect. No test authority reader is admitted into a release build.

`x-ricevanta-decision-replay: exact_result` is required only on the four approve/reject routes. Rule `R22` rejects omission there or addition elsewhere, especially one-time credential delivery. This marker selects the narrow replay branch below.

The validator enforces: every permission with identity-authority approval, and `authz.approvals.approve`, `authz.approvals.reject`, `identity.authority.approve` and `identity.tokens.create`, needs `reauth` other than `none`; any `reauth` other than `none` accepts the session only, so API tokens can request protected actions but never approve them (BE-09); `bound` is only for identity-authority approval; every permission whose catalogue protection is not `none` answers `202` with the `ApprovalAccepted` response and requires `Idempotency-Key`; unsafe session operations use the synchronizer class; navigation operations answer only `303`; and everything else answers the `Problem` response by default.

The Go server registers handlers in one route table, `server/internal/transport/api/routes.go`, with method, path template, operationId and binding per row. A test parses the embedded document and requires the set of rows to equal the set of documented operations with identical bindings, so a handler without a documented binding, or a binding change on one side only, fails the build. Unknown paths and methods under `/api/v1/` answer `404` and `405` problems; nothing is reachable without a row. The request pipeline runs, in order: request id and response headers; body size; credential parsing (section 7); the ordered guard of identity sessions section 4, including credential validation; permission and scope resolution through the `authz` module; fresh-authentication check; strict decoding and schema validation; idempotency; the handler. Decision routes alone branch after the ordered credential/CSRF guard: strict bounded decoding, current read visibility and exact-result replay under identity sessions section 6.2 precede decision-permission and freshness checks. If no decision exists, apply those new-decision checks and the fenced transition in section 6.1. A replay terminates the pipeline without calling an executor. Their `reauth` binding describes new decisions, not this read-only result path. Catalogue metadata never authorizes: the `authz` module resolves current grants and scope for every request (permission catalogue section 1).

Canonical catalogue revision 4 binds `identity.providers.create`, `identity.providers.delete` and the exact operation selectors for identity, break-glass, principal-link, session, approval and change-stream reads. The validator reads `schemas/permissions/v1/catalogue.json` directly and checks its schema. The private code-defined delta in `scripts/ci/catalogue_compat.py` retains the exact transition under [permission API migration](permission-api-migration.md); no active catalogue proposal remains. [Contract validation Task 1](../plans/contract-validation.md#task-1-catalogue-migration-and-coverage) requires canonical and embedded bytes, the event-bound compatibility guard and the completed permission coverage source refresh to pass independent implementation review and CI together. This metadata change admits no production handler.

The canonical catalogue covers every named permission action. `getSession`, logout, re-authentication, own/eligible approval reads and requester-only enrollment-code claim use subject ownership. Login options and SP metadata are public metadata; callbacks, local login, enrollment and setup use their distinct protocol proofs, not synthetic permissions. `streamChanges` uses subject authentication plus every topic's permission and scope from change-stream section 2. Selector branches are server-selected from authoritative owner/kind/visibility, never accepted as a caller's claim. An unmatched selector denies; a subject exemption applies only where this paragraph and identity sessions explicitly name one.

Every protected proposal requires a `justification` of 1 to 2,000 characters, including DELETE/action requests with a small JSON body. The approval binding includes operation, requester, epoch, policy generation, canonical request digest, exact resource revisions, complete dependency/affected-method closure and frozen targets. `getApprovalRequestTargets` returns pages of those frozen targets, ordered by resource kind and uid, with before/after hashes and sanitized canonical JSON before/after views; absent before/after is JSON null. Secret fields become keyed fingerprints plus change indicators, never raw values or ciphertext. Each view uses its resource's read schema and excludes write-only input fields. A decider needs the relevant resource read permission as well as decision eligibility; pending create views use the proposed resource's read permission. Target pages and detail apply the same own/eligible/queue-reader checks, never an unsigned page-token grant. The action's target count, page set and digest must agree; absent/redacted required inspection data prevents approval. Ordinary device-action dispatch schemas remain owned by their domain specs, not this identity slice.

For provider, link and local-account mutations the list/detail resource's positive `revision` produces `ETag` exactly as `"r<revision>"`; lists expose that per-item string. The server rechecks it at proposal creation and again as the frozen before-image at apply. All list operations use the fixed pagination order of section 5. Newly created approval Location is `/api/v1/approval-requests/<uid>`; token creation omits Location because this revision has no token-detail route.

## 9. Generated console client

The console build runs `openapi-typescript` 7.13.0 on the document into `console/src/api/generated/schema.ts`, which is build output and never committed, and uses `openapi-fetch` 0.17.0 as the typed `fetch` wrapper (BE-08). One client instance adds `X-Ricevanta-CSRF` on unsafe methods, `X-Request-Id`, and `X-Ricevanta-Background: 1` on background refreshes, and maps every problem to the discriminated union of console design section 1.2 by `type`; an unknown type maps to `unavailable`. `openapi-typescript` 7.13.0 depends on `@redocly/openapi-core`; its acceptance of `openapi: 3.1.2` and of the `x-ricevanta-*` extensions is a pinned-tool claim, verify before client implementation. Generate a checked `.ts` type-only module, not a declaration file, so console foundation section 2's declaration ban remains intact. Include it in the application compiler project and repeat source/coverage checks after generation. No exception or compiler relaxation is authorized here.

## 10. Validation commands and fixtures

`python3 -B schemas/openapi/v1/validate.py` checks the vendored schema digests, strict YAML, the OpenAPI 3.1 schema, every profile rule above with a rule code (`R01` to `R24`), the canonical catalogue schema and every fixture against [`models.py`](../../schemas/openapi/v1/models.py). `python3 -B -m unittest schemas/openapi/v1/test_validate.py` applies each mutation in `fixtures/document-mutations.json` and strict-YAML, request-shape and protocol regressions and requires the named rule code. Both use the design validator closure pinned in `.github/requirements-design.txt` and no network.

| Fixture | Consumers | Content |
|---|---|---|
| `problems.json` | Go problem writer, console problem mapping | Valid and invalid problem bodies, including status/type and member rules |
| `http-guards.json` | Go request pipeline | Credential, resource-isolation and request-forgery decisions |
| `return-paths.json` | Go login handlers, console login page | Return-path normalization |
| `totp.json` | Go break-glass verifier | RFC 6238 vectors and window/replay decisions |
| `sessions.json` | Go session store, console idle dialog | Expiry precedence, activity throttling, timeout ranges, exact `Set-Cookie` strings |
| `login.json` | Go OIDC callback and SAML consumer | Decision order and outcome codes |
| `sse.json` | Go encoder and topic parser, console stream reader | Exact frames, WHATWG parsing over chunk boundaries, subscription decisions |
| `security.json` | Identity/authorization qualification | Freshness, separate decision/replay/application predicates, stale generation, deny, transport deadlines and enrollment/claim predicates; not a journal or transport proof |
| `wire.json` | Schema consumers | Positive/negative request and response shapes, conditional factor enrollment and invalid calendar times |
| `document-mutations.json` | Validator tests | Rule-code expectations |

## 11. Security trace

Path: the reviewed document → validator in design CI → embedded byte copy and route-table equality test in the server build → request pipeline → handler. The document is metadata; a compromised build or repository can change it like any code, and review plus the drift tests are the controls.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Nothing on `/api/v1`: enrollment tokens are accepted only on `/agent/v1/enroll`, and no binding names them as a credential |
| Compromised agent host | The agent holds no API token or session; it can reach `/api/v1` like any network client and gets public login options and SAML metadata only |
| Compromised console session | Everything the operator's grants allow through ordinary operations; including other users' resources when the operator has explicit management rights, but never a permission outside the binding, never an approval without fresh authentication ([identity sessions](identity-sessions.md) section 9) |
| Rogue extension publisher | No path: console modules reach operations only through the bridge's safe-operation catalogue (EXT-04), which excludes every operation in this slice |
| Network position between agent and server | Not on this channel; between browser and server, TLS protects the API, `__Host-` cookies and HSTS block downgrade and subdomain cookie injection |
| Database writer without signing keys | Can delete/replay valid stored records or alter ordinary data; response MACs reject forged idempotency content and BE-12 rejects stale authority. Route/binding metadata lives in the binary but cannot authenticate database contents by itself |
| Server restored from backup | Serving stays sealed through the BE-12 transition; new-epoch credentials cannot reuse old idempotency records or approvals. Routes and bindings still come from the binary |

## 12. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one document drives the console types, the CLI and third-party clients; the authorization binding is checked against the catalogue in design CI and against the route table in the server build, so an undocumented or unbound operation cannot ship; closed request schemas and strict decoding make every input bounded; one problem table gives the console one error mapping.

Trade-offs: a hand-written document is maintained beside the handlers, accepted because generators cover OpenAPI 3.1 only partly (backend design section 2) and the drift test catches divergence; explicit concurrency classes and pinned versioned-operation IDs require manual upkeep but make header removal detectable; strict request decoding rejects clients that send extra fields, which is the point; unsigned page tokens trade tamper evidence for no key material, safe because authorization applies per page.

Dependencies: `jsonschema` 4.25.1, `referencing` 0.37.0 and PyYAML 6.0.3 in the existing design validator closure; the existing vendored OpenAPI Initiative schemas and their checked Apache-2.0 license bytes (a licensing-register row remains required before production adoption); `openapi-typescript` 7.13.0 and `openapi-fetch` 0.17.0 in the console; Go standard library on the server; BE-15 for the listener; the PostgreSQL platform slice for persistent idempotency.

Limits: source-address rate limits share one bucket behind a load balancer under the fixed TCP-peer source policy; API compatibility against the previous release is a review rule until the first release exists, after which release CI compares documents; generated types are only as current as the document.

Alternatives considered: inferring versioned writes from the presence of `If-Match` would silently accept its removal, so classification is independent. Generating the document from Go code (rejected: partial 3.1 generator support and authorization bindings hidden in code annotations); JSON instead of YAML for the document (not chosen: the strict loader removes YAML's ambiguities and the document stays reviewable); signed page tokens (rejected: a key for no authority gain); RFC 9457 `about:blank` with status-only errors (rejected: the console needs stable types); per-operation permission checks inside handlers only (rejected: an omitted check would be silent, while the route table makes the binding mandatory).

## 13. Unresolved questions

- Which reviewed BE-12 and platform integration plans provide the production dependency and publication checks?
- Which effective-role, directory-mapping and direct-authority-assignment contracts supply the current grants these bindings require?

The pinned generator must accept OpenAPI 3.1.2 and emit a type-only `.ts` module that passes the console's strict compiler and source checks before client integration.

TCP-peer source buckets are the fixed choice here, including shared limits behind a proxy. A forwarded-client-address feature requires its own trust configuration design.
