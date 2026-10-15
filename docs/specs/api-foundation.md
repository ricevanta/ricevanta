# API foundation

`/api/v1` is described by one hand-written OpenAPI 3.1 document, [`schemas/openapi/v1/openapi.yaml`](../../schemas/openapi/v1/openapi.yaml), and every operation in it follows the rules below: strict JSON, RFC 9457 problem details, keyset pagination, `ETag` concurrency, `Idempotency-Key` for requests that create approval requests, and an authorization binding that names the exact permission catalogue entry. The console client is generated from the document. This specification is the contract for the administration API; it does not by itself implement an operation.

Authorities: BE-05, BE-08 and BE-16 in [decisions](../decisions.md), [architecture](../architecture.md) section 3.3, [backend design](../design/backend.md) section 2, [console design](../design/console.md) section 1.2 and [the implementation plan](../plans/api-foundation.md). Identity and session operations are specified in [identity login](identity-login.md) and [identity sessions](identity-sessions.md); `/api/v1/changes` in [change stream](change-stream.md). The permission names come from the [permission catalogue](permission-catalogue.md).

## 1. Boundary and dependencies

Included: the document skeleton with the identity, session, approval-decision and change-stream operations; the shared components (problem details, pagination, identifiers, timestamps, approval request); the `x-ricevanta-*` extensions; the vendored OpenAPI 3.1 meta-schemas; the validator, its reference models and fixtures; the Go request pipeline that enforces these rules; the generated console client.

Excluded: domain operations of other areas (devices, alerts, policies and the rest of console design section 5), which each domain slice adds to the same document under these rules; the connector contracts under `schemas/openapi/connectors/`, which stay separate documents (EXT-05); GitOps resource schemas.

The `api` role and its listener come from the server runtime slice (BE-15, `docs/specs/server-runtime.md` on its slice branch): one root handler, reserved prefixes that never fall back to the console document, per-handler read and write deadlines and `/api/v1/*` answering `404` while no operation exists. This specification replaces that `404` with the route table of section 8 and inherits everything else. Persistent stores (idempotency records, sessions, change watermarks) need the PostgreSQL platform slice, which does not exist yet; until it does, the pipeline runs against the store interfaces and in-memory test implementations named in the plan.

## 2. Document and versioning

- One YAML file, at most 1 MiB, exactly one document, UTF-8, with no anchors, aliases, explicit tags, duplicate keys or non-string keys. [RFC 9512](https://www.rfc-editor.org/rfc/rfc9512.html) registers `application/yaml` and warns about alias expansion (section 4.2); refusing anchors removes that class instead of bounding it. The server serves the embedded bytes unchanged as `getOpenApiDocument` with `Content-Type: application/yaml`.
- `openapi: 3.1.2`. OpenAPI 3.1.2 ([specification](https://spec.openapis.org/oas/v3.1.2.html), 19 September 2025) states that tooling should treat 3.1 patch versions alike; pinning the exact patch keeps the validator and its vendored schema in step. The validator checks the document against the OpenAPI Initiative's published `schema-base/2026-08-03` and `dialect/2024-11-10` schemas, vendored with their digests and the Apache-2.0 license in [`schemas/openapi/upstream/`](../../schemas/openapi/upstream/lock.json). The specification calls that JSON Schema informational and itself authoritative; the profile rules in this document carry what the schema cannot.
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
| Field names | `snake_case`; times are RFC 3339 UTC with `Z` and at most nine fractional digits; hashes are `sha256:<hex>` |

The server decodes JSON strictly: invalid UTF-8, duplicate member names at any depth, unknown members, trailing data, nesting deeper than 32, integers outside the declared range and strings longer than declared are `validation_failed`. Go's `encoding/json` accepts duplicate names and replaces invalid UTF-8 ([documentation](https://pkg.go.dev/encoding/json)), so the pipeline tokenizes first, as the permission catalogue parser already does. Every request string has `maxLength`, every request array `maxItems`, every request integer both bounds and every request object `additionalProperties: false`; the validator rejects a request schema that lacks one.

## 4. Errors

Every error body is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) problem with `application/problem+json`. `type` is an absolute URI from the closed table below (section 3.1.1 recommends absolute URIs); `about:blank` is never sent. `title` is a fixed English string per type; the console shows its own localized text for the type. `instance`, when present, is `urn:uuid:<request_id>`. `detail` never contains request values, resource data, secrets or stack traces (section 5). Clients ignore unknown members (section 3.2).

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
| `not_implemented` | 501 | Operation documented but its gate (section 8) is closed in this build |
| `unavailable` | 503 | Dependency down; `Retry-After` |
| `recovery_sealed` | 503 | Serving sealed by BE-12 recovery; `Retry-After` |

Every problem carries `request_id`, the server-generated UUIDv7 that also appears in the `X-Request-Id` response header and the audit record. Navigation endpoints of the login flows answer with `303` redirects to `/login?error=<code>` instead of JSON, because a browser navigation cannot render a problem body usefully ([identity login](identity-login.md) section 2).

## 5. Pagination

List operations use keyset pagination: `page_size` 1 to 500, default 50; an opaque `page_token` of at most 512 base64url characters; responses `{items, next_page_token?, total: {count, exact}}` with `count` exact up to 10,000 and `exact: false` beyond (console design section 4). A token encodes a format version, the operation id, a SHA-256 digest of the normalized filter and sort parameters, and the last row's sort key. It is not secret and not signed: the server rejects a token whose operation or digest differs from the request as `validation_failed`, and authorization and scope apply to every page, so an edited token can only select another position in rows the caller may already read. Sorting is allowed only on the fields an operation declares indexed.

## 6. Concurrency and idempotency

Versioned resources carry a strong `ETag` `"r<revision>"`. `PUT`, `PATCH` and `DELETE` on them require `If-Match` with that value: absent is `428 precondition_required`, different is `412 precondition_failed`, and a weak validator is rejected. The console shows the server version beside the operator's edit on `412` (console design section 1.2).

Every operation that answers `202` with an approval request requires `Idempotency-Key`, 16 to 64 characters of `[A-Za-z0-9_-]`; other unsafe operations declare `x-ricevanta-idempotency: not_supported`. The header follows the expired IETF draft [draft-ietf-httpapi-idempotency-key-header-07](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) in name and purpose only; Ricevanta fixes its own rules. The server stores `(principal uid, operationId, key)` with the SHA-256 of the method, path template values and canonical body, and the final status and body, for 24 hours. A retry with the same digest returns the stored response; a different digest is `422 idempotency_key_reused`; a retry while the first request executes is `409 idempotency_in_progress`. Responses that carry a one-time secret (`createApiToken`, `claimBreakGlassEnrollmentCode`, break-glass enrollment) are `not_supported`, because storing the response would store the secret; a lost response means revoking and recreating. Idempotency records are not authority: approval requests also deduplicate on their binding hash, and BE-12 consumption remains the only replay guard for protected execution. A database restored from backup forgets keys newer than the backup, so a client retry after restore can create a second pending request, which still needs its own approval.

## 7. Credentials, request identity and response headers

An operation accepts the credentials its binding lists: the session cookie `__Host-rv_session` (with the synchronizer token on unsafe methods) or a bearer API token `rvt_…` in `Authorization`. A request carrying both is `credentials_ambiguous`. OpenAPI security requirements mirror the binding: `{session, csrf}` for unsafe session operations, `{session}` for safe ones, `{token}` where tokens are accepted, `[]` for public and protocol operations. The meaning of each credential, the CSRF rules and fresh authentication are in [identity sessions](identity-sessions.md).

The server generates a UUIDv7 request id for every request and returns it in `X-Request-Id`. A client `X-Request-Id` matching `^[A-Za-z0-9-]{1,64}$` is logged as `client_request_id`; it never becomes the server id. Every `/api/v1` response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin` and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. No `Access-Control-*` header is ever sent: the console is same-origin (architecture section 3.1), so a cross-origin browser request that needs a preflight fails, and `OPTIONS` is `405`.

Rate limits are token buckets keyed by principal for authenticated requests, 50 requests per second with a burst of 200 by default, and by source address for public and protocol operations at the per-operation values in [identity login](identity-login.md). Until a trusted-proxy configuration exists (BE-15 logs only the TCP peer), the source is the TCP peer, so requests behind one load balancer share a bucket; section 12 records that limit.

## 8. Authorization binding and route table

Every operation carries `x-ricevanta-authorization`, validated by [`extensions.schema.json`](../../schemas/openapi/v1/extensions.schema.json):

| Field | Values | Meaning |
|---|---|---|
| `principal` | `public`, `protocol`, `subject`, `permission` | Who may call: anyone; a protocol credential named in `protocol` (OIDC callback, SAML response, break-glass login, enrollment code, setup token); the authenticated subject acting on its own resources; or a holder of the listed permissions |
| `credentials` | `session`, `token` | Accepted credentials for `subject` and `permission` |
| `permissions` | `{name, uses, selector?}` | Each `name` must be an active catalogue entry whose `uses` contains this exact string; entries without `selector` are all required; among entries with selectors exactly one branch applies, chosen by the server from the request as the operation's description states |
| `reauth` | `none`, `recent`, `bound` | Fresh authentication: none, within 10 minutes, or within 10 minutes and bound to the approval request being decided |
| `csrf` | `none`, `synchronizer`, `origin`, `navigation`, `navigation_callback`, `cross_site_post` | The request-guard class of [identity sessions](identity-sessions.md) section 4 |

`x-ricevanta-gates` lists the decision ids whose unresolved blocker keeps the operation's server implementation closed; a closed gate answers `501 not_implemented`, never a reduced behaviour. `BE-12` is the only gate value in this revision.

The validator enforces: every permission with identity-authority approval, and `authz.approvals.approve`, `authz.approvals.reject`, `identity.authority.approve` and `identity.tokens.create`, needs `reauth` other than `none`; any `reauth` other than `none` accepts the session only, so API tokens can request protected actions but never approve them (BE-09); `bound` is only for identity-authority approval; every permission whose catalogue protection is not `none` answers `202` with the `ApprovalAccepted` response and requires `Idempotency-Key`; unsafe session operations use the synchronizer class; navigation operations answer only `303`; and everything else answers the `Problem` response by default.

The Go server registers handlers in one route table, `server/internal/transport/api/routes.go`, with method, path template, operationId and binding per row. A test parses the embedded document and requires the set of rows to equal the set of documented operations with identical bindings, so a handler without a documented binding, or a binding change on one side only, fails the build. Unknown paths and methods under `/api/v1/` answer `404` and `405` problems; nothing is reachable without a row. The request pipeline runs, in order: request id and response headers; body size; credential parsing (section 7); resource isolation and request-forgery checks; session or token validation; permission and scope resolution through the `authz` module; fresh-authentication check; strict decoding and schema validation; idempotency; the handler. Catalogue metadata never authorizes: the `authz` module resolves current grants and scope for every request (permission catalogue section 1).

New operations from this slice need catalogue bindings that revision 3 lacks: `identity.providers.create`, `identity.providers.delete` and operation-id uses for the identity, break-glass, principal-link, session and approval permissions. [`catalogue-proposal.json`](../../schemas/openapi/v1/catalogue-proposal.json) states the exact revision 4 delta; the validator merges it onto the canonical catalogue and checks the result against the catalogue schema. Plan Task 1 applies it to `schemas/permissions/v1/catalogue.json` and the embedded Go copy together, because the byte drift test (permission catalogue section 5) requires both files to change in one commit, then deletes the proposal; the validator rejects a proposal whose revision the catalogue already reached.

## 9. Generated console client

The console build runs `openapi-typescript` 7.13.0 on the document into `console/src/api/generated/schema.d.ts`, which is build output and never committed, and uses `openapi-fetch` 0.17.0 as the typed `fetch` wrapper (BE-08). One client instance adds `X-Ricevanta-CSRF` on unsafe methods, `X-Request-Id`, and `X-Ricevanta-Background: 1` on background refreshes, and maps every problem to the discriminated union of console design section 1.2 by `type`; an unknown type maps to `unavailable`. `openapi-typescript` 7.13.0 depends on `@redocly/openapi-core`; its acceptance of `openapi: 3.1.2` and of the `x-ricevanta-*` extensions is a pinned-tool claim, verify in plan Task 6. The console foundation's declaration-file ban (console foundation section 2) needs one reviewed exception for that generated file, which plan Task 6 records.

## 10. Validation commands and fixtures

`python schemas/openapi/v1/validate.py` checks the vendored schema digests, strict YAML, the OpenAPI 3.1 schema, every profile rule above with a rule code (`R01` to `R21`), the catalogue proposal and every fixture against [`models.py`](../../schemas/openapi/v1/models.py). `python schemas/openapi/v1/test_validate.py` applies each mutation in `fixtures/document-mutations.json` and five strict-YAML defects and requires the named rule code. Both use the design validator closure pinned in `.github/requirements-design.txt` and no network.

| Fixture | Consumers | Content |
|---|---|---|
| `problems.json` | Go problem writer, console problem mapping | Valid and invalid problem bodies, including status/type and member rules |
| `http-guards.json` | Go request pipeline | Credential, resource-isolation and request-forgery decisions |
| `return-paths.json` | Go login handlers, console login page | Return-path normalization |
| `totp.json` | Go break-glass verifier | RFC 6238 vectors and window/replay decisions |
| `sessions.json` | Go session store, console idle dialog | Expiry precedence, activity throttling, timeout ranges, exact `Set-Cookie` strings |
| `login.json` | Go OIDC callback and SAML consumer | Decision order and outcome codes |
| `sse.json` | Go encoder and topic parser, console stream reader | Exact frames, WHATWG parsing over chunk boundaries, subscription decisions |
| `document-mutations.json` | Validator tests | Rule-code expectations |

## 11. Security trace

Path: the reviewed document → validator in design CI → embedded byte copy and route-table equality test in the server build → request pipeline → handler. The document is metadata; a compromised build or repository can change it like any code, and review plus the drift tests are the controls.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Nothing on `/api/v1`: enrollment tokens are accepted only on `/agent/v1/enroll`, and no binding names them as a credential |
| Compromised agent host | The agent holds no API token or session; it can reach `/api/v1` like any network client and gets public login options and SAML metadata only |
| Compromised console session | Everything the operator's grants allow through ordinary operations; never another principal's resources, never a permission outside the binding, never an approval without fresh authentication ([identity sessions](identity-sessions.md) section 9) |
| Rogue extension publisher | No path: console modules reach operations only through the bridge's safe-operation catalogue (EXT-04), which excludes every operation in this slice |
| Network position between agent and server | Not on this channel; between browser and server, TLS protects the API, `__Host-` cookies and HSTS block downgrade and subdomain cookie injection |
| Database writer without signing keys | Can alter idempotency records to replay a stored response to the same principal, and stored pagination order; cannot create a route, binding or permission, which live in the binary |
| Server restored from backup | Forgets idempotency keys newer than the backup (section 6); routes and bindings come from the binary |

## 12. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one document drives the console types, the CLI and third-party clients; the authorization binding is checked against the catalogue in design CI and against the route table in the server build, so an undocumented or unbound operation cannot ship; closed request schemas and strict decoding make every input bounded; one problem table gives the console one error mapping.

Trade-offs: a hand-written document is maintained beside the handlers, accepted because generators cover OpenAPI 3.1 only partly (backend design section 2) and the drift test catches divergence; strict request decoding rejects clients that send extra fields, which is the point; unsigned page tokens trade tamper evidence for no key material, safe because authorization applies per page.

Dependencies: `jsonschema` 4.25.1, `referencing` 0.37.0 and PyYAML 6.0.3 in the existing design validator closure; the vendored OpenAPI Initiative schemas under Apache-2.0 ([licensing](../licensing.md)); `openapi-typescript` 7.13.0 and `openapi-fetch` 0.17.0 in the console; Go standard library on the server; BE-15 for the listener; the PostgreSQL platform slice for persistent idempotency.

Limits: source-address rate limits share one bucket behind a load balancer until a trusted-proxy configuration exists; API compatibility against the previous release is a review rule until the first release exists, after which release CI compares documents; generated types are only as current as the document.

Alternatives considered: generating the document from Go code (rejected: partial 3.1 generator support and authorization bindings hidden in code annotations); JSON instead of YAML for the document (not chosen: the strict loader removes YAML's ambiguities and the document stays reviewable); signed page tokens (rejected: a key for no authority gain); RFC 9457 `about:blank` with status-only errors (rejected: the console needs stable types); per-operation permission checks inside handlers only (rejected: an omitted check would be silent, while the route table makes the binding mandatory).

## 13. Unresolved questions

- Which trusted-proxy configuration identifies the client address behind the Helm ingress for rate limiting and audit? Until settled, the TCP peer is used and shared buckets are accepted.
- Does `openapi-typescript` 7.13.0 accept `openapi: 3.1.2` without a warning-free fallback? Plan Task 6 verifies; the document does not downgrade its declared version to suit a tool.
