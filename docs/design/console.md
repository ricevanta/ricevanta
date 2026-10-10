# Console design

How the web console is built: application structure, login and sessions, authorization in the UI and the approval queue, live data for large fleets, the views of every feature area, console security, internationalization and accessibility, the design system, testing, and build and delivery. The feature list is `../blueprint.md` section 3.8; the stack is section 2. Adjacent facts live elsewhere and are linked, not restated: the API and GitOps in `../architecture.md` section 3.3 and `../specs/policy-envelope.md` section 8; RBAC and approvals in BE-02 and `../specs/policy-envelope.md` section 2.3; console module isolation, slots and the bridge in `extensions.md` section 5; identity sources in BE-01; the build into the server binary in SH-04 and `../architecture.md` section 3.1. Decisions: BE-01 to BE-05, BE-08 to BE-11, EXT-02, EXT-04, DLP-02, DLP-03 and SH-04 in `../decisions.md`. This file settles two items of `../analysis.md` section 3: the console exploration views of the Lineage bullet (section 5.5) and the report template format of the Extensions bullet (`../specs/report-template.md`). Claims marked "verify" rest on vendor pages, repository files or memory rather than first-party documentation.

The console runs in the operator's browser and adds nothing to the agent's footprint. Operating-system differences reach the console only as data: per-device capability states with the reasons the agent reports (section 5.1).

## 1. Application structure

The [console foundation spec](../specs/console-foundation.md) and [implementation plan](../plans/console-foundation.md) define the first code slice, exact pins, generated tokens, catalogue validation and built-output CSP tests. Its foundation header specializes section 6.1 with frames and workers denied until reviewed consumers exist; API generation, authentication and live data remain dependent slices. Work follows [Vue instructions](../../instructions/vue.md).

### 1.1 Stack

| Concern | Choice | License |
|---|---|---|
| Framework | Vue 3.5 with the Composition API, `<script setup>` single-file components and TypeScript in strict mode; templates precompiled, runtime-only build | MIT |
| Build | Vite 8 | MIT |
| State | Pinia: one store for the session and permissions, one for preferences, and a cache store behind the `useResource` composable (section 4) | MIT |
| Routing | Vue Router 5, history mode, one lazily imported chunk per feature area; route `meta.requires` names the permissions the route needs (section 3) | MIT |
| API client | `openapi-typescript` requires a hand-written OpenAPI 3.1 contract under `schemas/openapi/`, absent and blocking generated console clients (`../analysis.md` section 3); `openapi-fetch` is the typed `fetch` wrapper | MIT, both |
| Components | Reka UI primitives under in-house styled components; TanStack Table and TanStack Virtual for data grids (section 8) | MIT |
| Charts | Apache ECharts, imported per component from `echarts/core` with the SVG renderer and the aria component | Apache-2.0 |
| Lineage graph | Cytoscape.js with the `cytoscape-dagre` layout and `dagre` | MIT |
| Policy editor | CodeMirror 6 with `@codemirror/lang-yaml`, `@codemirror/lint`, `@codemirror/autocomplete` and `@codemirror/merge`; the `yaml` package for parsing with source ranges; Ajv standalone validators compiled at build time | MIT; `yaml` ISC |
| Strings | `vue-i18n` 11 with `@intlify/unplugin-vue-i18n` precompiling messages | MIT |

The console source lives in `console/` (SH-04): `src/app` (bootstrap, router, error handling), `src/api` (generated types, client, problem mapping), `src/stores`, `src/ui` (the design system), `src/features/<area>` (one directory per section 5 area, each with its routes, views and composables), `src/locales` and `tests/`.

### 1.2 API client and errors

The OpenAPI document is hand-written and validated in CI (`backend.md` section 2). The console build runs `openapi-typescript` on it, so a removed or renamed field fails `vue-tsc` type checking before a test runs; generated files are build output, never committed. `openapi-fetch` returns `{ data, error, response }` typed per operation. Every console call goes through one client instance that adds the CSRF header (section 2.3), the `X-Request-Id` correlation header and the background marker of section 2.4.

Errors are RFC 9457 problem details (`application/problem+json`) with a `type` URI under `https://ricevanta.io/problems/`. The client maps them to one discriminated union: `validation` (field paths mapped onto form fields and editor ranges), `permission_denied` (names the missing permission), `reauth_required` (section 2.5), `conflict` (a stale `If-Match`: the view shows the server version beside the operator's edit), `not_found`, `rate_limited` (honours `Retry-After`), `unavailable` and `network`. A protected write answers `202 Accepted` with an approval request rather than an error (section 3.2). `app.config.errorHandler` and the router's `onError` catch unexpected exceptions and show the request id; no error text with resource data is sent anywhere.

Writes to versioned resources send `If-Match` with the resource's `ETag`, so two operators editing one policy cannot overwrite each other silently.

### 1.3 Code splitting

Each feature area is one route-level chunk. ECharts, Cytoscape.js and CodeMirror load only with the views that use them. The console is one first-party build with nothing to federate, so `@module-federation/vite` is not used; third-party UI enters only through console module iframes (EXT-04, `extensions.md` section 5).

## 2. Authentication and session

### 2.1 Login flows

The login page lists the identity providers configured under BE-01. Every flow ends in the same server-side session; the console never sees a token from an identity provider.

- OIDC: the console navigates the top-level window to `startOidcLogin`. The server, a confidential client, sets a pre-login cookie `__Host-rv_login` (`Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, 10 minutes) that references the stored `state`, `nonce` and PKCE (Proof Key for Code Exchange) verifier, and redirects to the provider with the authorization code flow and the `S256` challenge. The callback `completeOidcLogin` checks the cookie, `state`, `nonce` and ID token, resolves the immutable principal link and then maps ordinary role claims (`backend.md` section 1.1), creates the session and redirects with `303` to the console path stored at the start, accepted only as a same-origin path from the console's route table, so the callback is no open redirect. `Lax` lets the cookie travel on the provider's top-level `GET` back to the callback.
- SAML (Security Assertion Markup Language), where a provider lacks OIDC: SP-initiated only, with the HTTP-Redirect binding for the request and HTTP-POST to the assertion consumer service. A cookie set with an explicit `SameSite=Lax` travels only on safe-method top-level requests, never on a cross-site `POST` (MDN Set-Cookie), so the pre-login cookie `__Host-rv_saml` is `SameSite=None; Secure; HttpOnly` and short-lived; the consumer requires that cookie and an `InResponseTo` equal to the stored request id. IdP-initiated responses are refused, since they carry no request to bind and allow login cross-site request forgery.
- Break-glass local login (BE-01) at `/login/local`: user name, password and a TOTP (Time-based One-Time Password, RFC 6238) code in one form submitted by `fetch`. Paste and password managers work in every field (WCAG 3.3.8). Failures slow later attempts for that account and that source with a delay that doubles up to 15 minutes, rather than a hard lockout, which an attacker could use to deny the break-glass path. Every attempt is audited and every success raises an alert through the notifier connectors. A break-glass session shows a persistent banner and uses the shorter timeouts of section 2.4.
- First start: the server writes a one-time setup token to a file readable only by the server user and logs its path, never its value. The setup page consumes it to create the first administrator with a password and TOTP enrollment, then uses the protected flow to configure an identity provider. Before normal APIs open, setup also verifies the offline recovery quorum manifest (`backend.md` section 6.1). A single administrator uses an exact offline-signed authority request until a different unaffected approver exists; the setup token grants no later bypass.

### 2.2 Session cookie

`__Host-rv_session`: `Secure`, `HttpOnly`, `Path=/`, `SameSite=Strict`, no `Domain`. The value is 256 random bits; the `identity` module stores its SHA-256 with the user, the authentication time and method, the last activity time and the expiry. The session id rotates at login and at re-authentication. A login callback reached from the provider's site does not send the `Strict` cookie on that one document request, which needs none: the console document is a static shell, and its same-origin API calls carry the cookie.

### 2.3 Cross-site request forgery

Defence in three layers, following the OWASP cross-site request forgery cheat sheet, which treats `SameSite` as defence in depth only: the `Strict` cookie; a synchronizer token that `getSession` returns, held in memory only and sent in `X-Ricevanta-CSRF` on every unsafe method; and server rejection of an unsafe method whose `Sec-Fetch-Site` is present and not `same-origin` or whose `Origin` is present and not the console origin. Requests authenticated by an API token in `Authorization: Bearer` skip the token check, since browsers never attach a bearer token by themselves; a request that carries both a session cookie and a bearer token is refused.

### 2.4 Timeouts

| Session | Idle | Absolute | Configurable range |
|---|---|---|---|
| Single sign-on | 15 minutes | 8 hours | Idle 5 to 60 minutes; absolute 1 to 12 hours |
| Break-glass | 5 minutes | 1 hour | Idle 2 to 15 minutes; absolute 15 minutes to 4 hours |

The defaults sit inside the OWASP session-management ranges: 15 to 30 minutes idle for low-risk applications and 2 to 5 minutes for high-value ones, and 4 to 8 hours absolute for a working day. The single sign-on idle default takes the low end of the low-risk range because re-authentication (section 2.5) guards the high-value actions; break-glass sessions take the high-value range.

Idle time counts operator-initiated requests only: the change stream and background refreshes send `X-Ricevanta-Background: 1` and never extend a session. Two minutes before idle expiry a dialog offers to continue (WCAG 2.2.1). After expiry the console returns to the login page and restores the route afterwards; an unsaved policy draft survives in `sessionStorage` (section 6.4). Disabling a user through SCIM, LDAP sync or the console revokes their sessions and tokens at once; a role change takes effect on the next request, and the `session` topic (section 4) refreshes the console's permission set.

### 2.5 Re-authentication

Some actions require an authentication within the last 10 minutes: approving or rejecting a protected action, creating an API token, changing identity providers, principal links, claim or group mappings, directory sources, account recovery, roles, role assignments or access policies, changing the extension trust list, managing break-glass accounts and generating a signed offline uninstall object (`agent.md` section 9). The server answers `reauth_required`; the console sends the operator through the provider with `prompt=login` and `max_age=0` for OIDC, checking the returned `auth_time` claim (OpenID Connect Core 1.0 section 3.1.2.1), or `ForceAuthn="true"` for SAML (SAML 2.0 core section 3.4.1), or asks a break-glass operator for a fresh TOTP code, and then returns to the same view with the form intact. The operator submits again; nothing is replayed automatically. An identity-authority approval also names the authentication method that satisfied re-authentication. The server rejects a method whose provider, principal link, mapping, recovery path or credentials the requested change can affect.

### 2.6 API tokens

The API tokens view lists the operator's tokens with name, the first characters after the `rvt_` prefix, permissions, device-group scope, expiry, creation and last use. Creating one takes a name, a permission subset that the server checks against the creator's effective permissions, an optional device-group scope and an expiry (default 90 days, at most 365); the secret is shown once with a copy control and stored only as a hash. Operators with `identity.tokens.manage` list and revoke every token. A token stops working when its owner is disabled. A token can request protected actions but never approve one: approval needs an interactive session with recent authentication (section 2.5).

## 3. Authorization in the UI

The [permission catalogue](../specs/permission-catalogue.md) owns exact names, scope kinds, operation mappings and approval metadata; its [implementation plan](../plans/permission-catalogue.md) defines the isolated Go library. Catalogue lookup does not authorize a request.

### 3.1 Permission-aware views

`getSession` returns the operator, the effective permissions as `{ name, scope }` pairs (scope `all` or a list of device groups; every name has the form `<module>.<resource>.<verb>`, for example `dlp.evidence.read`), the CSRF token, locale, server version, timeouts, the configured recovery quorum and whether configurable approval policies are disabled. The router hides navigation entries and blocks routes whose read permission is missing; action controls the operator cannot use stay visible but disabled with the missing permission named. That is presentation only: every request is authorized by the server (BE-05), a `permission_denied` problem renders the same "not permitted" state, and fields an operator may not read are omitted by the server, never hidden by the client. A DLP finding read without `dlp.evidence.read` arrives without its snippet.

Device-group scoping is applied by the server to every list, count, chart and report. The group picker offers only the operator's groups. "Select all matching" on a large list sends the filter, not row ids, and the server resolves and freezes the target set inside the operator's scope when it creates the action or approval request.

### 3.2 Approval queue

A protected action from any view (BE-02, `../specs/policy-envelope.md` section 2.3) returns an approval request instead of executing. The console then shows the request id, the approver group, the exact fields the approval binds, the frozen target list with its count and a paged view, and a required justification.

The approvals view has three tabs: awaiting my decision, my requests, and all requests (with `authz.approvals.read`). A request shows requester, time, action, justification, the exact fields and their hash, the frozen targets, the dry-run result where one exists (the compiled-outcome diff for a policy change, section 5.8), the expiry (default 72 hours, set per access policy) and links to its audit events. Approve and reject need a comment and recent authentication (section 2.5). The requester sees the controls disabled with the reason; the server refuses approval by the requesting account in any case. After approval the request shows per-target dispatch state from the command journal reports (`../specs/policy-envelope.md` section 7): pending, delivered, succeeded, failed, refused, undelivered. The `approvals` topic keeps the badge count current, and console modules receive `approval.pending` through the bridge. An installation with configurable approval policies disabled shows the persistent BE-02 warning on every page. The warning also names a one-custodian recovery quorum; single-administrator mode does not disable identity-authority protection.

Identity-authority actions are always protected, even when configurable approval policies are disabled. They include provider trust, issuer, signing certificate, discovery or metadata URL, endpoints and client credentials; principal linking or unlinking; claim and directory group mapping; directory source, sync filter and stable-id choice; account recovery; break-glass creation, reset, second-factor replacement, enable, disable or deletion; and any direct assignment of `identity.authority.approve`. The request binds the immutable internal users, external principal keys, affected authority uids and exact before and after resource hashes. Its approver must be a different enabled internal user with a direct `identity.authority.approve` assignment, and must re-authenticate through an authority not in the affected set. Directory group membership and a mapping being changed cannot confer that permission. The apply transaction reloads those facts and consumes the approval once; a changed mapping, user, authority, hash or authentication method expires the request. Recovery with no unaffected approver uses the offline authority-recovery ceremony in `backend.md` section 6.1, binds the exact authority change and advances the epoch. The ceremony leaves a critical audit record. An interactive session alone cannot bypass the boundary.

## 4. Live data and large fleets

Views refresh from Server-Sent Events (SSE). `streamChanges` (`GET /api/v1/changes`, `text/event-stream`) carries invalidations only: `{ topic, watermark }`, never row data. Each `api` replica reads the per-module, per-device-group change watermarks once every 2 seconds and fans them out to its connected streams, so the database cost is one query per replica, independent of operators, and `NOTIFY` stays off the ingest path (`backend.md` section 3). The stream sends a comment every 25 seconds, under the 60-second proxy idle timeout, and `retry: 5000`; reconnection sends `Last-Event-ID` (WHATWG HTML) and the server replays the current watermarks. Topics are filtered by the operator's read permissions: `devices`, `device/<uid>`, `alerts`, `alert/<id>`, `dlp.findings`, `approvals`, `commands/<device>`, `enrollments`, `certificates`, `rollouts`, `extensions`, `exports` and `session`. The server resolves per-id topics (`device/<uid>`, `alert/<id>`, `commands/<device>`) against the operator's device-group scope at subscription and re-resolves them on the `session` topic; a request for an out-of-scope id is refused as `not_found`. Device-scoped aggregate topics (`devices`, `alerts`, `dlp.findings`) advance per device group, and a stream receives only the watermarks of its operator's groups.

`useResource` caches each operation and parameter set, serves the cached value while revalidating, and refetches a visible view when its topic advances, at most once every 5 seconds per view. A tab hidden for 5 minutes closes its stream and refetches when shown. After three failed reconnections the console polls every 30 seconds and shows that live updates are paused. SSE is preferred because the traffic is one-way, it uses the session cookie and the ordinary request authorization, reconnects by itself, and needs no handshake origin checks; over HTTP/1.1 a browser holds at most six connections per domain, while HTTP/2, which the `api` role serves, negotiates up to 100 streams (MDN).

Lists use keyset pagination: `page_size` 50 by default and at most 500, an opaque `page_token`, and sorting only on the fields the operation declares indexed. Counts are exact up to 10,000 and shown as "10,000+" beyond. Tables render only visible rows through TanStack Virtual and keep at most 5,000 rows in memory; beyond that the view asks for a narrower filter or an export (`createExport`, CSV or OCSF JSON as a background job into the blob store). Search inputs debounce 300 ms. Facet counts are computed by the server and capped. These rules hold the 20,000-endpoint target of EV-01: no view fetches the fleet.

## 5. Feature areas

Each area lists its views, the data it reads, its actions and the OpenAPI operation ids it calls. The owning domain design defines the data; the operation ids are the console's requirements on the OpenAPI document, whose authors fix paths and shapes. Protected actions are marked (P).

### 5.1 Devices

- Views: fleet list with filters (OS, group, label, lifecycle state, compliance, agent version, last check-in, capability state), saved filters, device detail with tabs: overview, hardware and OS inventory, software, users, compliance, capabilities, policies in force, certificates, alerts, DLP findings, commands, footprint.
- Capabilities tab: one row per capability-matrix row (`../platform-support.md`) with its state: supported, unsupported with the agent's `Unsupported(reason)` (`agent.md` section 2) shown as a localized OS-limit text, failing self-test, community adapter (self-tested, not qualified), degraded by the watchdog (AG-08), "not available in this version" for the v2.0.0 capabilities, and OS leaving the support window with the required upgrade. Preflight results and the enforcement components' state sit beside them.
- Policies tab: installed assignment sequence and bundle against the current one, placement labels, and policies the device reports as unsupported. Commands tab: open and recent commands from the journal reports, undelivered ones flagged. Footprint tab: CPU, memory, descriptors and event rates against budget (AG-09).
- Actions: edit labels, groups and ownership; lock; wipe (P); restart; suspend; retire; re-run preflight; issue a recovery token; generate a signed offline uninstall object for a nonce the device displays (re-authentication).
- Operations: `listDevices`, `getDevice`, `getDeviceInventory`, `listDeviceSoftware`, `getDeviceCapabilities`, `getDevicePolicyState`, `listDeviceCommands`, `getDeviceFootprint`, `updateDevice`, `createDeviceAction`, `createUninstallCode`.

### 5.2 Enrollment, management and compliance

- Views: enrollment tokens; pending enrollment approvals showing the request, CSR (Certificate Signing Request) fingerprint, attestation evidence and hardware identifiers, since approval binds that exact request (PKI-02); enrollment configuration download; Apple MDM push certificate setup and renewal with the days remaining; Windows OMA-DM enrollment settings; baselines; software library and deployments; OS update policies; compliance by device, group and baseline item. The meaning of "compliant", baselines, software and update management are defined in `mdm.md`.
- Actions: create a scoped, expiring token (shown once, inside the configuration file offered at creation); approve or reject an enrollment (re-authentication); upload the push certificate; create and assign baselines and deployments through the policy editor (section 5.8).
- Operations: `listEnrollmentTokens`, `createEnrollmentToken`, `revokeEnrollmentToken`, `listEnrollmentRequests`, `decideEnrollmentRequest`, `getEnrollmentConfiguration`, `getApplePushCertificate`, `createApplePushCsr`, `uploadApplePushCertificate`, `listSoftwarePackages`, `createSoftwareDeployment`, `listComplianceResults`.

### 5.3 Alerts and investigations

- Views: alert list (severity, rule, ATT&CK technique, device, user, status, assignee, time); alert detail with the process tree and the bounded context around the finding (`../specs/ocsf-profile.md` section 4), a timeline, the rule, ATT&CK links, enrichment from `enricher` connectors marked by source, related lineage, and response history; investigations that group alerts with notes, status and assignee; telemetry search over the raw store with structured OCSF field filters, at most 7 days and 10,000 rows per query, which states when raw telemetry is not enabled for a device's group (EV-01). The EDR mechanisms are in `edr.md`.
- Attribution: wherever a Sigma match is shown (alert row, alert detail, investigation, dashboard panel, report table) the rule's author from `analytic.author` appears beside the rule name and cannot be hidden by column settings (`../licensing.md`, DRL 1.1).
- Actions: assign, change status, merge into an investigation; kill process, kill and ban, quarantine file, restore file (P), isolate host, release host (P), collect a triage package, scan, run script (P), unban (P); any of these on more than 10 devices (P). Blocking a process by hash or signer is an `edr` policy edit (`edr.md` section 7.2), not a response command (`../specs/edr-response-actions.md`).
- Operations: `listAlerts`, `getAlert`, `updateAlert`, `listInvestigations`, `createInvestigation`, `updateInvestigation`, `searchTelemetry`, `createResponseAction`, `listResponseActions`.

### 5.4 DLP

- Views: DLP policies (the policy list of section 5.8 filtered to `dlp`); classification catalogue (DLP-03); exceptions with expiry, flagged a week ahead; findings list (channel, action, disposition, policy, classification, device, user, destination); finding detail with content hash, rule id, byte offsets, enforcement mode and the redacted snippet of at most 200 characters when the policy kept it and the operator holds `dlp.evidence.read` (DLP-02). No view shows, fetches or downloads raw content, because the server holds none.
- Actions: create and edit policies, categories and exceptions through the editor (weakening changes are P); mark a finding reviewed.
- Operations: `listDlpFindings`, `getDlpFinding`, `updateDlpFinding`, `listClassifications`, `listExceptions`.

### 5.5 Lineage

- Entry points: a file (content hash, or path on a device), a DLP finding, an alert, or a device.
- Graph view: a depth-bounded query in one direction, ancestors (where data came from) or descendants (where it went), over a time window. Defaults: depth 3, window 30 days. The server caps every query at depth 8, 500 nodes and 2,000 edges, collapses more than 50 edges of one type from one node into an aggregate node expandable on request, and reports when a cap cut the result. Node kinds (file, content, process, user, device, destination) differ by shape and icon as well as colour; observed edges are solid and inferred edges dashed with an "inferred" label; every edge shows type and confidence, and selecting it opens its evidence: the source event uid and the summary of `lineage.md` section 1. Fan-out detections and reduced confidence are shown on the node that caused them.
- List view: the same result as a keyboard-navigable tree table (node, relation, confidence, observed or inferred, time), which is the accessible equivalent of the canvas and the view that exports to CSV.
- Rendering: Cytoscape.js on canvas with the `dagre` layered layout, left to right in time order; zoom and pan also have buttons (WCAG 2.5.7).
- Operations: `queryLineage` (root, direction, depth, window, page token), `getLineageEdge`.

### 5.6 Certificates and certificate authorities

- Views: certificate inventory (profile, issuer, subject, SAN, device, status, expiry) with expiry filters; certificate detail with chain and revocation state; issuing CAs with CRL and OCSP status; certificate profiles; external CA connectors; root ceremony records, where the console uploads issuing CA certificates the offline root signed and never handles the root key; the policy signing certificate and its rotation (`pki.md` section 4).
- Actions: revoke a certificate with a reason; edit profiles and external CA configuration; CA key operations (P).
- Operations: `listCertificates`, `getCertificate`, `revokeCertificate`, `listIssuingCas`, `getCaStatus`, `listCertificateProfiles`, `updateCertificateProfile`, `createCaKeyOperation`.

### 5.7 RADIUS and VPN

- Views: gateways (network access servers) with transport (UDP or RadSec), RadSec client certificate and a write-only shared secret; gateway profiles for FortiGate (SSL VPN where shipped, IPsec IKEv2), Cisco ASA and ASAv, and 802.1X, each with the generated gateway configuration excerpt (`../specs/radius-gateway-profiles.md`); network access profiles (`NetworkAccessProfile`); network policies through the editor; authentication log from OCSF `authentication` events with accept and reject reasons; active sessions from accounting with a disconnect action and the session-timeout bound shown per gateway (RAD-06). Attribute profiles, accounting and CoA are defined in `radius.md`. Creating or widening a gateway registration is protected (P, BE-02).
- Actions: add a gateway, rotate its secret, simulate an authorization decision for a certificate identity against current policy.
- Operations: `listRadiusGateways`, `createRadiusGateway`, `updateRadiusGateway`, `rotateRadiusSecret`, `listRadiusProfiles`, `listNetworkAccessProfiles`, `listRadiusAuthentications`, `listRadiusSessions`, `disconnectRadiusSession`, `simulateRadiusAuthorization`.

### 5.8 Policies and the policy editor

- Policy semantics, defaults and conflict rules are in `policy.md` and `../specs/policy-envelope.md`; this section covers the views.
- List: every `Policy`, `Exception` and `Baseline` with domain, mode, priority, scope summary, placement label, labels, author, version and GitOps ownership.
- Editor: a form generated from the JSON Schema beside the YAML text, both editing one `yaml` document so comments survive form edits. The YAML pane validates locally against the policy JSON Schema with the Ajv standalone validator built from `schemas/policy/v1alpha1/` and maps errors to source ranges. CEL (Common Expression Language) assistance completes variables and fields from the domain's declarations (`getCelEnvironment`, the `variables.json` content of `../specs/cel-profile.md` section 5) and the profile's functions, and shows hover help. The server is the authority: `validatePolicy` runs 500 ms after typing stops and returns the CEL profile, cost estimate and reference errors with ranges, since only `cel-go` decides the profile.
- Diff and dry run: the merge view diffs the draft against the stored version; the write operation called as a dry run (`policy.md` section 2.3) returns the compiled outcome per scope, affected device counts, placement labels, `warn` downgrades, unsupported channels per OS and whether the change weakens enforcement and so is protected. Publishing a weakening change creates an approval request carrying that dry run (section 3.2).
- History: every published version with author and approval; rollback republishes earlier content as a new version (`../specs/policy-envelope.md` section 6).
- GitOps: a resource last written by a GitOps source is read-only in the console and links to its file and commit, because the next apply restores the repository state; an operator with the `policy.ownership.override` permission can still edit it, which is audited and reported as drift (`policy.md` section 2.1).
- Operations: `listPolicies`, `getPolicy`, `createPolicy`, `updatePolicy`, `deletePolicy`, `validatePolicy`, `listPolicyVersions`, `getCelEnvironment`, and the same set for exceptions and baselines.

### 5.9 Rule packs

- Views: packs with format, version, SPDX license, author and attribution text, source URL and commit, the scopes each version is published to, and the adapter's translation report listing every untranslated rule with its reason (`../specs/policy-envelope.md` section 5); rule browser with ATT&CK mapping and, for Sigma, the author; diff between two pack versions; the pack's fixture test results and an operator backtest over stored events (`policy.md` section 7.3); the ATT&CK coverage matrix and the DLP channel coverage view (`policy.md` section 7.4); the license classes of each rule (accepted, review-required, blocked) with the publish approval carrying the approver's license-review attestation (POL-07).
- Actions: import a pack (upload, URL or extension); run its tests and a backtest; publish to a scope (P, with the license-review attestation); withdraw from a scope (P where it weakens an enforcing policy).
- Operations: `listRulePacks`, `getRulePack`, `importRulePack`, `getRulePackReport`, `runRulePackTests`, `createBacktest`, `getBacktest`, `getCoverage`, `publishRulePack`, `withdrawRulePack`.

### 5.10 Dashboards and reports

- Dashboards: a first-party dashboard per domain and operator-defined dashboards whose panels are report datasets rendered as KPI, chart or table blocks, plus console module panels in the dashboard slot (EXT-04). Panels refresh on their topics, at most once every 30 seconds.
- Reports: templates in the `ReportTemplate` format (`../specs/report-template.md`, BE-11), runs, and schedules. First-party templates: DLP findings by category and channel, compliance by baseline, alerts by ATT&CK tactic, certificate expiry, agent version distribution, RADIUS rejects by reason, administrative activity. Running a template needs `events.reports.run`, and every run reader, including the runner, must currently hold every source read permission and cover the recorded entity footprint; list, read, dataset download and cached dashboard paths apply the same check (`../specs/report-template.md` section 4). The console renders a run with the design system's charts and tables; exports are CSV or JSON per dataset and the browser's print to PDF through a print stylesheet.
- Operations: `getReportCatalogue`, `listReportTemplates`, `createReportTemplate`, `createReportRun`, `getReportRun`, `listReportRuns`, `listReportSchedules`, `createReportSchedule`, `updateReportSchedule`, `listDashboards`, `updateDashboard`.

### 5.11 Users, groups, RBAC and SSO

- Views: users with immutable user uid, linked external principal keys, source (SCIM, LDAP, local), status and sessions; groups; roles, built-in and custom, with a permission picker grouped by module; role assignments to users or directory groups with optional device-group scope; access policies naming protected actions and approver groups (BE-02); direct authority approvers; identity providers (OIDC and SAML) with write-only client secrets and claim mapping; directory sync status, stable-id mapping, collisions, the SCIM token and write-only LDAP bind credentials; break-glass accounts with TOTP enrollment, whose seed is shown once as text and as a QR code the server renders with `rsc.io/qr` (BSD-3-Clause).
- Actions: every change here requires re-authentication (section 2.5); section 3.2 always protects identity-authority actions; access-policy changes and role changes that grant a permission named in an access policy follow BE-02.
- Operations: `listUsers`, `updateUser`, `listGroups`, `listRoles`, `createRole`, `updateRole`, `listRoleAssignments`, `createRoleAssignment`, `deleteRoleAssignment`, `listAccessPolicies`, `updateAccessPolicy`, `listIdentityProviders`, `updateIdentityProvider`, `getDirectorySyncStatus`, `listSessions`, `revokeSession`.

### 5.12 Audit log

- Views, under `audit.events.read`: administrative events (`api_activity`, `user_management`, `role_management`, `entity_management`, extension events) with actor, authentication method, action, target, approval link, result, request id and `extension_origin` (`../specs/ocsf-profile.md` section 2); filters by actor, action, target, time and extension; the hash-chain verification status and the configured immutable anchor (EV-06, `events.md` section 6); export as CSV or OCSF JSON, or as a signed audit bundle of records plus checkpoints.
- Operations: `listAuditEvents`, `getAuditEvent`, `createExport`, `exportAuditBundle`, `getAuditChainStatus`.

### 5.13 APIs and GitOps

- Views: API tokens (section 2.6); GitOps repositories with URL, branch, path, polling interval, write-only credentials or the public half of a deploy key, last applied commit, sync status, pending approval requests created by applies, and drift between the repository and stored resources; a dry run of the repository head; the OpenAPI document and CLI downloads.
- Operations: `listApiTokens`, `createApiToken`, `revokeApiToken`, `listGitOpsSources`, `updateGitOpsSource`, `getGitOpsStatus`, `dryRunGitOpsSource`, `getOpenApiDocument`.

### 5.14 Agent versions and updates

- Views: available releases from verified manifests with their expiry; version distribution by OS, group and component; rollouts staged by device group and percentage (AG-07) with health-gate results and rollbacks reported by updaters (`agent.md` section 8); devices in update-only mode outside the compatibility window (AG-04); devices on an OS leaving the support window.
- Actions: create, advance, pause and resume a rollout; pin a group to a version.
- Operations: `listAgentReleases`, `listRollouts`, `createRollout`, `updateRollout`, `getVersionDistribution`.

### 5.15 Extensions

- Views: installed packages with id, version, publisher name and fingerprint, SPDX license, kinds, components, grant generation and status; install from upload, URL or the index, showing manifest, signature result, file hashes, interface versions, the license and the requested capabilities per component (`extensions.md` section 2.2); trust list with keys, id prefixes and revocations; browser registrations; console module slots; connector registrations with contract versions and health; per-device component health from degraded modules; index settings.
- Actions: install, upgrade, enable, grant (P); disable or uninstall (P when an enforcing policy or a qualified adapter depends on the component); add a publisher-key revocation (never held); add an id or version revocation (P when an enforcing policy or a qualified adapter depends on the id or version); other trust-list changes (P); browser-registration changes (P).
- Operations: `listExtensions`, `uploadExtension`, `installExtension`, `updateExtensionGrants`, `setExtensionEnabled`, `uninstallExtension`, `getTrustList`, `updateTrustList`, `listBrowserRegistrations`, `listConnectors`, `createExtensionBridgeBinding` (first-party host only). Modules use only the reviewed safe-operation catalogue in `extensions.md` section 5.3; token creation, approval decisions and authority administration are excluded even when the operator holds those permissions.

### 5.16 Events and export

- Views: export destinations with write-only credentials, per-destination cursor lag, delivery rate, last error and dead letters (`events.md` section 4); pipeline status with spool gaps and drops per device class (`events.md` section 1); telemetry profile per device group (EV-01); retention settings, legal holds and archive state (`events.md` section 5); quarantined events from ingest validation (`../specs/ocsf-profile.md` section 6). Creating, enabling, disabling or deleting a destination, changing its filter, projection, endpoint or credentials, releasing or narrowing a hold, and shortening audit retention are protected (P, BE-02).
- Operations: `listExportDestinations`, `createExportDestination`, `updateExportDestination`, `getExportStatus`, `getPipelineStatus`, `listDeadLetters`, `replayDeadLetters`, `listHolds`, `createHold`, `releaseHold`, `listTelemetryProfiles`, `updateTelemetryProfile`, `listQuarantinedEvents`.

## 6. Console security

### 6.1 Response headers

The `api` role serves the console document with:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self';
  manifest-src 'self'; frame-src https://<console-host>/ext/; form-action 'none';
  base-uri 'none'; object-src 'none'; frame-ancestors 'none';
  require-trusted-types-for 'script'; trusted-types vue
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()
Strict-Transport-Security: max-age=31536000
```

`frame-src` is the value `extensions.md` section 5.1 fixes. The policy allows no inline script, no inline style element and no `eval`: Vue templates are precompiled, `vue-i18n` messages are precompiled and its JIT mode produces message ASTs rather than JavaScript (vue-i18n optimization guide), Ajv validators are generated at build time rather than with the `Function` constructor (Ajv standalone and security pages), and ECharts is used without `vue-echarts`, whose module injects a global `<style>` element. The CSP specification gates CSSOM `cssText` setters and `insertRule` on `'unsafe-eval'` in `style-src`, which the console never grants, while single-property setters stay allowed; Vue applies a string `:style` through `style.cssText` and an object through `setProperty` (Vue `runtime-dom` source), so a lint rule admits only object syntax. Browsers differ in how far they enforce the CSSOM rule (verify), so a library that relies on `cssText` is caught by the end-to-end CSP check rather than assumed safe. CodeMirror's `style-mod` mounts its rules through `adoptedStyleSheets` and `insertRule` only when the editor sits in a shadow root; in a document root it creates a `<style>` element, which `style-src 'self'` blocks. The policy editor therefore mounts in an open shadow root, where the design tokens still reach it as inherited custom properties, and the end-to-end CSP check covers its constructable stylesheet, since the CSP specification gates `insertRule` on `'unsafe-eval'` and browsers differ in enforcing that (verify). `frame-ancestors 'none'` with `X-Frame-Options: DENY` prevents clickjacking. Every end-to-end test runs under this exact header and fails on any `securitypolicyviolation` event, which is how a dependency upgrade that needs a weaker policy is caught.

Trusted Types: browsers ship the API from Chrome 83, Firefox 148 and Safari 26 (MDN browser compatibility data for `TrustedTypePolicyFactory`; the directive's own table was not confirmed). Vue added Trusted Types compatibility in 3.5.0 (Vue changelog), and its runtime creates one policy named `vue` (Vue `runtime-dom` source), the only name `trusted-types` lists. The console creates no policy of its own: lint rules forbid `v-html`, `innerHTML` and `insertAdjacentHTML`, and ECharts tooltips use `renderMode: 'richText'` instead of `html` (ECharts `TooltipModel` source). Where a browser ignores the directive, the lint rules carry the same guarantee.

### 6.2 Subresource Integrity

Not used. Subresource Integrity protects a page against a different host serving altered files (MDN); the console's scripts come from the same origin and the same binary as the document, so an attacker able to alter a chunk can alter the document and its hashes too.

### 6.3 Dependencies

Every runtime dependency needs a row in `../licensing.md` before use and is imported from the lockfile only, never from a CDN. The package manager is pnpm with a committed lockfile, dependency install scripts disabled except for an allow list, and a minimum release age of 7 days (`minimumReleaseAge` of 10,080 minutes): pnpm runs no dependency lifecycle script unless allowed (`allowBuilds`, pnpm 10.26 and later) and `minimumReleaseAge` exists from pnpm 10.16 (pnpm settings documentation). CI runs a license check against the allow list (MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, OFL-1.1 for fonts; BlueOak-1.0.0 and Python-2.0.1 for development and build tooling only; MPL-2.0 for test tools and unmodified build-time tools only, with none of their code shipped in the console bundle) and an OSV vulnerability scan, and the release SBOM includes the console. The build-output license check must reject any MPL-2.0, BlueOak-1.0.0 or Python-2.0.1 licensed file or code included in shipped assets, using the emitted module graph and the provenance of copied assets. Record tooling packages and pinned LICENSE evidence in `../licensing.md`. For pinned `argparse` 2.0.1 only, normalize declared `Python-2.0` metadata to `Python-2.0.1` using that LICENSE evidence before dependency and build-output checks; retain the declared identifier alongside the normalized identifier. Do not apply this mapping to other packages or versions, or to missing or mismatched LICENSE evidence. Require fixtures for normalized tooling acceptance, runtime rejection, and rejection of bundled modules and copied files under the normalized license. A dependency that requires a weaker CSP is rejected.

### 6.4 Secrets and browser storage

The console never receives a secret it does not need: the session cookie is `HttpOnly`; identity-provider client secrets, LDAP and Git credentials, RADIUS shared secrets, connector tokens and export credentials are write-only fields that read back as `has_secret` and the time they were set; API tokens, enrollment tokens and TOTP seeds are shown once at creation; CA and signing keys never leave the server roles that hold them (`backend.md` section 6); DLP evidence is the redacted snippet only. `localStorage` holds preferences only (theme, density, locale, table layout); `sessionStorage` holds unsaved editor drafts and is cleared at logout; the CSRF token lives in memory. Console modules receive only the `init` message of `extensions.md` section 5.2.

## 7. Internationalization and accessibility

Every string is a `vue-i18n` key from the first component (`../project.md`): English source strings in `src/locales/en.json` and the Vietnamese translation in `vi.json`, precompiled by `@intlify/unplugin-vue-i18n`, with the Composition API mode. A CI check fails on a raw string in a template, a key missing from `vi.json` or an unused key. Locale order: the operator's saved preference, then the browser's languages, then English. Numbers, dates and relative times use `Intl` through `vue-i18n`'s `n` and `d`; count messages use `vue-i18n`'s explicit zero, one and many forms in both locales rather than browser plural data, since current CLDR data gives Vietnamese the cardinal categories one and other (CLDR `plurals.xml`) and a browser's bundled CLDR release may differ (verify per browser). Times are stored in UTC, shown in the operator's time zone with a UTC toggle and the full ISO 8601 value on hover. Enumerations (severity, lifecycle state, channel, OCSF activity names) have localized labels; resource names, rule names, policy text and evidence are data and are not translated (`../project.md`).

The target is WCAG 2.2 level AA. Rules the design system enforces: visible focus with at least 3:1 contrast; targets at least 24 by 24 CSS pixels in both densities (2.5.8); sticky headers reserve scroll padding so focus is never hidden (2.4.11); every drag interaction (graph pan, column reorder, dashboard layout) has a button or menu alternative (2.5.7); authentication allows paste and password managers (3.3.8); colour is never the only signal, so severity carries an icon and text; every chart has a data-table view and an ECharts aria description; toasts and live counts use polite live regions, throttled; motion respects `prefers-reduced-motion`. Testing is in section 9.

## 8. Design system

Components: Reka UI supplies unstyled primitives that follow the WAI-ARIA Authoring Practices for keyboard support (Reka UI accessibility page): dialog, menu, select, combobox, tabs, tooltip, popover, toast, checkbox, radio, switch. `src/ui/` wraps them in Ricevanta components styled with plain CSS over design tokens. The data grid is in-house on TanStack Table (sorting, selection, column state) and TanStack Virtual (row virtualization), with table semantics and `aria-sort` on sortable headers. Icons are inline SVG components in `src/ui/icons/`, drawn in-project with the rounded geometry of `../../branding/BRAND_SPEC.md` section 7.

Tokens are CSS custom properties on `:root`, derived from the brand palette (`../../branding/BRAND_SPEC.md` section 3) and switched by a `data-theme` attribute: light, dark, or system through `prefers-color-scheme`. Contrast ratios are computed with the WCAG relative-luminance formula:

| Token | Light | Dark | Contrast |
|---|---|---|---|
| Page background | `#F6F2E7` rice ivory | `#0F1E2B` | |
| Surface | `#FFFFFF` | `#16293A` | |
| Text | `#1B2733` | `#F6F2E7` | 15.17 and 13.29 on surface |
| Secondary text | `#4A5866` | `#B9C2CB` | 7.29 and 8.24 on surface |
| Primary action fill and text on it | `#173B54` indigo, white text | `#DDB85C` harvest gold, `#173B54` text | 11.73; 6.19 |
| Control border | `#6E747C` | `#7D8C9A` | 4.22 on page and 4.72 on surface; 4.91 and 4.31 |
| Focus ring | `#173B54` | `#DDB85C` | 10.49 on page; 8.93 on page |
| Severity critical, high, medium, low, informational (text and icon) | `#B42318`, `#B54708`, `#8A6100`, `#1F5FA8`, `#4A5866` | `#FF8A80`, `#FDB27A`, `#E8C66A`, `#8EC1F5`, `#B9C2CB` | All at least 4.85 on page and surface |

Gold is never text or a control on light surfaces (1.89:1 on white), and red is reserved for critical severity and destructive confirmations (`../../branding/BRAND_SPEC.md` section 3). The header uses `RicevantaLogo` with the `horizontal` variant and the favicon set from `branding/dist/web/` (section 9 of the brand specification).

Typography: Be Vietnam Pro at weights 400, 500, 600 and 700, self-hosted as WOFF2 subsets for Latin, Latin Extended and Vietnamese, built from the upstream repository's release; OFL 1.1 permits bundling the font with software when each copy carries the copyright notice and the license, which ship beside the font files; the system monospace stack for YAML, hashes and command lines. Density: comfortable (40 px rows, 36 px controls) and compact (32 px rows, 28 px controls) per operator preference; compact is the default for tables on screens at least 1440 px wide.

## 9. Testing

| Layer | Tool | Scope |
|---|---|---|
| Unit | Vitest | Stores, `useResource` invalidation, problem mapping, permission checks, formatting in both locales |
| Component | Vitest browser mode with the `@vitest/browser-playwright` provider, `@vue/test-utils` | Each `src/ui` component and feature view in a real browser engine: keyboard paths, focus order, ARIA states |
| End to end | Playwright on Chromium, Firefox and WebKit | Against `ricevanta-server` and PostgreSQL in Docker Compose, seeded with synthetic data (20,000 devices, alerts with Sigma authors, DLP findings with redacted snippets, a lineage graph, certificates) and test OIDC and SAML providers; every flow of section 5, the approval flow with two accounts, re-authentication, timeouts, CSRF refusal and the production CSP |
| Visual regression | Playwright `toHaveScreenshot` | A fixed view list in both themes, both locales and both densities, rendered on Chromium in a pinned container |
| Accessibility | `@axe-core/playwright` (MPL-2.0, test only) | Every route and dialog state with the WCAG 2.0, 2.1 and 2.2 A and AA rules including `target-size`, which axe disables by default; any violation fails CI |
| Manual | NVDA with Firefox on Windows, VoiceOver with Safari on macOS | Login, device list, alert triage, approval, policy publish and lineage list, once per minor release, recorded as qualification evidence for the administration workflow (`../specs/platform-qualification.md` section 5) |

Automated rules find only part of the failures, 57 % of issues on average in Deque's own study, which is why the keyboard and screen-reader passes remain. A scale case asserts that the device list's first page renders within 1 second of the server response on the 20,000-device seed.

## 10. Build and delivery

`vite build` writes `console/dist/` with content-hashed files under `/assets/`; a build script precompresses them with Node's built-in Brotli and gzip. The server build copies `dist/` into the `transport` module, which serves it through Go `embed`, so a server binary carries exactly one console build (BE-03, SH-04). In development, the Vite server proxies `/api` to a local server.

| Path | Served | Cache-Control |
|---|---|---|
| `/assets/*` | Embedded build, precompressed variant by `Accept-Encoding` | `public, max-age=31536000, immutable` |
| `/brand/*` | Favicons and manifest from `branding/dist/web/` | `public, max-age=86400` |
| `/ext/<id>/<version>/<package-sha256>/<component>/<asset-mount>/*` | Only the binding's frozen, hash-verified asset list with the candidate sandbox header (`extensions.md` sections 5.1 and 5.2); no module mount before egress qualification | `no-store`, with an integrity `ETag`; disabled or revoked asset mounts return 404 |
| `/api/v1/*` | API | `no-store` |
| Any other `GET` that accepts `text/html` | `index.html` | `no-cache`, `ETag` from the build digest |

Paths under `/api/`, `/agent/`, `/ext/`, `/assets/`, `/brand/`, `/mdm/`, `/scep` and `/acme` never fall back to `index.html`; they answer their own 404, so a missing extension asset cannot load the console document inside a module frame.

Version pinning: the console carries the product version (SH-04) and `getSession` returns the server's. During a rolling upgrade an open tab can meet a replica of the other version; a mismatch shows a reload banner, and a failed chunk load, reported by Vite's `vite:preloadError` event (Vite build guide), reloads the page once, guarded by a `sessionStorage` flag. `/api/v1` changes additively within a major (`../architecture.md` section 7), so an older tab keeps working until it reloads.

Bundle budgets, checked in CI against the previous release: the initial route at most 250 KB of Brotli-compressed JavaScript, a feature chunk at most 150 KB, and the editor and graph chunks at most 400 KB each; a regression above 5 % fails the build. The console supports the current and previous major releases of Chrome, Edge and Firefox, Firefox ESR, and Safari on the macOS releases `../platform-support.md` makes eligible.

## 11. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one write path and server-side authorization make the console a client like the CLI, with no privileges of its own; a strict CSP without `eval` or inline code, Trusted Types and opaque-origin module frames limit what injected content can do; invalidation-only SSE keeps live views cheap at 20,000 endpoints and never sends row data past per-request authorization; Reka UI primitives give WAI-ARIA keyboard behaviour while the brand tokens stay fully in-house; the report format lets extensions ship reports without code.

Trade-offs: in-house styled components and the data grid are more work than a styled library, accepted for accessibility and token control; `openapi-fetch` is pre-1.0 (0.17), so its API can change between minors; hand-written OpenAPI means the console's types are only as current as the document, which CI validates; Cytoscape.js draws on canvas, so the lineage list view carries accessibility; re-authentication adds a provider round trip to approvals.

Dependencies: Vue, Vite, Pinia, Vue Router, `vue-i18n` and `@intlify/unplugin-vue-i18n`, `openapi-typescript`, `openapi-fetch`, Reka UI, TanStack Table and Virtual, Apache ECharts, Cytoscape.js, `cytoscape-dagre`, `dagre`, CodeMirror 6 packages, `yaml`, Ajv, Be Vietnam Pro; for tests Vitest, `@vue/test-utils`, Playwright and `@axe-core/playwright`; for builds TypeScript, `vue-tsc`, ESLint and `eslint-plugin-vue`. Rows that `../licensing.md` lacks are proposed with this design.

Limits: Trusted Types apply only in browsers that implement the directive; the lint rules cover the rest. A strict `SameSite` cookie and `frame-ancestors 'none'` mean the console cannot be embedded in another portal. The lineage canvas shows at most 500 nodes per query. Console strings ship in English and Vietnamese only at v1.0.0. PDF reports come from the browser's print, so page layout varies by browser.

Alternatives considered:

- Element Plus, whose row in `../licensing.md` this design replaces: not chosen; its documentation makes no accessibility statement and its virtualized table is labelled beta ("use at your own risk").
- PrimeVue 5: rejected; its license requires a license key and forbids redistribution without an OEM license. PrimeVue 4 is MIT but its repository receives security fixes only.
- Naive UI: not chosen; its README says components need no CSS import, which points to styles injected at runtime (verify), against `style-src 'self'`.
- Monaco with `monaco-yaml`: not chosen; heavier and worker-based, and neither README states a CSP or Trusted Types position, against CodeMirror 6, which states screen-reader support.
- WebSocket for live data: rejected; bidirectional transport no view needs, a handshake that needs its own origin and CSRF checks, and more server code. Polling only: rejected; 30-second latency for alerts and approvals and a fleet-scaled query load per open tab.
- ELK.js for the lineage layout: rejected; it is `EPL-2.0 OR GPL-3.0-or-later`. Sigma.js with graphology (MIT, WebGL) and Vue Flow (MIT): not chosen; the server caps a query at 500 nodes, which Cytoscape.js handles, and neither ships a layered layout (verify). The ECharts graph series: not chosen; its layouts are force-directed and circular, with no layered layout (verify).
- `vue-echarts`: not chosen; it injects a global style element at module load.
- Subresource Integrity, server-side PDF rendering and TanStack Query: not chosen (sections 6.2 and 5.10; the topic invalidation of section 4 needs only a small cache).
- Nuxt or server-side rendering: rejected; the server is Go, the console is an authenticated single-page application, and SSR would add a Node.js runtime to the server image.

## Sources

- Vue: [license](https://raw.githubusercontent.com/vuejs/core/main/LICENSE), [changelog, Trusted Types in 3.5.0](https://raw.githubusercontent.com/vuejs/core/main/CHANGELOG.md), [runtime-only build](https://vuejs.org/guide/scaling-up/tooling.html); [Pinia license](https://raw.githubusercontent.com/vuejs/pinia/master/LICENSE); [Vue Router lazy loading](https://router.vuejs.org/guide/advanced/lazy-loading.html), [license](https://raw.githubusercontent.com/vuejs/router/main/LICENSE); [Vite license](https://raw.githubusercontent.com/vitejs/vite/main/LICENSE), [build options](https://vite.dev/config/build-options.html).
- `vue-i18n`: [license](https://raw.githubusercontent.com/intlify/vue-i18n/master/LICENSE), [optimization and CSP](https://vue-i18n.intlify.dev/guide/advanced/optimization.html), [unplugin-vue-i18n](https://github.com/intlify/bundle-tools/tree/main/packages/unplugin-vue-i18n).
- API client: [openapi-typescript](https://openapi-ts.dev/introduction), [license](https://raw.githubusercontent.com/openapi-ts/openapi-typescript/main/LICENSE), [openapi-fetch license](https://raw.githubusercontent.com/openapi-ts/openapi-typescript/main/packages/openapi-fetch/LICENSE).
- Components: [Reka UI accessibility](https://reka-ui.com/docs/overview/accessibility), [license](https://raw.githubusercontent.com/unovue/reka-ui/main/LICENSE); [TanStack Table license](https://raw.githubusercontent.com/TanStack/table/main/LICENSE), [TanStack Virtual license](https://raw.githubusercontent.com/TanStack/virtual/main/LICENSE); [Element Plus Table V2](https://element-plus.org/en-US/component/table-v2.html); [PrimeVue 5 license](https://cdn.jsdelivr.net/npm/primevue@5.0.2/LICENSE.md), [PrimeVue repository](https://github.com/primefaces/primevue).
- Charts and graphs: [ECharts accessibility](https://echarts.apache.org/handbook/en/best-practices/aria/), [ECharts v5 upgrade guide](https://echarts.apache.org/handbook/en/basics/release-note/v5-upgrade-guide/), [ECharts NOTICE](https://raw.githubusercontent.com/apache/echarts/master/NOTICE); [vue-echarts README, CSP](https://raw.githubusercontent.com/ecomfe/vue-echarts/main/README.md); [Cytoscape.js license](https://raw.githubusercontent.com/cytoscape/cytoscape.js/master/LICENSE), [cytoscape-dagre license](https://raw.githubusercontent.com/cytoscape/cytoscape.js-dagre/master/LICENSE), [dagre license](https://raw.githubusercontent.com/dagrejs/dagre/master/LICENSE).
- Editor and validation: [CodeMirror](https://codemirror.net/), [license](https://raw.githubusercontent.com/codemirror/dev/main/LICENSE); [Ajv standalone](https://ajv.js.org/standalone.html), [Ajv security](https://ajv.js.org/security.html), [Ajv draft 2020-12](https://raw.githubusercontent.com/ajv-validator/ajv/master/docs/json-schema.md).
- Tests: [Vitest license](https://raw.githubusercontent.com/vitest-dev/vitest/main/LICENSE), [Vue Test Utils license](https://raw.githubusercontent.com/vuejs/test-utils/main/LICENSE), [Playwright visual comparisons](https://playwright.dev/docs/test-snapshots), [Playwright license](https://raw.githubusercontent.com/microsoft/playwright/main/LICENSE), [axe-core license](https://raw.githubusercontent.com/dequelabs/axe-core/develop/LICENSE), [axe-core rules](https://github.com/dequelabs/axe-core/blob/develop/doc/rule-descriptions.md).
- Web platform: [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [browser compatibility data](https://raw.githubusercontent.com/mdn/browser-compat-data/main/api/TrustedTypePolicyFactory.json), [require-trusted-types-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for), [frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors), [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity), [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie), [Sec-Fetch-Site](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site), [EventSource](https://developer.mozilla.org/en-US/docs/Web/API/EventSource), [server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html).
- Accessibility: [WCAG 2.2](https://www.w3.org/TR/WCAG22/), [What's new in WCAG 2.2](https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/).
- Sessions and requests: [OWASP cross-site request forgery prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700), [SAML 2.0 core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf), [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238), [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457).
- Build and supply chain: [Vite load error handling](https://vite.dev/guide/build), [pnpm build settings](https://pnpm.io/settings/build), [pnpm minimumReleaseAge](https://pnpm.io/settings/dependency-resolution), [pnpm 10.26 allowBuilds](https://pnpm.io/blog/releases/10.26), [Vite SRI request, issue 2377](https://github.com/vitejs/vite/issues/2377), [Go embed](https://pkg.go.dev/embed), [Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control), [`yaml` API](https://eemeli.org/yaml/v2/), [`yaml` license](https://raw.githubusercontent.com/eemeli/yaml/main/package.json), [`rsc.io/qr`](https://pkg.go.dev/rsc.io/qr).
- Fonts and accessibility testing: [Be Vietnam Pro OFL](https://github.com/bettergui/BeVietnamPro/blob/master/OFL.txt), [OFL 1.1 text](https://openfontlicense.org/open-font-license-official-text/), [Deque automated testing study](https://www.deque.com/blog/automated-testing-study-identifies-57-percent-of-digital-accessibility-issues).
- Source files checked: [Vue `runtime-dom` nodeOps](https://github.com/vuejs/core/blob/main/packages/runtime-dom/src/nodeOps.ts), [Vue style module](https://github.com/vuejs/core/blob/main/packages/runtime-dom/src/modules/style.ts), [ECharts TooltipModel](https://github.com/apache/echarts/blob/master/src/component/tooltip/TooltipModel.ts), [CLDR plurals](https://github.com/unicode-org/cldr/blob/main/common/supplemental/plurals.xml), [CSP Level 3, style-src and CSSOM](https://w3c.github.io/webappsec-csp/), [Vitest browser mode](https://vitest.dev/guide/browser/).
