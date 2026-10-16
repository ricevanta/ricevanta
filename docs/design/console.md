# Console design

How the web console is built: application structure, login and sessions, authorization in the UI and the approval queue, live data for large fleets, the views of every feature area, console security, internationalization and accessibility, the design system, testing, and build and delivery. The feature list is `../blueprint.md` section 3.8; the stack is section 2. Adjacent facts live elsewhere and are linked, not restated: the API and GitOps in `../architecture.md` section 3.3 and `../specs/policy-envelope.md` section 8; RBAC and approvals in BE-02 and `../specs/policy-envelope.md` section 2.3; console module isolation, slots and the bridge in `extensions.md` section 5; identity sources in BE-01; the build into the server binary in SH-04 and `../architecture.md` section 3.1. Decisions: BE-01 to BE-05, BE-08 to BE-11, EXT-02, EXT-04, DLP-02, DLP-03 and SH-04 in `../decisions.md`. This file settles two items of `../analysis.md` section 3: the console exploration views of the Lineage bullet (section 5.5) and the report template format of the Extensions bullet (`../specs/report-template.md`). Claims marked "verify" rest on vendor pages, repository files or memory rather than first-party documentation.

The console runs in the operator's browser and needs no Ricevanta browser extension or endpoint agent. The [console browser window](../platform-support.md#browser-coverage) is separate from endpoint browser DLP coverage. Endpoint operating-system differences reach the console as per-device capability states with the reasons the agent reports (section 5.1).

## 1. Application structure

The [console foundation spec](../specs/console-foundation.md) and [implementation plan](../plans/console-foundation.md) define the first code slice, exact pins, generated tokens, catalogue validation and built-output CSP tests. Its foundation header specializes section 6.1 with frames and workers denied until reviewed consumers exist; API generation, authentication and live data remain dependent slices. Work follows [Vue instructions](../../instructions/vue.md).

### 1.1 Stack

| Concern | Choice | License |
|---|---|---|
| Framework | Vue 3.5 with the Composition API, `<script setup>` single-file components and TypeScript in strict mode; templates precompiled, runtime-only build | MIT |
| Build | Vite 8 | MIT |
| State | Pinia: one store for the session and permissions, one for preferences, and a cache store behind the `useResource` composable (section 4) | MIT |
| Routing | Vue Router 5, history mode, one lazily imported chunk per feature area; route `meta.requires` names the permissions the route needs (section 3) | MIT |
| API client | `openapi-typescript` generates a checked type-only `.ts` module from the [API foundation contract](../specs/api-foundation.md); `openapi-fetch` is the typed wrapper; independent review and the integration plan remain gates | MIT, both |
| Components | Reka UI primitives under in-house styled components; TanStack Table and TanStack Virtual for data grids (section 8) | MIT |
| Charts | Apache ECharts, imported per component from `echarts/core` with the SVG renderer and the aria component | Apache-2.0 |
| Lineage graph | Cytoscape.js with the `cytoscape-dagre` layout and `dagre` | MIT |
| Policy editor | CodeMirror 6 with `@codemirror/lang-yaml`, `@codemirror/lint`, `@codemirror/autocomplete` and `@codemirror/merge`; the `yaml` package for parsing with source ranges; Ajv standalone validators compiled at build time | MIT; `yaml` ISC |
| Strings | `vue-i18n` 11 with `@intlify/unplugin-vue-i18n` precompiling messages | MIT |

The console source lives in `console/` (SH-04): `src/app` (bootstrap, router, error handling), `src/api` (generated types, client, problem mapping), `src/stores`, `src/ui` (the design system), `src/features/<area>` (one directory per section 5 area, each with its routes, views and composables), `src/locales` and `tests/`.

### 1.2 API client and errors

[API foundation](../specs/api-foundation.md) owns generated-client rules, problem types, headers, pagination, conditional writes and idempotency. The console maps problems to localized validation, permission, re-authentication, conflict, not-found, rate-limit, unavailable and network states. On a precondition failure the view shows the server revision beside the draft. Protected writes show the approval request, not a success claiming execution. Unknown errors show only the server request id; never export resource data in error messages.

### 1.3 Code splitting

Each feature area is one route-level chunk. ECharts, Cytoscape.js and CodeMirror load only with the views that use them. The console is one first-party build with nothing to federate, so `@module-federation/vite` is not used; third-party UI enters only through console module iframes (EXT-04, `extensions.md` section 5).

## 2. Authentication and session

### 2.1 Login flows

[Identity login](../specs/identity-login.md) owns OIDC, SP-initiated SAML, generated local credentials, first start, principal links and provider administration. The login page shows its enabled methods and performs top-level provider navigation or local JSON fetch. Paste and password managers work in all credential fields (WCAG 3.3.8). Credentials shown once never enter browser storage. First start grants no later identity-authority bypass; a single administrator uses exact offline repair until an unaffected second approver exists.

### 2.2 Session cookie

[Identity sessions](../specs/identity-sessions.md) section 2 owns cookie attributes, rotation, generation checks and CSRF derivation. The static shell needs no cookie; its same-origin API requests establish the session. Every tab shares the browser cookie jar, and rotation invalidates stale in-flight unsafe requests.

### 2.3 Cross-site request forgery

Identity sessions section 4 owns the complete guard and precedence. The shared API client sends the in-memory synchronizer token for unsafe session operations. Origin is mandatory for those requests even when Fetch Metadata is absent. No client control replaces server authorization.

### 2.4 Timeouts

Identity sessions section 3 owns idle/absolute defaults, ranges, activity, caps and revocation. Background requests carry `X-Ricevanta-Background: 1`. Two minutes before idle expiry a dialog offers Continue; expiry returns to login and restores the safe route afterwards. Local authentication shows a persistent break-glass banner. User or epoch changes clear session storage and protected caches; permission changes drop protected caches before refetch.

### 2.5 Re-authentication

Identity sessions sections 5 and 6 own verified freshness, same-user checks, unaffected methods and exact approval binding. The console preserves the form while the operator authenticates, then requires explicit submission. It never automatically replays a mutation. If no unaffected method exists, show the offline-repair requirement, not an online bypass.

### 2.6 API tokens

Identity sessions section 7 owns creation, scope ceilings, expiry and revocation. The view shows token name, public prefix, scope, expiry and last use, and displays a newly issued secret once. Tokens never decide approvals. A loss of the creation response requires revocation and fresh issuance.

## 3. Authorization in the UI

The [permission catalogue](../specs/permission-catalogue.md) owns exact names, scope kinds, operation mappings and approval metadata; its [implementation plan](../plans/permission-catalogue.md) defines the isolated Go library. Catalogue lookup does not authorize a request.

### 3.1 Permission-aware views

`getSession` returns the [identity sessions](../specs/identity-sessions.md) response, whose exact schema is in OpenAPI. Permission scopes distinguish organization-wide access from device-group sets. The router hides navigation entries and blocks routes whose read permission is missing; action controls the operator cannot use stay visible but disabled with the missing permission named. That is presentation only: every request is authorized by the server (BE-05), a `permission_denied` problem renders the same "not permitted" state, and fields an operator may not read are omitted by the server, never hidden by the client. A DLP finding read without `dlp.evidence.read` arrives without its snippet.

Device-group scoping is applied by the server to every list, count, chart and report. The group picker offers only the operator's groups. "Select all matching" on a large list sends the filter, not row ids, and the server resolves and freezes the target set inside the operator's scope when it creates the action or approval request.

### 3.2 Approval queue

A protected action from any view (BE-02, `../specs/policy-envelope.md` section 2.3) returns an approval request instead of executing. The console then shows the request id, the approver group, the exact fields the approval binds, the frozen target list with its count and a paged view, and a required justification.

The approvals view has three tabs: awaiting my decision, my requests, and all requests (with `authz.approvals.read`). A request shows requester, time, action, justification, the exact fields and their hash, the frozen targets, the dry-run result where one exists (the compiled-outcome diff for a policy change, section 5.8), the expiry (default 72 hours, set per access policy) and links to its audit events. Approve and reject need a comment and recent authentication (section 2.5). The requester sees the controls disabled with the reason; the server refuses approval by the requesting account in any case. After approval the request shows per-target dispatch state from the command journal reports (`../specs/policy-envelope.md` section 7): pending, delivered, succeeded, failed, refused, undelivered. The `approvals` topic keeps the badge count current, and console modules receive `approval.pending` through the bridge. An installation with configurable approval policies disabled shows the persistent BE-02 warning on every page. The warning also names a one-custodian recovery quorum; single-administrator mode does not disable identity-authority protection.

While the committed setting disables configurable approval policies, a protected action other than an identity-authority action creates no approval request. The server records a single-administrator exemption for the requesting account, bound to the same exact fields, hash, frozen targets and recovery epoch an approval would bind, then proceeds. The exemption is journaled with the setting's generation, consumed once and audited as an exemption, and the request view shows it in place of an approver. No account approves anything, so the refusal of approval by the requesting account holds in every configuration. Changing the setting is itself a protected action and makes every exemption and approval bound under the old setting stale. A request whose requester is the server image's system principal, such as a first-party extension proposal ([extension admission section 6](../specs/extension-admission.md#6-approval-binding)), is never exempt and waits for an operator's approval in every configuration.

Identity-authority actions are always protected, even when configurable approval policies are disabled. They include provider trust, issuer, signing certificate, discovery or metadata URL, endpoints and client credentials; principal linking or unlinking; claim and directory group mapping; directory source, sync filter and stable-id choice; account recovery; break-glass creation, reset, second-factor replacement, enable, disable or deletion; and any direct assignment of `identity.authority.approve`. The request binds the immutable internal users, external principal keys, affected authority uids and exact before and after resource hashes. Its approver must be a different enabled internal user with a direct `identity.authority.approve` assignment, and must re-authenticate through an authority not in the affected set. Directory group membership and a mapping being changed cannot confer that permission. [Identity sessions](../specs/identity-sessions.md) section 6 owns decision, exact-result replay and application state and freshness checks. The UI reads current status separately after a replayed decision result. Recovery with no unaffected approver uses the offline authority-recovery ceremony in `backend.md` section 6.1, binds the exact authority change and advances the epoch. The ceremony leaves a critical audit record. An interactive session alone cannot bypass the boundary.

## 4. Live data and large fleets

[Change stream](../specs/change-stream.md) owns topics, per-permission scope, equality tokens, framing, snapshot reconnects, authority leases, polling and resource budgets. The console uses a fetch reader, not EventSource; it sends no Last-Event-ID. `useResource` caches by operation and parameters, refetches visible views on invalidation and performs the independent reconciliation fetch even while the stream is healthy. Permission changes discard protected caches. Stream messages contain no rows.

[API foundation](../specs/api-foundation.md) owns keyset pagination and counts. Tables render only visible rows through TanStack Virtual and keep at most 5,000 rows in memory; larger results require a narrower filter or an authorized export. Search inputs debounce 300 ms. Facets remain server-computed and capped. No view fetches the entire fleet.

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
- Actions: install, upgrade, enable, grant or target update (P), each decided by [the admission function](../specs/extension-admission.md); approve or reject a first-party release proposal from the server image (`authz.approvals.approve`); disable or uninstall (P when an enforcing policy or a qualified adapter depends on the component); add a publisher-key revocation (never held); add an id or version revocation (P when an enforcing policy or a qualified adapter depends on the id or version); other trust-list changes (P); browser-registration changes (P).
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

Trusted Types runtime enforcement is required throughout the console browser window. The [W3C specification](https://w3c.github.io/trusted-types/dist/spec/) separates guarded-sink refusal from policy creation; an API presence check proves neither. Vue creates the allowed policy named `vue`, whose HTML conversion is not a sanitizer. The console creates no policy of its own: source checks forbid unsafe HTML sinks, and ECharts tooltips use `renderMode: 'richText'` instead of `html`. Source checks reduce mistakes but cannot replace runtime enforcement. The [foundation contract](../specs/console-foundation.md#4-production-header-and-trust-boundary) owns the source-to-browser path and attacker limits; its section 7 owns the negative controls. A browser that ignores a required directive fails qualification. Keep the CSP and browser window intact while resolving that blocker.

### 6.2 Subresource Integrity

Not used. Subresource Integrity protects a page against a different host serving altered files (MDN); the console's scripts come from the same origin and the same binary as the document, so an attacker able to alter a chunk can alter the document and its hashes too.

### 6.3 Dependencies

Every runtime dependency needs a row in `../licensing.md` before use and is imported from the lockfile only, never from a CDN. The package manager is pnpm with a committed lockfile, dependency install scripts disabled except for an allow list, and pnpm's default minimum release age of one day (`minimumReleaseAge` of 1,440 minutes): pnpm runs no dependency lifecycle script unless allowed (`allowBuilds`, pnpm 10.26 and later) and `minimumReleaseAge` exists from pnpm 10.16 (pnpm settings documentation). CI runs a license check against the allow list (MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, OFL-1.1 for fonts; BlueOak-1.0.0 and Python-2.0.1 for development and build tooling only; MPL-2.0 for test tools and unmodified build-time tools only, with none of their code shipped in the console bundle) and an OSV vulnerability scan, and the release SBOM includes the console. The build-output license check must reject any MPL-2.0, BlueOak-1.0.0 or Python-2.0.1 licensed file or code included in shipped assets, using the emitted module graph and the provenance of copied assets. Record tooling packages and pinned LICENSE evidence in `../licensing.md`. For pinned `argparse` 2.0.1 only, normalize declared `Python-2.0` metadata to `Python-2.0.1` using that LICENSE evidence before dependency and build-output checks; retain the declared identifier alongside the normalized identifier. Do not apply this mapping to other packages or versions, or to missing or mismatched LICENSE evidence. Require fixtures for normalized tooling acceptance, runtime rejection, and rejection of bundled modules and copied files under the normalized license. A dependency that requires a weaker CSP is rejected.

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

Paths under `/api/`, `/agent/`, `/ext/`, `/assets/`, `/brand/`, `/mdm/`, `/scep`, `/acme`, `/metrics`, `/healthz` and `/readyz` never fall back to `index.html`; they answer their own 404, so a missing extension asset cannot load the console document inside a module frame.

Version pinning: the console carries the product version (SH-04) and `getSession` returns the server's. During a rolling upgrade an open tab can meet a replica of the other version; a mismatch shows a reload banner, and a failed chunk load, reported by Vite's `vite:preloadError` event (Vite build guide), reloads the page once, guarded by a `sessionStorage` flag. `/api/v1` changes additively within a major (`../architecture.md` section 7), so an older tab keeps working until it reloads.

Bundle budgets, checked in CI against the previous release: the initial route at most 250 KB of Brotli-compressed JavaScript, a feature chunk at most 150 KB, and the editor and graph chunks at most 400 KB each; a regression above 5 % fails the build. The console browser window and required OS coverage live in [platform support](../platform-support.md#browser-coverage). The pinned Linux engine tests are foundation evidence only; the full browser and OS matrix remains unqualified.

## 11. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one write path and server-side authorization make the console a client like the CLI, with no privileges of its own; a strict CSP without `eval` or inline code, Trusted Types and opaque-origin module frames limit what injected content can do; invalidation-only SSE keeps live views cheap at 20,000 endpoints and never sends row data past per-request authorization; Reka UI primitives give WAI-ARIA keyboard behaviour while the brand tokens stay fully in-house; the report format lets extensions ship reports without code.

Trade-offs: in-house styled components and the data grid are more work than a styled library, accepted for accessibility and token control; `openapi-fetch` is pre-1.0 (0.17), so its API can change between minors; hand-written OpenAPI means the console's types are only as current as the document, which CI validates; Cytoscape.js draws on canvas, so the lineage list view carries accessibility; re-authentication adds a provider round trip to approvals.

Dependencies: Vue, Vite, Pinia, Vue Router, `vue-i18n` and `@intlify/unplugin-vue-i18n`, `openapi-typescript`, `openapi-fetch`, Reka UI, TanStack Table and Virtual, Apache ECharts, Cytoscape.js, `cytoscape-dagre`, `dagre`, CodeMirror 6 packages, `yaml`, Ajv, Be Vietnam Pro; for tests Vitest, `@vue/test-utils`, Playwright and `@axe-core/playwright`; for builds TypeScript, `vue-tsc`, ESLint and `eslint-plugin-vue`. Rows that `../licensing.md` lacks are proposed with this design.

Limits: every eligible console browser must pass CSP and Trusted Types runtime enforcement tests; source checks supply no substitute, and missing browser or OS evidence blocks release. A strict `SameSite` cookie and `frame-ancestors 'none'` mean the console cannot be embedded in another portal. The lineage canvas shows at most 500 nodes per query. Console strings ship in English and Vietnamese only at v1.0.0. PDF reports come from the browser's print, so page layout varies by browser.

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
