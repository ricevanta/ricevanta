# Decisions

Register of decisions in force, grouped by domain. IDs are domain prefix plus sequence (`SH-01`, `DLP-02`); they are stable and never reused. Entries are short and current; design detail lives in the linked design document. Format and rules: `instructions/documentation.md`. C-numbers refer to `analysis.md`.

## Shared (SH)

### SH-01. Full support for every feature at v1.0.0
Decision: every blueprint feature ships with full support, including blocking enforcement, at v1.0.0 on the v1.0.0 targets. Reduced behaviour (alert-only, deferred) is permitted only inside a v0.x release and must name the release that completes it. The only exceptions are the capabilities listed under "Deferred to v2.0.0" in `platform-support.md`, which cannot be tested without a company account.
Why: the blueprint states v1.0.0 is not an MVP; untestable work must not block the release on vendor timelines.
Rejected: an MVP v1.0.0 with alert-only DLP on Windows and no browser extension.

### SH-02. Policy envelope, CEL profile and OCSF profile defined first
Decision: the policy envelope, a CEL subset profile and the OCSF profile are defined in v0.1.x. Both CEL runtimes (Go on the server, Rust on the agent) pass the `cel-spec` conformance suite for the profile in CI; policies outside the profile are refused.
Why: EDR and DLP ship before the rule adapters, and two CEL runtimes can diverge (C8, C11).
Rejected: ad hoc per-module formats until v0.8.x; forces a migration.
Detail: `specs/policy-envelope.md`, `specs/cel-profile.md`, `specs/ocsf-profile.md`.

### SH-03. Single organization per server
Decision: v1.0.0 serves one organization per server. Tables carry an organization ID so multi-tenancy is a later addition, not a migration.
Why: no requirement for multi-tenancy at v1.0.0.

### SH-04. One repository, one release version
Decision: one repository with `agent/`, `driver/`, `extension/`, `server/`, `console/`, `schemas/`, `rulepacks/`, `deploy/`, `tests/`, `docs/` and `instructions/`. Server, console, agent and extension share one SemVer version per release.
Why: cross-component changes (policy envelope, agent API) land in one change and one test run.
Rejected: the blueprint's `integrations/` directory; adapters are server modules and live with the server.
Detail: `architecture.md` section 6.

## Platform (PF)

### PF-01. v1.0.0 targets
Decision: macOS ARM64, Windows x64, Linux x64. Windows ARM64, Linux ARM64 and macOS x64 follow in v1.x; the design stays architecture-independent.
Why: largest installed bases; separate driver signing and CI hardware for the others.
Detail: `platform-support.md`.

### PF-02. Modern OS support and qualification
Decision: qualify the current and previous stable macOS major releases on Apple silicon, Microsoft-maintained Windows 11 x64 Pro, Enterprise and Education releases for their edition and servicing channel, and maintained Linux releases meeting the distribution and runtime-capability rules in `platform-support.md`. OS eligibility does not establish support: each exact configuration must pass the platform qualification specification, including required blocking behavior.
Why: maintained releases reduce compatibility branches; Linux enforcement depends on active hooks, not the version string alone (C3, C12).
Rejected: fixed OS floors with no lifecycle rule; telemetry-only results labeled as full support.
Detail: `platform-support.md`.

### PF-03. Vendor programs held by the project
Decision: development and testing on personal accounts; a company registered before sensor distribution holds the Apple team, the MDM Vendor CSR Signing Certificate, Partner Center account, EV certificate and the HLK lab for WHCP certification of the driver; all production binaries are signed under it and the production push-certificate signing service runs under its vendor certificate.
Why: entitlements and driver signatures bind to one organization (C1), and WHCP submissions need a Partner Center account and HLK results (AG-01).
Detail: `project.md`.

### PF-04. Platform qualification is a release gate
Decision: a finite required-unit manifest covers every eligible OS release and every blueprint feature across the declared configuration profiles; whole-product workflows, negative security cases, offline recovery, updates and resource budgets also pass. An unresolved required enforcement mechanism blocks release and cannot become an unsupported-feature exception.
Why: a build or a notification does not prove complete endpoint protection.
Rejected: one smoke test per OS; support inferred from vendor API availability.
Detail: `specs/platform-qualification.md`.

## Agent (AG)

### AG-01. Windows kernel component
Decision: a kernel component with a file-system minifilter, process-creation callbacks that deny creation, and a WFP callout where user-mode WFP is insufficient; ETW stays the telemetry source and the driver carries authorization decisions and synchronous events only. Written in C, since `windows-drivers-rs` is not production-ready and lacks minifilter and WFP bindings, with tamper resistance through driver self-protection (`ObRegisterCallbacks`). The production driver is WHCP-certified through HLK testing; attestation and preproduction signing serve development only.
Why: ETW cannot block (C3); Microsoft labels attestation signing testing-only and the Windows Driver Policy admits only WHCP-signed drivers (verify that attestation-signed drivers are blocked under enforcement).
Rejected: alert-only DLP on Windows (SH-01); attestation-signed production drivers.

### AG-02. Scanner helper and memory metric
Decision: content inspection runs in a separate helper process started on demand with a memory cap and stopped when idle. Idle RAM is the sum over all resident Ricevanta user-mode processes, including the Endpoint Security extension and session helpers, of the per-OS private footprint metric (`phys_footprint`, private working set, proportional set size); kernel pool and BPF maps are reported separately.
Why: the 80 MB target cannot hold with rules, models and parsers resident (C4).
Detail: `design/agent.md` section 6.

### AG-03. Process topology and local IPC
Decision: one core service per endpoint owns the server connection, identity, policy, events and domain logic. Sensors and enforcement points (macOS Endpoint Security and Network Extension system extensions, the Windows driver, Linux eBPF programs), the updater, the scanner helper, one session helper per graphical session and the browser relays never talk to the server. Local IPC is XPC on macOS, Unix domain sockets on Linux and named pipes on Windows, with peer identity checks and `postcard`-serialized messages; the browser extension uses the native messaging each browser provides; the driver uses its communication port.
Why: the OSes require separate privileged components (C3, C5); one server connection keeps identity and policy single.
Rejected: JSON for local IPC; too slow for Endpoint Security event volume.
Detail: `architecture.md` section 2 and `design/agent.md` section 4.

### AG-04. Agent protocol
Decision: `/agent/v1` over HTTPS with mTLS terminated by the server process and required on every path except enrollment, HTTP/2 preferred, JSON bodies: periodic check-in, long-poll for signed commands delivered under a `jobs`-signed dispatch grant bound to a fresh agent nonce, ETag-based signed policy bundles with a signed per-device assignment so an agent refuses older or foreign bundles, zstd-compressed NDJSON OCSF event batches with idempotent batch IDs, and command results and journal reports signed by the device identity key. The server serves agents from the current minor release and the two before it; older agents enter update-only mode.
Why: one serialization (OCSF JSON) and one API stack; a client certificate does not survive TLS termination at an ingress.
Rejected: gRPC with Protobuf; a second API stack and a Protobuf mapping of OCSF.
Detail: `architecture.md` section 3.4.

### AG-05. Local state and event spool
Decision: SQLite in WAL mode for local state, in two databases, the response-action journal fully synchronous with received, running and terminal states keyed by command uid and action-specific crash reconciliation, and the lineage graph batched. An append-only segment spool holds one event class per segment, a CRC per record, a shared disk cap, and whole-segment drops from the lowest class first, with the drop recorded. Cached policy stays in force offline without expiry.
Why: the lineage graph needs recursive queries, and drops by class need a segment layout that no existing shipper provides (blueprint sections 5 and 7).
Rejected: RocksDB or a pure-Rust key-value store, which have no SQL; policy expiry offline, which would turn an outage into a loss of enforcement.
Detail: `design/agent.md` section 5.

### AG-06. Enforcement points hold compiled rules
Decision: the core compiles the policy bundle into rule sets installed incrementally into each enforcement point; rule-only decisions complete inside the enforcement point and are never throttled or muted. Content decisions pass an open file descriptor to the core and the scanner helper within a per-policy deadline; every policy declares its fail mode, `open` (default, with an audit event) or `closed`; a repeated scanner crash on the same content applies `closed`. Ricevanta's own processes are excluded from their own checks.
Why: authorization callbacks have OS deadlines and must not wait on IPC or inspection (blueprint section 7).
Rejected: routing every decision through the core; adds IPC latency to every file and process operation.
Detail: `design/agent.md` section 3; the rule-only subset is in `specs/policy-envelope.md` section 2.2.

### AG-07. Signed releases and staged updates
Decision: release manifests and packages are signed with offline Ed25519 release keys, a root and a successor, whose public keys are compiled into the updater; self-builders substitute their own. A separate `ricevanta-updater` service verifies the release signature, the manifest expiry and the OS code signature, refuses lower manifest versions, applies through the OS package mechanism, and restores the previous package unless the core reports healthy locally within a window. Rollout is staged by device group and percentage.
Why: the download channel and the server's blob store are untrusted for code (blueprint section 8), and a broken core cannot roll itself back.
Rejected: trusting the server TLS connection alone for updates; the core applying its own updates.
Detail: `design/agent.md` section 8.

### AG-08. Self-watchdog and hot-source control
Decision: the agent meters CPU per OS thread and memory per owned data structure for each unit of work (telemetry source, rule pack, scan) against budgets in the policy bundle, throttles and then disables a unit that exceeds its budget, and reports the degradation. Notification telemetry rate-limits per path and per process and mutes busy sources at the enforcement point with the mute reported; authorization and permission rules are exempt, a throttled content check takes the policy fail mode, and repeated mutes attributed to one user are a detection.
Why: no comparable EDR and DLP agent publishes a footprint near the 80 MB target (blueprint section 7), and the documented failures of osquery and Sysmon trace to unbounded work on busy paths (verify).
Rejected: a fixed process memory cap that restarts the agent, which loses enforcement; muting authorization rules, which would let a user flood a path to get it unprotected.
Detail: `design/agent.md` section 7.

### AG-09. Footprint telemetry, incremental rules and a performance gate
Decision: every agent process ships its own CPU, memory, descriptor and event-rate samples as OCSF events; policy bundle updates install only the changed rules into enforcement points; every agent build runs the footprint benchmark in CI and fails on regression against the last release, on hosted runners for the core and helpers and on self-hosted machines for the sensors.
Why: targets are measured, not assumed (blueprint section 7), and a reload that reinstalls everything is the failure Sysmon shipped (verify).
Rejected: measuring only in the v0.9.x performance milestone; regressions would accumulate unnoticed for eight releases.
Detail: `design/agent.md` section 7.

## MDM

### MDM-01. Native MDM servers
Decision: an Apple MDM server (MDM protocol, DDM, APNs push) and a Windows OMA-DM server (MS-MDE2 discovery, Provisioning CSP) inside the Go monolith. The agent remains the primary management path on Windows and Linux; OMA-DM covers enrollment-time provisioning, CSP-only settings and native wipe. Apple enrollment is manual and token-based at v1.0.0.
Why: profiles, DDM, OS updates, lock, wipe and FileVault escrow only work over Apple's MDM channel (C2).
Rejected: agent-only management; Apple features unreachable.
Detail: `design/backend.md` section 2.

## EDR

### EDR-01. Sigma evaluation placement
Decision: single-event Sigma rules evaluate on the agent (Rust) over process, file, network, registry, Windows Event Log and Linux syscall logsources; correlation rules evaluate on the server (Go). Windows Event Log and PowerShell script-block collection are required telemetry, and Falco rules map through a second logsource mapping. Unsupported logsources or modifiers are listed in the console with the reason.
Why: Sigma targets Sysmon and Windows Event Log fields, not OCSF; offline detection is required (C7).
Rejected: server-only evaluation.

## DLP

### DLP-01. Browser extension and session helpers
Decision: browser channels are gated at the browser's own hold point: the core serves one `content_analysis_sdk`-compatible local agent for Chrome (through Chrome Enterprise Core), Edge (Windows and macOS) and Firefox, and the managed extension's content script with a synchronous `webRequest` backstop gates Chrome without cloud management, Edge on Linux and Safari. Clipboard blocking is owner-side mediation: the session helper re-owns the clipboard on every change and answers each consumer request after the decision, the re-own interval is an OS limit with a measured bound, and Wayland is served through `ext-data-control-v1` where the compositor offers it. Cloud sync clients are the file channel through known sync folders.
Why: browsers expose uploads, pastes and printing only through their own analysis hooks, and after the re-own the clipboard owner answers every consumer request (C5).
Rejected: TLS interception, which contradicts the privacy principle and breaks pinning; clearing or replacing the clipboard after a change, which never mediates a request.
Detail: `platform-support.md`, `design/agent.md` section 3, `specs/platform-qualification.md`.

### DLP-02. Evidence
Decision: a match stores the content hash, rule ID, byte offsets and a redacted snippet of at most 200 characters; the snippet can be disabled by policy. Raw user content is never stored; script content is exported under `specs/ocsf-profile.md` section 3 after the secret and identifier detectors redact it.
Why: blueprint section 8 limits raw content collection; investigations need evidence.

### DLP-03. Classification aligned with Vietnamese data protection law
Decision: classification categories and rule packs carry an optional regulatory reference (regulation, article). The first packs implement Vietnamese personal identifiers and financial data as defined by Decree 13/2023 and the Personal Data Protection Law in force from 2026 (verify article numbering), distinguishing personal from sensitive personal data, with State Bank of Vietnam circular templates following after v1.0.0. Reports can group findings by regulation; the same field carries GDPR, PCI DSS and others later.
Why: blueprint section 3.3 names Vietnamese identifiers first; adding the reference later changes three schemas at once.
Rejected: pattern-only detectors; loses reporting value and costs a later schema change.

## Events (EV)

### EV-01. Telemetry default and scale targets
Decision: the default profile sends findings, lineage, inventory, configuration state and agent health plus bounded context to PostgreSQL (`specs/ocsf-profile.md` section 4). A device group can be switched to full raw telemetry, which goes to the optional bundled ClickHouse, to an external destination through the exporters (OpenSearch, Elasticsearch, a SIEM), or, for a bounded investigation set of at most 50 devices for 7 days, into PostgreSQL. Targets, measured not assumed: Docker Compose 2,000 endpoints, 30-day detection retention, 7-day raw retention; Helm 20,000 endpoints.
Why: fleet-wide raw telemetry exceeds what PostgreSQL alone should hold (C9), and the bounded mode spares small installations a second store for occasional investigations.
Rejected: OpenSearch as the bundled store, kept as an export destination; raw telemetry only outside PostgreSQL, which forces a second store for a single investigation.
Detail: `design/backend.md` section 5.

### EV-02. OCSF version and extension
Decision: OCSF 1.9.0 is the event schema; what each domain emits and what the `ricevanta` extension adds are in EV-03. The pinned version moves only at a minor release with a documented mapping.
Why: agents, server and exporters must agree on one schema before EDR ships (C11).
Detail: `specs/ocsf-profile.md`.

### EV-03. OCSF profile and extension
Decision: each domain emits the OCSF 1.9.0 classes in the profile table with the `host` and `security_control` profiles, and the `ricevanta` extension, registered with the OCSF project before v1.0.0 and on the development uid until then, adds what OCSF lacks for lineage, PKI, agent health, classification references, match evidence and enforcement mode. Every event carries a UUIDv7, the bundle in force and a correlation uid; fixtures are validated in CI and events failing validation at ingest are quarantined.
Why: OCSF has no PKI, lineage or agent health class and no regulation reference, and mapping drift must fail a build rather than a customer's query (EV-02).
Rejected: emitting PKI events as `authentication`, whose activities do not fit issuance; lineage inside `detection_finding.evidences`, which would inflate the finding store; deprecated classes; a self-assigned extension uid, since the registry assigns them.
Detail: `specs/ocsf-profile.md`.

## Policy (POL)

### POL-01. CEL runtimes
Decision: `cel-go` on the server and the `cel` crate (cel-rust) on the agent. Both run the cel-spec conformance tests for the CEL profile in CI (SH-02); the profile excludes anything on the `cel` crate's ignored-test list.
Why: `cel` is pure Rust, MIT, and ships the cel-spec conformance harness (C8).
Rejected: `cel-cxx`; wraps cel-cpp through a C++ build chain that limits cross-compilation.
Detail: `design/backend.md` section 2.

### POL-02. Policy envelope
Decision: `Policy`, `Exception`, `RulePack` and `Baseline` resources in the Kubernetes object shape under `apiVersion: ricevanta.io/v1alpha1`, compiled per scope into a signed bundle, with a signed per-device assignment that binds device, scope, bundle hash and an organization-wide sequence. Enforcement-weakening changes to DLP and EDR policies are protected actions, and an excepted, monitoring or disabled policy never votes in conflict resolution.
Why: one validator serves the console, the API, GitOps and the compiler; an agent cannot verify its own scope, so the assignment is what stops a stolen TLS key serving another scope's bundle (blueprint section 4, `architecture.md` section 4).
Rejected: inline exceptions, which die with their policy; scope binding inside the bundle alone, which the agent cannot check; OPA-style JWT bundle signatures, since DSSE is simpler and shared with in-toto; a policy bundle expiry, which AG-05 forbids.
Detail: `specs/policy-envelope.md`.

### POL-03. CEL profile
Decision: conditions use the profile `ricevanta-cel-1`, the subset of types, operators, macros, functions and regular-expression syntax that `cel-go` and the `cel` crate evaluate identically, with no mixed numeric operands, UTC-only time accessors and no shorthand regex classes. The server bounds cost with the `cel-go` estimator and the agent enforces size limits; extensions enter the profile only when both runtimes pass the corresponding cel-spec file in CI.
Why: the two runtimes differ on optional types, two-variable comprehensions, parse edge cases, cross-type numeric comparison and the Unicode meaning of regex shorthand classes, so only the common subset evaluates identically (C8).
Rejected: a full CEL environment with per-runtime flags, which makes a condition pass on one side and fail on the other; a custom expression language without a conformance suite; Rego or Cedar, which lack a conformant Rust runtime or are authorization languages.
Detail: `specs/cel-profile.md`.

## Lineage (LIN)

### LIN-01. Graph model and storage
Decision: lineage is a PROV-style graph with evidence-carrying edges, keyed on identities that survive reboots and remounts, uploaded as its own event class, and stored in SQLite on the endpoint and PostgreSQL on the server with depth-bounded recursive path queries. The graph is bounded by edge age with roll-up summaries, and fan-out through busy processes lowers confidence and raises a detection rather than cutting inheritance.
Why: recursive SQL covers depth-bounded provenance paths without a second storage technology, and a silent fan-out cut would be an evasion.
Rejected: a graph database, since the embedded candidates are archived or too large and the server ones are a second service or an extension; `ltree`, which fits trees only; keeping every edge forever.
Detail: `design/lineage.md`.

## PKI

### PKI-01. Enrollment and certificate protocols
Decision: the agent enrolls through a token bootstrap (PKI-02) and renews through ACME with the device identity key as the ACME account key, so the JWS over the server replay nonce authorizes replacement and the CSR proves the new key; mTLS admits the request, optional `device-attest-01` adds evidence without replacing those proofs, and lost-key recovery needs a new token and administrator approval. The PKI also serves SCEP (RSA and ECDSA) and ACME for Apple MDM payloads, network devices and third-party clients. The root CA stays offline under an M-of-N custodian quorum and is the certificate agents pin; only issuing CAs are online.
Why: Secure Enclave keys are P-256 only and SCEP commonly assumes RSA (C10).
Rejected: SCEP for the agent.
Detail: `design/pki.md` sections 2 to 4.

### PKI-02. Enrollment bootstrap
Decision: the company-signed installer ships unchanged; an enrollment configuration delivered beside it carries the server URL, the Ricevanta root CA to pin and an enrollment token scoped to a device group and expiring, single-use with administrator approval by default for any group that can receive network-access certificates or MDM management. The agent posts a certificate signing request with the token and a platform attestation where available, checked against an imported endorsement-key allow list; `jobs` independently verifies proof and derives issuance authority from protected records, with approvals bound to the exact request, CSR, device and profile. Expired certificates renew within a grace period; beyond it, or after re-imaging, a new token is issued, and taking over an existing record needs proof of the previous key or approval, never hardware identifiers alone.
Why: signed packages cannot be rebuilt per installation (PF-03), the first contact has no certificate yet, and a stolen token must not become a VPN credential or a takeover of another device's record (blueprint section 8).
Rejected: enrollment configuration embedded in the installer; multi-use tokens without approval as the default; re-enrollment matched on serial numbers.
Detail: `design/pki.md`.

## RADIUS (RAD)

### RAD-01. Both RADIUS architectures
Decision: certificate-derived identity authorization (the gateway validates the certificate, Ricevanta authorizes by SAN or DN identity against issued, unrevoked certificates and device compliance) and EAP-TLS termination, over UDP and RadSec. FortiGate SSL VPN and IKEv2 and Cisco ASA profiles are acceptance-tested against gateways. EAP-TLS is implemented in-project in Go, because no maintained Go library ships it.
Why: FortiClient and Cisco Secure Client do not initiate EAP-TLS; EAP-TLS serves 802.1X and native OS clients (C6).
Rejected: FreeRADIUS as the EAP server (GPL-2.0).
Detail: `design/backend.md` section 2.

## Backend and console (BE)

### BE-01. Identity sources
Decision: administrator single sign-on through OIDC, SAML where a provider lacks OIDC, with users and groups through SCIM 2.0 push or LDAP sync. Local accounts only for the first administrator and break-glass, with a second factor and audited, alerting logins. Devices link to users at enrollment and from observed login sessions.
Why: policies and RADIUS need group membership; the console needs administrator login.
Rejected: local accounts as the primary user store; drifts from the directory.
Detail: `design/backend.md` section 2.

### BE-02. RBAC with access policies for protected actions
Decision: one permission per action, bundled into built-in and custom roles, assignable to users or directory groups, optionally scoped to device groups. Access policies name protected actions and an approver group; a protected action from the console, the API or GitOps becomes a pending request that a different account approves before dispatch, with targets frozen at request time and requester, approver and targets audited; wipe, response actions on more than 10 devices, rule-pack publish, CA key operations, weakening DLP and EDR policies and publishing ones with isolate, revoke or kill actions (`specs/policy-envelope.md` section 2.3) are protected by default. Single-administrator installations can disable approval policies and see a persistent warning; just-in-time role activation is not in v1.0.0.
Why: a compromised or mistaken administrator is the most damaging failure; regulated customers require separation of duties (DLP-03).
Rejected: RBAC and audit only; no protection against one compromised account.

### BE-03. One server binary with roles
Decision: `ricevanta-server` is a Go modular monolith that runs the roles `api`, `agent`, `device`, `radius` and `jobs` in one process by default and as separate deployments under Helm, with the console compiled into the binary. Private keys follow exposure: the master key and the signing key live in `api` and `jobs`, the issuing CA keys in `jobs` only, and the agent-facing `agent`, `device` and `radius` roles hold their TLS keys, role-scoped data keys and per-role database credentials that write only events, check-ins, results and request rows, which `jobs` treats as untrusted input and authorizes against protected records before issuance or dispatch. Jobs elect one leader per job through a lease row in PostgreSQL, and agent-facing handlers read no fleet-wide shared state per routine request.
Why: self-hosters get one artifact and roles scale separately (blueprint section 5); a compromised exposed replica must not be able to sign commands or mint identities.
Rejected: one service per domain; Redis as a second stateful service; advisory locks for leader election, which pin connections and fail behind transaction pooling; signing keys in every role.
Detail: `architecture.md` section 3.1 and `design/backend.md` sections 3 and 7.

### BE-04. Module boundaries
Decision: modules `identity`, `authz`, `devices`, `mdm`, `policy`, `detection`, `dlp`, `lineage`, `pki`, `radius`, `events`, `audit`, `transport` and `platform`. Each owns one PostgreSQL schema that no other module reads or writes, exposes Go interfaces, publishes on an in-process bus, and coordinates across replicas only through PostgreSQL; an import-graph check in CI enforces the boundaries.
Why: the monolith stays splittable and testable per module.
Rejected: shared tables across modules; couples schemas and blocks later extraction.
Detail: `design/backend.md` section 1.

### BE-05. API style and GitOps
Decision: `/api/v1` is a JSON REST API described by OpenAPI 3.1 and is the only write path; the console and the `ricevanta` CLI use it with browser sessions from the BE-01 identity sources or scoped API tokens. GitOps is a directory of `ricevanta.io/v1*` YAML resources applied as a declarative three-way diff by the CLI or by the server polling a repository; protected actions become approval requests (BE-02).
Why: one write path keeps authorization and audit complete; YAML resources match the policy envelope format.
Rejected: a separate GraphQL or gRPC administration API; no consumer needs it.
Detail: `architecture.md` section 3.3.

### BE-06. Storage
Decision: PostgreSQL 17+ as the system of record with natively day-partitioned event tables, batched `COPY` ingest and partition-drop retention; a blob store with local-filesystem and S3-compatible backends for installers, release packages, rule-pack archives and reports; secrets at rest under envelope encryption with a server master key from the environment, a file or an external KMS, with PKCS#11 as the alternative for CA keys. Backups are `pg_dump` plus the blob store plus the separately held master key under Docker Compose, and the PostgreSQL operator's backups under Helm.
Why: minimal infrastructure (blueprint section 5) while keeping large binaries out of the database.
Rejected: storing packages in PostgreSQL; TimescaleDB, whose retention and compression are not under Apache-2.0; `pg_partman`, an extension for what a small job does.
Detail: `design/backend.md` sections 5 and 6.

### BE-07. Deployment and high availability
Decision: Docker Compose runs all roles in one container with PostgreSQL and an optional ClickHouse profile; Helm runs one deployment per role group, `agent` and `device` behind TLS passthrough or a layer-4 load balancer, `radius` behind separate UDP and TCP `LoadBalancer` services with local traffic policy and client-IP hashing at both the service and the external load balancer, and PostgreSQL external or through the CloudNativePG operator for evaluation. `api`, `agent` and `device` are stateless with two or more replicas, `jobs` elects leaders, `radius` replicas hold their own EAP state; migrations are forward-only and compatible with the previous server version for rolling upgrades.
Why: EV-01 scale targets and self-hoster simplicity.
Rejected: a required message queue; PostgreSQL `LISTEN`/`NOTIFY` and job tables cover the coordination needed.
Detail: `architecture.md` section 5.
