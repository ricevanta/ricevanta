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

### SH-03. Single organization per server
Decision: v1.0.0 serves one organization per server. Tables carry an organization ID so multi-tenancy is a later addition, not a migration.
Why: no requirement for multi-tenancy at v1.0.0.

## Platform (PF)

### PF-01. v1.0.0 targets
Decision: macOS ARM64, Windows x64, Linux x64. Windows ARM64, Linux ARM64 and macOS x64 follow in v1.x; the design stays architecture-independent.
Why: largest installed bases; separate driver signing and CI hardware for the others.
Detail: `platform-support.md`.

### PF-02. Version floor
Decision: macOS 14+; Windows 11 23H2+ and Windows 10 22H2 until Microsoft support ends; Linux kernel 5.10+ with BTF and BPF LSM on the listed distributions.
Why: BPF CO-RE needs BTF; blocking on Linux needs BPF LSM (C3, C12).
Detail: `platform-support.md`.

### PF-03. Vendor programs held by the project
Decision: development and testing on personal accounts; a company registered before sensor distribution holds the Apple team, Partner Center account and EV certificate; all production binaries signed under it.
Why: entitlements and driver signatures bind to one organization (C1).
Detail: `project.md`.

## Agent (AG)

### AG-01. Windows kernel component
Decision: a signed kernel component with a file-system minifilter, process-creation callbacks that deny creation, and a WFP callout where user-mode WFP is insufficient. ETW stays the telemetry source; the driver carries authorization decisions and synchronous events only. C unless `windows-drivers-rs` is production-ready before v0.5.x. Tamper resistance through driver self-protection (`ObRegisterCallbacks`).
Why: ETW cannot block; blocking file movement needs a minifilter (C3).
Rejected: alert-only DLP on Windows (SH-01).

### AG-02. Scanner helper and memory metric
Decision: content inspection runs in a separate helper process started on demand with a memory cap and stopped when idle. Idle RAM is the sum of all resident Ricevanta user-mode processes, including the Endpoint Security extension and session helpers; kernel pool is reported separately.
Why: the 80 MB target cannot hold with rules, models and parsers resident (C4).

## MDM

### MDM-01. Native MDM servers
Decision: an Apple MDM server (MDM protocol, DDM, APNs push) and a Windows OMA-DM server (MS-MDE2 discovery, Provisioning CSP) inside the Go monolith. The agent remains the primary management path on Windows and Linux; OMA-DM covers enrollment-time provisioning, CSP-only settings and native wipe. Apple enrollment is manual and token-based at v1.0.0.
Why: profiles, DDM, OS updates, lock, wipe and FileVault escrow only work over Apple's MDM channel (C2).
Rejected: agent-only management; Apple features unreachable.

## EDR

### EDR-01. Sigma evaluation placement
Decision: single-event Sigma rules evaluate on the agent (Rust) over process, file, network, registry, Windows Event Log and Linux syscall logsources; correlation rules evaluate on the server (Go). Windows Event Log and PowerShell script-block collection are required telemetry. Falco rules map through a second logsource mapping. Unsupported logsources or modifiers are listed in the console with the reason.
Why: Sigma targets Sysmon and Windows Event Log fields, not OCSF; offline detection is required (C7).
Rejected: server-only evaluation.

## DLP

### DLP-01. Browser extension and session helpers
Decision: a browser extension for Chrome, Edge, Firefox and Safari, force-installed through managed-browser policy, asks the agent over native messaging for allow, warn or block on uploads, pastes and downloads. A per-user-session helper on each OS monitors the clipboard and blocks by clearing or replacing it. Cloud sync clients are the file-system channel through known sync folders. Wayland clipboard is unsupported and shown as such.
Why: no OS exposes browser uploads or clipboard events to a system service (C5).
Rejected: TLS interception; contradicts the privacy principle and breaks pinning.

### DLP-02. Evidence
Decision: a match stores the content hash, rule ID, byte offsets and a redacted snippet of at most 200 characters; the snippet can be disabled by policy. Raw content is never stored.
Why: blueprint section 8 limits raw content collection; investigations need evidence.

### DLP-03. Classification aligned with Vietnamese data protection law
Decision: classification categories and rule packs carry an optional regulatory reference (regulation, article). The first packs implement Vietnamese personal identifiers and financial data as defined by Decree 13/2023 and the Personal Data Protection Law in force from 2026 (verify article numbering), distinguishing personal from sensitive personal data. State Bank of Vietnam circular templates follow after v1.0.0. Reports can group findings by regulation; the same field carries GDPR, PCI DSS and others later.
Why: blueprint section 3.3 names Vietnamese identifiers first; adding the reference later changes three schemas at once.
Rejected: pattern-only detectors; loses reporting value and costs a later schema change.

## Events (EV)

### EV-01. Telemetry default and scale targets
Decision: the default profile sends detections plus bounded context to PostgreSQL. A device group can be switched to full raw telemetry, which requires the optional OpenSearch or Elasticsearch store or an external SIEM. Targets, measured not assumed: Docker Compose 2,000 endpoints, 30-day detection retention, 7-day raw retention; Helm 20,000 endpoints.
Why: raw telemetry volume exceeds what PostgreSQL alone should hold (C9).

## PKI

### PKI-01. Enrollment and certificate protocols
Decision: the agent enrolls its identity through a native enrollment API over mTLS and renews through ACME with a device-attested challenge. The PKI also serves SCEP (RSA and ECDSA) and ACME for Apple MDM payloads, network devices and third-party clients. Agent identity, management and network-access certificates are all issued at v1.0.0. Root CA key ceremonies use M-of-N custodian quorum.
Why: Secure Enclave keys are P-256 only and SCEP commonly assumes RSA (C10).
Rejected: SCEP for the agent.

## RADIUS (RAD)

### RAD-01. Both RADIUS architectures
Decision: certificate-derived identity authorization (the gateway validates the certificate, Ricevanta authorizes by SAN or DN identity against issued, unrevoked certificates and device compliance) and EAP-TLS termination, over UDP and RadSec. FortiGate SSL VPN and IKEv2 and Cisco ASA profiles are acceptance-tested against gateways. EAP-TLS is implemented in Go on `layeh/radius`.
Why: FortiClient and Cisco Secure Client do not initiate EAP-TLS; EAP-TLS serves 802.1X and native OS clients (C6).
Rejected: FreeRADIUS as the EAP server (GPL-2.0).

## Backend and console (BE)

### BE-01. Identity sources
Decision: administrator single sign-on through OIDC, SAML where a provider lacks OIDC. Users and groups through SCIM 2.0 push or LDAP sync. Local accounts only for the first administrator and break-glass, with a second factor and audited, alerting logins. Devices link to users at enrollment and from observed login sessions.
Why: policies and RADIUS need group membership; the console needs administrator login.
Rejected: local accounts as the primary user store; drifts from the directory.

### BE-02. RBAC with access policies for protected actions
Decision: one permission per action, bundled into built-in and custom roles, assignable to users or directory groups, optionally scoped to device groups. Access policies name protected actions and an approver group; a protected action becomes a pending request that a different account approves before dispatch, with targets frozen at request time and requester, approver and targets audited. API and GitOps changes use the same path. Default protection: wipe, response actions on more than 10 devices, rule-pack publish, CA key operations. Single-administrator installations can disable approval policies and see a persistent warning. Just-in-time role activation is not in v1.0.0.
Why: a compromised or mistaken administrator is the most damaging failure; regulated customers require separation of duties (DLP-03).
Rejected: RBAC and audit only; no protection against one compromised account.
