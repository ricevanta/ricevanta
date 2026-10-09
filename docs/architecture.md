# Architecture

The system view: which processes exist, how they talk, who holds which key, and how the system is deployed. Requirements are in `blueprint.md`; decisions are registered in `decisions.md`. The agent's internals are in `design/agent.md`, the server's in `design/backend.md`, enrollment and certificates in `design/pki.md`, the lineage graph in `design/lineage.md`; schemas and protocols go in `specs/`. Claims that rest on vendor behaviour rather than first-party documentation are marked "verify".

## 1. Components

| Component | Runs on | Language | Privilege | Purpose |
|---|---|---|---|---|
| `ricevanta-server` | Server, one binary with selectable roles | Go | Unprivileged container user | API, console, agent endpoints, native MDM protocols, PKI, RADIUS, jobs, exporters |
| Console | Served by `ricevanta-server`, runs in the browser | Vue 3, TypeScript | Browser | Administration |
| `ricevanta` CLI | Administrator workstation, CI | Go | User | Same API as the console; GitOps apply |
| PostgreSQL 17+ | Server | | | System of record |
| ClickHouse | Server, optional | | | Raw telemetry store (EV-01); OpenSearch and Elasticsearch are export destinations |
| Blob store | Server: local volume or S3-compatible bucket | | | Installers, agent packages, rule-pack archives |
| `ricevanta-agent` | Endpoint, system service | Rust | root, LocalSystem | Agent core: identity, policy, events, MDM, EDR and DLP logic, lineage |
| `ricevanta-updater` | Endpoint, system service | Rust | root, LocalSystem | Applies signed updates, watches core health, rolls back |
| `Ricevanta.app` | macOS, system-wide application | Swift shim | User | Hosts the two system extensions and the Safari extension handler; activates the extensions |
| Endpoint Security extension | macOS system extension | Rust, Swift shim | System extension | Process and file telemetry and authorization |
| Network Extension | macOS system extension | Swift shim, Rust logic | System extension, sandboxed | Network telemetry and blocking |
| `ricevanta.sys` | Windows kernel driver | C (AG-01) | Kernel, WHCP-certified | Minifilter, process-creation callbacks, WFP callout, self-protection |
| eBPF programs | Linux kernel, loaded by the core | C, CO-RE, dual MIT/GPL | Kernel | Telemetry, BPF LSM blocking |
| `ricevanta-scan` | Endpoint, started on demand by the core | Rust | Reduced privilege, memory cap | Content inspection (AG-02) |
| `ricevanta-session` | Endpoint, one per graphical login session | Rust | Logged-in user | Clipboard, user prompts, session context (DLP-01) |
| `ricevanta-nmhost` | Endpoint, started by Chrome, Edge or Firefox | Rust | Logged-in user | Native messaging relay between the browser extension and the core |
| Browser extension | Chrome, Edge, Firefox, Safari | TypeScript | Browser | Upload, paste and download decisions (DLP-01) |

The agent is one product with one installer, one identity and one update lifecycle. It is several processes because the operating systems require it (blueprint section 5).

## 2. Agent topology

| OS | Core and updater | Kernel or system component | Helpers |
|---|---|---|---|
| macOS | launchd system daemons | `Ricevanta.app` hosts `io.ricevanta.agent.es` (Endpoint Security) and `io.ricevanta.agent.ne` (Network Extension content filter) | `ricevanta-scan`; `ricevanta-session` as a launchd user agent; `ricevanta-nmhost` for Chrome, Edge and Firefox; the Safari extension handler inside `Ricevanta.app` |
| Windows | Services, LocalSystem | `ricevanta.sys` | `ricevanta-scan`; `ricevanta-session` launched into each interactive session by the core; `ricevanta-nmhost` |
| Linux | systemd services, root | eBPF programs loaded by the core with links and maps pinned in bpffs; fanotify from the core | `ricevanta-scan`; `ricevanta-session` through an XDG autostart entry per graphical session; `ricevanta-nmhost` |

The core owns the server connection, the device identity, the policy cache, the event pipeline and all domain logic. Every other process is a sensor, an enforcement point, the updater or a user-session proxy, and never talks to the server. Enforcement points hold their own compiled rules and decide locally; only content decisions ask the core (AG-06). Processes in the user session are untrusted input to the core. The internal structure, enforcement model, local IPC, state, memory budget, resource governance, updates and tamper resistance are in `design/agent.md`.

## 3. Server

### 3.1 One binary, selectable roles

`ricevanta-server` is a Go modular monolith. A process runs the roles named in its configuration; the default is all roles, which is what Docker Compose runs. Helm runs separate deployments per role group.

| Role | Listeners | State and keys |
|---|---|---|
| `api` | HTTPS: console, `/api/v1`, embedded console assets; any certificate | Stateless; holds the master key and the policy and command signing key, and signs at creation |
| `agent` | HTTPS: `/agent/v1`; server certificate from the Ricevanta PKI, pinned by agents; TLS terminated by the server itself; a client certificate is requested on every connection and required on every path except enrollment; renewal accepts an expired, unrevoked certificate within the grace period | Holds long-poll connections; public keys only; PostgreSQL credentials that read bundles and commands and write only events, check-ins, command results and certificate requests |
| `device` | HTTPS: Apple MDM, OMA-DM, SCEP and ACME for MDM payloads, network devices and third-party clients; publicly trusted or Ricevanta certificate; TLS terminated by the server itself | Stateless; its TLS key only; SCEP envelopes and certificate requests go to `jobs` through request rows |
| `radius` | UDP 1812 and 1813, RadSec TCP 2083 | EAP conversations live in the replica's memory; its TLS key and the per-gateway shared secrets under a role-scoped data key |
| `jobs` | None | Schedulers, exporters, retention, directory sync, correlation, certificate issuance, APNs pushes; holds the master key, the issuing CA keys, the APNs push key and the signing key; one active leader per job through a lease row (`design/backend.md` section 3) |

Key custody follows exposure: the agent-facing `agent`, `device` and `radius` roles never receive the master key or any CA or signing key, hold their TLS keys under role-scoped data keys, run with per-role PostgreSQL credentials, and cannot write bundle, command, approval or certificate rows, only request rows that `jobs` answers (`design/pki.md` section 3, BE-03).

The `agent` and `device` roles terminate TLS in the server process: a client certificate does not survive an ingress that terminates TLS, and the agent pins the Ricevanta root CA. Ingress controllers in front of them run in TLS passthrough mode or as layer-4 load balancers.

The console is a Vue 3 single-page application compiled into the binary and served from the same origin as `/api/v1`, so there is no cross-origin configuration.

### 3.2 Modules

Fourteen modules with schema ownership and an import-graph check (BE-04); contents, rules, library choices, coordination, pipelines and storage are in `design/backend.md`.

### 3.3 APIs

| API | Path | Consumers | Authentication | Format |
|---|---|---|---|---|
| Administration | `/api/v1` | Console, CLI, GitOps, integrations | Browser session from OIDC, SAML or break-glass local login (BE-01), or a scoped API token | JSON, described by a hand-written OpenAPI 3.1 document in `schemas/openapi/` validated in CI |
| Agent | `/agent/v1` | `ricevanta-agent` | mTLS with the device identity certificate; enrollment token on `/agent/v1/enroll`; expired certificate accepted on `/agent/v1/acme` within the grace period | JSON; NDJSON batches for events, zstd-compressed; ACME for renewal |
| Native device protocols | `/mdm/apple`, `/mdm/windows`, `/scep`, `/acme` | MDM clients, network equipment, third-party clients | Protocol-specific (`design/pki.md`, MDM-01) | Protocol-specific |

The administration API is the only write path; the console and the CLI have no privileges the API does not expose. GitOps is a directory of YAML resources (`apiVersion: ricevanta.io/v1*`; kinds such as `Policy`, `RulePack`, `DeviceGroup`, `Baseline`, `ExportDestination`) applied by `ricevanta apply` or by the server polling a Git repository. Apply is a declarative three-way diff against the stored state; protected actions become approval requests (BE-02).

### 3.4 Agent protocol

HTTPS with required mTLS, HTTP/2 preferred and HTTP/1.1 accepted, JSON bodies. No gRPC. The four flows:

| Flow | Mechanism |
|---|---|
| Check-in | `POST /agent/v1/checkin` every 5 minutes (policy-tunable) with health, versions and inventory deltas; the response carries the current policy bundle version and pending command count |
| Commands | `GET /agent/v1/commands` long-poll; the hold time is a server setting, default 50 s so that a 60 s proxy idle timeout is never hit, raised to minutes once the operator sets the load balancer timeout above it. A `NOTIFY` on the commands channel wakes the replica holding the device's connection. Every command is signed (section 4), acknowledged, and its result posted individually |
| Policy | `GET /agent/v1/policy` with `If-None-Match`; the body is a signed bundle compiled for the device's scope and carrying the organization, scope ID and a sequence number; the agent refuses a lower sequence or a foreign scope |
| Events | `POST /agent/v1/events` with NDJSON OCSF batches, zstd, a batch ID for idempotent retry, at most 5 MB per request |
| CRL and update | `GET /agent/v1/crl` for the issuing CA's CRL, fetched with the policy and cached; `GET /agent/v1/update` for the release manifest |

Compatibility window: the server serves `/agent/v1` to agents from the current minor release and the two before it. Older agents are placed in update-only mode: they keep their cached policy, may fetch the release manifest and renew their certificate and nothing else, and the console flags them. The handler rules that keep this path cheap at 20,000 endpoints are in `design/backend.md`.

## 4. Keys and what they sign

| Key | Held by | Signs | Verified by |
|---|---|---|---|
| Root CA | Offline, M-of-N custodian quorum (PKI-01); its certificate is what agents pin | Issuing CA certificates | Everything that trusts the PKI |
| Issuing CAs (device, server, network access) | `jobs` role: software key under envelope encryption, or PKCS#11 | Device identity, management and network-access certificates; server certificates for the `agent` and `device` roles; the policy signing certificate | Agents, MDM clients, VPN gateways, RADIUS |
| Policy and command signing key (Ed25519, one per organization) | `api` and `jobs` roles, under envelope encryption; its public key is carried in a certificate from the issuing CA | Policy bundles, rule packs and every agent command, each command bound to the device ID, a nonce and an expiry | Agents, against the pinned root and the CRL (`design/pki.md` section 4) |
| Release signing keys (Ed25519) | Project maintainers, offline root and successor keys; self-builders use their own | Release manifests, which carry an expiry, and packages | `ricevanta-updater`; both public keys are compiled in, a manifest signed by the successor retires the root |
| Platform code-signing identities | The company (PF-03) | Binaries, system extensions, the WHCP submission of the driver | Operating systems |

For `/agent/v1`, TLS protects the transport and the signatures bind policy, commands and releases to keys the agent-facing roles never hold, so a stolen `agent`-role TLS key, a wrong pin or a mirrored download cannot inject policy, commands or code. The native MDM channels have no second signature: Apple MDM and OMA-DM commands rest on the `device` role's TLS key, which is therefore short-lived, kept in the KMS or PKCS#11 device where one is configured, and revocable from the console. Enrollment, renewal and recovery are in `design/pki.md`; updates in `design/agent.md`.

## 5. Deployment

| Shape | Composition | Target |
|---|---|---|
| Docker Compose | `ricevanta-server` (all roles), PostgreSQL, optional ClickHouse profile, local blob volume | Evaluation and small installations, 2,000 endpoints (EV-01) |
| Helm | Deployments per role group: `api` behind an ordinary ingress; `agent` and `device` behind an ingress in TLS passthrough mode or a layer-4 load balancer; `jobs` with no service; `radius` behind two `LoadBalancer` services, one UDP for 1812 and 1813 and one TCP for RadSec, because mixed-protocol services are not supported on every provider, each with `externalTrafficPolicy: Local` and client-IP affinity, and the external load balancer configured to hash on client IP as well, so the gateway's source address and EAP conversation stay on one replica; PostgreSQL external or through the CloudNativePG operator for evaluation, since the Bitnami images are no longer maintained for free use; ClickHouse external or as a single-replica StatefulSet; S3-compatible blob store | 20,000 endpoints (EV-01) |

High availability: `api`, `agent` and `device` are stateless and run two or more replicas; `jobs` runs replicas with per-job leader election; `radius` replicas each hold their own EAP state, and gateways are configured with a primary and a secondary server; PostgreSQL high availability is the operator's choice. Upgrades run `ricevanta-server migrate` before the new version serves; migrations are forward-only and compatible with the previous server version for a rolling upgrade.

Observability: Prometheus metrics on `/metrics`, structured JSON logs, health and readiness endpoints, optional OpenTelemetry traces. The server's own audit and security events are OCSF events in the same pipeline.

## 6. Repository layout

```
ricevanta/
├── agent/        Rust workspace: crates (core, updater, os-macos, os-windows, os-linux, scan, session, nmhost), bpf/ (dual MIT/GPL), app bundles, packaging
├── driver/       Windows kernel driver (C), WDK build, HLK test configuration
├── extension/    Browser extension (TypeScript, Manifest V3), Safari handler sources
├── server/       Go module: cmd/ricevanta-server, cmd/ricevanta, internal/<module>
├── console/      Vue 3 application, built into server/ at release
├── schemas/      Policy envelope JSON Schema, CEL profile, OCSF profile and extension, OpenAPI
├── rulepacks/    First-party rule packs with license records
├── deploy/       Docker Compose, Helm chart, examples
├── tests/        Capability matrix acceptance tests, integration and end-to-end tests, footprint benchmark
├── docs/         Design documents
└── instructions/ How to work
```

One repository, one version number per release for server, console, agent and extension (SH-04). Language-specific instructions are added when the first directory is created (`instructions/workflow.md`).

## 7. Cross-cutting rules

- Versioning: SemVer for the product; `/api/v1` and `/agent/v1` change additively within a major; the policy envelope is `apiVersion: ricevanta.io/v1alpha1` throughout v0.x and `v1` from v1.0.0. The v1.0.0 server migration relabels stored resources; agents receive compiled bundles whose format is versioned with `/agent/v1`, so the envelope label never reaches them.
- Failure behaviour: every policy declares its fail mode for each enforcement point (`design/agent.md`); every unsupported capability is reported, never silently skipped.
- Privacy: classification runs on the endpoint; only the evidence DLP-02 allows leaves the device.
- Configuration: the server reads environment variables and one YAML file; the agent reads the enrollment configuration (`design/pki.md`) plus server-delivered signed policy. Agent configuration cannot be changed locally, and the agent cannot be removed without the uninstall authorization in `design/agent.md` section 9.
- Tamper resistance against a local administrator is prevention only where the OS provides it and reporting elsewhere; the preconditions per OS are in `design/agent.md` and `platform-support.md`.
- Time: the server is the clock of record; agent events carry monotonic sequence numbers and the agent's clock, and the server records receipt time.
- Internationalization: console strings through `vue-i18n` from the first component (`project.md`).

## 8. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one server binary and one agent package keep deployment and upgrades simple for self-hosters, the shape Fleet, Velociraptor, Loki and Teleport scale with; enforcement points that hold their own rules keep decision latency off the IPC path; signed policy, commands and releases with keys the agent-facing roles never hold make the TLS certificate, the ingress and the download channel non-critical for integrity; per-module schemas keep the monolith splittable later.

Trade-offs: JSON over HTTPS costs more bytes than gRPC and Protobuf for telemetry, paid back by one serialization format (OCSF JSON) and one API stack. Long-poll holds one connection per agent on the `agent` role, which is cheap in Go. TLS passthrough for the `agent` and `device` roles removes ingress-level TLS management for those endpoints. WHCP certification of the driver needs an HLK lab and adds weeks to every driver release.

Dependencies: listed per domain in `design/agent.md`, `design/backend.md` and `design/pki.md`, plus CloudNativePG, the Prometheus client and the OpenTelemetry SDK for deployment and observability; every one has a row in `licensing.md`.

Limits: Kubernetes clusters without a UDP-capable load balancer need an external one for RADIUS. The macOS extensions need the company's entitlements for production (PF-03). The agent compatibility window means a server more than two minor releases ahead stops serving old agents except for updates.

Alternatives considered: recorded as the Rejected line of each decision this document introduces (SH-04, AG-03, AG-04, BE-03, BE-05, BE-07) and of the domain designs' decisions.
