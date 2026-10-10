# Architecture

The system view: which processes exist, how they talk, who holds which key, and how the system is deployed. Requirements are in `blueprint.md`; decisions are registered in `decisions.md`. The agent's internals are in `design/agent.md`, the server's in `design/backend.md`, enrollment and certificates in `design/pki.md`, the lineage graph in `design/lineage.md`, the extension model in `design/extensions.md`, the console in `design/console.md`, the event pipeline and audit log in `design/events.md`, and the domains in `design/mdm.md`, `design/edr.md`, `design/dlp.md`, `design/radius.md` and `design/policy.md`; schemas and protocols go in `specs/`. Claims that rest on vendor behaviour rather than first-party documentation are marked "verify".

## 1. Components

| Component | Runs on | Language | Privilege | Purpose |
|---|---|---|---|---|
| `ricevanta-server` | Server, one binary with selectable roles | Go | Unprivileged container user | API, console, agent endpoints, native MDM protocols, PKI, RADIUS, jobs, exporters |
| Console | Served by `ricevanta-server`, runs in the browser | Vue 3, TypeScript | Browser | Administration |
| `ricevanta` CLI | Administrator workstation, CI | Go | User | Same API as the console; GitOps apply |
| `ricevanta-rulec` | Server, inside the server image; started per call by the `policy` module | Rust, built from the agent workspace | Unprivileged; CPU-time, memory and wall-time limits | Compiles rule patterns, YARA-X rules, SQL statements and CEL conditions with the agent's engines and runs rule fixtures (POL-05) |
| PostgreSQL 17+ | Server | | | System of record |
| ClickHouse | Server, optional | | | Raw telemetry store (EV-01); OpenSearch and Elasticsearch are export destinations |
| Authority journal | Server: independent local volume or qualified S3-compatible store | | | Authenticated authority and audit tail, writer fences and recovery epochs; executable protocol remains blocked (`design/backend.md` section 6.1) |
| Blob store | Server: local volume or S3-compatible bucket | | | Installers, agent packages, rule-pack archives, extension packages, diagnostics bundles and triage packages, the event export log, fingerprint sets |
| `ricevanta-agent` | Endpoint, system service | Rust | root, LocalSystem | Agent core: identity, policy, events, MDM, EDR and DLP logic, lineage |
| `ricevanta-updater` | Endpoint, system service | Rust | root, LocalSystem | Applies signed updates, watches core health, rolls back |
| `Ricevanta.app` | macOS, system-wide application | Swift shim | User | Hosts the two system extensions and the Safari extension handler; activates the extensions |
| Endpoint Security extension | macOS system extension | Rust, Swift shim | System extension | Process and file telemetry and authorization |
| Network Extension | macOS system extension | Swift shim, Rust logic | System extension, sandboxed | Network telemetry and blocking |
| `ricevanta.sys` | Windows kernel driver | C (AG-01) | Kernel, WHCP-certified | Minifilter, process-creation callbacks, WFP callout, self-protection |
| eBPF programs | Linux kernel, loaded by the core | C, CO-RE, dual MIT/GPL | Kernel | Telemetry, BPF LSM blocking |
| `ricevanta-scan` | Endpoint, started on demand by the core; also in the server image, run by `jobs` as a subprocess to fingerprint registered documents | Rust | Reduced privilege, memory cap | Content inspection (AG-02) and fingerprinting (DLP-05) |
| `ricevanta-ext` | Endpoint, started on demand by the core | Rust, `wasmtime` | Reduced privilege, memory cap | Runs sandboxed WebAssembly extension modules: classifiers, parsers, collectors, responder plans (EXT-03) |
| `ricevanta-session` | Endpoint, one per graphical login session | Rust | Logged-in user | Clipboard, user prompts, session context (DLP-01) |
| `ricevanta-nmhost` | Endpoint, started by a browser whose adapter declares a native host | Rust | Logged-in user | Native messaging relay between the browser extension and the core |
| Browser extension | Browsers declared by a browser adapter (EXT-06); first-party adapters: Chrome, Edge, Firefox, Safari | TypeScript | Browser | Content-script candidates and browser context; required Safari and Chromium fallback transfer blockers are defined in `design/dlp.md` section 6.5; decisions come from the core's content-analysis agent |
| Console modules | Sandboxed iframes inside the console | Web assets from any toolchain | Opaque origin; network isolation requires browser qualification (`design/extensions.md` section 5) | Extension UI in console slots through the bridge (EXT-04) |
| Service connectors | Operator's infrastructure: own container, Compose service or Helm deployment | Any | Chosen by the operator | Export destinations, external CA, notifiers and enrichers over versioned HTTP contracts (EXT-05) |

The agent is one product with one installer, one identity and one update lifecycle. It is several processes because the operating systems require it (blueprint section 5).

## 2. Agent topology

| OS | Core and updater | Kernel or system component | Helpers |
|---|---|---|---|
| macOS | launchd system daemons | `Ricevanta.app` hosts `io.ricevanta.agent.es` (Endpoint Security) and `io.ricevanta.agent.ne` (Network Extension content filter) | `ricevanta-scan`; on-demand DLP and batch instances of `ricevanta-ext`; `ricevanta-session` as a launchd user agent; `ricevanta-nmhost` for every browser whose adapter declares a native host; the Safari extension handler inside `Ricevanta.app` |
| Windows | Services, LocalSystem | `ricevanta.sys` | `ricevanta-scan`; on-demand DLP and batch instances of `ricevanta-ext`; `ricevanta-session` launched into each interactive session by the core; `ricevanta-nmhost` |
| Linux | systemd services, root | eBPF programs loaded by the core with links and maps pinned in bpffs; fanotify from the core | `ricevanta-scan`; on-demand DLP and batch instances of `ricevanta-ext`; `ricevanta-session` through an XDG autostart entry per graphical session; `ricevanta-nmhost` |

Inventory SQL requires an isolated on-demand query process under `specs/rule-adapters.md` section 8.1. The process has zero idle allocation, receives only a bounded snapshot and has no server or device-identity access. Its native launcher, sandbox, resource accounting and cancellation contract remain implementation blockers; no worker binary is selected.

The core owns the server connection, the device identity, the policy cache, the event pipeline and all domain logic. Every other process is a sensor, an enforcement point, the updater, a content or extension helper, or a user-session proxy, and never talks to the server. For updates, the core fetches the manifest and package and streams opaque bytes into the updater's authenticated local inbox; the updater owns verification, install and rollback and never receives the identity key (`design/agent.md` section 8). `ricevanta-ext` is one binary with at most one active DLP instance and one active batch instance, each separately replaceable and capped at 128 MB by default, with a 256 MB default aggregate active cap. Batch work cannot borrow the DLP process, workers or memory reserve. Both instances stop when idle, and modules never receive resident processes of their own (`specs/extension-agent-runtime.md` section 1). Browser adapters select policy names and capabilities within a protected browser registration that owns each exact policy and native-host target (`design/extensions.md` section 7). Enforcement points hold compiled rule-only programs and finalize locally only when the global conflict plan proves that unresolved core outcomes cannot change the ordered decision or its actions (AG-06). Other triggers ask the core, including conditions that need no content scan. Processes in the user session are untrusted input to the core. The internal structure, enforcement model, local IPC, state, memory budget, resource governance, updates and tamper resistance are in `design/agent.md`.

## 3. Server

### 3.1 One binary, selectable roles

`ricevanta-server` is a Go modular monolith. A process runs the roles named in its configuration; the default is all roles, which is what Docker Compose runs. Helm runs separate deployments per role group.

| Role | Listeners | State and keys |
|---|---|---|
| `api` | HTTPS: console, `/api/v1`, embedded console assets, extension assets under `/ext/`; any certificate | Stateless; holds the master key and the policy and command signing key; signs bundles, rule packs and commands at creation, while `jobs` signs assignments and dispatch grants; verifies extension packages against the trust list at install |
| `agent` | HTTPS: `/agent/v1`; server certificate from the Ricevanta PKI, pinned by agents; TLS terminated by the server itself; a client certificate is requested on every connection and required on every path except enrollment; renewal accepts an expired, unrevoked certificate within the grace period | Holds long-poll connections; public keys only; PostgreSQL credentials that read bundles and commands and insert only events (the tables listed in `design/events.md` section 3.6: event, quarantine, batch-ledger, export-log index, correlation inbox, device-stream and held-event tables, lineage edges, finding inboxes and ClickHouse raw rows), check-ins, command results, certificate and dispatch requests and minted ACME nonces, plus artifact parts into a staging prefix of the blob store and create-only export-log objects under their own prefix, which only `jobs` reads; commit-head updates and index inserts occur only through the narrow functions of `design/events.md` section 4.1 |
| `device` | HTTPS: Apple MDM, OMA-DM, SCEP and ACME for MDM payloads, network devices and third-party clients; publicly trusted or Ricevanta certificate; TLS terminated by the server itself | Stateless; its TLS key and per-role PostgreSQL credentials that read queued MDM commands and insert check-ins and results; SCEP envelopes and certificate requests go to `jobs` through request rows; writes minted ACME nonces |
| `radius` | UDP 1812 and 1813, RadSec TCP 2083 | EAP conversations and the authorization snapshot live in the replica's memory; its TLS keys and the X25519 sealing key that opens per-gateway secrets, under a role-scoped data key; read-only credentials on the snapshot and the `network` table; writes decision events, accounting rows and session-control outcomes (`design/radius.md`) |
| `jobs` | None; outbound calls to service connectors | Schedulers, exporters, connector calls and health probes, retention, directory sync, correlation, certificate issuance, APNs pushes; holds the master key, the issuing CA keys, the audit checkpoint and journal signing keys, the APNs push key, the signing key and the `service` client key it presents to connectors; one active leader per job through a lease row (`design/backend.md` section 3) |

Key custody follows exposure: the agent-facing `agent`, `device` and `radius` roles never receive the master key or any CA or signing key, hold their TLS keys under role-scoped data keys, run with per-role PostgreSQL credentials, and cannot write bundle, command, approval or certificate rows. Issuing CA keys and the audit checkpoint and journal signing keys are readable and unwrappable by `jobs` alone (`design/backend.md` section 6). Certificate and dispatch request rows are untrusted input: `jobs` verifies protocol proof and reconstructs authorization from protected records before issuance or a fresh dispatch grant (`design/pki.md` section 3, `specs/policy-envelope.md` section 7, BE-03).

The `agent` and `device` roles terminate TLS in the server process: a client certificate does not survive an ingress that terminates TLS, and the agent pins the Ricevanta root CA. Ingress controllers in front of them run in TLS passthrough mode or as layer-4 load balancers.

The console is a Vue 3 single-page application compiled into the binary and served from the same origin as `/api/v1`, so there is no cross-origin configuration.

### 3.2 Modules

Fifteen modules with schema ownership and an import-graph check (BE-04); contents, rules, library choices, coordination, pipelines and storage are in `design/backend.md`.

### 3.3 APIs

| API | Path | Consumers | Authentication | Format |
|---|---|---|---|---|
| Administration | `/api/v1`, including `/api/v1/extension-bridge/bindings` | Console, console extension bridge, CLI, GitOps, integrations | Browser session from OIDC, SAML or break-glass local login (BE-01), or a scoped API token; extension bridge dispatch also requires a live server-side mount binding (EXT-04) | JSON, described by a hand-written OpenAPI 3.1 document, validated in CI, that lives in `schemas/openapi/` from the first server build (v0.1.x) |
| Agent | `/agent/v1` | `ricevanta-agent` core | mTLS with the device identity certificate; enrollment token on `/agent/v1/enroll`; expired certificate accepted only on `/agent/v1/renew` within the grace period | JSON; NDJSON batches for events, zstd-compressed; private JWS renewal on `/agent/v1/renew` |
| Native device protocols | `/mdm/apple`, `/mdm/windows`, `/scep`, `/acme` | MDM clients, network equipment, third-party clients | Protocol-specific (`design/pki.md`, MDM-01) | Protocol-specific |
| Extension assets | `/ext/<id>/<version>/<package-sha256>/<component>/<asset-mount>/` on the `api` role | Console module iframes | No client credentials; serve only a live server-issued binding's frozen, hash-verified asset list with the candidate sandbox header and qualification gates of `design/extensions.md` sections 5.1 and 5.2 | Immutable mounted files from the blob store |
| Connector contracts | Outbound from `jobs` to each registered connector URL | `export-destination`, `ca-connector`, `notifier` and `enricher` connectors | mTLS with `service` certificates from the Ricevanta PKI, or a pinned certificate and scoped token (EXT-05) | JSON and NDJSON; required OpenAPI 3.1 contracts under `schemas/openapi/connectors/` are absent and block connector clients (`analysis.md` section 3) |

The administration API is the only write path; the console, its extension bridge and the CLI have no privileges the API does not expose. The bridge route fixes the extension identity in a server-side binding and invokes the same authorization and application handlers as the requested operation (`design/extensions.md` section 5.2). The console refreshes from `/api/v1/changes`, a Server-Sent Events stream of per-topic invalidations (BE-10). Errors are RFC 9457 problem details. GitOps is a directory of YAML resources (`apiVersion: ricevanta.io/v1*`; kinds such as `Policy`, `RulePack`, `DeviceGroup`, `Baseline`, `ExportDestination`, `Extension`) applied by `ricevanta apply` or by the server polling a Git repository. Apply is a declarative three-way diff against the stored state; protected actions become approval requests (BE-02).

### 3.4 Agent protocol

HTTPS with required mTLS, HTTP/2 preferred and HTTP/1.1 accepted, JSON bodies. No gRPC. The agent flows:

| Flow | Mechanism |
|---|---|
| Check-in | `POST /agent/v1/checkin` every 5 minutes (policy-tunable) with health, versions, the installed assignment envelope (`specs/policy-envelope.md` section 6) and inventory deltas; the check-in carries the journal report of `specs/policy-envelope.md` section 7, signed by the device identity key; the response carries the current assignment `(recovery_epoch, sequence)` and pending command count |
| Commands | `GET /agent/v1/commands` long-poll with a fresh `poll_nonce`; default hold 50 s, below a 60 s proxy idle timeout. The long poll also returns early with the current assignment `(recovery_epoch, sequence)` when the device's assignment changes, so the agent fetches policy without waiting for the next check-in. `NOTIFY` wakes the replica. Every signed command is delivered under a `jobs`-signed dispatch grant bound to that device, poll nonce and command, which is the freshness guard, while the agent's journal is the replay guard; longer holds can exceed the grant budget and trigger an immediate fresh poll. Receipt, ordering, execution and reconciliation follow `specs/policy-envelope.md` section 7; results are posted individually and signed by the device identity key |
| Policy | `GET /agent/v1/policy` with `If-None-Match`; the body is a signed bundle plus a signed per-device assignment binding device, scope, bundle hash and an organization-wide `(recovery_epoch, sequence)`; the agent refuses a bundle without a valid assignment for itself or with a pair not above the installed pair (`specs/policy-envelope.md` section 6) |
| Events | `POST /agent/v1/events` with NDJSON OCSF batches, zstd, a batch ID for idempotent retry, at most 5 MB per request; descriptor header, acknowledgement and retry rules in `design/events.md` section 2.4 |
| Blobs and artifacts | `GET /agent/v1/blobs/<sha256>` with HTTP range requests for installers named in a signed bundle or command (`design/mdm.md` section 4); `PUT /agent/v1/artifacts/<command_uid>/<part>` with zstd parts of at most 5 MB, a SHA-256 per part and a manifest signed by the device identity key, idempotent by command uid and part index, for triage packages and diagnostics bundles of at most 100 MiB; the `agent` role writes parts to a staging prefix of the blob store as untrusted input and `jobs` verifies the manifest before the package joins an investigation or device record (`specs/edr-response-actions.md` section 3.5, `design/mdm.md` section 8) |
| Threat intelligence | `GET /agent/v1/intel?since_epoch=<epoch>&since=<sequence>` returns a DSSE delta of the scope's indicator sets signed by the policy signing key, or a full snapshot when the base is missing; the check-in carries the installed intel epoch and sequence (`design/edr.md` section 8.3) |
| CRL and update | `GET /agent/v1/crl` for the issuing CA's CRL, fetched with the policy and cached; the core fetches `GET /agent/v1/update` and its package URL, then hands the opaque bytes to the updater over local IPC (`design/agent.md` section 8) |

Compatibility window: the server serves `/agent/v1` to agents from the current minor release and the two before it. Older agents are placed in update-only mode: they keep their cached policy, may fetch the release manifest and renew their certificate and nothing else, and the console flags them. The handler rules that keep this path cheap at 20,000 endpoints are in `design/backend.md`.

## 4. Keys and what they sign

| Key | Held by | Signs | Verified by |
|---|---|---|---|
| Root CA | Offline, custodian quorum (PKI-01); its certificate is what agents pin | Issuing CA certificates, journal signer certificate and recovery quorum manifest | Everything that trusts the PKI |
| Issuing CAs (device, server, network access) | `jobs` role: software key under envelope encryption, or PKCS#11 | Device identity, management and network-access certificates; server certificates for the `agent` and `device` roles; `service` certificates for `jobs` and service connectors; the policy signing certificate | Agents, MDM clients, VPN gateways, RADIUS, `jobs` and connectors |
| Policy and command signing key (Ed25519, one per organization) | `api` and `jobs` roles, under envelope encryption; its public key is carried in a certificate from the issuing CA | Policy bundles, device assignments, rule packs and their manifests, commands, dispatch grants, compliance statements, intel deltas and offline release objects, bound by `specs/policy-envelope.md` sections 6 and 7 | Agents, against the pinned root, the device issuing CA, the policy-signing subject and extended key usage, and a fresh CRL (`design/pki.md` section 4) |
| Journal signing key (Ed25519, one per organization) | `jobs` only, wrapped under its scoped key and certified by the offline root | Live authority and audit heads, prepare and commit records under `design/backend.md` section 6.1 | Every role against the independent current journal; journal protocol is an implementation blocker |
| Audit checkpoint key (Ed25519, one per organization) | `jobs` role only, wrapped under the `jobs`-scoped key that the master key does not unwrap (`design/backend.md` section 6) | Audit-log checkpoints binding the independent tail, in DSSE envelopes every hour and every 10,000 records (`design/events.md` section 6) | `jobs` verification against the independent live head and the newest checkpoint of every `audit: true` destination, `ricevanta audit verify --anchor`, auditors holding an export |
| Offline recovery custodian keys (Ed25519) | Separate offline media; default two signatures from three distinct keys, or a declared one-custodian single-administrator setup | Exact authority repairs and recovery transitions, including signer replacement, under the root-signed quorum manifest (`design/backend.md` section 6.1) | Every server role and agent against the manifest and distinct required signatures |
| Release signing keys (Ed25519) | Project maintainers, offline root and successor keys; self-builders use their own | Release manifests, which carry an expiry, and packages | `ricevanta-updater`; both public keys are compiled in, a manifest signed by the successor retires the root |
| Extension publisher keys (Ed25519) | Each publisher; the project's extension publisher key is held offline by maintainers | Extension manifests in DSSE envelopes; the project key also signs the extension index | `api` at install, against the operator's trust list; agents never verify them (EXT-02) |
| RADIUS sealing key (X25519) | `radius` role, under its role-scoped data key; public key known to `api` | Nothing; `api` seals gateway shared secrets and binding tokens to it | `radius` replicas open them |
| Platform code-signing identities | The company (PF-03) | Binaries, system extensions, the WHCP submission of the driver | Operating systems |

The shared policy and command signing key cannot sign escrow acknowledgements or retirement authorizations because it cannot establish that only `jobs` verified durable escrow before signing. Escrow-acknowledgement and retirement-authorization issuance and acceptance and recovery-route retirement remain blocked until independently reviewed contracts adopt a dedicated jobs-only key and certificate profile, its trust, custody, rotation, recovery and retained-key rules, and acknowledgement and fresh retirement-authorization rules (`design/mdm.md` section 12 and `specs/mdm-evidence-recovery.md`).

For `/agent/v1`, TLS protects the transport and signatures bind policy, commands and releases to keys the agent-facing roles never hold. Command dispatch also needs a fresh device/poll-bound grant so stored signed bytes cannot authorize a delayed expired action. A stolen `agent`-role TLS key cannot forge those artifacts. The native MDM channels have no second signature: Apple MDM and OMA-DM commands rest on the `device` role's TLS key, which is therefore short-lived, kept in the KMS or PKCS#11 device where one is configured, and revocable from the console. Enrollment, renewal and recovery are in `design/pki.md`; updates in `design/agent.md`.

The extension trust list (publisher fingerprints, allowed id prefixes, revocations) is server state owned by the `extensions` module. Agent-bound extension components reach agents only inside the signed policy bundle, so the agent's trust chain stays the organization's policy signing key and the per-device assignment (`design/extensions.md` section 2).

## 5. Deployment

| Shape | Composition | Target |
|---|---|---|
| Docker Compose | `ricevanta-server` (all roles), PostgreSQL, optional ClickHouse profile, local blob volume | Evaluation and small installations, 2,000 endpoints (EV-01) |
| Helm | Deployments per role group: `api` behind an ordinary ingress; `agent` and `device` behind an ingress in TLS passthrough mode or a layer-4 load balancer; `jobs` with no service; `radius` behind two `LoadBalancer` services, one UDP for 1812 and 1813 and one TCP for RadSec, because mixed-protocol services are not supported on every provider, each with `externalTrafficPolicy: Local` and client-IP affinity, and the external load balancer configured to hash on client IP as well, so the gateway's source address and EAP conversation stay on one replica; PostgreSQL external or through the CloudNativePG operator for evaluation, since the Bitnami images are not maintained for free use (verify); ClickHouse external or as a single-replica StatefulSet; S3-compatible blob store | 20,000 endpoints (EV-01) |

High availability: `api`, `agent` and `device` are stateless and run two or more replicas; `jobs` runs replicas with per-job leader election; `radius` replicas each hold their own EAP state, and gateways are configured with a primary and a secondary server; PostgreSQL high availability is the operator's choice. Upgrades run `ricevanta-server migrate` before the new version serves; migrations are forward-only and compatible with the previous server version for a rolling upgrade.

Server container images are built for `linux/amd64` and `linux/arm64`.

Observability: Prometheus metrics on `/metrics`, structured JSON logs, health and readiness endpoints, optional OpenTelemetry traces. Server security events enter the event pipeline; administrative audit records live in the `audit` schema and are exported as OCSF (`design/events.md` section 6).

## 6. Repository layout

```
ricevanta/
├── agent/        Rust workspace: crates (core, updater, os-macos, os-windows, os-linux, scan, ext, session, nmhost), bpf/ (dual MIT/GPL), app bundles, packaging
├── driver/       Windows kernel driver (C), WDK build, HLK test configuration
├── browser/      Browser extension (TypeScript, WebExtensions) built per engine family: chromium (Manifest V3), gecko, webkit with the Safari handler sources
├── server/       Go module: cmd/ricevanta-server, cmd/ricevanta, internal/<module>
├── console/      Vue 3 application, built into server/ at release
├── extensions/   Extension SDK (guest bindings, console bridge library, connector contract test kit, `ricevanta ext` packaging and signing) and first-party extensions, including the browser adapters
├── schemas/      Policy envelope JSON Schema, CEL profile, OCSF profile and extension, OpenAPI; extension/ (manifest and adapter JSON Schemas), wit/, console-bridge/, openapi/connectors/
├── rulepacks/    First-party rule packs with license records
├── deploy/       Docker Compose, Helm chart, examples
├── tests/        Capability matrix acceptance tests, integration and end-to-end tests, footprint benchmark
├── docs/         Design documents
└── instructions/ How to work
```

One repository, one version number per release for server, console, agent, browser extension and first-party extensions (SH-04). Third-party extensions version on their own against interface versions (EXT-07). Language-specific instructions are added when the first directory is created (`instructions/workflow.md`).

## 7. Cross-cutting rules

- Versioning: SemVer for the product; `/api/v1` and `/agent/v1` change additively within a major; the policy envelope is `apiVersion: ricevanta.io/v1alpha1` throughout v0.x and `v1` from v1.0.0. The v1.0.0 server migration relabels stored resources; agents receive compiled bundles whose format is versioned with `/agent/v1`, so the envelope label never reaches them. Extension interfaces carry their own versions (`ext.ricevanta.io/<kind or contract>/v1`, WIT package versions, the console bridge schema version, connector contract versions), change additively within a major and are the compatibility key for extensions, not the product version (EXT-07).
- Failure behaviour: every policy declares its fail mode for each enforcement point (`design/agent.md`); every unsupported capability is reported, never silently skipped.
- Privacy: classification runs on the endpoint; only the evidence DLP-02 allows leaves the device.
- Configuration: the server reads environment variables and one YAML file; the agent reads the enrollment configuration (`design/pki.md`) plus server-delivered signed policy. Ricevanta rejects unsigned local configuration changes and requires authorization on its own uninstall paths; OS and administrator escape paths follow the limits in `design/agent.md` section 9.
- Tamper resistance against a local administrator is prevention only where the OS provides it and reporting elsewhere; the preconditions per OS are in `design/agent.md` and `platform-support.md`.
- Time: the server is the clock of record; agent events carry monotonic sequence numbers and the agent's clock, and the server records receipt time.
- Internationalization: console strings through `vue-i18n` from the first component (`project.md`).
- Platform support: `platform-support.md` owns maintained-release eligibility and required configuration. `specs/platform-qualification.md` defines whole-product workflows, negative cases and evidence; unsupported configurations and unresolved required mechanisms are distinct states.

## 8. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one server binary and one agent package keep deployment and upgrades simple for self-hosters, the shape Fleet, Velociraptor, Loki and Teleport scale with; enforcement points that hold their own rules keep decision latency off the IPC path; signed policy, commands and releases with keys the agent-facing roles never hold make the TLS certificate, the ingress and the download channel non-critical for integrity; per-module schemas keep the monolith splittable later; extensions add browsers, detectors, UI and integrations while no third-party code runs in the agent core, the server or the sensors (`design/extensions.md`).

Trade-offs: JSON over HTTPS costs more bytes than gRPC and Protobuf for telemetry, paid back by one serialization format (OCSF JSON) and one API stack. Long-poll holds one connection per agent on the `agent` role, which is cheap in Go. TLS passthrough for the `agent` and `device` roles removes ingress-level TLS management for those endpoints. WHCP certification of the driver needs an HLK lab and adds weeks to every driver release. Server-side extension code runs as connector processes the operator deploys, because no Go WebAssembly runtime offers WASIp2 with fuel metering without cgo (EXT-05).

Dependencies: listed per domain in `design/agent.md`, `design/backend.md` and `design/pki.md`, plus CloudNativePG, the Prometheus client and the OpenTelemetry SDK for deployment and observability; every one has a row in `licensing.md`.

Limits: Kubernetes clusters without a UDP-capable load balancer need an external one for RADIUS. The macOS extensions need the company's entitlements for production (PF-03). The agent compatibility window means a server more than two minor releases ahead stops serving old agents except for updates. Community adapters are not qualified (`design/extensions.md` section 7.3).

Alternatives considered: recorded as the Rejected line of each decision this document introduces (SH-04, AG-03, AG-04, BE-03, BE-05, BE-07, EXT-01 to EXT-07) and of the domain designs' decisions.
