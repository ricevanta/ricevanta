# Decisions

Register of decisions in force, grouped by domain. IDs are domain prefix plus sequence (`SH-01`, `DLP-02`); they are stable and never reused. Entries are short and current; design detail lives in the linked design document. Format and rules: `instructions/documentation.md`. C-numbers refer to `analysis.md`.

## Shared (SH)

### SH-01. Full support for every feature at v1.0.0
Decision: every blueprint feature ships with full support, including blocking enforcement, at v1.0.0 on the v1.0.0 targets. Reduced behaviour (alert-only, deferred) is permitted only inside a v0.x release and must name the release that completes it. The only exceptions are the capabilities listed under "Deferred to v2.0.0" in `platform-support.md`, which cannot be tested without a company account.
Why: the blueprint states v1.0.0 is not an MVP; untestable work must not block the release on vendor timelines.
Rejected: an MVP v1.0.0 with alert-only DLP on Windows and no browser extension.
Detail: `platform-support.md`.

### SH-02. Policy envelope, CEL profile and OCSF profile defined first
Decision: the policy envelope, a CEL subset profile and the OCSF profile are defined in v0.1.x. Both CEL runtimes (Go on the server, Rust on the agent) pass the `cel-spec` conformance suite for the profile in CI; policies outside the profile are refused.
Why: EDR and DLP ship before the rule adapters, and two CEL runtimes can diverge (C8, C11).
Rejected: ad hoc per-module formats until v0.8.x; forces a migration.
Detail: `specs/policy-envelope.md`, `specs/cel-profile.md`, `specs/ocsf-profile.md`.

### SH-03. Single organization per server
Decision: v1.0.0 serves one organization per server. Tables carry an organization ID so multi-tenancy is a later addition, not a migration.
Why: no requirement for multi-tenancy at v1.0.0.
Rejected: multi-tenancy at v1.0.0, which no requirement asks for and which would add a tenant check to every table and query.
Detail: `architecture.md` and `design/backend.md`.

### SH-04. One repository, one release version
Decision: one repository with `agent/`, `driver/`, `browser/`, `server/`, `console/`, `extensions/`, `schemas/`, `rulepacks/`, `deploy/`, `tests/`, `docs/` and `instructions/`. Server, console, agent, browser extension and the first-party extensions in `extensions/` share one SemVer version per release; third-party extensions carry their own versions and declare the interface versions they need (EXT-07).
Why: cross-component changes (policy envelope, agent API, extension interfaces) land in one change and one test run.
Rejected: a separate `integrations/` directory for rule and destination adapters, since they are server modules and live with the server; a separate repository for first-party extensions, which would test the extension interfaces apart from their first users.
Detail: `architecture.md` section 6.

### SH-05. Shared DSSE envelope profile
Decision: one standard-library-only Go primitive signs and verifies the Ricevanta DSSE profile with Ed25519, a closed payload-type list, strict envelope fields, standard padded base64 and exactly one signature. Signers emit canonical bytes; envelope hashes bind exact received bytes, and certificate fingerprints remain hints without authority.
Why: policy and extension consumers need identical Go and Rust byte contracts, and dispatch grants must bind the exact command envelope delivered to the agent.
Rejected: per-module parsers, hashes of re-encoded envelopes and accept-any-signature recovery checks, which permit parser disagreements, byte substitution or quorum weakening.
Detail: [DSSE envelope spec](specs/dsse-envelope.md) and [implementation plan](plans/dsse-envelope.md).

## Platform (PF)

### PF-01. v1.0.0 targets
Decision: macOS ARM64, Windows x64, Linux x64. Windows ARM64, Linux ARM64 and macOS x64 follow in v1.x; the design stays architecture-independent.
Why: largest installed bases; separate driver signing and CI hardware for the others.
Rejected: all six targets at v1.0.0, which needs separate driver signing and CI hardware per architecture.
Detail: `platform-support.md`.

### PF-02. Modern OS support and qualification
Decision: qualify the current and previous stable macOS major releases on Apple silicon, Microsoft-maintained Windows 11 x64 Pro, Enterprise and Education releases for their edition and servicing channel, and maintained Linux releases meeting the distribution and runtime-capability rules in `platform-support.md`. OS eligibility does not establish support: each exact configuration must pass the platform qualification specification, including required blocking behavior.
Why: maintained releases reduce compatibility branches; Linux enforcement depends on active hooks, not the version string alone (C3, C12).
Rejected: fixed OS floors with no lifecycle rule; telemetry-only results labeled as full support.
Detail: `platform-support.md`.

### PF-03. Vendor programs held by the project
Decision: development and testing on personal accounts; a company registered before sensor distribution holds the Apple team, the MDM Vendor CSR Signing Certificate, Partner Center account, EV certificate and the HLK lab for WHCP certification of the driver; all production binaries are signed under it and the production push-certificate signing service runs under its vendor certificate.
Why: entitlements and driver signatures bind to one organization (C1), and WHCP submissions need a Partner Center account and HLK results (AG-01).
Rejected: filing entitlements and driver submissions under a personal account, which cannot be transferred to the company.
Detail: `project.md`.

### PF-04. Platform qualification is a release gate
Decision: a finite required-unit manifest covers every eligible OS release and every blueprint feature across the declared configuration profiles; whole-product workflows, negative security cases, offline recovery, updates and resource budgets also pass. An unresolved required enforcement mechanism blocks release and cannot become an unsupported-feature exception.
Why: a build or a notification does not prove complete endpoint protection, and Linux is many platforms (C12).
Rejected: one smoke test per OS; support inferred from vendor API availability.
Detail: `specs/platform-qualification.md`.

## Agent (AG)

### AG-01. Windows kernel component
Decision: a kernel component with a file-system minifilter, process-creation callbacks that deny creation, and a WFP callout where user-mode WFP is insufficient; ETW stays the telemetry source and the driver carries authorization decisions and synchronous events only. Written in C, since `windows-drivers-rs` describes itself as not production-ready and lacks minifilter and WFP bindings (verify), with tamper resistance through driver self-protection (`ObRegisterCallbacks`). The production driver is WHCP-certified through HLK testing; attestation and preproduction signing serve development only.
Why: ETW cannot block (C3); Microsoft labels attestation signing testing-only and the Windows Driver Policy admits only WHCP-signed drivers (verify that attestation-signed drivers are blocked under enforcement).
Rejected: alert-only DLP on Windows (SH-01); attestation-signed production drivers.
Detail: `design/agent.md` and `design/edr.md`.

### AG-02. Scanner helper and memory metric
Decision: content inspection runs in a separate helper process started on demand with a memory cap and stopped when idle; inventory SQL requires a separate snapshot-only query process whose native containment and hard bounds remain implementation blockers (`specs/rule-adapters.md` section 8.1). Active-helper accounting includes the query worker, which has zero idle allocation and a 64 MiB total cap including its 32 MiB SQLite heap. Idle RAM is the sum over all resident Ricevanta user-mode processes, including the Endpoint Security extension and session helpers, of the per-OS private footprint metric (`phys_footprint`, private working set, proportional set size); kernel pool and BPF maps are reported separately.
Why: the 80 MB target cannot hold with rules, models and parsers resident (C4).
Rejected: inspection inside the core process, which would keep rules, models and parsers resident.
Detail: `design/agent.md` section 6.

### AG-03. Process topology and local IPC
Decision: one core service per endpoint owns the server connection, identity, policy, events and domain logic. Sensors and enforcement points (macOS Endpoint Security and Network Extension system extensions, the Windows driver, Linux eBPF programs), the updater, the scanner helper, the required on-demand inventory SQL worker, the extension helper (EXT-03), one session helper per graphical session and the browser relays never talk to the server. Local IPC is XPC on macOS, Unix domain sockets on Linux and named pipes on Windows, with peer identity checks and `postcard`-serialized messages; the browser extension uses the native messaging each browser provides; the driver uses its communication port, and the core delivers update bytes to the updater over authenticated local IPC without giving the updater device-identity access.
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
Decision: the core compiles one global conflict plan into incremental enforcement-point rules, and a local candidate becomes final only when unresolved core policies and exceptions cannot change the verdict or actions. Other decisions reach the core and the scanner or extension helper within the per-policy deadline, using the declared fail mode, `open` by default with an audit event or `closed`, with repeated scanner crashes forcing `closed`. Authorization rules are never throttled or muted; Ricevanta's own processes retain the policy self-exemption of `design/agent.md` section 3.
Why: proven point-local finality avoids IPC latency, and deadline-bound core evaluation preserves one global verdict when unresolved policies can change it (blueprint section 7).
Rejected: routing every decision through the core; adds IPC latency to every file and process operation.
Detail: `design/agent.md` section 3; the rule-only subset is in `specs/policy-envelope.md` section 2.2.

### AG-07. Signed releases and staged updates
Decision: release manifests and packages are signed with offline Ed25519 release keys, a root and a successor, whose public keys are compiled into the updater; self-builders substitute their own. The core fetches the manifest and package over its authenticated transport and stages them locally; a separate `ricevanta-updater` service with no network or device-identity access verifies the release signature, the manifest expiry and the OS code signature, refuses lower manifest versions, applies through the OS package mechanism, and restores the previous package unless the core reports healthy locally within a window. Rollout is staged by device group and percentage; a broken download path requires rollback to the retained healthy package or administrator repair with a signed OS package.
Why: the download channel and the server's blob store are untrusted for code (blueprint section 8), and a broken core cannot roll itself back.
Rejected: trusting the server TLS connection alone for updates; the core applying its own updates.
Detail: `design/agent.md` section 8.

### AG-08. Self-watchdog and hot-source control
Decision: the agent meters CPU per OS thread and memory per owned data structure for each unit of work (telemetry source, rule pack, scan, extension module) against budgets in the policy bundle, throttles and then disables a unit that exceeds its budget, and reports the degradation. Notification telemetry rate-limits per path and per process and mutes busy sources at the enforcement point with the mute reported; authorization and permission rules are exempt, a throttled content check takes the policy fail mode, and repeated mutes attributed to one user are a detection.
Why: no comparable EDR and DLP agent publishes a footprint near the 80 MB target (blueprint section 7), and the documented failures of osquery and Sysmon trace to unbounded work on busy paths (verify).
Rejected: a fixed process memory cap that restarts the agent, which loses enforcement; muting authorization rules, which would let a user flood a path to get it unprotected.
Detail: `design/agent.md` section 7.

### AG-09. Footprint telemetry, incremental rules and a performance gate
Decision: every agent process ships its own CPU, memory, descriptor and event-rate samples as OCSF events; policy bundle updates install only the changed rules into enforcement points; every agent build runs the footprint benchmark in CI and fails on regression against the last release, on hosted runners for the core and helpers and on self-hosted machines for the sensors.
Why: targets are measured, not assumed (blueprint section 7), and a reload that reinstalls everything is the failure Sysmon shipped (verify).
Rejected: measuring only in the v0.9.x performance milestone; regressions would accumulate unnoticed for eight releases.
Detail: `design/agent.md` section 7.

### AG-10. Spool format library
Decision: the first Rust slice is `ricevanta-spool` in `agent/crates/spool`, a file-free v1 byte codec with borrowed prefix recovery, strict header and sequence checks, a 1 MiB payload ceiling, shared fixtures and stable deterministic mutation tests.
Why: exact bytes and recovery errors can be tested on all three target OS/architecture pairs without assuming native durable sync or a complete spool manager.
Rejected: a file-owning writer before native crash ordering is qualified; silent truncation of unsupported headers or checksum-valid sequence gaps, which hides incompatible data or stream defects.
Detail: [spool format spec](specs/agent-spool-format.md) and [implementation plan](plans/agent-spool-format.md).

### AG-11. Sealed batch writer
Decision: `ricevanta-batch` in `agent/crates/batch` converts one complete spool segment into the EV-08 header and descriptor plus one EV-09 zstd frame, using the pinned zstd binding, NDJSON-inclusive agent limits and live Go decoder conformance tests.
Why: the second Rust slice needs exact server-compatible bytes without assuming native file durability, upload or retry behavior.
Rejected: sealing recovered prefixes, record-limit overshoot and codec-only round trips, which can hide lost records, oversized bodies or cross-language disagreement.
Detail: [batch writer spec](specs/agent-batch-writer.md) and [implementation plan](plans/agent-batch-writer.md).

## MDM

### MDM-01. Native MDM servers
Decision: an Apple MDM server (MDM protocol, DDM, APNs push) and a Windows OMA-DM server (MS-MDE2 discovery, Provisioning CSP) inside the Go monolith. The agent remains the primary management path on Windows and Linux; OMA-DM carries enrollment, Windows settings that a CSP exposes (MDM-03), Windows Update policies and native wipe. Apple enrollment is manual and token-based at v1.0.0; profile-based Device Enrollment supervises Macs on macOS 11 and later.
Why: profiles, DDM, OS updates, lock, wipe and FileVault escrow only work over Apple's MDM channel (C2).
Rejected: agent-only management; Apple features unreachable.
Detail: `design/mdm.md`.

### MDM-02. Device lifecycle
Decision: devices move through `pending`, `active`, `suspended` and `retired`; suspension keeps the installed bundle, stops new assignments, holds network-access certificates and permits only the documented commands, resume and retirement. Retirement is terminal and BE-02-protected, queues removal for every enrolled channel and revokes network-access and `user_device` certificates at once. Each channel keeps only removal access until its own cleanup completes or 24 hours pass; agent completion includes browser-policy cleanup, and a timed-out channel keeps the device "retired, removal pending" with local cleanup paths and no uid reuse.
Why: a lost or investigated device must keep its protections and stay reachable for lock and wipe, while a retired one must lose its network credentials at once but keep the identity that carries its removal commands until they are delivered.
Rejected: suspension by revoking the identity certificate, which cuts the lock and wipe path; revoking the identity certificate at the retirement transition, which cuts delivery of the uninstall, `RemoveProfile` and `Unenroll` commands; a wipe that also retires the record before its result arrives.
Detail: `design/mdm.md` section 1.

### MDM-03. Windows management channels
Decision: Windows browser-adapter policy values use the agent at registered vendor targets with exclusive ownership and journaled removal (EXT-06); every other setting exposed by a CSP goes over OMA-DM, and remaining settings use the agent. The agent writes no `SOFTWARE\Policies` values outside that browser exception and enrolls the device in OMA-DM with `RegisterDeviceWithManagement` and a single-use token. The agent starts OMA-DM sessions when commands are queued, so WNS push and Entra ID are not used.
Why: Windows applies, tracks and removes CSP policy as MDM policy with its own Group Policy precedence, and WNS needs a Microsoft Store app registration.
Rejected: general agent writes to policy registry keys, which bypass CSP ownership and cleanup; WNS push, a Microsoft-hosted dependency.
Detail: `design/mdm.md` sections 2 and 10.

### MDM-04. Software distribution and integrity
Decision: installers live in the blob store, addressed by the SHA-256 the signed bundle or command carries, and are fetched with range requests. Before install the agent checks the hash and the format's own signature: Developer ID Installer for `pkg`, Authenticode for `msi` and `exe`, the MSIX package signature, `rpmkeys --checksig` for `rpm`, and signed repositories for apt, dnf, zypper and flatpak. Detection rules make installs idempotent. Publishing a `SoftwarePackage` is a protected action whose approval binds the package to its allowed device groups, and the compiler refuses a `software` item whose policy scope reaches outside them; signed software commands are protected actions.
Why: the blob store is not a trust anchor (blueprint section 8), and `deb` files and dnf local installs carry or check no signature by default.
Rejected: trusting the TLS download alone; Munki-style client manifests that duplicate the policy bundle.
Detail: `design/mdm.md` section 4.

### MDM-05. OS update management
Decision: on macOS only the DDM declarations `softwareupdate.settings` and `softwareupdate.enforcement.specific` with their status items; on Windows the Policy CSP `Update` area over OMA-DM, with the agent reporting Windows Update state and triggering urgent installs; on Linux the agent runs the package manager in maintenance windows and owns the reboot policy. Windows are evaluated in device-local time by the agent.
Why: Apple deprecated the legacy update commands and payload in macOS 26 and removed them in macOS 27 (C2); Linux has no native management channel.
Rejected: legacy Apple update commands as a fallback; leaving the distributions' automatic-update timers on beside the agent.
Detail: `design/mdm.md` section 6.

### MDM-06. Compliance definition and consumers
Decision: compliance assesses current approved desired baseline revisions using matching evidence, the server conditions and fixed per-revision grace episodes; unknown evidence is noncompliant and gets no grace. `jobs` stores and signs the state for RADIUS, console and CEL consumers, while the agent combines the matching required-set statement with local results. Agent evidence requires its signed report counter and installed assignment; Apple queries require CMS origin verification and current-request consumption, unsolicited status freshness remains a release blocker, and unsigned OMA-DM results trust `device` unless the item is agent-authoritative.
Why: RADIUS, CEL conditions and the console need one answer; freshness, revocation and lifecycle are server facts, and origin, revision and freshness verification prevent an exposed role from reusing an old pass to grant compliance.
Rejected: compliance computed on the agent alone; an unsigned compliance flag in the check-in response.
Detail: `specs/baseline.md` section 4.

### MDM-07. Lock and wipe mechanisms
Decision: macOS uses Apple MDM `DeviceLock` and `EraseDevice`; Windows wipes through OMA-DM `RemoteWipe/doWipeProtected`, and Linux wipes with `cryptsetup luksErase`. Windows and Linux lock by retaining exactly one fresh acknowledged recovery route, deleting every other protector or slot of the BitLocker OS volume or managed LUKS2 root and restarting. Acknowledgement and retirement-authorization issuance and acceptance and recovery-route retirement are implementation-blocked until independently reviewed contracts adopt a dedicated jobs-only key and certificate profile, its trust, custody, rotation, recovery and retained-key rules, and acknowledgement and fresh per-deletion retirement-authorization rules bound to the current epoch, transaction and challenge; Windows and Linux lock is unavailable until then.
Why: Windows 11 has no desktop remote-lock CSP, and Linux has no native wipe; disk encryption and complete route removal prevent current alternate keys from unlocking after restart; they cannot retract a previously copied volume key or header backup.
Rejected: disabling local accounts, which a local administrator reverses; session lock alone, which a restart defeats.
Detail: `design/mdm.md` section 8.

### MDM-08. Push-certificate signing service
Decision: the project operates `mdm-push.ricevanta.io`, which signs each server's push certificate request with the project's MDM Vendor CSR Signing Certificate after email verification. It never receives the push key. Servers renew 60 days ahead and activate a renewal only when its topic matches. `ricevanta mdm sign-push-request` signs with an operator's own vendor certificate, so the project step can be removed.
Why: every self-hosted Apple MDM needs a vendor-signed push request (C1), and a signing outage must not stop push.
Rejected: shipping the vendor key to self-hosters, which Apple's terms and key custody forbid; depending on a third-party signer.
Detail: `design/mdm.md` section 9.4.

### MDM-09. Baseline authoring
Decision: first-party baselines ship as the signed `content` extension `io.ricevanta.baselines`, written from OS vendor documentation and reusable open sources with public control identifiers, including CIS Benchmark numbers but never CIS text. Operators author baselines and import XCCDF benchmarks they hold with a report of untranslated rules. Weakening deployed required compliance is protected even for read-only checks and report policies, with approval bound to exact before and after revisions and affected devices.
Why: CIS Benchmarks are not redistributable, and regulated customers need control mappings.
Rejected: bundling CIS content; OVAL as the native format.
Detail: `specs/baseline.md` section 5.

### MDM-10. MDM authoring schemas and decoded validation
Decision: Baseline, SoftwarePackage and DeviceGroup use closed JSON Schema 2020-12 authoring contracts and a standard-library Go validator, with shared positive and negative fixtures enforcing structural and semantic agreement. Every apply-capable Baseline kind carries an explicit protected-publication classification; validation does not authorize execution.
Why: the missing MDM resource schemas block resource validation, and privileged configuration needs a classification that author input cannot disable.
Rejected: a Go JSON Schema dependency that still needs custom semantic checks; unconstrained settings and author-controlled protection flags.
Detail: [MDM resource schemas](specs/mdm-resource-schemas.md) and [implementation plan](plans/mdm-resource-schemas.md).

## EDR

### EDR-01. Sigma evaluation placement
Decision: single-event Sigma rules evaluate on the agent (Rust) over process, file, network, registry, Windows Event Log and Linux syscall logsources; correlation rules evaluate on the server (Go). Windows Event Log and PowerShell script-block collection are required telemetry, and Falco rules map through a second logsource mapping. Unsupported logsources or modifiers are listed in the console with the reason.
Why: Sigma targets Sysmon and Windows Event Log fields, not OCSF; offline detection is required (C7).
Rejected: server-only evaluation.
Detail: `specs/ocsf-profile.md` section 5.

### EDR-02. Telemetry sources follow the compiled rule set
Decision: each OS collects from the source list in `design/edr.md` section 1.2: Endpoint Security and the Network Extension on macOS; ETW, Event Log subscriptions, the USN journal and the driver on Windows; eBPF programs, fanotify and the systemd journal on Linux. Collection runs in three tiers: a base set that is always on, sources that a bundle's rules demand, and everything under the full profile. The compiler decides the collection set per scope, and upload stays under EV-01.
Why: idle cost must follow what consumes the data (blueprint section 7), and Sigma rules need sources beyond the base set (C7).
Rejected: every source always on, which spends CPU and memory on events no rule reads; Sysmon or the Linux audit framework as sources, which means a second product to deploy or changes to the host's audit rules.
Detail: `design/edr.md` section 1.

### EDR-03. Correlation over uploaded rule matches
Decision: Sigma correlation, all seven types of specification 2.1.0, runs in `detection` on `jobs` over uploaded base-rule matches, with tags, references, shards, group state and findings keyed by immutable `{pack, version, pack_digest, rule_key}`. Each shard has one lease, bounded in-memory window state and PostgreSQL checkpoints, while stored matches support recomputation of late uploads. DLP cross-device counters use the same engine.
Why: correlation must work under the default telemetry profile and across devices (C9, EV-01).
Rejected: correlation over raw events, which needs the full profile fleet-wide; server-side re-evaluation of base rules, which needs a second evaluator.
Detail: `design/edr.md` section 5.2.

### EDR-04. Response catalogue, isolation mechanisms and authorization
Decision: response actions use the signed catalogue and per-action journal contracts of `specs/edr-response-actions.md`, binding validation and each side effect to the same target object; macOS termination and script containment and unresolved quarantine transactions remain required release blockers. Blocks and bans live in policy, while host isolation uses macOS Network Extension default-drop rules, Windows persistent and boot-time WFP filters and Linux root-cgroup BPF, with an address allow list and DNS only when explicitly listed. Un-isolation, quarantine restore, interim-ban retirement and scripts are protected actions, and offline isolation release requires a signed device-bound object and the device's nonce.
Why: a delayed command must not hit a reused pid or a replaced file, a ban must reach re-imaged and offline devices, and the actions that reduce containment or run arbitrary code need separation of duties (BE-02).
Rejected: per-device block commands, which offline or re-imaged devices miss; allowing DNS during isolation, which is a tunnel; immediate deletion instead of quarantine, which leaves no restore after a false positive.
Detail: `design/edr.md` section 7, `specs/edr-response-actions.md`.

### EDR-05. Threat intelligence ingestion and delivery
Decision: the `detection` module ingests TAXII 2.1 collections, STIX 2.1 bundles, MISP feeds, plain indicator lists and enricher connectors. Agents receive indicator sets as DSSE-signed deltas from `/agent/v1/intel`, signed by the policy signing key, within a memory cap per scope. They match hashes, addresses, domains and browser URLs locally, and the server matches new indicators retroactively. No indicator feed is bundled; ATT&CK data is.
Why: offline detection and blocking need indicators on the endpoint, and hourly indicator churn cannot ride in the policy bundle.
Rejected: indicator sets inside the bundle, which recompile and re-download every bundle hourly; bundling community feeds, whose terms forbid it or state none.
Detail: `design/edr.md` section 8.

## DLP

### DLP-01. Browser extension and session helpers
Decision: every browser gate must bind one verdict to exact bytes and one transfer; Safari exact-transfer mediation and established-session mediation for Chrome without Chrome Enterprise Core on every required OS and Edge on Linux remain required release blockers (`design/dlp.md` section 6.5). Clipboard blocking remains a release blocker on every required session until the native mechanism mediates the first and every later read; delayed or promised rendering and watcher-based re-ownership do not establish that contract. Cloud sync clients remain part of the file channel.
Why: blocking requires mediation before every transfer or clipboard read, including later consumers, rather than a notification or a reusable destination allowance (C5).
Rejected: TLS interception, which contradicts the privacy principle and breaks pinning; clearing or replacing the clipboard after access; treating delayed or promised rendering as a per-read authorization hook; a tab-wide or timed Safari allowance.
Detail: `platform-support.md`, `design/agent.md` section 3, `design/extensions.md` section 7, `specs/platform-qualification.md`.

### DLP-02. Evidence
Decision: a match stores the content hash, rule ID, byte offsets and a redacted snippet of at most 200 characters; the snippet can be disabled by policy. Raw user content is never stored; script content is exported under `specs/ocsf-profile.md` section 3 after the secret and identifier detectors redact it.
Why: blueprint section 8 limits raw content collection; investigations need evidence.
Rejected: storing the matched content for review, which blueprint section 8 forbids.
Detail: `specs/ocsf-profile.md` section 3.

### DLP-03. Classification categories and references
Decision: classification categories carry an optional free-text `reference` that an organization fills for its own compliance mapping; Ricevanta ships none. The first packs implement Vietnamese personal identifiers and financial data by their formats (`specs/dlp-detectors.md`), with bank-specific templates after v1.0.0. Reports group findings by category and channel.
Why: blueprint section 3.3 names Vietnamese identifiers first; what an identifier means legally is the customer's compliance work, not the product's.
Rejected: regulation and article fields with first-party legal values, which tie releases to legal interpretation the project cannot own.
Detail: `design/dlp.md` section 5.

### DLP-04. Scanner type detection and extraction
Decision: `ricevanta-scan` detects file types by magic numbers and the Magika model on the pure-Rust `tract` runtime (pending confirmation of the model weights' license; in-project heuristics classify text types until the model ships), never by extension, and extracts text with PDFium, in-project OOXML, ODF and legacy Office readers on `zip`, `quick-xml` and `cfb`, `calamine`, `mail-parser`, `msg_parser`, Tesseract with Vietnamese and English models, and permissively licensed archive readers. OCR covers every rendered PDF page regardless of its text layer, and skipped work returns incomplete coverage; RAR is not extracted. Cached matches bind the canonical scan plan, selected artifacts and configuration, extension grant generations and recovery epoch, and never substitute for current policy evaluation (`design/dlp.md` sections 2.4 and 2.6).
Why: Apache Tika cannot run on the endpoint (C4), and these permissively licensed libraries cover the formats, including Vietnamese text and scanned documents.
Rejected: MuPDF (AGPL-3.0); UnRAR (license forbids RAR-compatible archivers, not open source); `ocrs` (CC-BY-SA-4.0 weights, no Vietnamese model); ONNX Runtime for Magika (a C++ runtime in the scanner).
Detail: `design/dlp.md` section 2.

### DLP-05. Content fingerprints
Decision: the server fingerprints registered documents with the same `ricevanta-scan` binary into a signed `fingerprint` rule pack: BLAKE3 over bytes and normalized text, TLSH over normalized text (match at distance 50 or less), and winnowed 50-character shingles (window 30) with a default partial-match threshold of 12 shared fingerprints. Agents match inside the scanner against an index bounded at 64 MB per scope.
Why: TLSH answers whole-document similarity but not excerpts, and one binary on both sides keeps normalization identical.
Rejected: ssdeep (GPL-2.0); TLSH alone; computing fingerprints on agents from pushed documents, which would send confidential documents to every endpoint.
Detail: `design/dlp.md` section 4.

### DLP-06. Classification and confidence
Decision: recognizers pair a low-scored bare pattern with a high-scored labelled pattern and a validator from a closed catalogue whose tables ship in packs. Per-object category confidence uses noisy-OR over distinct values, and the label is the highest category at its threshold raised by direct inheritance and the durable sensitivity floor of `design/lineage.md` section 3. Busy-process compaction preserves the maximum source floor and marks pressure-derived inference; reduced provenance confidence cannot lower that floor.
Why: Vietnamese identifiers without check digits need corroboration, and inheritance classifies content the scanner cannot read, such as encrypted archives.
Rejected: one fixed score per recognizer; named-entity models on the endpoint; classification from the scan alone.
Detail: `design/dlp.md` section 5 and `specs/dlp-detectors.md`.

### DLP-07. Hold point for newly written content
Decision: a file verdict must bind an immutable byte snapshot, and no process may release different bytes through a pre-existing descriptor, mapping or concurrent mutation. Newly typed bytes must be held before they reach removable media or a network share. The current close-after-write and next-open design does not meet either condition, so file-channel completion is a v1.0.0 release blocker until each OS has a staging or read and mapping mediation design that passes the qualification cases.
Why: an open made before the pending mark and a writable mapping can bypass a later open hold, while remediation after a remote or removable write is not prevention.
Rejected: close-after-write plus next-open as a complete gate; lineage alone for newly typed content; post-write deletion; a Windows-only staging path that leaves macOS and Linux incomplete.
Detail: `design/dlp.md` section 6.4.

### DLP-08. Warn interaction
Decision: `warn` opens a `ricevanta-session` dialog with an optional or required justification and a 60 s timeout that cancels. Hold points that can wait (a connector within its `expires_at`, the content-script gate) hold the transfer. File and clipboard channels deny, then grant a 60 s one-time allowance for the retried operation. Without a reachable session, `unattended` decides, `block` by default.
Why: OS authorization deadlines cannot wait for a person, and a notification is not a choice.
Rejected: warn as allow plus notification on file channels; the browser's own warn dialog alone, which captures no justification.
Detail: `design/dlp.md` section 6.3.

## Events (EV)

### EV-01. Telemetry default and scale targets
Decision: the default profile sends findings, lineage, inventory, configuration state and agent health plus bounded context to PostgreSQL (`specs/ocsf-profile.md` section 4). A device group can be switched to full raw telemetry, which goes to the optional bundled ClickHouse, to an external destination through the exporters (OpenSearch, Elasticsearch, a SIEM), or, for a bounded investigation set of at most 50 devices for 7 days, into PostgreSQL. Targets, measured not assumed: Docker Compose 2,000 endpoints, 30-day detection retention, 7-day raw retention; Helm 20,000 endpoints.
Why: fleet-wide raw telemetry exceeds what PostgreSQL alone should hold (C9), and the bounded mode spares small installations a second store for occasional investigations.
Rejected: OpenSearch as the bundled store, kept as an export destination; raw telemetry only outside PostgreSQL, which forces a second store for a single investigation.
Detail: `design/backend.md` section 5.

### EV-02. OCSF version and extension
Decision: OCSF 1.9.0 is the event schema; what each domain emits and what the `ricevanta` extension adds are in EV-03. The pinned version moves only at a minor release with a documented mapping.
Why: agents, server and exporters must agree on one schema before EDR ships (C11).
Rejected: ECS or a proprietary schema; the blueprint names OCSF as the canonical format.
Detail: `specs/ocsf-profile.md`.

### EV-03. OCSF profile and extension
Decision: each domain emits the OCSF 1.9.0 classes in the profile table with the `host` and `security_control` profiles, and the `ricevanta` extension, on the development uid 999 without registration, adds what OCSF lacks for lineage, PKI, agent health, classification references, match evidence, enforcement mode and the extension that caused an event. Every event carries a UUIDv7, the bundle in force and a correlation uid; fixtures are validated in CI and events failing validation at ingest are quarantined.
Why: OCSF has no PKI, lineage or agent health class and no category reference, and mapping drift must fail a build rather than a customer's query (EV-02).
Rejected: emitting PKI events as `authentication`, whose activities do not fit issuance; lineage inside `detection_finding.evidences`, which would inflate the finding store; deprecated classes; a registered extension uid, which adds an external registration for no functional gain.
Detail: `specs/ocsf-profile.md`.

### EV-04. Event delivery guarantee
Decision: events are delivered at least once from a synced spool record to the store commit: each spool class uploads its sealed segments first in, first out with one batch in flight and a per-class sequence under a stream epoch, and ingest is idempotent by device and batch id and by event uid. Every new and duplicate acknowledgement re-reads the ledger on the current primary and waits for a fresh synchronous WAL marker covering that commit before the agent deletes its segment; a primary change requires a new ledger observation and fence. Context and raw classes use primary-only durability by default, or configured `remote_write` standby durability, which does not cover a standby operating-system crash; other classes use `on`; events failing validation are quarantined, overload is answered with `503` and `Retry-After` per class, and every spool drop is recorded and counted.
Why: blueprint section 3.7 requires reliable delivery, and asynchronous commit (`design/backend.md` section 5) would otherwise lose acknowledged rows.
Rejected: acknowledging on receipt or ledger visibility before durable commit, which loses acknowledged events on a server crash; a previous-primary WAL position as proof after promotion; a forced flush per data transaction when bounded acknowledgement grouping can amortize the flush.
Detail: `design/events.md` sections 1 to 3.

### EV-05. Export log and destination adapters
Decision: ingest writes enriched events that any destination selects into an export log of zstd NDJSON objects in the blob store, indexed in PostgreSQL through transactional, gapless commit-order counters shared by protocol with the correlation inbox, behind narrow database functions. Each `ExportDestination` is a `jobs` job with its own cursor, filter, projection, retries, dead-letter table and failure alerts, delivering at least once with `metadata.uid` as the destination's duplicate key. Adapters exist for Elasticsearch, OpenSearch, Splunk HEC, syslog, OTLP, Loki, Microsoft Sentinel, Kafka (`franz-go`), S3-compatible storage and the `export-destination` connector. S3 persists exact bytes and a configuration-bound plan, uses a new namespace for intentional replay and verifies exact size and SHA-256 on `412`; its plan schema and recovery fixtures remain implementation blockers.
Why: raw telemetry sent only to an external destination is never in PostgreSQL (EV-01), a slow destination must not hold partition retention, and BE-07 forbids a required message queue.
Rejected: exporters reading the event tables by cursor, which misses raw-only events and races partition drops; a bundled Kafka, NATS or Vector, a second stateful service.
Detail: `design/events.md` section 4, `specs/event-export.md`.

### EV-06. Administrative audit log integrity
Decision: every administrative record has a signed prepare and current-tail commitment in an independent journal before its action transaction can commit, followed by an immutable commit or offline-quorum resolution. Database rows are insert-only and hash-chained, with hourly and 10,000-record checkpoints and export to every `audit: true` destination; the journal storage, fencing and publication protocol remains an implementation blocker under BE-12. The intended guarantee includes the uncheckpointed suffix against a database-only writer, while protection against a journal administrator requires independent immutable evidence and a trusted current head.
Why: a checkpoint alone cannot detect changes or deletion after its signed tail, and full administrative auditing is a blueprint section 8 requirement.
Rejected: database permissions alone; a periodic checkpoint as the current-tail authority; a mandatory external cloud service.
Detail: `design/events.md` section 6 and `design/backend.md` section 6.1.

### EV-07. Retention, holds and archive before drop
Decision: retention is set per store and class and runs by fenced partition drop, without autonomous ClickHouse source-table TTL. A hold moves from `capturing` to `active` only after a shared producer and retention fence records a durable capture boundary, source pins and verified held copies for events, raw rows and lineage; cross-store tasks remain pending through crashes. Releasing or narrowing a hold is protected, an S3 archive verifies the exact planned manifest and objects before a permitted drop, and the capture and recovery specification and fault-injection fixtures remain implementation blockers.
Why: partition drop cannot skip rows (BE-06), and investigations and legal holds must outlive default retention.
Rejected: row-level DELETE with hold exceptions, which brings back the vacuum load that partition drop avoids.
Detail: `design/events.md` section 5.

### EV-08. Event upload descriptor wire contract
Decision: event upload v1 uses one canonical ASCII descriptor header and one fixed-size binary descriptor skippable frame; both descriptors must match, and only mTLS supplies device identity.
Why: bounded parsing and one representation prevent ambiguous batch routing and retry identities.
Rejected: JSON descriptors, permissive header lists and trusting either copy on mismatch, which add representations or admit conflicting metadata.
Detail: `specs/event-upload-wire.md` and `schemas/events/v1/`.

### EV-09. Bounded event batch body decoding
Decision: the internal Go body decoder accepts one checksummed, sized zstd frame using `github.com/klauspost/compress/zstd` v1.20.1, bounded input, window and streamed output. Actual line count must match the descriptor; strict identity extraction and positional sequences yield per-line quarantine results only after batch integrity passes.
Why: resource bounds and unambiguous bindings stop malformed batches from bypassing admission while preserving good events beside a failing event (EV-03).
Rejected: whole-output decompression, concatenated frames, permissive JSON extraction and whole-batch rejection for event binding faults, which weaken bounds or prevent per-event quarantine.
Detail: [event batch body spec](specs/event-batch-body.md), [implementation plan](plans/event-batch-body.md) and `schemas/events/v1/fixtures/body.json`.

### EV-10. ExportDestination authoring validation
Decision: ExportDestination uses a closed JSON Schema with one typed block per adapter, reference-only credential fields and bounded selection, projection, repeats and batch settings. A standard-library-only Go validator checks decoded JSON and shares positive and negative fixtures with the Python design validator; validation supplies no runtime authority.
Why: typed configuration catches misspelled parameters and inline credential carriers without coupling offline checks to secret access or delivery (analysis section 3).
Rejected: a Go JSON Schema runtime dependency for this bounded resource; permissive parameter maps and validation that contacts destinations, which add dependency or authority without proving delivery.
Detail: [schema spec](specs/export-destination-schema.md) and [implementation plan](plans/export-destination-schema.md).

## Policy (POL)

### POL-01. CEL runtimes
Decision: `cel-go` on the server and the `cel` crate (cel-rust) on the agent. Both run the cel-spec conformance tests for the CEL profile in CI (SH-02); the profile excludes anything on the `cel` crate's ignored-test list.
Why: `cel` is pure Rust, MIT, and ships the cel-spec conformance harness (C8).
Rejected: `cel-cxx`; wraps cel-cpp through a C++ build chain that limits cross-compilation.
Detail: `design/backend.md` sections 1.1 and 2.

### POL-02. Policy envelope
Decision: `Policy`, `Exception`, `RulePack` and `Baseline` resources in the Kubernetes object shape under `apiVersion: ricevanta.io/v1alpha1`, compiled per scope into a signed bundle, with a signed per-device assignment that binds device, scope, bundle hash and an organization-wide `(recovery_epoch, sequence)` under BE-12. Enforcement-weakening changes to DLP and EDR policies are protected, and one conflict plan preserves priority and exception semantics across point and core predicates, with excepted, monitoring and disabled policies excluded. Expiring exceptions use signed nonce-bound time anchors, suspend-inclusive monotonic expiry and durable expired markers, and remain inactive after uncertain time or reboot until refreshed.
Why: one validator serves the console, the API, GitOps and the compiler; an agent cannot verify its own scope, so the assignment is what stops a stolen TLS key serving another scope's bundle (blueprint section 4, `architecture.md` section 4).
Rejected: inline exceptions, which die with their policy; scope binding inside the bundle alone, which the agent cannot check; OPA-style JWT bundle signatures, since DSSE is simpler and shared with in-toto; a policy bundle expiry, which AG-05 forbids.
Detail: `specs/policy-envelope.md`.

### POL-03. CEL profile
Decision: conditions use the profile `ricevanta-cel-1`, the subset of types, operators, macros, functions and regular-expression syntax that `cel-go` and the `cel` crate evaluate identically, with no mixed numeric operands, UTC-only time accessors and no shorthand regex classes. The server bounds cost with the `cel-go` estimator and the agent enforces size limits; extensions enter the profile only when both runtimes pass the corresponding cel-spec file in CI.
Why: the two runtimes differ on optional types, two-variable comprehensions, parse edge cases, cross-type numeric comparison and the Unicode meaning of regex shorthand classes, so only the common subset evaluates identically (C8).
Rejected: a full CEL environment with per-runtime flags, which makes a condition pass on one side and fail on the other; a custom expression language without a conformance suite; Rego or Cedar, which lack a conformant Rust runtime or are authorization languages.
Detail: `specs/cel-profile.md`.

### POL-04. Rule adapters translate into one matcher program
Decision: rule adapters are Go packages in the server `policy` module that translate each `RulePack` format at import. Sigma and Falco rules become one versioned matcher program evaluated by a single Rust engine in the agent core, YARA, Presidio-style and Gitleaks-style rules keep their patterns for `ricevanta-scan`, and every source rule gets a per-OS report entry with a closed-list reason code instead of a dropped clause. Sigma correlation runs on the server over events tagged with immutable `{pack, version, pack_digest, rule_key}` identities; concurrent versions and late events cannot satisfy a different rule version.
Why: Sigma and Falco rules do not target OCSF and share field-test semantics that one engine with shared literal prefilters evaluates at a cost proportional to candidate rules rather than installed rules (C7, EDR-01).
Rejected: translating Sigma into CEL, which needs functions outside the profile and cannot share prefilters across thousands of rules; running pySigma or sigma-cli, which are Python, LGPL-2.1 and produce backend queries rather than an evaluator.
Detail: `design/policy.md` section 5, `specs/rule-adapters.md`.

### POL-05. Agent engines on the server through ricevanta-rulec
Decision: `ricevanta-rulec`, a Rust binary built from the agent workspace with the agent's matcher, scanner detectors, YARA-X, SQLite and `cel` crate, ships in the server image. The `policy` module calls it as a resource-limited subprocess to compile every pattern, prepare every SQL statement, parse every CEL condition a second time, and run rule fixtures and operator tests.
Why: Go RE2, Python `regex` and the Rust `regex` crate differ, YARA-X has no Go compiler without cgo, and the `cel` crate skips cel-spec parse cases the profile admits, so only the agent's own engines prove at write time that a rule runs on the agent (C8).
Rejected: Go-only validation, which lets rules pass on the server and fail on endpoints; YARA-X Go bindings, which need cgo; agent-only compilation, which reports errors only after publication.
Detail: `design/policy.md` sections 2.2 and 5.1.

### POL-06. osquery packs over the agent's inventory tables
Decision: osquery packs, discovery and baseline queries use bounded read-only SQLite over inventory snapshots with an admitted function catalogue, connection, value, allocation and result limits, and isolated on-demand execution. The native worker and cancellation contract remains an implementation blocker. No osquery binary ships, evented `*_events` tables are not served, and scheduled results are OCSF `evidence_info` events.
Why: the inventory tables already exist in the agent's SQLite (`design/mdm.md` section 3), and a second collector set would duplicate collection and add a resident process against the 80 MB target (blueprint section 7).
Rejected: embedding or shipping osquery, which brings its own collectors and watchdog under Apache-2.0 OR GPL-2.0-only; translating osquery SQL into CEL over a snapshot, which loses joins and aggregates.
Detail: `specs/rule-adapters.md` section 8.

### POL-07. Signed rule-pack manifests and license classes
Decision: publishing a rule-pack version makes `api` sign a DSSE pack manifest. The manifest binds name, version, format, the archive, compiled-output and report hashes, the adapter version and the license record. The compiler includes only packs whose manifest verifies. Each rule's SPDX license is classified as accepted, review-required (attested by the publish approver) or blocked, and blocked rules are excluded with a report.
Why: the blob store and registry rows are not trust anchors, and bundles redistribute rules to every endpoint, so licenses are reviewed before publication (blueprint sections 4 and 9).
Rejected: trusting the stored archive hash alone, which a database write could change; one license per pack, which misses Sigma rules that declare their own license.
Detail: `design/policy.md` section 6.

### POL-08. CEL declaration catalogue
Decision: `variables.json` uses a bounded, versioned JSON type grammar with closed record shapes and explicit presence rules; each supported version tuple identifies one immutable complete catalogue. A standard-library Go loader rejects malformed declarations, unresolved references, cycles and same-version catalogue changes before any consumer uses them.
Why: the CEL declaration gap in analysis section 3 leaves the compiler, editor and agent without one machine-readable environment and permits type or evidence drift.
Rejected: protobuf declaration JSON, which couples the format to excluded CEL message types; unrestricted dynamic maps and additive same-version declarations, which lose field checks and fixed compatibility.
Detail: [CEL declarations](specs/cel-declarations.md) and [implementation plan](plans/cel-declarations.md).

## Lineage (LIN)

### LIN-01. Graph model and storage
Decision: lineage is a PROV-style graph with revision-qualified evidence over device-qualified file incarnations, stored in SQLite and PostgreSQL and uploaded as its own event class. Durable sensitivity floors preserve inherited labels independently of graph retention, and lowering a floor requires approved reclassification. Storage, candidate work, frontier and deadline caps compact provenance into bounded summaries without lowering floors; native continuity, floor transactions and bounded compaction remain implementation blockers.
Why: reused native identifiers and in-place writes must not change prior evidence, and graph pressure or retention must not clear inherited classification.
Rejected: a graph database, since the embedded candidates are archived or too large and the server ones are a second service or an extension; `ltree`, which fits trees only; keeping every edge forever.
Detail: `design/lineage.md`.

## PKI

### PKI-01. Enrollment and certificate protocols
Decision: the agent enrolls through the token bootstrap (PKI-02) and renews through a private nonce-bound protocol signed by its current device identity key, with a self-signed certificate signing request proving the replacement key; mTLS admits the request, optional attestation adds evidence, and lost-key recovery requires a fresh token and approval. Standard ACME for Apple payloads, service connectors, network and third-party clients keeps account and certificate keys separate and changes the account key only through RFC 8555 `keyChange`; SCEP supports RSA and ECDSA. The root CA stays offline under its custodian quorum and is the certificate agents pin, while issuing CAs stay online and BE-12 defines recovery authority.
Why: hardware-backed certificate keys must renew without redefining standard ACME account semantics (C10).
Rejected: SCEP for the agent; treating a certificate key replacement as ACME account rollover.
Detail: `design/pki.md` sections 2 to 4.

### PKI-02. Enrollment bootstrap
Decision: the company-signed installer ships unchanged; an enrollment configuration delivered beside it carries the server URL, the Ricevanta root CA to pin and an enrollment token scoped to a device group and expiring, single-use with administrator approval by default for any group that can receive network-access certificates or MDM management; the Windows imaging token is the one multi-use exception, admits OMA-DM enrollment only and leaves enrollments `pending` until approval. The agent posts a certificate signing request with the token and a platform attestation where available, checked against an imported endorsement-key allow list; `jobs` independently verifies proof and derives issuance authority from protected records, with approvals bound to the exact request, CSR, device and profile. Expired certificates renew within a grace period; beyond it, or after re-imaging, a new token is issued, and taking over an existing record needs proof of the previous key or approval, never hardware identifiers alone.
Why: signed packages cannot be rebuilt per installation (PF-03), the first contact has no certificate yet, and a stolen token must not become a VPN credential or a takeover of another device's record (blueprint section 8).
Rejected: enrollment configuration embedded in the installer; multi-use tokens without approval as the default; re-enrollment matched on serial numbers.
Detail: `design/pki.md`.

## RADIUS (RAD)

### RAD-01. Both RADIUS architectures
Decision: certificate-derived identity authorization (the gateway validates the certificate; Ricevanta authorizes the SAN or CN network identity against issued, unrevoked certificates, device state and compliance) and EAP-TLS termination, over RadSec and UDP. Required gateway qualification profiles: FortiGate SSL VPN on FortiOS releases that still ship tunnel mode, FortiGate IPsec IKEv2 dialup (certificate-derived with FortiClient, EAP-TLS with native clients), Cisco ASA and ASAv (certificate-derived), and 802.1X wired and Wi-Fi. EAP-TLS is implemented in-project in Go, because no maintained Go library ships it.
Why: FortiClient and Cisco Secure Client do not initiate EAP-TLS to these gateways (verify); FortiOS 7.6.3 removes SSL VPN tunnel mode; EAP-TLS serves 802.1X and native OS clients (C6).
Rejected: FreeRADIUS as the EAP server (GPL-2.0).
Detail: `design/radius.md`, `specs/radius-gateway-profiles.md`.

### RAD-02. Network-access identity binding
Decision: each network-access identity has a unique, never-reused `jobs`-minted `netid` and unique identity names that multiple certificate generations may share during renewal overlap. Name-only authorization requires an active identity with an issued, unrevoked, unexpired certificate and the gateway profile's binding proof, but exposes only identity-level facts with unknown certificate generation; generation-specific policy and audit fields require EAP-TLS or a qualified exact certificate binding, and compilation and admission refuse unavailable evidence. Replicas use the materialized snapshot; FortiGate binding-token and ASA Authorize-Only behavior remain qualification requirements.
Why: RADIUS sees only the name the gateway extracted, so the name must be unforgeable by issuance and unreachable from password logins on the same gateway (C6); per-request reads of authoritative tables break the BE-03 handler rules.
Rejected: authorizing any gateway-supplied name; selecting a current inventory certificate as evidence of the authenticated generation; using the device uid as the SAN value, which cannot distinguish a user's certificate on a device.
Detail: `design/radius.md` sections 1 to 3.

### RAD-03. RADIUS transport
Decision: RadSec with mutual TLS is the default, the gateway presenting a `network-gateway` certificate from the server issuing CA or an SPKI-pinned external certificate bound to its registration. UDP is accepted where RadSec is unavailable, with a Ricevanta-generated per-gateway secret, source-prefix restriction, and `Message-Authenticator` required on every Access-Request and sent first in every response, with no per-gateway override. Gateway registrations and widening them are protected actions, secrets are sealed to the `radius` role's key, and compromise recovery excludes copied credentials and replaces the role wrapping root before distributing replacement private material or regenerating gateway secrets without overlap.
Why: BlastRADIUS forges UDP responses that lack `Message-Authenticator` (draft-ietf-radext-deprecating-radius), and the certificate-derived binding rests on the authenticity of the RADIUS channel (C6).
Rejected: a per-gateway opt-out of `Message-Authenticator` for older gateways; RFC 9765 RADIUS/1.1, which is Experimental and supported by neither gateway family.
Detail: `design/radius.md` section 5.

### RAD-04. EAP-TLS profile
Decision: Go `crypto/tls` behind the in-project EAP state machine, with TLS 1.3 per RFC 9190 and TLS 1.2 with extended master secret per RFC 5216, ECDHE AEAD suites only, no session resumption, client certificates validated against the network-access issuing CA and the identity's issued certificate in the snapshot, and conversation state per replica. `layeh/radius` is the packet codec only; listeners, RadSec framing, authenticity checks and duplicate detection are in-project.
Why: Windows 11 never resumes EAP-TLS, and a full handshake keeps revocation and compliance fresh; `layeh/radius` does not verify `Message-Authenticator`, has no RadSec and is untagged.
Rejected: ticket-based resumption, which needs a ticket key shared across replicas; `wxccs/radius` for RadSec, which has no known importers.
Detail: `design/radius.md` section 4.

### RAD-05. Network access fails closed
Decision: an Access-Accept is sent only after its decision event commits to PostgreSQL. An unreachable database, a materializer heartbeat older than 120 seconds or an unconfirmed `network` authorization table rejects every request, and accounting is acknowledged only after commit. `jobs` audits each accept against authoritative records within one minute.
Why: every accept must retain its proved identity or exact certificate evidence and current compliance state, and a cached accept cannot see a revocation (blueprint section 3.6).
Rejected: answering from cached state during an outage; logging decisions asynchronously through the event buffer, which loses accepts on a crash.
Detail: `design/radius.md` section 10.

### RAD-06. Session control
Decision: authority changes re-evaluate every possibly active session, including missing or stale accounting, through one monotonically versioned desired state and one fenced dispatcher per session; event-time and boot-generation evidence prevent delayed accounting from closing newer sessions. CoA requires the exact qualified attribute transition, clearing operations and stale-packet exclusion, while obsolete or ambiguous transmissions require reconciliation or Disconnect before later grants. Every accept carries an enforced original timeout, default 8 hours for VPN and 1 hour for 802.1X; unproved termination or expiry blocks the required gateway unit, and the exact accounting and dispatch protocols remain implementation blockers.
Why: gateway revocation checks apply only at connection time, omitted CoA attributes persist, and local dispatch versions do not order gateway packets (C6).
Rejected: closing a session after missing interims; independent control-row claims; treating a profile's new attributes or an ACK as full current-state replacement.
Detail: `design/radius.md` sections 7 and 8, `specs/radius-gateway-profiles.md` section 3.1.

## Backend and console (BE)

### BE-01. Identity sources
Decision: administrator single sign-on through OIDC, SAML where a provider lacks OIDC, with users and groups through SCIM 2.0 push or LDAP sync, linked to immutable internal user uids by provider-specific stable principal keys rather than email or mutable claims. Local accounts only for the first administrator and break-glass, with a second factor and audited, alerting logins. Devices link to users at enrollment and from observed login sessions.
Why: policies and RADIUS need group membership; the console needs administrator login.
Rejected: local accounts as the primary user store; drifts from the directory.
Detail: `design/backend.md` section 2.

### BE-02. RBAC with access policies for protected actions
Decision: one permission per action, bundled into built-in and custom roles, assignable to users or directory groups, optionally scoped to device groups. Access policies name protected actions and an approver group; a protected action from the console, the API or GitOps becomes a pending request that a different account approves from an interactive session (BE-09) before dispatch, with targets frozen at request time and requester, approver and targets audited; protected by default are wipe, device retirement, lock, restart and shutdown on more than 10 devices, publishing a software package or an apply-capable baseline, changing either resource's canonical content or allowed groups, applying such a baseline to a scope and any change that newly delivers it to a device, and weakening required compliance through a baseline, report-policy scope or exception, including read-only checks with exact before and after revisions and affected devices bound (`specs/baseline.md` section 5), publishing a script to a scope and signed software and script commands, response actions on more than 10 devices, un-isolating a host, restoring a quarantined file, retiring an interim ban and running an operator script (`specs/edr-response-actions.md` section 2), rule-pack publish, extension install, upgrade, enable and capability grants, browser-registration changes, trust-list changes other than adding a revocation, and disabling a component an enforcing policy depends on (EXT-02), CA key operations, creating or widening a RADIUS gateway registration, weakening DLP, EDR and network policies and publishing ones with isolate, revoke or kill actions (`specs/policy-envelope.md` section 2.3), creating, enabling, disabling or deleting an export destination, changing its filter or projection, endpoint or credentials, any change to a destination that receives the audit log or archives, releasing or narrowing a legal hold, shortening audit retention, access-policy changes, and role or role-assignment changes that grant a permission an access policy names. Software-package and baseline approvals bind the exact revision and allowed device groups, which the compiler rechecks. Single-administrator installations may disable configurable approval policies with a persistent warning, but identity-authority actions always need a different directly assigned authority approver using unaffected authentication, or an exact offline-quorum repair under BE-12; first-start setup is one-use and grants no later exception, and just-in-time role activation is not in v1.0.0.
Why: a compromised or mistaken administrator is the most damaging failure, including one who silences the SIEM or the audit trail, or opens a new export stream, before acting; regulated customers require separation of duties.
Rejected: RBAC and audit only; no protection against one compromised account.
Detail: `design/console.md` section 3.2, `design/backend.md` sections 1.1 and 6.1, `specs/policy-envelope.md` section 2.3, `specs/event-export.md` section 1, `design/events.md` sections 5 and 6, `specs/edr-response-actions.md` section 2.

### BE-03. One server binary with roles
Decision: `ricevanta-server` is a Go modular monolith that runs the roles `api`, `agent`, `device`, `radius` and `jobs` in one process by default and as separate deployments under Helm, with the console compiled into the binary. Private keys follow exposure: the master key and the signing key live in `api` and `jobs`, the issuing CA keys and the audit checkpoint and journal signing keys in `jobs` only, and the agent-facing `agent`, `device` and `radius` roles hold their TLS keys, role-scoped data keys and per-role database credentials that insert only events (the `events` event, quarantine, batch-ledger, export-log index, correlation inbox, device-stream and held-event tables, `lineage` edges, the `detection` and `dlp` finding inboxes and ClickHouse raw rows; the full list is `design/events.md` section 3.6), check-ins, results, request rows, minted ACME nonces, artifact parts into a staging prefix of the blob store, for `agent` create-only export-log objects under their own blob prefix that only `jobs` reads, and, for `radius`, accounting rows and session-control outcomes, which `jobs` treats as untrusted input and authorizes against protected records before issuance or dispatch. Export and correlation index insertion, acknowledgement markers and capture coordination use narrow database functions without direct head-update or capture-state rights; jobs elect one leader per routine job through a lease row in PostgreSQL, and agent-facing handlers read no fleet-wide shared state per routine request.
Why: self-hosters get one artifact and roles scale separately (blueprint section 5); a compromised exposed replica must not be able to sign commands or mint identities.
Rejected: one service per domain; Redis as a second stateful service; advisory locks for leader election, which pin connections and fail behind transaction pooling; signing keys in every role.
Detail: `architecture.md` section 3.1 and `design/backend.md` sections 3 and 6.

### BE-04. Module boundaries
Decision: fifteen modules, `identity`, `authz`, `devices`, `mdm`, `policy`, `detection`, `dlp`, `lineage`, `pki`, `radius`, `events`, `extensions`, `audit`, `transport` and `platform`. Each owns one PostgreSQL schema that no other module reads or writes, exposes Go interfaces, publishes on an in-process bus, and coordinates routine work across replicas through PostgreSQL, with authority changes also fenced by the independent journal (BE-12); an import-graph check in CI enforces the boundaries.
Why: the monolith stays splittable and testable per module.
Rejected: shared tables across modules; couples schemas and blocks later extraction.
Detail: `design/backend.md` section 1.

### BE-05. API style and GitOps
Decision: `/api/v1` is a JSON REST API described by OpenAPI 3.1 and is the only write path; the console and the `ricevanta` CLI use it with browser sessions from the BE-01 identity sources or scoped API tokens. GitOps is a directory of `ricevanta.io/v1*` YAML resources applied as a declarative three-way diff by the CLI or by the server polling a repository; protected actions become approval requests (BE-02).
Why: one write path keeps authorization and audit complete; YAML resources match the policy envelope format.
Rejected: a separate GraphQL or gRPC administration API; no consumer needs it.
Detail: `architecture.md` section 3.3.

### BE-06. Storage
Decision: PostgreSQL 17+ as the system of record with natively day-partitioned event tables, batched `COPY` ingest and partition-drop retention; a blob store with local-filesystem and S3-compatible backends for installers, release packages, rule-pack archives, extension packages and reports; secrets at rest under envelope encryption with a server master key from the environment, a file or an external KMS, with PKCS#11 as the alternative for CA keys. A complete backup includes PostgreSQL, blobs, the independent authority journal and a signed key-custody manifest covering every wrapping root, role key and external KMS or PKCS#11 recovery dependency; an isolated restore must unwrap or access every key, verify certificates, sign challenges and open data fixtures before the backup passes.
Why: minimal infrastructure (blueprint section 5) while keeping large binaries out of the database.
Rejected: storing packages in PostgreSQL; TimescaleDB, whose retention and compression are not under Apache-2.0; `pg_partman`, an extension for what a small job does.
Detail: `design/backend.md` sections 5 and 6.

### BE-07. Deployment and high availability
Decision: Docker Compose runs all roles in one container with PostgreSQL and an optional ClickHouse profile; Helm runs one deployment per role group, `agent` and `device` behind TLS passthrough or a layer-4 load balancer, `radius` behind separate UDP and TCP `LoadBalancer` services with local traffic policy and client-IP hashing at both the service and the external load balancer, and PostgreSQL external or through the CloudNativePG operator for evaluation. `api`, `agent` and `device` are stateless with two or more replicas, `jobs` elects leaders, `radius` replicas hold their own EAP state; migrations are forward-only and compatible with the previous server version for rolling upgrades.
Why: EV-01 scale targets and self-hoster simplicity.
Rejected: a required message queue; PostgreSQL `LISTEN`/`NOTIFY` and job tables cover the coordination needed.
Detail: `architecture.md` section 5.

### BE-08. Console stack and components
Decision: the console is a Vue 3 single-page application in TypeScript built by Vite, with Pinia, Vue Router route-level chunks, a client typed by `openapi-typescript` and `openapi-fetch` from the hand-written OpenAPI 3.1 document, and in-house components on Reka UI primitives with TanStack Table and Virtual; Apache ECharts draws charts, Cytoscape.js with dagre draws lineage graphs, and CodeMirror 6 edits policies. Nothing in the build needs `eval`, inline script or inline style elements; CodeMirror injects its styles through constructable stylesheets, which needs its host element in a shadow root.
Why: WCAG 2.2 AA and a strict Content-Security-Policy need components with WAI-ARIA keyboard behaviour and static styles, and the brand tokens must drive every surface.
Rejected: Element Plus, which states no accessibility position and labels its virtualized table beta; PrimeVue 5, whose license requires a key and forbids redistribution; Monaco, heavier and worker-based.
Detail: `design/console.md` section 1.

### BE-09. Console sessions
Decision: OIDC login (authorization code with PKCE) or SP-initiated SAML ends in a server-side session in a `__Host-` cookie with `SameSite=Strict`, defended by a synchronizer CSRF token plus Fetch Metadata and Origin checks; idle and absolute timeouts default to 15 minutes and 8 hours, and to 5 minutes and 1 hour for break-glass. Approving a protected action and changing identity providers, principal links, mappings, directory authorities, recovery paths, break-glass accounts, roles, access policies or the trust list need an interactive session authenticated within 10 minutes; identity-authority approval must use an unaffected authentication method; API tokens can request protected actions but never approve them.
Why: a stolen or unattended session is the cheapest route to a protected action, and OWASP treats SameSite as defence in depth only.
Rejected: tokens in browser storage, readable by any injected script; IdP-initiated SAML, which binds no request.
Detail: `design/console.md` section 2.

### BE-10. Console live updates
Decision: the console refreshes from a Server-Sent Events stream on `/api/v1/changes` that carries per-topic invalidation watermarks and never rows; each `api` replica reads module watermarks from PostgreSQL every 2 seconds, views refetch through ordinary authorized operations, and 30-second polling is the fallback.
Why: the traffic is one-way, rides the session cookie and per-request authorization, and costs one query per replica rather than per operator at 20,000 endpoints (EV-01).
Rejected: WebSocket, a bidirectional channel no view needs, with its own handshake checks; polling only, which costs a query per tab and delays alerts and approvals.
Detail: `design/console.md` section 4.

### BE-11. Report templates
Decision: reports, schedules and dashboard panels use `ReportTemplate`, a declarative `ricevanta.io/v1alpha1` resource of parameters, datasets over a server-published source catalogue with fixed filter operators and measures, and a layout of text, KPI, chart and table blocks, with no SQL, script or markup. The `events` module owns templates, runs and schedules, and every module publishes and executes its report sources through a Go interface; runs execute with the runner's permissions and device-group scope, and every later reader, including the runner, must currently hold every source permission and cover the immutable entity footprint on metadata, result, download and cache paths. Private result blobs cannot bypass that check; the extension `content` format `report` carries the same resource.
Why: extensions and GitOps must ship reports without code execution, and a shared template must not widen access.
Rejected: SQL in templates, which bypasses module schema ownership (BE-04) and device-group scope; scripted templates; embedding Grafana, a second service with its own authentication.
Detail: `specs/report-template.md`.

### BE-12. Independent authority journal and recovery epochs
Decision: grants, denies, counter floors and consumed authorizations commit through an authenticated independent journal, with a prepare/apply/commit publication barrier and stale-writer fences; its executable storage and database protocol remains an implementation blocker. Restore stays sealed until the live journal and complete key inventory reconcile, then an offline root-certified custodian quorum authorizes an exact epoch transition, with two distinct signatures from three keys by default or a declared one-custodian single-administrator setup. Every installation-authority artifact and generation carries the epoch, old tokens and approvals cannot authorize new work, and ambiguous resources remain `recovery_pending`.
Why: database rollback must not revive revoked identities, reuse spent authorization or roll back security counters (blueprint section 8).
Rejected: floors collected from returning devices; elapsed restore timers; a database or operator-selected head as proof of current authority.
Detail: `design/backend.md` section 6.1, `design/pki.md` section 4 and `specs/policy-envelope.md` sections 6 and 7.

### BE-14. Permission catalogue
Decision: a versioned JSON catalogue under `schemas/permissions/v1/` defines exact permission names, scope kinds, grant kinds and approval metadata; the Go `authz/catalogue` library embeds an identical copy guarded by a byte drift test, rejects unknown or retired names, and keeps permanent retirement tombstones.
Why: console, API and GitOps consumers need one explicit inventory without giving runtime data authority to redefine permissions.
Rejected: generated Go literals add a generator, runtime loading admits replacement metadata, and wildcard permissions obscure distinct actions.
Detail: [Permission catalogue](specs/permission-catalogue.md) and [implementation plan](plans/permission-catalogue.md).

## Extensions (EXT)

### EXT-01. Extension model and kinds
Decision: third parties extend Ricevanta through one signed package format, `extension.yaml` under `apiVersion: ricevanta.io/v1alpha1` and `kind: Extension`, carrying components of five kinds: `content`, `browser-adapter`, `agent-module`, `console-module` and `service-connector`. No third-party code runs inside `ricevanta-agent`, `ricevanta-server`, the sensors, the driver, the system extensions or the browser extension; code enters only through the `ricevanta-ext` WebAssembly helper, a sandboxed console iframe or a separately deployed connector process, and everything else is data validated against a JSON Schema.
Why: the surveyed platforms give extension code either the host's address space (Caddy, Kibana, Headlamp, Velociraptor's compiled-in plugins) or an unauthenticated process (go-plugin calls its handshake "not a security measure"), so isolation and signing must be Ricevanta's own.
Rejected: one in-process plugin API per component, which puts foreign code beside enforcement and signing keys; compile-time modules as in Caddy, which force self-hosters to rebuild and re-sign binaries.
Detail: `design/extensions.md`.

### EXT-02. Extension trust and signing
Decision: DSSE and the publisher's Ed25519 key authenticate the exact manifest and all listed file hashes under an approved id prefix; ids occupy one installation namespace, and an accepted id/version can never acquire different bytes or a different publisher. Protected install, grant, ownership, registration and trust changes follow BE-02; stored grants carry a never-reused `(recovery_epoch, component generation)` under BE-12 into signed bundles, while agents retain only the organization's trust root. Revocation invalidates live console and callback bindings immediately and removes agent components at the next compile; publisher-key revocation never waits for approval.
Why: Grafana loads only signed plugins with a hashed manifest and Mattermost checks bundles against a trusted-key list, and Ed25519 over DSSE gives the same model offline in Go and Rust with code the project already needs for bundles, while `sigstore-rs` describes itself as experimental and Sigstore's offline bundle verification is only partly documented.
Rejected: Sigstore keyless signing with Rekor as the required trust root, an online dependency with an experimental Rust client; agents verifying publisher keys, which adds a second trust root to every endpoint and pushes publisher-key rotation to the fleet.
Detail: `design/extensions.md` section 2.

### EXT-03. Agent extension runtime
Decision: `wasm32-wasip2` modules run in separately replaceable DLP and batch instances of reduced-privilege `ricevanta-ext`, with fuel, memory, independent capacity and one end-to-end monotonic deadline. Collectors receive only core-projected and privacy-filtered snapshot data from the bounded filesystem broker; every guest log stays local, and handles and telemetry bind the recovery epoch and component generation. Responders return a fully validated durable plan under a parent command authorized and approved for every permitted child action; recovery never revives stale authority or repeats completed steps.
Why: `wasmtime` is the only surveyed runtime with documented CPU limits (fuel, epoch interruption) and a memory limiter and marks WASIp2 and the component model Tier 1, while Starlark, Rhai and Lua document no sandbox for untrusted code and native loading shares the address space without a stable Rust ABI; fuel and epoch interruption bound guest execution but not synchronous host I/O, and raw privileged directory preopens cannot exclude denied descendants, so host async embedding, a core broker and a durable plan journal keep those authorities outside untrusted code.
Rejected: Extism, which has no component model and no 1.0 stability statement; embedded interpreters; native dynamic libraries; one subprocess per module, whose resource caps the sources leave to each OS and whose resident processes work against the 80 MB target.
Detail: `specs/extension-agent-runtime.md`.

### EXT-04. Console module isolation
Decision: a `console-module` uses an opaque-origin `<iframe sandbox="allow-scripts">` only after its exact loaded-asset and external-egress contract passes Chromium, Firefox and WebKit qualification; the candidate CSP, including the draft WebRTC control, has no such evidence and remains a v1.0.0 release blocker. A server-issued immutable asset mount and binding fix package and component digests, recovery epoch, grant generation, slot and operator session, and every dispatch rechecks committed authority plus a deny-by-default safe-operation catalogue. Credential issuance, authentication, approval decisions, identity authority, RBAC, bridge binding creation, trust and capability administration never cross the bridge; invalidation fences queued work and closes the mount.
Why: Grafana without its preview sandbox, Backstage, Kibana, Mattermost, Headlamp and Home Assistant hand plugin code the host page's session and API objects, and an opaque-origin frame, as in Figma's plugin UI, is the privilege boundary browsers offer; an asset 404 cannot revoke an existing `MessagePort`, and browser-held grant state cannot authorize server operations after disable, revocation or role change, so the server holds the binding.
Rejected: same-page loading of third-party code through Module Federation (`@module-federation/vite`) or Vue async components; Web Components and Shadow DOM, which MDN does not describe as a security boundary; ShadowRealm, which browsers have not shipped (verify).
Detail: `design/extensions.md` section 5.

### EXT-05. Service connectors out of process
Decision: server extension code stays in separately deployed `service-connector` processes with versioned HTTP contracts (`export-destination`, `ca-connector`, `notifier`, `enricher`) called by `jobs` over mTLS or a scoped token. Pending CA requests and callback credentials bind immutable connector identity, request and CSR digests, recovery epoch and component and registration generations; admission and consumption reload committed authority under the recovery fence. Disable, revocation, grant or registration changes invalidate pending callbacks, while already-issued external certificates retain a separate reconciliation obligation and never restore callback authority.
Why: `wazero` implements WASI preview 1 only and documents no fuel metering, `wasmtime-go` needs cgo and supports x86_64 only, which breaks ARM64 server images, Go's `plugin` package supports Linux, FreeBSD and macOS only and shares the address space, and go-plugin has no authenticity check and would give a third-party binary the server's network and database position.
Rejected: in-process server plugins on any of those four, to revisit when `wazero` implements WASIp2 with fuel metering, since the contracts are written so an in-process runtime could implement them.
Detail: `design/extensions.md` section 6.

### EXT-06. Browser adapters
Decision: browser support is adapter data constrained by a separately approved registration for one browser. The registration owns exact canonical OS policy and native-host targets and a bounded engine-specific policy-name allow list; server and agent intersect the adapter request, registration and grant, reject reserved namespaces and aliases, and permit only agent-generated values. First-party registrations and adapters for Chrome, Edge, Firefox and Safari are required qualification units; other registered adapters remain community status until qualified.
Why: Chrome and Edge read Chromium policy and native-host conventions, Brave reads Chromium policy, and Waterfox and Zen ship the Firefox policy engine (verify), so browsers of one engine family differ in paths and keys rather than in code, and a registration preserves that data-only addition while preventing an adapter from turning the privileged agent into a writer for arbitrary OS policy, filesystem, plist or registry namespaces.
Rejected: a fixed browser list in the agent, which makes every new browser a core change; qualifying an adapter because it loads, since only the bypass self-test shows that the gate holds a transfer until the decision.
Detail: `design/extensions.md` section 7.

### EXT-07. Distribution and compatibility
Decision: no marketplace service; the project publishes a DSSE-signed static JSON index of first-party and listed community packages with publisher fingerprints, download URLs and hashes, which the server fetches only when the operator enables it, and packages also arrive by console upload or the GitOps kind `Extension`. Each kind has its own interface version (`ext.ricevanta.io/<kind or contract>/v1`, WIT package versions, the console bridge schema version, connector contract versions) that changes additively within a major; the server refuses a package that needs an interface version it does not serve and names that version. The product version is not the compatibility key.
Why: OCI 1.1 does not require registries to accept arbitrary artifact types and referrers support on GHCR, Harbor, Distribution and Zot is unconfirmed, while Kubernetes-style versioned groups let each interface move on its own.
Rejected: an OCI registry as the v1.0.0 channel, which the package format can still be wrapped for later; a project-hosted marketplace, a service every installation would depend on; product-version ranges as in VS Code's `engines` and Grafana's `grafanaDependency`, which tie an extension to release numbers instead of the interfaces it uses.
Detail: `design/extensions.md` section 8.

### EXT-08. Extension manifest validation boundary
Decision: retain YAML and its DSSE payload type for package manifests, with a closed decoded schema, bounded capability requests, canonical identity strings and explicit file ownership; the pure Go validator validates decoded trees without granting admission. The later strict YAML loader uses `go.yaml.in/yaml/v3` v3.0.4 and preserves signed bytes.
Why: package identity, file commitments and requested authority need exact rejection rules before stateful admission can consume them.
Rejected: JSON-only payloads, which exclude ordinary YAML manifests; permissive struct decoding, which loses unknown-field evidence; schema-only admission, which cannot prove ownership, key authority or grants.
Detail: [manifest contract](specs/extension-manifest.md) and [implementation plan](plans/extension-manifest.md).
