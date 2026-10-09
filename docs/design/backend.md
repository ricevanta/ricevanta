# Backend design

How `ricevanta-server` is built inside: modules, the libraries they build on, the agent-facing handler rules and cross-replica coordination, the policy and event pipelines, storage, and secrets. This file also holds the server side of the events and policy domains. Roles, listeners, key custody per role, APIs and deployment are in `../architecture.md`; certificates in `pki.md`. Decisions: BE-01 to BE-07, EV-01 to EV-03 and POL-01 to POL-03 in `../decisions.md`.

## 1. Modules

```
server/internal/
├── identity     organizations, users, groups, OIDC and SAML login, SCIM, LDAP sync, API tokens
├── authz        permissions, roles, access policies and approvals (BE-02)
├── devices      device records, groups, tags, lifecycle, device-to-user links
├── mdm          agent-delivered management, Apple MDM and DDM server, APNs, Windows OMA-DM server
├── policy       envelope validation, CEL profile, compilation, signing, distribution, rule-pack registry, adapters
├── detection    server-side Sigma correlation, alerts, investigations, response-action dispatch, threat intelligence
├── dlp          classification catalogue, rule packs, matches, evidence, reports by regulation (DLP-03)
├── lineage      graph storage and queries
├── pki          issuing CAs, profiles, issuance, ACME, SCEP, revocation, CRL and OCSP, external CA
├── radius       RADIUS and RadSec servers, EAP-TLS, authorization, gateway profiles
├── events       ingestion, OCSF validation, PostgreSQL and raw store, retention, exporters
├── audit        append-only administrative audit log
├── transport    HTTP routers, long-poll registry, command dispatch
└── platform     configuration, database, blob store, in-process bus, jobs, metrics, secrets
```

Rules:

- A module owns one PostgreSQL schema named after it and is the only code that reads or writes those tables.
- Modules call each other only through Go interfaces defined by the callee, and publish facts on the in-process bus (`platform/bus`) for the others to consume. Cross-replica coordination goes through PostgreSQL (`LISTEN`/`NOTIFY`, lease rows, job tables), never through the in-process bus.
- An import-graph check in CI fails the build when a module imports another module's internal packages, so the boundaries hold without code review.
- Every module has its own package of tests that run against a real PostgreSQL in CI.

## 2. Library choices

- Apple MDM: NanoMDM's `http`, `service` and `storage` layers with the PostgreSQL backend; the DDM engine is written in-project, since no maintained open-source DDM server exists; APNs is a direct HTTP/2 client.
- Windows MDM: Fleet's MIT-licensed MS-MDE2 and SyncML code, file by file.
- PKI: `smallstep/crypto` for X.509, KMS and PKCS#11; `micromdm/scep` for SCEP; the ACME server is written in-project on the same packages, since no standalone Go ACME server library exists.
- RADIUS: `layeh/radius` for transport; EAP-TLS written in-project, seeded from the MIT `radius-eap` state machine and interoperability-tested against `wpa_supplicant`, because no maintained Go library ships it.
- Identity: `go-oidc`, `go-ldap`, `elimity-com/scim` at a pinned commit (early-stage, no bulk operations); the SAML library is chosen after an activity check, because the common one is stale (verify).
- Data: `pgx`, `klauspost/compress` for zstd, `minio-go` for S3-compatible blob storage, `clickhouse-go` for the raw store, the OpenSearch and Elasticsearch Go clients for export destinations.
- CEL: `cel-go`, with the agent's `cel` crate passing the same conformance subset (POL-01).
- HTTP: the standard library router; the OpenAPI 3.1 document is hand-written and validated in CI, since generator support for 3.1 is partial.

## 3. Agent-facing handler rules

Taken from the documented scaling failures of comparable servers (Fleet's per-check-in reads of shared state and commit-bound result writes, Elastic Fleet Server's per-check-in authentication):

- Routine check-ins and waiting long polls avoid fleet-wide shared-state reads; the current policy bundle version per scope is held in process memory and refreshed by `NOTIFY`. When a command is ready, `jobs` reads the protected command, frozen target and approval records before signing a dispatch grant for the device's fresh poll nonce. These authorization reads are required and cannot be replaced by the exposed handler's cached claims (`../specs/policy-envelope.md` section 7).
- The certificate-to-device lookup is cached in process for the certificate's lifetime; a revocation `NOTIFY` evicts the entry, and every TLS handshake also checks an in-memory revocation set refreshed by the same channel, so a revoked device loses access at its next connection.
- Events are written in batches with `COPY` into the day partitions, never row by row.
- Enrollment is rate-limited per source.
- `LISTEN` needs a direct PostgreSQL connection, so the server keeps a small pool outside any transaction-pooling proxy; `NOTIFY` is used only for the low-rate commands, policy-version and issuance channels, never on the ingest path, because a `NOTIFY` inside a transaction takes a global lock at commit.
- Leader election for `jobs`: one lease row per job, taken and renewed at 80 % of its interval against database time; a replica whose renewal fails stops the job and logs it.

Reference points: Fleet runs 10 instances for 25,000 hosts; Elastic Fleet Server runs one 8 GB instance from 10,000 to 75,000 agents. The `agent` role targets 20,000 endpoints on two to three replicas, measured.

## 4. Policy and event pipelines

```
Author (console, CLI, GitOps)
  └─> policy: validate envelope and CEL profile ──> compile per domain ──> sign in api ──> store bundle versions
        └─> transport: agents fetch bundle for their scope
              └─> agent policy: verify assignment and signature ──> CEL single-event evaluation ──> compiled rule sets to enforcement points

Sensors ──> agent events: OCSF construction, telemetry profile filter ──> spool ──> batch upload
  └─> server events: validate, store detections and context, raw to the raw store if enabled
        ├─> detection: correlation rules, alerts
        ├─> lineage: edges uploaded by agents as lineage events, plus cross-device edges from content hashes
        └─> exporters: SIEM destinations with per-destination queues and retries
```

Certificate and command-dispatch requests from exposed roles are untrusted. The PKI module derives issuance authority from protected records and independently verifies proof (`pki.md` section 3); the command dispatcher verifies approval and expiry against database time before signing a fresh artifact-bound grant. Request-row insertion never confers signing authority. Module interfaces provide those protected records under BE-04; roles do not bypass schema ownership.

Single-event rules evaluate on the agent, correlation on the server (EDR-01). The same policy envelope carries MDM desired state, EDR detections and DLP enforcement with domain-specific execution semantics (blueprint section 4).

Events are OCSF 1.9.0 (EV-02); the classes each domain emits and the `ricevanta` extension are in `../specs/ocsf-profile.md`.

## 5. Storage

- PostgreSQL 17 or later is the system of record; 17 is the floor for its support window (16 leaves support in 2028, 17 in 2029, verify) and so that operators who prefer physical backups have incremental backup available. Event tables use native declarative partitioning by day with no DEFAULT partition; a `jobs` task creates partitions two days ahead and, past the configured retention (EV-01 defaults), runs `DETACH PARTITION CONCURRENTLY` and drops them, so retention never runs a row-by-row DELETE. Events carry typed columns for the keys used to filter and retain (time, class, severity, device, rule) with B-tree indexes, and one `jsonb` column for the full OCSF body under `lz4` TOAST compression, stored once and referenced by detections; no GIN index sits on the ingest path. Ingest uses `pgx` `CopyFrom` in batches of 5,000 to 10,000 rows, tuned by measurement; `synchronous_commit=off` is allowed for context events and bounded raw rows only, where losing the last 600 ms on a crash is acceptable, never for detections, lineage, audit or administrative rows. 10^7 events a day is about 116 rows per second, so the binding limits are disk, vacuum and query latency, not row rate; a load test on the target hardware sets the point where the raw store is required.
- Raw telemetry, when a device group is switched to the full profile, goes to the bundled ClickHouse, to an external search destination through the exporters, or, for a bounded investigation set of at most 50 devices for 7 days, into PostgreSQL partitions under the same rules (EV-01); at C9's upper rate that set is at most 5×10^6 rows a day. ClickHouse is Apache-2.0, needs no JVM, documents a single-node minimum of 8 GB (verify) and ships two LTS releases a year each supported for one year, and columnar storage with codecs stores events in a fraction of a search index's space (vendor benchmark, verify); investigation queries are structured filters plus substring matches on command lines, which it serves without a full-text index. The raw store holds bounded-retention telemetry and is excluded from backups by default. Two hedges: the `events` module writes raw telemetry through a raw-store interface with two implementations at v1.0.0, ClickHouse and none, so a later OpenSearch implementation is an adapter rather than a redesign; and the ClickHouse schema (typed OCSF base columns plus one JSON column, native JSON type or string to be measured) and the Sigma-to-SQL translator are benchmarked on real EDR telemetry in v0.4.x (`../roadmap.md`) on ingest rate, bytes per event and query latency, with the outcome "keep, or swap to OpenSearch before v0.8.x". Every deployment profile sets a per-query memory limit and a query timeout, since an unbounded aggregation can take the node's RAM.
- The blob store (`platform/blob`) has two backends, local filesystem and S3-compatible. It holds installer packages, agent release packages, rule-pack archives and exported reports. Evidence snippets stay in PostgreSQL (DLP-02).
- Backup is `pg_dump` of PostgreSQL plus the blob store plus the master key held separately for Docker Compose; the Helm chart relies on the PostgreSQL operator's backups. Restore order: master key, PostgreSQL, blob store, then the issuing CA keys are verified against the stored certificates before the `jobs` role starts issuing.

## 6. Secrets

Secrets at rest use envelope encryption: a server master key from the environment, a file or an external KMS wraps per-secret data keys, so rotating the master key rewraps data keys without re-encrypting the data. The master key reaches only the `api` and `jobs` roles. Issuing CA key rows are readable only by the `jobs` database credentials, and their data keys are wrapped under a `jobs`-scoped key that the master key does not unwrap, so an `api` replica, which holds the master key, can neither read nor unwrap a CA key. Each agent-facing role (`agent`, `device`, `radius`) receives its own role-scoped data key from the environment, which unwraps only its TLS key and, for `radius`, the gateway shared secrets. Issuing CA keys and the `device` role's TLS key may instead live in a PKCS#11 device or the KMS.

The inventory: issuing CA keys, server TLS private keys for the `agent`, `device` and `radius` roles, the policy and command signing key, the APNs push key and certificate, RADIUS shared secrets, SCEP challenge secrets, break-glass second-factor seeds, directory bind credentials, OIDC and SAML client credentials, Git credentials, and export, mail and webhook destination credentials.

## 7. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: per-module schemas and the import-graph check keep the monolith splittable later; PostgreSQL as the only coordination layer means one stateful service to back up; the handler rules are the fixes comparable servers had to make after shipping.

Trade-offs: writing the DDM engine, the ACME server and EAP-TLS in-project is work that a library would otherwise carry, accepted because no maintained Apache-compatible library exists for any of the three; `NOTIFY` stays off every high-rate path because its commit lock is cluster-wide and scales with the rate of notifying commits.

Dependencies: `cel-go`, `pgx`, `klauspost/compress`, `layeh/radius`, `radius-eap`, `go-oidc`, `go-ldap`, `elimity-com/scim`, `minio-go`, `clickhouse-go`, NanoMDM, `smallstep/crypto`, `micromdm/scep`, Fleet's MS-MDE2 code, the OpenSearch and Elasticsearch clients; all with rows in `../licensing.md`.

Limits: fleet-wide raw telemetry needs ClickHouse or an external destination; the bounded PostgreSQL mode is for investigations, not fleets; Sigma-to-SQL translation for investigation queries is written in-project, since no SigmaHQ-maintained ClickHouse or PostgreSQL backend exists; the SCIM library lacks bulk operations; the SAML library is unsettled until its activity check.

Alternatives considered: Redis for caches and live results as Fleet uses it (rejected: a second stateful service; in-process caches and PostgreSQL cover the scale target); PostgreSQL session advisory locks for leader election (rejected: they pin a connection and fail behind transaction pooling; a lease row does not); TimescaleDB for event tables (rejected: retention and compression sit under the Timescale License; native partitioning covers the need); `pg_partman` (rejected: an extension in every image for what a small job does); OpenSearch as the bundled raw store (rejected: a JVM with heap and shard sizing for self-hosters, and its Sigma backend matters little since single-event rules evaluate on the agent; it stays an export destination); Elasticsearch and Loki as the raw store (rejected: license); Quickwit (rejected: an object-storage log search engine now owned by Datadog, verify, without the typed-column analytics the investigations need); a generated OpenAPI document (not chosen: generator support for 3.1 is partial); MicroMDM as the MDM base (rejected: in maintenance mode, its own notes point to NanoMDM); FreeRADIUS as a separate process (rejected: GPL-2.0).
