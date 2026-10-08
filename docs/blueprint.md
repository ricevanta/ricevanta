# Ricevanta — Project Context & Technical Blueprint

**Tagline:** Lightweight by Nature. Powerful by Design.

**Slogan:** One Agent. Unified Protection. Open to Everyone.

**Status:** Planning and architecture design  
**Target:** v1.0.0 — First complete, production-ready release  
**License:** Apache-2.0  
**Development:** Open-source, community-driven, self-hosted

---

## 1. Project Vision

Ricevanta is a free, open-source, self-hosted endpoint security and management platform combining:

1. Mobile/Endpoint Device Management (MDM)
2. Endpoint Detection and Response (EDR)
3. Data Loss Prevention (DLP)
4. Data Lineage
5. Public Key Infrastructure (PKI)
6. RADIUS authentication and network access control
7. Unified Security Policies and Community Detection Rules
8. Security Event Management and SIEM Integrations

The name is inspired by rice, an essential source of daily energy across Asia.

Our philosophy: **Security should be essential, lightweight, reliable, and accessible to everyone.**

### Core Principles

- One lightweight, modular endpoint agent.
- One management platform and device identity.
- Shared telemetry, policy and enforcement architecture.
- High performance with low CPU, RAM and battery consumption.
- Completely free and open-source, including enterprise capabilities.
- No device-count restrictions, paid feature tiers, or mandatory subscriptions.
- Fully self-hosted with no required external cloud.
- Cross-platform, architecture-independent design.
- Support open standards and reusable community security rules.
- Privacy-first: process sensitive data locally whenever possible.
- Learn from existing projects, but design our own architecture and implementation.

The objective is not to combine existing agents into a single installer. Ricevanta should be an independently designed platform with a common runtime, extensible modules and OS-specific integrations.

---

## 2. Technology Stack

| Component | Technology |
|---|---|
| Endpoint Agent | Rust |
| Backend/API | Go |
| Web Console | Vue 3 + TypeScript |
| Primary Database | PostgreSQL |
| Default Security Event Schema | OCSF JSON |
| Unified Policy Format | YAML with CEL-style conditions |
| Communication | HTTPS, mTLS, optional gRPC/Protobuf |
| Certificate Management | Built-in PKI, X.509, ACME, SCEP |
| VPN Authentication | RADIUS, EAP-TLS where supported |
| Authentication | OIDC / SAML |
| Deployment | Docker Compose and Helm |
| Optional Event Search | OpenSearch / Elasticsearch |
| Source License | Apache-2.0 |

### Supported Platforms

Required before v1.0.0, chosen for the largest installed bases:

- macOS ARM64 (Apple silicon)
- Windows x64
- Linux x64

In v1.x: Windows ARM64, Linux ARM64, and macOS x64 where Apple still supports it. The design must stay architecture-independent so these are build and test work, not redesign. See `platform-support.md`.

These are intended support targets, not a claim of existing compatibility.

The endpoint must use one managed Rust agent architecture, with native OS helpers, extensions or drivers only where required.

OS-specific technologies:

- **macOS:** Endpoint Security, System Extensions, native Apple MDM/Declarative Device Management, Secure Enclave.
- **Windows:** ETW, Windows APIs, MDM/CSP, TPM; signed minifilter drivers where necessary.
- **Linux:** eBPF, fanotify, native service and package-management interfaces.

Avoid unnecessary kernel drivers and privileged components.

The v1.0.0 scope covers endpoint management for macOS, Windows and Linux. Android/iOS management is not an agreed requirement.

---

## 3. Core Features — v1.0.0

All modules below are part of the initial complete product, developed incrementally during v0.x.y releases.

### 3.1 MDM — Device Management

- Device enrollment and identity.
- Hardware and software inventory.
- Operating-system and application inventory.
- Software installation, updates and removal.
- Device configuration and supported management profiles.
- OS update management.
- Security baseline and compliance assessment.
- Remote commands and management actions.
- Remote lock and wipe where supported.
- Device grouping, ownership, tags and policies.
- Device lifecycle: enrollment, operation, suspension and retirement.
- Native management protocols and enrollment integration.

### 3.2 EDR — Endpoint Detection & Response

- Process and process-tree monitoring.
- File and filesystem monitoring.
- Network and connection telemetry.
- File integrity monitoring.
- Behavioral threat detection.
- Suspicious process execution and activity correlation.
- Sigma-compatible detection rules for supported event schemas.
- Alerts, investigations and response actions.
- Supported process termination and file quarantine.
- Threat intelligence and MITRE ATT&CK mappings.
- Security event history.

### 3.3 DLP — Data Loss Prevention

- Sensitive content identification and classification.
- PII, secrets, credentials and confidential-document detection.
- File-format detection independent of extensions.
- Document content extraction.
- File and archive inspection.
- Clipboard, USB, browser and cloud-data movement monitoring where supported.
- Data exfiltration detection.
- Content fingerprints and partial matching.
- Application, user and destination context.
- Allow, monitor, warn and block actions on supported channels.
- Organization-specific classification rules and exceptions.

Initial emphasis should include source code, API keys, customer information, Vietnamese personal identifiers and financial data.

### 3.4 Data Lineage — Data Provenance

Track supported data transformations and relationships:

- Where data originated.
- Which user, device and process accessed it.
- File copy, move and rename events.
- File modifications and derived documents.
- Data extraction into new files.
- Compression and archive relationships.
- Movement to USB, applications, browsers and external destinations.
- Relationships between original and derived content.
- Classification inheritance where justified.
- Lineage confidence and supporting evidence.

Use hashes, content fingerprints, process relationships and event correlation.

Do not assume every copy or transformation can be detected. Distinguish directly observed events from inferred relationships.

Data Lineage is a shared intelligence layer for EDR and DLP.

### 3.5 PKI — Certificate Management

- Built-in certificate authority capabilities.
- Unique device identities.
- Certificate issuance, enrollment and renewal.
- Certificate revocation and status checking.
- X.509, ACME and SCEP.
- Integration with external CAs.
- Separate certificates for agent identity, management and network access.
- Secure key storage, TPM/Secure Enclave where available.
- Certificate-based device authentication.

### 3.6 RADIUS — VPN & Network Authentication

Provide a self-hosted RADIUS service integrated with platform identity, certificates and device compliance.

Primary use case:

**Allow organizations to configure VPN gateways such as FortiGate and Cisco ASA/ASAv to authenticate or authorize managed users/devices using certificates issued by Ricevanta.**

Support two architectures:

1. Gateway validates the client certificate and uses RADIUS for supported additional authentication/authorization.
2. Compatible gateways pass EAP-TLS authentication to the RADIUS service, which validates the client certificate.

RADIUS requests do not inherently carry the client certificate. Integration must securely bind the authenticated certificate identity to the authorization decision.

Requirements:

- RADIUS authentication and authorization.
- EAP-TLS where supported.
- Device/user identity and compliance policies.
- Certificate trust and revocation validation.
- Access-Accept/Access-Reject.
- Authentication logs and auditing.
- FortiGate and Cisco VPN integration profiles.
- Optional 802.1X Wi-Fi and wired network access.

### 3.7 Security Events & SIEM

- OCSF JSON as the canonical security event format.
- Local event buffering and forwarding.
- Event enrichment, deduplication and filtering.
- Reliable delivery and retries.
- Multiple external SIEM destinations.
- Events for MDM, EDR, DLP, lineage, PKI, RADIUS and audit operations.
- Configurable export and retention.

Target integrations:

- ELK / Elasticsearch
- Splunk HEC
- OpenSearch
- Syslog
- OpenTelemetry Collector
- Grafana Loki
- Microsoft Sentinel
- Kafka
- S3-compatible storage

Prioritize standard OCSF JSON forwarding through authenticated transport and a configurable collector. Add dedicated destination adapters as needed.

No external SIEM is mandatory for Ricevanta to operate.

### 3.8 Web Console & Administration

- Device inventory and details.
- Device enrollment and compliance.
- Security alerts and investigations.
- DLP policies and violations.
- Data lineage exploration.
- Certificate inventory and CA administration.
- RADIUS/VPN integration configuration.
- Central policy management.
- Rule-pack management.
- Dashboard and reporting.
- Users, groups, RBAC and SSO.
- Audit logs.
- APIs and GitOps configuration.
- Agent/version management and updates.

---

## 4. Unified Rules & Policies

We need one common policy specification for the entire platform.

### Canonical Formats

- **OCSF JSON:** Events.
- **YAML:** Policy configuration.
- **CEL-style expressions:** Policy conditions.
- **Native rule formats:** Reused through adapters.

The common policy envelope should include:

- Metadata and rule ID.
- Domain: MDM, EDR, DLP, Lineage, PKI or Network.
- User/device/group/OS scope.
- Trigger/event type.
- Detection references.
- Conditions.
- Actions.
- Exceptions.
- Severity and confidence.
- Logging and evidence requirements.

Example proposed format:

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Policy

metadata:
  id: dlp.block-confidential-upload
  name: Block Confidential Uploads

spec:
  domain: dlp

  scope:
    device_groups:
      - corporate-devices

  trigger: data.egress.attempt

  detectors:
    - ref: yara:confidential-documents
    - ref: pii:vn.national-id

  condition: >
    data.classification == "restricted" &&
    destination.managed == false &&
    confidence >= 0.90

  enforcement:
    supported: block
    unsupported: alert
    audit: true
```

This schema is illustrative and must be formally defined.

### Community Rule Support

Support importing existing public security knowledge without rewriting every detection.

| Rule/Standard | Purpose |
|---|---|
| Sigma | Security logs and behavioral detection |
| YARA / YARA-X | File and content matching |
| Presidio-style recognizers | PII detection |
| Gitleaks-style patterns | Secrets detection |
| osquery packs | Device inventory and security assessment |
| Falco rules | Linux runtime detection where translatable |
| MITRE ATT&CK | Detection classification and coverage |
| CEL | Cross-module condition expressions |

Build a rule-adapter framework.

Unsupported syntax or OS capabilities must be reported explicitly rather than silently ignored.

Rule packs must be versioned, validated, tested, attributed, signed and reviewed for license compatibility.

Use one policy envelope but allow distinct execution semantics for MDM desired state, EDR detections and DLP enforcement.

---

## 5. Architecture

```text
                 Ricevanta Web UI
                  Vue 3 / TypeScript
                          |
                    Go Backend
          +---------------+----------------+
          |               |                |
     Management       Policy Engine     PKI / RADIUS
          |               |                |
          +---------------+----------------+
                          |
                  Event & Lineage
                     Services
                          |
                     PostgreSQL
                          |
                   SIEM Exporters
                          |
                     HTTPS/mTLS
                          |
                 Rust Endpoint Agent
          +---------------+----------------+
          |               |                |
         MDM             EDR              DLP
          |               |                |
          +---------------+----------------+
                          |
                   Data Lineage
                          |
             Shared Event / Policy Engine
                          |
                 Native OS Adapters
                          |
               macOS / Windows / Linux
```

### Agent Design

- One managed installation and update lifecycle.
- One endpoint identity.
- One policy synchronization pipeline.
- Shared OS event collectors.
- Shared local telemetry queues.
- Shared policy and classification cache.
- Independent feature modules.
- Asynchronous, event-driven architecture.
- Native OS integrations isolated behind common interfaces.
- Local operation during network outages.
- Secure agent update and rollback mechanism.

**One agent does not require exactly one process.** OS extensions, drivers and specialized helpers are permitted where necessary.

### Backend Design

Start with a Go modular monolith.

Logical modules:

- Device management
- Policy management
- Security detection
- DLP classification
- Lineage relationships
- PKI
- RADIUS integration
- Event ingestion and export
- Authentication and authorization
- Audit and administration

Keep databases, queues and external infrastructure minimal.

---

## 6. Open-Source Research References

Study the following projects and technologies to understand architectures, algorithms and protocols.

We do not intend to clone or mechanically combine existing products.

| Area | References | Main learning objectives |
|---|---|---|
| MDM | FleetDM, NanoMDM, Munki, osquery | Enrollment, inventory, configuration, software management |
| EDR | Wazuh, Santa, Tetragon, Tracee, Falco, Velociraptor | Endpoint sensors, event processing, detection and response |
| macOS Sensor | HarfangLab endpoint-sec, Santa, Mac Monitor | Endpoint Security framework, performance, authorization |
| Windows Sensor | Windows ETW, Windows Drivers RS | Process/file/network telemetry, native enforcement |
| DLP | Presidio, MyDLP, OpenDLP, Apache Tika | Sensitive-data classification, content extraction, DLP concepts |
| Content Detection | YARA-X, Magika, Gitleaks, detect-secrets | Pattern matching, file recognition, secrets |
| Data Lineage | OpenLineage, OpenMetadata, W3C PROV, BLAKE3 | Provenance, fingerprints, graph relationships |
| PKI | Smallstep step-ca, ACME, SCEP | Certificate lifecycle and device identity |
| RADIUS | FreeRADIUS, layeh/radius, radius-eap | Protocol handling, EAP-TLS, policy integration |
| Policy | CEL, Cedar, OPA, SigmaHQ, pySigma | Policy evaluation, rule interoperability |
| Telemetry | OCSF, OpenTelemetry Collector, Vector, Fluent Bit | Events, buffering, routing and export |

### Primary Repositories

**MDM**
- https://github.com/fleetdm/fleet
- https://github.com/micromdm/nanomdm
- https://github.com/osquery/osquery
- https://github.com/munki/munki

**EDR**
- https://github.com/wazuh/wazuh
- https://github.com/northpolesec/santa
- https://github.com/HarfangLab/endpoint-sec
- https://github.com/cilium/tetragon
- https://github.com/aquasecurity/tracee
- https://github.com/falcosecurity/falco
- https://github.com/Velocidex/velociraptor

**DLP**
- https://github.com/data-privacy-stack/presidio
- https://github.com/VirusTotal/yara-x
- https://github.com/google/magika
- https://github.com/gitleaks/gitleaks
- https://github.com/apache/tika

**Data Lineage**
- https://github.com/OpenLineage/OpenLineage
- https://github.com/open-metadata/OpenMetadata
- https://github.com/BLAKE3-team/BLAKE3

**PKI / RADIUS**
- https://github.com/smallstep/certificates
- https://github.com/FreeRADIUS/freeradius-server
- https://github.com/layeh/radius

**Policies / Standards**
- https://github.com/ocsf/ocsf-schema
- https://github.com/SigmaHQ/sigma
- https://github.com/SigmaHQ/pySigma
- https://github.com/cel-expr/cel-spec
- https://github.com/cedar-policy/cedar
- https://github.com/open-policy-agent/opa

**Logging**
- https://github.com/open-telemetry/opentelemetry-collector
- https://github.com/vectordotdev/vector
- https://github.com/fluent/fluent-bit

Commercial products to benchmark: Cyberhaven, Nightfall, CrowdStrike, Microsoft Intune/Defender and Jamf.

These are learning references, not approved code dependencies.

---

## 7. Performance Objectives

Ricevanta must be designed for ordinary employee and developer laptops, including devices with 16 GB RAM.

Initial engineering targets:

| Metric | Target |
|---|---|
| Idle agent RAM | ≤ 80 MB |
| Typical idle CPU | < 1% averaged |
| CPU architectures | x64 and ARM64 |
| Baseline monitoring | Event-driven |
| Content scanning | On-demand, cached, resource-limited |
| AI/NLP | Optional backend workload |
| Offline mode | Supported |
| Event delivery | Batching, buffering, retries |
| Battery impact | Minimized and benchmarked |

Targets must be measured across operating systems and workloads; they are not established performance results.

Heavy analysis must not block normal file operations unnecessarily.

Optimize for bounded memory, low wakeups, minimal duplicated telemetry and low-latency enforcement.

---

## 8. Security and Privacy Requirements

- Secure device enrollment and bootstrap.
- Unique device identities using mTLS.
- Signed policies and software updates.
- Secure local credentials and private keys.
- RBAC and SSO for administrators.
- Full administrative audit logs.
- Protected agent configuration and tamper-resistance controls.
- Local sensitive-data classification by default.
- Avoid unnecessary raw file-content collection.
- Encryption in transit and at rest.
- Secret management and secure key rotation.
- Configurable retention and data minimization.
- Offline policy evaluation.
- Explicit failure behavior for unsupported or unavailable enforcement.
- Cross-platform security and compatibility testing.

Do not promise enforcement on a data channel until the implementation can demonstrate it.

---

## 9. Open-Source and Licensing Strategy

The intended Ricevanta source license is **Apache-2.0**.

Requirements:

- Free self-hosting.
- No enterprise-only proprietary source modules.
- No artificial endpoint-count limits.
- Public source code for all product functionality.
- Permissively licensed dependencies preferred.
- Maintain third-party attribution and SBOM.
- Track community rule licenses independently from application code.

Important:

- Fleet Free's MIT-licensed portions can be considered for reuse.
- Wazuh and FreeRADIUS include GPL code requiring separate compatibility assessment.
- MyDLP is an older GPL-based reference, not a preferred implementation foundation.
- Community YARA/Sigma rule repositories may use licenses different from their specifications.
- Commercial source-available enterprise modules must not be copied without authorization.
- GPL-licensed services may sometimes be integrated as separately distributed processes, subject to legal review.

Learn from the projects, but independently implement Ricevanta's own architecture where appropriate.

---

## 10. Development Roadmap

Use SemVer and multiple development releases before the first complete stable release. `roadmap.md` refines this table with what each release must also contain.

| Release | Primary Milestone |
|---|---|
| v0.1.x | Repository, Rust agent, Go backend, Vue UI, secure enrollment |
| v0.2.x | Device inventory and core MDM |
| v0.3.x | Built-in PKI and certificates |
| v0.4.x | EDR telemetry, detection and response |
| v0.5.x | DLP classification and enforcement |
| v0.6.x | Data lineage tracking and investigations |
| v0.7.x | RADIUS and VPN integration |
| v0.8.x | Unified policies, rule adapters and SIEM integration |
| v0.9.x | Complete integration, OS compatibility, performance and security hardening |
| **v1.0.0** | **Complete production-ready release covering every agreed feature domain** |
| v2.0.0 | Capabilities that need vendor programs unavailable to a personal account: Automated Device Enrollment, Windows ELAM and protected process |

Earlier modules must continue to evolve throughout subsequent v0.x.y releases.

v1.0.0 is not intended as a restricted MVP.

Before v1.0.0, each functional module must have an end-to-end, documented, tested operational capability on its declared supported platforms. Features must not be silently omitted. Exact OS-specific capability matrices and acceptance tests should be established during the design phase.

---

## 11. Suggested Repository Structure

```text
ricevanta/
├── agent/             # Rust endpoint agent
├── server/            # Go backend and services
├── console/           # Vue 3 administration UI
├── schemas/           # Event and policy specifications
├── rulepacks/         # Native/community security rules
├── integrations/      # MDM, PKI, RADIUS, SIEM adapters
├── deploy/            # Docker Compose, Helm, examples
├── docs/              # Architecture, ADRs, specifications
├── tests/             # Integration, E2E, compatibility tests
├── LICENSE
└── README.md
```

The final repository layout should be determined during architecture design.

---

## 12. Instructions for AI agents

Working rules for agents and contributors live in `AGENTS.md` and `instructions/` at the repository root. Design work proceeds in the order given by `instructions/workflow.md`: analysis (`analysis.md`), decisions (`decisions.md`), architecture, per-domain designs, specifications. Do not implement features before the design covers OS limits, resource consumption, security implications and compatibility. Prefer native integrations, open standards, measurable performance and maintainability over microservices, duplicated collectors and vendor-specific dependencies. Every design states benefits, trade-offs, dependencies, limits and alternatives.

### Final Vision

Ricevanta should ultimately provide one management platform through which organizations can:

- Manage their endpoints.
- Detect and respond to security threats.
- Identify and prevent sensitive-data leakage.
- Understand where their data comes from and where it goes.
- Manage device certificates.
- Authorize compatible VPN and network access.
- Apply common security policies.
- Integrate with existing enterprise security infrastructure.

All from a free, open-source, self-hosted platform built around one lightweight managed endpoint agent.

**Lightweight by Nature. Powerful by Design.**

**One Agent. Unified Protection. Open to Everyone.**
