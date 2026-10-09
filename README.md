# Ricevanta

Lightweight by Nature. Powerful by Design.

Ricevanta is a free, open-source, self-hosted endpoint security and management platform built around one lightweight agent: device management (MDM), endpoint detection and response (EDR), data loss prevention (DLP), data lineage, PKI, RADIUS network access, unified policies and SIEM export. One agent, one platform, one device identity, no device-count limits, no paid tiers.

Status: design phase. No application code yet. The design lives in `docs/`:

| File | Content |
|---|---|
| `docs/blueprint.md` | Product requirements and vision |
| `docs/project.md` | Domain, hosting, license, vendor programs |
| `docs/analysis.md` | Platform conflicts, dependencies, open specifications |
| `docs/decisions.md` | Decisions in force, by domain |
| `docs/platform-support.md` | Targets, version floor, capability matrix |
| `docs/licensing.md` | Third-party code and rule licenses |
| `docs/roadmap.md` | Release milestones |
| `docs/architecture.md` | System design: components, roles, protocols, keys, deployment |
| `docs/design/<domain>.md` | Per-domain design: `agent.md`, `backend.md`, `pki.md`, `lineage.md` |
| `docs/specs/<name>.md` | Policy envelope, CEL profile, OCSF profile, platform qualification; machine-readable files in `schemas/` |
| `branding/` | Brand identity (`BRAND_SPEC.md`), vector masters, build script and generated assets |

Targets for v1.0.0: macOS on Apple silicon, Windows x64, Linux x64.

Official sensor binaries (macOS Endpoint Security extension, Windows kernel driver) are signed by the project because Apple and Microsoft tie those signatures to one organization. Self-built sensors run without the features that need them.

License: Apache-2.0. Contributions: see `CONTRIBUTING.md`.
