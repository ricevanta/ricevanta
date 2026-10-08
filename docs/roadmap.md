# Roadmap

Refines blueprint section 10. Milestone numbers and their primary goals are unchanged; this file adds what each release must also contain so that v1.0.0 covers every feature with full support on the v1.0.0 targets (`platform-support.md`). Earlier modules keep evolving in later releases.

| Release | Primary goal (blueprint) | Additions |
|---|---|---|
| v0.1.x | Repository, Rust agent, Go backend, Vue console, secure enrollment | Policy envelope, CEL profile and OCSF profile defined. Minimal CA for enrollment identity. Personal developer accounts and test machines for all sensor work (`project.md`). |
| v0.2.x | Device inventory and core MDM | Apple MDM server with APNs and DDM. Windows OMA-DM enrollment server. |
| v0.3.x | Built-in PKI | Full CA, ACME, SCEP (RSA and ECDSA), external CA integration, hardware-backed keys on all three OSes. |
| v0.4.x | EDR telemetry, detection, response | ES extension, ETW collectors, eBPF programs, Windows Event Log collection, first Windows driver build under test signing (alert-only allowed in this release). Company registered; Apple entitlement, EV certificate and Partner Center requests filed. |
| v0.5.x | DLP classification and enforcement | Scanner helper, blocking on Windows driver, ES and Linux BPF LSM and fanotify, session clipboard helpers, browser extension for Chrome and Edge. Alert-only allowed in this release only where blocking is not yet passing. |
| v0.6.x | Data lineage | Lineage graph. Browser extension for Firefox and Safari. |
| v0.7.x | RADIUS and VPN | EAP-TLS and RadSec. FortiGate and Cisco ASA profiles tested against gateways. |
| v0.8.x | Unified policies, rule adapters, SIEM | Sigma, YARA, Falco, Presidio-style, Gitleaks-style and osquery adapters. SIEM destinations. |
| v0.9.x | Integration, compatibility, performance, hardening | Capability matrix acceptance tests pass on macOS ARM64, Windows x64 and Linux x64. Performance benchmarks published. |
| v1.0.0 | Complete release | Every feature domain, full support, three targets, production signing under the company. |
| v1.x | | Windows ARM64, Linux ARM64, macOS x64 where Apple still supports it (`platform-support.md`, targets). |
| v2.0.0 | | Capabilities deferred because they cannot be tested on personal accounts (`platform-support.md`, deferred to v2.0.0). |

Ordering constraints behind the additions:

- Enrollment (v0.1.x) needs device certificates before the full PKI (v0.3.x), so a minimal CA ships first.
- EDR and DLP ship before the rule adapters (v0.8.x), so the policy envelope and event schema are fixed in v0.1.x to avoid a later migration.
- Apple entitlements and the EV certificate have month-long lead times and bind to the company that files them, so the company is registered and the requests filed in v0.4.x, once the sensors work on personal setups.
- Browser extension store publication has its own lead time, so the extension starts in v0.5.x.
