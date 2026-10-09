# Requirements analysis

Where the blueprint collides with platform realities or with itself, what depends on what, and what is still unspecified. Decisions that resolve a conflict are in `decisions.md` (IDs such as `AG-01`). Support facts are in `platform-support.md`; license facts in `licensing.md`. Claims marked "verify" rest on vendor or forum sources rather than first-party documentation.

## 1. Conflicts

### C1. Vendor programs break "no external cloud" for the agent

Apple MDM needs an Apple push certificate. Endpoint Security and Network Extensions need Apple-granted entitlements tied to one developer team. Windows kernel drivers need an EV certificate and WHCP certification through HLK testing; ELAM needs Microsoft Virus Initiative membership. The server runs without any cloud, but the agent's privileged components cannot be built by self-hosters. Details in `platform-support.md`, vendor programs table. Resolved by PF-03.

### C2. The native MDM channel is mandatory

On macOS, configuration profiles, DDM, OS update enforcement (legacy MDM update commands are reported removed in the 2026 OS release, verify), remote lock, erase, activation lock and FileVault escrow only work over Apple's MDM protocol. DDM runs on top of that channel. On Windows, an on-premises OMA-DM server works without Entra ID through MS-MDE2 discovery and the Provisioning CSP; Autopilot needs Entra. On Linux the agent is the whole MDM. Resolved by MDM-01.

### C3. Blocking without kernel code

| Channel | macOS (Endpoint Security) | Windows user mode | Windows driver | Linux (fanotify, BPF LSM) |
|---|---|---|---|---|
| Block process execution | Yes | No | Yes, process-creation callback | Yes, BPF LSM `bprm_check_security` |
| Block file open | Yes | No | Yes | Yes, `FAN_OPEN_PERM` |
| Block write, rename, copy to destination | Yes | No | Yes | BPF LSM; fanotify has no write-permission event |
| Block removable media mount | Yes | Device install policy | Yes | udev, BPF LSM `sb_mount` |
| Block network connection | Network Extension | WFP user mode | Yes | BPF cgroup and LSM hooks |

ETW is telemetry only. Fanotify permission events need CAP_SYS_ADMIN; BPF LSM needs kernel 5.7+ built with BPF LSM enabled, which not every distribution ships (verify per distribution). Resolved by AG-01 and PF-02.

### C4. Memory target vs content inspection

The 80 MB idle target holds for the core runtime, not with YARA-X rules, a Magika model, document parsers and a CEL evaluator resident. Apache Tika is Java and cannot run in the agent. Resolved by AG-02.

### C5. Clipboard, browser and cloud channels have no OS hook

- Clipboard: macOS has no event (poll `NSPasteboard.changeCount` in the login session); Windows needs a clipboard listener window in the user session; Linux X11 allows a selection watcher; Wayland forbids reading another client's clipboard.
- Browser uploads: no OS exposes them. A browser extension (store publication per browser; Safari needs notarization) or TLS interception. Managed-browser policy can force-install extensions.
- Cloud sync clients: observable as writes into known sync folders, a file-system channel.
- Email, messaging, AirDrop: not observable without app-specific integration.

Resolved by DLP-01.

### C6. VPN gateways do not pass EAP-TLS from their own clients

- FortiGate SSL VPN (FortiOS 7.4.1+): the gateway validates the certificate and sends RADIUS a user name from a SAN field (UPN, email, DNS). Fortinet is moving SSL VPN toward IPsec (verify for FortiOS 7.6 and 8.0).
- FortiGate IKEv2: EAP passes through to RADIUS, but FortiClient initiates only EAP-MSCHAPv2 and EAP-TTLS; EAP-TLS is documented with the Windows native IKEv2 client. RadSec is required in FIPS mode.
- Cisco ASA with Secure Client: certificate authentication is local to the ASA; RADIUS authorizes with a user name from certificate DN attributes. EAP-TLS pass-through from Secure Client is not documented (verify).

RADIUS therefore sees only the user name the gateway extracted. Binding that name to the certificate needs unique per-device SAN values, RadSec mutual TLS, per-gateway secrets, and rejection of names without an issued, unrevoked certificate. Resolved by RAD-01.

### C7. Sigma rules do not target OCSF

Sigma rules declare Sysmon or Windows Event Log logsources and field names. Evaluating them needs a field map per logsource and the matching telemetry: event IDs 4688, 4624, 7045, registry, PowerShell script blocks, Sysmon-equivalent network and image-load events. Falco rules need a second map. Resolved by EDR-01.

### C8. Two CEL runtimes

Server policies evaluate in `cel-go`; agent policies in Rust (the `cel` crate, which ships the cel-spec conformance harness with an ignored-test list; or `cel-cxx`, which wraps cel-cpp through a C++ build chain). Divergence means a policy passes on the server and fails on an endpoint. Resolved by SH-02 and POL-01.

### C9. PostgreSQL alone vs telemetry volume

Raw process, file and network telemetry is 10^4 to 10^5 events per endpoint per day; 1,000 endpoints produce 10^7 to 10^8 rows per day. PostgreSQL with partitioning holds detections and bounded context, not raw telemetry at that rate. Resolved by EV-01.

### C10. Hardware-backed keys constrain TLS and enrollment

Secure Enclave keys are P-256 and non-exportable; TPM and CNG keys are reached through platform APIs. mTLS from Rust needs a TLS stack that delegates signing to a platform key (`rustls` with a per-platform `SigningKey`, or the platform TLS stack). SCEP commonly assumes RSA. Resolved by PKI-01.

### C11. Roadmap ordering

Enrollment (v0.1.x) needs certificates before the PKI milestone (v0.3.x). EDR and DLP ship before the policy envelope milestone (v0.8.x). The Apple MDM server and the browser extension had no milestone. Resolved by SH-02 and `roadmap.md`.

### C12. Linux is many platforms

Kernel floor, BTF availability, distribution families and package managers, init systems, X11 vs Wayland, desktop vs server. Resolved by PF-02.

## 2. Dependency order

```
OCSF profile ──────────────┐
Policy envelope + CEL profile ─┤
Agent runtime + OS adapters ───┼─> Enrollment + device identity (minimal CA)
                               │        ├─> MDM agent ──> Apple MDM server, Windows OMA-DM server
                               │        ├─> PKI (CA, ACME, SCEP) ──> RADIUS ──> VPN profiles
                               │        ├─> EDR telemetry ──> Sigma adapter ──> response actions
                               │        │        └─> Lineage (stable file and process identities)
                               │        ├─> DLP classification (scanner helper) ──> DLP enforcement
                               │        │        └─> Lineage classification inheritance
                               │        └─> Event export ──> SIEM adapters
```

Lineage needs the stable file and process identities of `design/lineage.md` section 2 from both EDR and DLP before it can be built.

## 3. Missing specifications

To be settled in design documents with a stated default.

- Identity: OIDC claim and directory attribute mapping; user-to-device binding on shared devices.
- MDM: installer hosting and package formats; security baseline authoring (CIS Benchmarks cannot be bundled); the definition of "compliant" and its consumers.
- EDR: telemetry source list per OS and the default set; response action catalogue and authorization; threat intelligence feeds and licenses.
- DLP: Vietnamese identifier validation rules (12-digit CCCD, 9-digit CMND, tax code, bank account patterns) and financial data types; fingerprinting method and partial-match threshold; Rust extraction libraries per document format.
- Lineage: confidence scoring, cross-device joins, console exploration views (model, identities, storage and retention are settled by LIN-01).
- PKI: certificate profiles and lifetimes, OCSP, CRL serving for non-agent consumers, external CA protocol.
- RADIUS: accounting, CoA and disconnect, FortiGate and Cisco attribute profiles.
- Events: OCSF class profile per domain and the `io.ricevanta` extension; export guarantees.
- Backend: audit log immutability.
- Agent: the offline one-time uninstall code's derivation and lifetime.
- Program: test lab (Apple silicon hardware for macOS CI), AI/NLP models.

## 4. Facts to verify

- Whether Apple issues MDM push certificates to accounts without Apple Business Manager.
- Timing of legacy MDM software-update command removal and DDM mandates in macOS 26 and 27.
- FortiClient and Cisco Secure Client EAP-TLS support; FortiOS SSL VPN deprecation status.
- Whether attestation-signed drivers are blocked once the Windows Driver Policy enforces; Microsoft's pages name only WHCP-signed and allow-listed drivers.
- `windows-drivers-rs` minifilter and WFP binding coverage and WHCP acceptance of Rust drivers; not production-ready as of its README.
- Firefox policy equivalent of Chrome's `NativeMessagingUserLevelHosts`; Safari native messaging from the sandboxed handler to the core's Mach service.
- `device-attest-01` draft status and whether a macOS daemon can obtain any platform attestation.
- Licenses of TLSH and its Rust crate, `clickhouse-go` and the `crc32c` crate; ClickHouse's documented single-node minimum; reading the Linux inode generation from BPF per file system.
- The `cel` crate's ignored-test list against the CEL profile once the profile is written.
- Licenses of pySigma, Magika model weights and `tss-esapi`.

## 5. Sources

- Apple push certificates: [appaloosa.io](https://www.appaloosa.io/blog/apple-push-notification-service-apns-mdm), [Kaspersky](https://support.kaspersky.com/KSC/13.1/en-US/64666.htm)
- DDM and macOS 26: [intuneirl.com](https://intuneirl.com/macos-ios-26-for-enterprise-ddm-deployment-and-the-intel-mac-sunset/), [ebf.com](https://ebf.com/en/trends/apple/wwdc-2026-sets-a-clear-direction-for-device-management/), [capaone.com](https://capaone.com/mdm-migration-without-wipe-macos-26-apple-fleet-consolidation/)
- Endpoint Security entitlement: [Apple forums 743263](https://developer.apple.com/forums/thread/743263), [736042](https://developer.apple.com/forums/thread/736042)
- Windows driver signing: [Driver signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [ELAM submission](https://learn.microsoft.com/et-ee/windows-hardware/drivers/install/elam-driver-submission), [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/desktop/Services/protecting-anti-malware-services-)
- Windows MDM: [MS-MDE2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/98547779-b770-4730-9261-8ecaa1604c10), [Provisioning CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/provisioning-csp)
- Sigma license: [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License)
- CEL in Rust: [FOSDEM 2026](https://fosdem.org/2026/schedule/event/rust-cel), [cel-cxx](https://docs.rs/crate/cel-cxx/latest), [cel-rust](https://github.com/cel-rust/cel-rust)
- FortiGate: [FortiOS 7.4 RADIUS certificate auth](https://docs.fortinet.com/document/fortigate/7.4.0/new-features/471933), [FortiOS 8.0 IKEv2 EAP-TLS](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/726232), [IKEv2 RADIUS tip](https://community.fortinet.com/fortigate-3/technical-tip-ikev2-dialup-ipsec-tunnel-with-radius-server-authentication-and-forticlient-93597)
- Linux: [fanotify_init](https://www.mankier.com/2/fanotify_init), [fanotify(7)](https://manpages.courier-mta.org/htmlman7/fanotify.7.html)
- OCSF: [Ocsf.Schema 1.9.0](https://www.nuget.org/packages/Ocsf.Schema), [Tenzir OCSF versions](https://docs.tenzir.com/reference/ocsf)
- windows-drivers-rs: [The Register](https://theregister.com/2025/09/04/rust_windows_drivers)
