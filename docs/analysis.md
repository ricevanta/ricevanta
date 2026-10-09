# Requirements analysis

Where the blueprint collides with platform realities or with itself, what depends on what, and what is still unspecified. Decisions that resolve a conflict are in `decisions.md` (IDs such as `AG-01`). Support facts are in `platform-support.md`; license facts in `licensing.md`. Claims marked "verify" rest on vendor or forum sources rather than first-party documentation.

## 1. Conflicts

### C1. Vendor programs break "no external cloud" for the agent

The control plane is self-hosted, but Apple MDM delivery uses Apple's push service, and each deployment needs its own Apple MDM Push Certificate whose signing request the project signs with its MDM vendor certificate: a project-operated signing step at setup and at yearly renewal, the one dependency on the project that a self-hoster cannot remove. Chrome's content-analysis connector policies are `cloud_only`, so the strong browser gate on Chrome needs Chrome Enterprise Core, a Google-hosted dependency the operator accepts per deployment or forgoes for the content-script gate. Endpoint Security and Network Extensions need Apple-granted entitlements tied to a developer team. Windows driver distribution needs the submission accounts and production signature; ELAM needs Microsoft Virus Initiative membership. Self-builders need their own applicable grants and signatures for complete sensor support. Details and primary sources are in `platform-support.md`, vendor programs. Resolved by PF-03.

### C2. The native MDM channel is mandatory

On macOS, the required managed profiles, DDM, OS update management, remote lock and erase, activation lock management and FileVault escrow use Apple's management channel. The modern macOS baseline uses DDM for update management and qualifies the exact declarations on each eligible release. On Windows, an on-premises OMA-DM server works without Entra ID through MS-MDE2 discovery and the Provisioning CSP; Autopilot needs Entra. On Linux the agent is the whole MDM. Resolved by MDM-01.

### C3. Blocking without kernel code

| Channel | macOS (Endpoint Security) | Windows user mode | Windows driver | Linux (fanotify, BPF LSM) |
|---|---|---|---|---|
| Block process execution | Yes | No | Yes, process-creation callback | Yes, BPF LSM `bprm_check_security` |
| Block file open | Yes | No | Yes | Yes, `FAN_OPEN_PERM` |
| Block write, rename, copy to destination | Yes | No | Yes | BPF LSM; fanotify has no write-permission event |
| Block removable media mount | Yes | Device install policy | Yes | udev, BPF LSM `sb_mount` |
| Block network connection | Network Extension | WFP user mode | Yes | BPF cgroup and LSM hooks |

ETW is telemetry only. Fanotify permission groups need CAP_SYS_ADMIN. BPF LSM needs build support and activation in the running kernel's LSM list; version and successful program attachment do not prove that a hook runs. The installer triggers each required denial probe before completing preflight. Resolved by AG-01 and PF-02; runtime checks are in `platform-support.md`.

### C4. Memory target vs content inspection

The 80 MB idle target holds for the core runtime, not with YARA-X rules, a Magika model, document parsers and a CEL evaluator resident. Apache Tika is Java and cannot run in the agent. Resolved by AG-02.

### C5. Browser and clipboard channels need mediation in their own context

- Clipboard: observing a change and clearing afterwards is not blocking, since a consumer can read first. Every OS offers owner-side mediation instead: on Windows the owner sets delayed-rendering formats and receives `WM_RENDERFORMAT` only when a consumer requests the data, and `GetOpenClipboardWindow` names that consumer; macOS has promised pasteboard data (verify); on X11 the selection owner answers each `SelectionRequest` and sees the requestor. The residual race is the interval between the source's write and the helper's re-own, which is measured, not assumed. Wayland needs `ext-data-control-v1`, which compositors adopt unevenly.
- Browser transfers: Chrome's `webRequest` blocking callback is synchronous and `asyncBlocking` applies only to `onAuthRequired`, so an extension cannot hold an upload for a native-messaging scan there. Chrome, Edge and Firefox instead offer a local content-analysis agent interface (`content_analysis_sdk`; Firefox's `ContentAnalysis` policy) that holds uploads, pasted text, printing and downloads until the agent answers; Chrome's policies are `cloud_only` and Edge's exist on Windows and macOS only, and Safari has no such hook, so those cases rest on content-script interception, the weakest gate. Which hook a browser offers on which OS is declared in its browser adapter (EXT-06), so these facts live in data rather than in the agent.
- Cloud sync clients: observable as writes into known sync folders, a file-system channel.
- Email, messaging, AirDrop: not observable without app-specific integration.

Resolved by DLP-01; `specs/platform-qualification.md` defines the proof obligations, including bypass tests.

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

Enrollment (v0.1.x) needs a minimal CA before the full PKI milestone (v0.3.x). EDR and DLP need the policy and event contracts from v0.1.x, before adapter completion in v0.8.x. Native MDM and browser extension milestones are explicit in `roadmap.md`. Resolved by SH-02 and the roadmap.

### C12. Linux is many platforms

Distribution maintenance, the running kernel and active enforcement hooks, package managers, init systems, filesystems and mount layout, X11 versus Wayland, desktop versus server. A named maintained release is eligible, but support needs the exact configuration and behavioral evidence. Resolved by PF-02 and PF-04.

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
- MDM: installer hosting and package formats; security baseline authoring (CIS Benchmarks cannot be bundled); the definition of "compliant" and its consumers; the project-operated push-certificate signing service and its renewal flow (C1).
- EDR: telemetry source list per OS and the default set; response action catalogue and authorization; threat intelligence feeds and licenses.
- DLP: Vietnamese identifier validation rules (12-digit CCCD, 9-digit CMND, tax code, bank account patterns) and financial data types; fingerprinting method and partial-match threshold; Rust extraction libraries per document format.
- Lineage: confidence scoring, cross-device joins, console exploration views (model, identities, storage and retention are settled by LIN-01).
- PKI: certificate profiles and lifetimes, OCSP, CRL serving for non-agent consumers, external CA protocol; the policy-signing extended key usage OID under the project's IANA Private Enterprise Number.
- RADIUS: accounting, CoA and disconnect, FortiGate and Cisco attribute profiles.
- Events: export guarantees (classes and the extension are settled by EV-03).
- Backend: audit log immutability.
- Agent: the offline one-time uninstall code's derivation and lifetime.
- DLP channels: the clipboard re-own interval per OS and its measured bound; the Safari content-script gate and its bypass tests; the connector agent registration on Chrome and Edge per OS; the hold point for newly written content, since no OS offers a permission event on write completion (next open, rename to the final name, or unmount); the macOS pasteboard pre-approval; the GNOME Shell extension's selection ownership.
- Extensions: the exact WIT interfaces per capability (`classifier`, `parser`, `collector`, `responder`) with their match, text, broker and row schemas; machine-readable schemas for `extension.respond`, durable step rows, browser registrations, console bridge bindings and bridge messages; the connector contracts (`export-destination`, `ca-connector`, `notifier`, `enricher`) with their timeouts and retry rules; the `service` certificate profile; the report template format; community adapter facts for Brave, Vivaldi, Opera, Arc and the Firefox forks (LibreWolf, Waterfox, Zen) (`design/extensions.md`, `specs/extension-agent-runtime.md`).
- Program: test lab (Apple silicon hardware for macOS CI), AI/NLP models.

## 4. Facts to verify

- The exact DDM update declarations and reporting supported on every eligible macOS release; qualification uses those declarations rather than legacy update-command fallbacks.
- FortiClient and Cisco Secure Client EAP-TLS support; FortiOS SSL VPN deprecation status.
- Whether attestation-signed drivers are blocked once the Windows Driver Policy enforces; Microsoft's pages name only WHCP-signed and allow-listed drivers.
- `windows-drivers-rs` minifilter and WFP binding coverage and WHCP acceptance of Rust drivers; its README calls it not production-ready.
- Firefox has no policy equivalent of Chrome's `NativeMessagingUserLevelHosts` (none found in the Firefox policy schema) and the lookup order between user-level and system manifests; Safari native messaging from the sandboxed handler to the core's Mach service; a Safari web extension inside a Developer ID-signed, notarized `Ricevanta.app` distributed outside the App Store.
- Edge's further connector setup (whether an Edge for Business sign-in is required); Firefox `ContentAnalysis` on macOS and Linux; Chromium's connector timeout; Edge's agent pinning equivalent of Chrome's `verification` keys; the read-open of the completed spool file as the print hold point on each OS; Safari's `declarativeNetRequest` coverage of request methods and body types.
- macOS promised pasteboard data as the clipboard mediation point and whether the reader can be identified; whether a managed setting pre-approves an application's pasteboard reads under `NSPasteboard.accessBehavior`; Mutter's lack of `ext-data-control-v1` and the stability of `MetaSelection` across GNOME releases.
- Whether Apple grants the MDM Vendor CSR Signing Certificate to an individual Developer Program account; `mdmcert.download` availability as the fallback signer.
- `device-attest-01` draft status and whether a macOS daemon can obtain any platform attestation.
- Licenses of TLSH and its Rust crate, `clickhouse-go` and the `crc32c` crate; ClickHouse's documented single-node minimum; reading the Linux inode generation from BPF per file system.
- OCSF extension registration: the next free uid; an OCSF event validator for CI; whether `event_log_actvity` keeps its spelling in later schema versions; whether `is_truncated` and `untruncated_size` exist on `metadata` in 1.9.0; the `clipboard_activity` activity names.
- `cel-go` default option values (`CrossTypeNumericComparisons`, cost limit) and the exact excluded-case names of the CEL profile at the pinned cel-spec version.
- Licenses of pySigma, Magika model weights and `tss-esapi`.
- Extensions: wasmtime Tier 1 support on the three v1.0.0 host targets (macOS ARM64, Windows x64, Linux x64); whether `frame-src` on the console document governs a module frame's own navigations in every qualified browser; the license expression of `wasmtime`, `wit-bindgen` and `wasm-tools` (Apache-2.0 WITH LLVM-exception or Apache-2.0) and the size of `ricevanta-ext` with Cranelift against a no-compiler build; the safety contract of `Module::deserialize` for precompiled artifacts; the CSP `sandbox` response header on a top-level navigation in Safari and `'self'` matching in an opaque-origin document; Brave's reuse of Chrome's native-host directories and the Edge policy directory on Linux; Edge's inheritance of blocking `webRequest` for policy-installed extensions; the operating systems `content_analysis_sdk` supports, which its repository does not state.

## 5. Sources

- Maintained OS releases, enrollment, vendor signing and kernel prerequisites: primary sources in `platform-support.md`.
- Browser gating: [Chromium OnFileAttachedEnterpriseConnector](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/OnFileAttachedEnterpriseConnector.yaml), [Edge OnFileAttachedEnterpriseConnector](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/onfileattachedenterpriseconnector), [Edge OnBulkDataEntryEnterpriseConnector](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/onbulkdataentryenterpriseconnector), [Firefox policy templates, ContentAnalysis](https://mozilla.github.io/policy-templates/#contentanalysis), [content_analysis_sdk](https://github.com/chromium/content_analysis_sdk), [Chrome webRequest](https://developer.chrome.com/docs/extensions/reference/api/webRequest), [Firefox onBeforeRequest](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onBeforeRequest)
- Clipboard mediation: [Windows clipboard operations](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-operations), [GetOpenClipboardWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getopenclipboardwindow), [ext-data-control](https://gitlab.freedesktop.org/wayland/wayland-protocols/-/merge_requests/336)
- Safari and GNOME: [Safari web extension compatibility](https://developer.apple.com/documentation/safariservices/assessing-your-safari-web-extension-s-browser-compatibility), [NSPasteboard](https://developer.apple.com/documentation/appkit/nspasteboard), [Mutter meta-selection.h](https://gitlab.gnome.org/GNOME/mutter/-/blob/main/src/meta/meta-selection.h)
- Apple MDM vendor certificate: [MDM Vendor CSR Signing Certificate](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/), [forum 800736](https://developer.apple.com/forums/thread/800736)
- Endpoint Security entitlement: [Apple forums 743263](https://developer.apple.com/forums/thread/743263), [736042](https://developer.apple.com/forums/thread/736042)
- Windows driver signing: [Driver signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [ELAM submission](https://learn.microsoft.com/et-ee/windows-hardware/drivers/install/elam-driver-submission), [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/desktop/Services/protecting-anti-malware-services-)
- Windows MDM: [MS-MDE2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/98547779-b770-4730-9261-8ecaa1604c10), [Provisioning CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/provisioning-csp)
- Sigma license: [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License)
- CEL in Rust: [FOSDEM 2026](https://fosdem.org/2026/schedule/event/rust-cel), [cel-cxx](https://docs.rs/crate/cel-cxx/latest), [cel-rust](https://github.com/cel-rust/cel-rust)
- FortiGate: [FortiOS 7.4 RADIUS certificate auth](https://docs.fortinet.com/document/fortigate/7.4.0/new-features/471933), [FortiOS 8.0 IKEv2 EAP-TLS](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/726232), [IKEv2 RADIUS tip](https://community.fortinet.com/fortigate-3/technical-tip-ikev2-dialup-ipsec-tunnel-with-radius-server-authentication-and-forticlient-93597)
- Linux: [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [LSM activation](https://docs.kernel.org/admin-guide/LSM/index.html), [fanotify_init](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html).
- OCSF: [OCSF schema releases](https://github.com/ocsf/ocsf-schema/releases), [Ocsf.Schema 1.9.0](https://www.nuget.org/packages/Ocsf.Schema), [Tenzir OCSF versions](https://docs.tenzir.com/reference/ocsf)
- windows-drivers-rs: [The Register](https://theregister.com/2025/09/04/rust_windows_drivers)
- Wasmtime host async embedding: [`LinkerInstance::func_wrap_async`](https://docs.rs/wasmtime/latest/wasmtime/component/struct.LinkerInstance.html#method.func_wrap_async)
