# Platform support

What Ricevanta supports on each operating system, which mechanism delivers it, and which limits the operating system imposes. Acceptance tests in v0.9.x prove every row; until then, entries are the mechanism expected to deliver the capability, not results.

## Targets

| Target | Release |
|---|---|
| macOS ARM64 (Apple silicon) | v1.0.0 |
| Windows x64 | v1.0.0 |
| Linux x64 | v1.0.0 |
| Windows ARM64 | v1.x; needs ARM64 driver signing and ARM64 CI hardware |
| Linux ARM64 | v1.x; eBPF and the agent are architecture-neutral, so this is a build and test matter |
| macOS x64 (Intel) | v1.x, only if still supported by Apple at that time; macOS 26 is reported as the last Intel release (verify) |

The design stays architecture-independent: no x64-only assumptions in the agent, the driver or the build.

## Version floor

| OS | Floor | Reason |
|---|---|---|
| macOS | 14 | Endpoint Security and DDM feature set |
| Windows | 11 23H2; Windows 10 22H2 until Microsoft support ends | Driver and CSP baseline |
| Linux | Kernel 5.10 with BTF and BPF LSM enabled; Ubuntu 22.04+, Debian 12+, RHEL 9 family, Fedora current, openSUSE Leap 15.6+ | BPF CO-RE needs BTF; blocking needs BPF LSM; fanotify permission events need CAP_SYS_ADMIN |

Out of scope at v1.0.0 unless a decision adds them: Windows Home editions, Windows Server, Linux without BPF LSM (telemetry only), Android, iOS.

## Deferred to v2.0.0

These cannot be tested on personal accounts (`project.md`, vendor programs), so no acceptance test can pass before v1.0.0 (SH-01). The console shows them as "not available in this version".

| Capability | Needs | v1.0.0 behaviour |
|---|---|---|
| Apple Automated Device Enrollment | Apple Business Manager | Manual and token-based enrollment |
| Windows ELAM and protected process | Microsoft Virus Initiative membership, HLK submission | Driver self-protection (`ObRegisterCallbacks`) |

## Vendor programs and signing

External dependencies the project holds on behalf of all self-hosters (PF-03). Self-built sensors run without the features that depend on them.

| Platform | Component | Dependency | Lead time |
|---|---|---|---|
| macOS | MDM server | Apple push certificate from the Apple Push Certificates Portal; one-year lifetime; renew with the same Apple ID or every device re-enrolls | Days |
| macOS | Endpoint Security client, Network Extension | Entitlements granted by Apple to one developer team; months of waiting reported (verify); manual signing with a provisioning profile; notarization | Months |
| Windows | Kernel driver | Partner Center account, EV certificate, minifilter altitude from Microsoft (30 business days), WHCP certification through an HLK lab (controller plus physical test clients); attestation and preproduction signing for development only | Months |
| macOS | Automated Device Enrollment (v2.0.0) | Apple Business Manager account | Weeks |
| Windows | ELAM and protected process (v2.0.0) | Microsoft Virus Initiative membership plus HLK submission; membership not guaranteed | Months |

## Capability matrix

"Driver" is the Windows kernel component (AG-01). "Ext" is the browser extension (DLP-01). "ES" is macOS Endpoint Security. "NE" is a macOS Network Extension.

| Capability | macOS | Windows | Linux |
|---|---|---|---|
| Process telemetry | ES | ETW | eBPF |
| Block process exec | ES AUTH_EXEC | Driver process-creation callback | BPF LSM |
| File telemetry | ES | ETW, USN journal, driver | fanotify, eBPF |
| Block file open | ES AUTH_OPEN | Driver | fanotify permission event |
| Block write, rename, copy to a destination | ES AUTH_RENAME, AUTH_CREATE, AUTH_COPYFILE | Driver | BPF LSM |
| Block write to removable media | ES AUTH_MOUNT plus path rules | Driver plus device install policy | BPF LSM, udev |
| Network telemetry | ES plus NE | ETW | eBPF |
| Block network | NE | WFP user mode; driver callout where needed | eBPF cgroup and LSM hooks |
| Clipboard monitor and block | Session helper (poll `changeCount`, replace) | Session helper (listener, clear) | X11 session helper; Wayland unsupported |
| Browser upload, paste, download | Ext (Chrome, Edge, Firefox); Safari upload and paste through Ext, download through the file channel | Ext | Ext |
| Profiles, OS updates, lock, wipe | Apple MDM server | Agent plus OMA-DM server | Agent; no native wipe, LUKS key destruction where LUKS is managed |
| Software install, update, remove | Agent (pkg; Homebrew optional) plus MDM | Agent (msi, msix, exe; winget optional) | Agent (apt, dnf, zypper, flatpak) |
| Hardware key for identity | Secure Enclave (P-256) | TPM 2.0 | TPM 2.0 if present, else a root-only software key flagged per device |
| Tamper resistance (preconditions in `design/agent.md` section 9) | ES extension protection with the MDM `SystemExtensions` payload | Driver self-protection; reporting only against a local administrator until ELAM and protected process (v2.0.0) | Permissions, immutable attributes, BPF LSM self-protection; reporting only against root |

## OS-imposed limits

Recorded as unsupported and shown per device in the console:

- Wayland clipboard: the protocol forbids reading another client's clipboard.
- Linux fanotify permission checks lapse while the agent core is down; BPF LSM rules, the Windows driver and the Endpoint Security extension keep enforcing (`design/agent.md` section 3).
- Linux native remote wipe.
- Content inspection inside email clients, messaging apps and AirDrop; these are observed through file and network channels only.
- Safari downloads: Safari exposes no downloads API to extensions, so they are observed through the file channel only.
- Windows devices whose code-integrity policy rejects the driver: none expected with WHCP certification and HVCI-compatible code (verify).
