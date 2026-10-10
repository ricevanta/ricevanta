# Platform support

Ricevanta targets modern, maintained operating systems. This document owns OS eligibility, required configuration and the capability matrix. Matrix entries are design mechanisms, not compatibility results; the [qualification specification](specs/platform-qualification.md) defines the evidence required before claiming support.

## Targets

| Target | Release |
|---|---|
| macOS ARM64 (Apple silicon) | v1.0.0 |
| Windows x64 | v1.0.0 |
| Linux x64 | v1.0.0 |
| Windows ARM64 | v1.x; needs ARM64 driver signing and ARM64 CI hardware |
| Linux ARM64 | v1.x; eBPF and the agent are architecture-neutral, so this is a build and test matter |
| macOS x64 (Intel) | v1.x, only on releases Apple still maintains and after separate qualification |

The design stays architecture-independent: no x64-only assumptions in the agent, the driver or the build.

## OS eligibility and qualification

| OS | Eligible releases | Required baseline |
|---|---|---|
| macOS | Current and previous stable major releases on Apple silicon | Endpoint Security and Network Extension entitlements; profile-based Device Enrollment, which is user-approved and supervises the Mac on macOS 11 and later; managed Safari extension settings require macOS 15 or later |
| Windows | Windows 11 x64 Pro, Enterprise and Education releases receiving Microsoft security maintenance for that edition and servicing channel | Production-signed driver, tested management CSPs and required browser policies; HVCI qualification |
| Linux | Maintained x64 releases in the distribution table below | Running kernel 5.10 or later, usable BTF and CO-RE, active BPF LSM, required fanotify permission hooks, cgroup BPF programs attachable at the root of the cgroup v2 unified hierarchy, and a qualified filesystem/session configuration |

The macOS window is Ricevanta's policy, not an Apple lifecycle promise. Windows eligibility follows Microsoft's edition-specific lifecycle, including the servicing channel; an extended-support purchase does not restore an end-of-life release to eligibility. Windows 10, Windows Home, Windows Server, Android and iOS are outside v1.0.0 scope.

| Linux distribution | Eligible release rule |
|---|---|
| Ubuntu LTS | 22.04 or later while receiving standard security maintenance |
| Debian | 12 or later while receiving Debian security maintenance or Debian LTS coverage for the required packages |
| RHEL family | RHEL 9 or later and compatible rebuilds while the installed vendor release receives security updates |
| Fedora | Releases still in Fedora maintenance |
| openSUSE Leap | 16 or later while receiving maintenance updates |

Vendor maintenance and the API baseline make a release eligible. Support applies to declared configuration profiles that have qualification evidence, not every possible hardware and software combination. The finite required-unit manifest in `specs/platform-qualification.md` enumerates every eligible OS release and the browser, Linux kernel/filesystem/session, security and deployment coverage required for a Ricevanta release. Evidence records the exact lab environment and package digests. Neither a version number nor a successful build establishes support. Every required unit must pass before v1.0.0 ships.

Qualification is a property of a release candidate on a configuration profile (`specs/platform-qualification.md`). A device in the field has no qualification state: it reports its preflight result and per-capability support, and the console shows unsupported capabilities per device with the reason. Before an OS leaves the support window, the console identifies affected devices and the required upgrade. Cached policy remains installed when an OS becomes unsupported; continued operation is not a compatibility guarantee. An unresolved required mechanism remains a release blocker, not a reason to relabel the feature as optional.

### Browser coverage

A browser is supported through a browser adapter (EXT-06): data that declares its policy backend, native host locations, connector and blocking support per OS (`design/extensions.md` section 7). The required coverage for v1.0.0 is the four first-party adapters; each remains candidate until its required gates pass:

| Browser | Adapter | Required platforms | Eligible versions |
|---|---|---|---|
| Chrome | `io.ricevanta.browser.chrome`, required | macOS, Windows, Linux | Current stable release with current vendor security updates |
| Edge | `io.ricevanta.browser.edge`, required | macOS, Windows, Linux | Current stable release with current vendor security updates; connector policies from Edge 137 on Windows and Edge 151 on macOS, the content-script gate on Linux |
| Firefox | `io.ricevanta.browser.firefox`, required | macOS, Windows, Linux | Current stable release from 137 and ESR releases from 140.2 while they receive vendor security updates; `ContentAnalysis` exists from 137 and its download interception from 142 and ESR 140.2 |
| Safari | `io.ricevanta.browser.safari`, required | macOS | Vendor-maintained Safari version for each eligible macOS release, with its current security updates |

Each required browser/version enters the qualification manifest with its adapter, managed policy, browser extension and native-host package. The gate per browser and OS comes from its adapter (`design/agent.md` section 3). Browser applicability follows this table, not whether the browser happens to be installed on a test host. Preview channels do not qualify production support.

Any other browser, such as Brave, Vivaldi, Opera or a Firefox fork, is served by a `community` adapter. The agent runs the adapter's bypass self-test at preflight and after each adapter or browser change, and the console shows each capability on that browser as "community adapter, self-tested, not qualified", or as failing when the self-test fails. A community adapter becomes qualified only when the project adds it to the qualification manifest with evidence.

### Installation prerequisites

- macOS: verify the app and system-extension signatures, granted entitlements, extension activation, user-approved MDM and the supervision state needed by managed Safari settings. The host app must be installed before its Safari extension can be managed; the agent writes the native host manifest to the locations each browser adapter declares; Connector and `ContentAnalysis` policies name and pin the core (Chrome `verification` keys, Firefox `ClientSignature`); the Handoff restriction disables Universal Clipboard. No managed setting pre-approves pasteboard access, and neither user-granted access nor Handoff restriction supplies the missing per-read clipboard hook (`design/dlp.md` section 6.5).
- Windows: verify edition and release eligibility, the Microsoft-signed driver package, load and denial behavior with HVCI enabled, the configured code-integrity policy, required CSPs, the native host registry keys each browser adapter declares, managed browser connector and extension policies that name and pin the core, and `AllowClipboardHistory` and `AllowCrossDeviceClipboard` disabled. A policy that rejects the driver needs remediation before preflight passes.
- Linux: inspect `/sys/kernel/btf/vmlinux` and `/sys/kernel/security/lsm`, then load, attach and trigger the shipped CO-RE, BPF LSM and cgroup probes. Exercise fanotify allow and deny with the production flags on each protected filesystem class. Record kernel, boot configuration, cgroup mode, filesystem/mount layout and graphical sessions. Verify the native host manifests at the paths each browser adapter declares, the managed browser policies (`ContentAnalysis` pinning the core through `ClientSignature`, extension force-install) and the compositor's `ext-data-control-v1` support. A configuration flag or successful attach does not prove denial behavior.

Linux kernels may include BPF LSM without activating `bpf` in the boot-time LSM list. If activation needs a boot change, the installer proposes an additive change that preserves the complete existing LSM list. An administrator approves and reboots before preflight proceeds. A kernel package installed on disk does not qualify the running kernel. Required capabilities and permissions are tested before enrollment completes; preflight diagnostics do not make a telemetry-only device a supported v1 endpoint.

## Deferred to v2.0.0

These require vendor programs outside the v1.0.0 plan (`project.md`, vendor programs; SH-01). The console shows them as "not available in this version".

| Capability | Needs | v1.0.0 behaviour |
|---|---|---|
| Apple Automated Device Enrollment | Apple Business Manager | Profile-based Device Enrollment plus Ricevanta agent token bootstrap |
| Windows ELAM and protected process | Microsoft Virus Initiative membership, HLK submission | Driver self-protection (`ObRegisterCallbacks`); memory-protection telemetry from the Threat-Intelligence ETW provider is not collected |

## Vendor programs and signing

External dependencies are owned as described in PF-03 and `project.md`. Production qualification uses the signed distribution packages. Self-built sensors that lack the required entitlements or signatures do not provide the complete supported feature set.

| Platform | Component | Dependency |
|---|---|---|
| macOS | MDM server | MDM Vendor CSR Signing Certificate held by the project, granted by Apple Developer Support to a Developer Program or Enterprise Program account holder on request; each self-hosted MDM service obtains its own Apple MDM Push Certificate at identity.apple.com from a request the project's signing service signs, and renews it with the same Apple ID so the push topic and enrollments survive |
| macOS | Host app, Endpoint Security client, Network Extension | Project Apple developer team; granted entitlements and provisioning profiles; Developer ID signing, hardened runtime, notarization and stapling |
| Windows | Kernel driver | Hardware Dev Center/Partner Center account associated with an EV certificate, assigned minifilter altitude, HLK results and WHCP submission for Microsoft's production signature; attestation and preproduction signing are development paths |
| macOS | Automated Device Enrollment (v2.0.0) | Apple Business Manager |
| Windows | ELAM and protected process (v2.0.0) | Microsoft Virus Initiative membership and the required HLK submission |

## Capability matrix

"Driver" is the Windows kernel component (AG-01). "Ext" is the browser extension (DLP-01). "ES" is macOS Endpoint Security. "NE" is a macOS Network Extension.

Each row needs allow, deny, bypass and failure tests on the qualified configuration. File-channel protection of a downloaded file is a separate claim from preventing a browser transfer. A notification followed by remediation is a separate claim from preventing access.

| Capability | macOS | Windows | Linux |
|---|---|---|---|
| Process telemetry | ES | ETW | eBPF |
| Block process exec | ES AUTH_EXEC | Driver process-creation callback | BPF LSM |
| File telemetry | ES | ETW, USN journal, driver | fanotify, eBPF |
| Block file open | ES AUTH_OPEN | Driver | fanotify permission event |
| Rule-only block of write, rename, copy to a destination | ES AUTH_RENAME, AUTH_CREATE, AUTH_COPYFILE | Driver | BPF LSM |
| Rule-only block of removable media | ES AUTH_MOUNT plus path rules | Driver plus device install policy | BPF LSM, udev |
| Content block of file, removable-media and network-share transfers | Required exact-byte gate unresolved (`design/dlp.md` section 6.4) | Same required contract, mechanism unresolved | Same required contract, mechanism unresolved |
| Network telemetry | ES plus NE | ETW | eBPF |
| Block network | NE | WFP user mode; driver callout where needed | eBPF cgroup and LSM hooks |
| Clipboard monitoring | Session helper polling `changeCount` | Session helper receiving clipboard-change notifications | X11 selection watcher; Wayland through `ext-data-control-v1` where offered, the GNOME Shell extension on Mutter |
| Clipboard blocking | Required per-read gate unresolved (`design/dlp.md` section 6.5) | Same required contract, delayed rendering insufficient | X11 and Wayland owner candidates; first-read exclusion unresolved |
| Browser upload, paste, print blocking | Content-analysis agent for Chrome (Chrome Enterprise Core), Edge and Firefox (verify macOS); Chrome without cloud management and Safari retain required transfer blockers (`design/dlp.md` section 6.5); print outside a connector uses the unresolved exact-byte spool gate (`design/dlp.md` section 6.4); downloads through the connector hook where one exists, else the file channel | Content-analysis agent for Chrome (Chrome Enterprise Core), Edge and Firefox; Chrome without cloud management retains a required persistent-channel blocker (`design/dlp.md` section 6.5); print outside a connector uses the unresolved exact-byte spool gate (`design/dlp.md` section 6.4); downloads through the connector hook where one exists, else the file channel | Content-analysis agent for Chrome (Chrome Enterprise Core) and Firefox (verify Linux); Edge and Chrome without cloud management retain required persistent-channel blockers (`design/dlp.md` section 6.5); print outside a connector uses the unresolved exact-byte spool gate (`design/dlp.md` section 6.4); downloads through the connector hook where one exists, else the file channel |
| Profiles, OS updates, lock, wipe | Apple MDM server (DDM for updates, `DeviceLock`, `EraseDevice`) | OMA-DM (Policy CSP, `RemoteWipe`) plus agent (BitLocker forced-recovery lock, update orchestration) | Agent; lock by TPM2 slot removal and wipe by `luksErase` on a LUKS2 root the agent manages; no native wipe |
| Software install, update, remove | Agent (pkg; Homebrew optional) plus MDM | Agent (msi, msix, exe; winget optional) | Agent (apt, dnf, zypper, flatpak) |
| Hardware key for identity | Secure Enclave (P-256) | TPM 2.0 | TPM 2.0 if present, else a root-only software key flagged per device |
| Network-access key | Secure Enclave key through the MDM ACME payload for 802.1X and the built-in IKEv2 client; System keychain identity for FortiClient and Secure Client (verify hardware-bound use) | TPM 2.0 through the Microsoft Platform Crypto Provider, machine or user store | TPM 2.0 through tpm2-pkcs11 for NetworkManager; software key flagged per device for FortiClient and Secure Client (verify) |
| 802.1X EAP-TLS supplicant | MDM Wi-Fi and Ethernet payloads; TLS 1.3 from macOS 14 | WLAN and LAN profiles by the agent or OMA-DM; TLS 1.3 default | NetworkManager connection written by the agent |
| Network isolation | NE `NEFilterSettings` with default drop (verify persistence without the provider) | WFP persistent and boot-time hard filters | cgroup BPF at the cgroup v2 root |
| Process termination | Required identity-bound primitive unresolved (`specs/edr-response-actions.md` section 3.1) | `TerminateProcess` on a handle with terminate and query rights after successful identity validation | `pidfd_send_signal` |
| Operator-script descendant containment | Required mechanism unresolved (`specs/edr-response-actions.md` section 3.7) | Job object, qualification required | Transient cgroup, qualification required |
| File quarantine | Native identity exclusion unresolved (`specs/edr-response-actions.md` section 3.2) | Driver must exclude content mutation through handle-based removal | Lease, LSM guard and same-volume move candidate, proofs unresolved |
| Tamper resistance (preconditions in `design/agent.md` section 9) | MDM controls extension approval and activation; manual enrollment removal is an escape path that must be detected | Driver self-protection; reporting only against a local administrator until ELAM and protected process (v2.0.0); a local administrator can delete the WFP provider and its isolation filters, which the 60 s reconciliation reports as tamper (`specs/edr-response-actions.md` section 3.3) | Permissions, immutable attributes, BPF LSM self-protection; reporting only against root |

Clipboard rows pass only when every read, including the first read after copy and every read after an allowed consumer, is answered after its own decision or consumes a one-use allowance. Browser rows pass only when one verdict binds the exact bytes to one transfer and the gate contains every alternate request path. Both need bypass tests with simultaneous and later consumers, history and cross-device capture, page and worker APIs, established WebSocket and WebTransport sessions and a disconnected helper or extension. A notification, ownership change after a read, destination-wide allowance or later remediation does not pass.

## Required mechanism blockers

These are required v1.0.0 capabilities with no proved complete mechanism. They keep every affected required unit in candidate state and cannot become supported limits or `Unsupported` results:

- Clipboard: the required first-read and repeated-read contract and each native gap are defined in `design/dlp.md` section 6.5.
- File content, including newly typed removable-media and network-share writes, print spools and local download use: the exact-byte contract and existing-descriptor/mapping gap are defined in `design/dlp.md` section 6.4.
- Browser upload and paste: Safari exact-transfer mediation and established-session mediation for Chrome without Chrome Enterprise Core on each required OS and Edge on Linux remain unresolved under `design/dlp.md` section 6.5.
- macOS response: identity-bound termination and descendant containment for scripts remain unresolved under `specs/edr-response-actions.md` sections 3.1 and 3.7.
- Quarantine: native content and pathname exclusion remains unresolved under `specs/edr-response-actions.md` section 3.2; Linux requires proof of the candidate's LSM ordering, lease/mapping exclusion, exemptions and recovery on every required kernel/filesystem unit.

## OS-imposed limits

Recorded as unsupported and shown per device in the console:

- Wayland clipboard: the core protocol gives a background client no access to another client's selection; `ext-data-control-v1` (wayland-protocols staging) does, and KWin, wlroots compositors, Hyprland and Niri offer it. Mutter does not (verify), so GNOME sessions run the GNOME Shell extension that owns the selection inside the compositor (`design/agent.md` section 3); a session with neither is outside the eligible session configurations and is shown as unsupported.
- Chrome connector policies are `cloud_only`: without Chrome Enterprise Core, Chrome is gated by the content script. Edge connectors exist on Windows and macOS only, so Edge on Linux is gated by the content script.
- Print outside a connector requires the file gate at the rendered spool; the content-script gate does not cover print. The unresolved gate is listed under required mechanism blockers.
- Firefox native hosts: Firefox has no policy that disables user-level native messaging host manifests (verify), so a user-level manifest with Ricevanta's host name can take precedence over the system one (verify the lookup order). The agent reports such a manifest as a tamper finding; the content-analysis connector, pinned through `ClientSignature`, does not depend on the native host.
- macOS clipboard context: the reader of a pasteboard cannot be identified, and no managed setting pre-approves pasteboard access (the `com.apple.TCC.configuration-profile-policy` payload has no pasteboard service). These context limits remain even after the required per-read blocking mechanism is solved.
- Linux peer identity below kernel 6.5: without `SO_PEERPIDFD` the executable check through `/proc` has a residual PID-reuse window (`design/agent.md` section 4); Ubuntu 22.04 and RHEL 9 kernels are below 6.5.
- macOS attestation: no platform attestation exists for a daemon (verify), so macOS enrollment rests on the token and administrator approval (`design/pki.md` section 5).
- Linux fanotify permission checks lapse while the agent core is down; BPF LSM rules, the Windows driver and the Endpoint Security extension keep enforcing (`design/agent.md` section 3).
- Linux native remote wipe.
- Content inspection inside email clients, messaging apps and AirDrop; these are observed through file and network channels only.
- Safari downloads: no extension download API; the unresolved file gate can control local use only after download, so it does not prove prevention of the network transfer.
- Edge connector pin: Edge documents no equivalent of Chrome's `verification` key; the agent's pipe is created as the first instance with a SYSTEM-only creator ACL on Windows and its socket sits in a root-owned directory on macOS, so only an administrator can bind the name first.
- Windows remote lock: Windows 11 has no desktop remote-lock CSP; Ricevanta locks through BitLocker forced recovery, which Microsoft documents as unsupported on tablets, and a device without BitLocker and an escrowed recovery password reports lock unavailable.
- Linux lock and wipe need a LUKS2 root with an agent-enrolled TPM2 slot and escrowed recovery key; an unencrypted root cannot be encrypted in place.
- macOS: activation lock bypass codes are retrievable only within 15 days after supervision; `DeviceLock` on Apple silicon uses the Find My lock and fails without a recovery partition.
- Windows protected processes and SIP-protected macOS processes cannot be terminated, and files on the macOS signed system volume cannot be quarantined; the action reports `os_refused`.
- A running Windows executable cannot be deleted; quarantine schedules the delete for reboot unless its processes are killed.
- Linux hash-based exec blocks run through fanotify and lapse while the core is down; BPF LSM path rules stay in force. macOS and Windows hash blocks apply the policy fail mode on a verdict-cache miss while the core is down.
- Virtual machine traffic bridged through the host is not covered by host isolation (`specs/edr-response-actions.md` section 3.3), on every OS because each isolation mechanism is socket-level. macOS: the Network Extension filter sees flows of host sockets, and a guest's frames bridged by the hypervisor do not pass through it (verify). Windows: the WFP ALE layers see host connections, and a guest's frames through a Hyper-V external switch or bridged adapter do not (verify). Linux: the cgroup BPF programs see only sockets of host processes, and frames forwarded through a host bridge, `macvtap` or `tap` device never reach them.
- Application DNS over HTTPS or TLS is visible only as connections.
- Windows code-integrity policies can reject a driver despite its production signature. Such a configuration does not qualify until the policy permits the driver and its enforcement tests pass.

## Sources

- Lifecycle: [Apple security releases](https://support.apple.com/en-us/100100), [Windows release and edition servicing](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information), [Ubuntu](https://ubuntu.com/about/release-cycle), [Debian LTS](https://www.debian.org/lts/), [RHEL](https://access.redhat.com/support/policy/updates/errata), [Fedora](https://fedoraproject.org/wiki/Fedora_Release_Life_Cycle), [openSUSE Leap](https://news.opensuse.org/2026/04/01/leap-15-eol/).
- Apple prerequisites: [Safari extension management](https://support.apple.com/guide/deployment/depff7fad9d8/web), [Device Enrollment](https://support.apple.com/guide/deployment/device-enrollment-and-device-management-depd1c27dfe6/web), [certificates](https://developer.apple.com/help/account/create-certificates/certificates-overview), [notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), [MDM Vendor CSR Signing Certificate](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/).
- Windows signing: [driver signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [HLK](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/), [minifilter altitude](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request).
- Enforcement: [Chromium OnFileAttachedEnterpriseConnector](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/OnFileAttachedEnterpriseConnector.yaml), [Edge OnFileAttachedEnterpriseConnector](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/onfileattachedenterpriseconnector), [Edge OnBulkDataEntryEnterpriseConnector](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/onbulkdataentryenterpriseconnector), [Firefox policy templates, ContentAnalysis](https://mozilla.github.io/policy-templates/#contentanalysis), [content_analysis_sdk](https://github.com/chromium/content_analysis_sdk), [Chrome webRequest](https://developer.chrome.com/docs/extensions/reference/api/webRequest), [Firefox onBeforeRequest](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onBeforeRequest), [Safari declarative blocking](https://developer.apple.com/documentation/safariservices/blocking-content-with-your-safari-web-extension), [Endpoint Security open](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_open), [Endpoint Security mmap](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_mmap), [FwpmProviderAdd0 remarks on persistent objects](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovideradd0), [Windows clipboard operations](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-operations), [GetOpenClipboardWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getopenclipboardwindow), [ext-data-control](https://gitlab.freedesktop.org/wayland/wayland-protocols/-/merge_requests/336), [Linux LSM activation](https://docs.kernel.org/admin-guide/LSM/index.html), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [LSM file permissions](https://www.kernel.org/doc/html/latest/security/lsm-development.html), [Linux file leases](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.15.pdf), [`renameat2`](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.06.pdf), [fanotify permissions](https://man7.org/linux/man-pages/man2/fanotify_init.2.html).
