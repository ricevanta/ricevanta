# Agent design

How `ricevanta-agent` and its companion processes are built: internal structure, OS adapters, the enforcement model, local IPC, local state, the memory budget and its enforcement, updates, and tamper resistance. The process topology and the server protocol are in `architecture.md`; enrollment in `design/pki.md`. Decisions: AG-01 to AG-09 in `decisions.md`.

## 1. Internal structure of the core

```
ricevanta-agent
├── runtime        async executor, one OS thread per telemetry source, supervision of helpers, metering, health
├── identity       device identity, hardware-backed keys, enrollment, renewal
├── transport      server client: mTLS HTTPS, long-poll, upload
├── policy         bundle and command verification, CEL evaluation, compiled rule sets per enforcement point
├── events         OCSF event construction, filtering, spool, batching
├── state          SQLite: state.db (policy cache, inventory, action journal, helper state) and lineage.db
├── mdm            inventory collection, configuration, software, compliance
├── edr            telemetry normalization, Sigma evaluation, response actions
├── dlp            classification orchestration, channel decisions, evidence
├── lineage        file and process identity, edges, inheritance
└── os             traits implemented once per OS (section 2)
```

Domain modules depend on `runtime`, `policy`, `events`, `state` and `os`. They do not depend on each other; lineage consumes EDR and DLP events through the event pipeline.

## 2. OS adapter interface

Every OS-specific capability sits behind a trait in the `os` layer, implemented in one crate per OS (`os-macos`, `os-windows`, `os-linux`):

| Trait | Provides |
|---|---|
| `ProcessSource`, `FileSource`, `NetworkSource` | Telemetry streams from the mechanisms in the `platform-support.md` capability matrix; Windows ETW through `windows-rs` bindings directly, since the dedicated ETW crate has had no release since 2024 (verify) |
| `Enforcer` | Installs compiled rule sets into the enforcement point; delivers content-decision requests with an open file descriptor or handle |
| `KeyStore` | Creates, signs with and, where the platform offers it, attests hardware-backed keys; `rustls` signing through `rustls-cng` on Windows, `security-framework` on macOS and `tss-esapi` on Linux; the Linux fallback is a root-only software key flagged per device |
| `Inventory` | Hardware, OS, software, users and disks (MDM-01) |
| `Installer` | Software install, update and removal (MDM-01) |
| `Session` | Enumerates login sessions and reaches the session helper |

A capability the OS cannot deliver returns an explicit `Unsupported(reason)` that the core reports to the server and the console shows per device (blueprint section 8).

## 3. Enforcement model

Enforcement points hold their own decision data. The core compiles the policy bundle into per-enforcement-point rule sets (path, process, signer, destination and device rules) and installs them incrementally (section 7): into the Endpoint Security extension over XPC, into the driver through its communication port, into BPF maps. A rule-only decision never leaves the enforcement point; the target is under 1 ms at the 99th percentile, measured per OS. Authorization and permission rules are never throttled, sampled or muted by resource governance.

Content decisions (DLP) are the exception. The enforcement point holds the operation and passes an open descriptor or handle for the file to the core; the core passes it to `ricevanta-scan`; the answer returns within the per-policy deadline (default 2 s, bounded by the OS deadline). Every policy declares its fail mode for a missed deadline, a throttled check or an unavailable helper: `open` (allow and record an audit event, the default) or `closed` (block). A scanner crash is handled apart from a timeout: the decision is retried once with a fresh helper, and a second crash on the same content hash applies `closed` and raises an alert. The browser extension follows the same model within the browser's own timeouts.

Processes in the user session are untrusted input: a missing or unresponsive session helper or browser extension is an unavailable helper and is reported, and a policy may deny network connections to a browser process until its extension connects, using the network enforcement point, since the browser channels have no other one.

Ricevanta's own processes are excluded from their own checks: muted in Endpoint Security, listed by signature in the driver, held in a trusted-process map for BPF, so inspection cannot deadlock on itself.

Enforcement while the core is down (restart, update, crash) differs per OS: the Endpoint Security extension and the driver keep their installed rules; Linux BPF LSM rules survive through pinned links and maps; fanotify permission checks lapse. Content decisions during that time take the policy's declared fail mode, since the helper is unavailable.

## 4. Local IPC

- macOS: XPC Mach services with code-signing requirements. The core connects to each system extension's listener (`NSEndpointSecurityMachServiceName` and `NEMachServiceName`, both app-group-prefixed), and the Safari handler reaches the core through a Mach service registered under the app-group prefix, since sandboxed processes cannot look up arbitrary global names (verify both directions and the prefix rules).
- Linux: Unix domain sockets; the peer is checked with `SO_PEERCRED`, and with `SO_PEERPIDFD` on kernels 6.5 and later; below that the executable is verified through `/proc` with a residual PID-reuse window (verify).
- Windows: named pipes; the core opens a handle to the client process from its pipe client ID and keeps it for the connection's lifetime, then checks the process token and the signed image through that handle.
- Messages are length-prefixed and serialized with a Rust-native binary serializer (`postcard`), since both ends ship in the same release. File descriptors and handles travel with the message where the OS allows it.
- Browsers: Chrome, Edge and Firefox launch `ricevanta-nmhost` as a JSON native-messaging host that relays to the core; the managed browser policy disables user-level host manifests so a user cannot register a substitute host (`NativeMessagingUserLevelHosts` in Chrome and Edge; verify the Firefox equivalent). A `connectNative` port keeps the extension's service worker alive. Safari sends native messages to the extension handler inside `Ricevanta.app`. Force-install and the Safari `AlwaysOn` extension state follow DLP-01.
- Driver: the minifilter communication port with versioned C structs.

## 5. Local state and spool

State lives in SQLite (`rusqlite` with bundled SQLite, pinned to a current release), chosen because the lineage graph needs path queries, which recursive SQL gives and a key-value store does not, and because it is the one candidate with SQL, a documented durability model and no server process. Two databases, both readable only by root or LocalSystem and protected by section 9:

- `state.db`: policy cache, inventory snapshot, response-action journal, helper state. WAL mode with `synchronous=FULL`, since a response action that was executed must never be forgotten after a power loss.
- `lineage.db`: the lineage graph (`design/lineage.md`). WAL mode with `synchronous=NORMAL`, writes batched into one transaction per second and a checkpoint every 10 s, so a power loss costs at most the edges since the last checkpoint; per-edge fsyncs would cost battery and disk wakeups.

Memory rules for every connection: `cache_size=-2048` (2 MiB), `mmap_size=0`, a fixed prepared-statement cache, one connection per database. Recursive queries carry an explicit depth limit, which is the cycle guard. SQLite allows one writer at a time, which fits a single core process; helpers never open the databases.

Event spool: a directory per event class in drop order (raw telemetry, context, lineage edges, detections and DLP matches, audit), each holding append-only segment files of length-prefixed records with a CRC32C per record. A segment holds one class only, so dropping by class is dropping whole segments. One shared byte counter enforces the cap (default 512 MB or 5 % of the volume, whichever is smaller); when full, the oldest sealed segment of the lowest class is deleted first, and the drop is itself recorded as an audit event. Sealed segments are zstd-compressed and uploaded whole. The active segment is synced on seal and every 500 ms; on start the agent truncates each active segment at its first bad record. The one-class-per-segment rule is load-bearing: the surveyed shippers (Vector, Fluent Bit, Beats, osquery, the OpenTelemetry Collector) cap by bytes or count and drop oldest or newest, none by class.

Offline: the cached policy stays in force without expiry. Certificate renewal and recovery are in `design/pki.md`.

## 6. Memory budget

AG-02 defines idle RAM as the sum over resident user-mode Ricevanta processes of the per-OS private footprint metric: `phys_footprint` on macOS, private working set on Windows, proportional set size on Linux, so shared framework pages are not counted once per process. The reference configuration is one login session and one browser. The 80 MB target (blueprint section 7) is a design target, not a hard limit: the allocation below is the starting point, it is re-derived from the first prototype measurement, and the budgets the self-watchdog enforces (section 7) are policy values the operator can raise:

| Process | Idle budget |
|---|---|
| `ricevanta-agent` | 44 MB |
| `ricevanta-updater` | 4 MB |
| Endpoint Security extension and Network Extension (macOS) | 16 MB together |
| `ricevanta-session` | 6 MB per session |
| `ricevanta-nmhost` or the Safari handler | 2 MB per browser |
| `ricevanta-scan` | 0 when idle (not running); capped at 256 MB when running |

Reference total: 72 MB on macOS, 56 MB on Windows and Linux. Kernel pool and BPF map memory are reported separately.

## 7. Resource governance

No product that combines EDR and DLP publishes a footprint near 80 MB; telemetry-only agents reach tens of MB and full EDR agents sit at 200 MB and above (third-party measurements, verify). Low RAM and CPU are therefore properties the agent enforces on itself against measured budgets, not a number promised in advance.

- Self-watchdog: the `runtime` module meters CPU time per OS thread (one thread per telemetry source; helpers are metered as processes), samples rule evaluation time one event in N rather than timing every evaluation, and accounts memory by the owned data-structure size of each unit plus the per-process footprint. Budgets come from the policy bundle. When a budget is exceeded for longer than its window, the offending unit is throttled first and disabled second, the device reports the event, and the console shows the unit as degraded. The agent never grows to stay complete; osquery's watchdog applies the same rule by restarting its worker and denylisting the offending query.
- Hot-source control, telemetry only: every notification source keeps per-path and per-process event rates. A source that exceeds its rate is sampled, then muted at the enforcement point with the mute reported as an event, so a busy build directory or backup job cannot drive the agent past its budget. Authorization and permission rules are exempt (section 3); a throttled content check takes the policy fail mode and raises an alert; repeated mutes attributed to one user become a detection, since flooding a path to get it muted is an evasion.
- Footprint telemetry: each process samples its own CPU, footprint, open descriptors and event rates on a fixed interval (default 60 s) and ships them as OCSF events; the console shows the budget against the measurement per device and per group, and a fleet-wide regression is an alert.
- Incremental rule installation: a bundle update is diffed against the installed rule sets and only the changed rules are installed into the enforcement points, with the driver and BPF maps updated in place. A full reinstall per policy change is the failure that Sysmon's configuration reload showed (non-paged pool growth per reload, verify).
- Performance gate in CI: every agent build runs the footprint benchmark (idle footprint per process, idle CPU, event-path latency) and fails when a metric regresses against the last release beyond its tolerance. Footprint is gated on hosted runners for the core and helpers; CPU and latency, which are noisy on shared runners, and everything involving the Endpoint Security extension, the driver or BPF LSM are gated on the self-hosted machines in `project.md`. The gate exists from the first agent build (`roadmap.md`, v0.1.x).

## 8. Update

Releases publish signed packages per OS to the blob store or to the project's download URL. The server serves the release manifest at `GET /agent/v1/update`, the one path besides renewal that update-only mode keeps open; `ricevanta-updater` downloads, verifies the release signature, the manifest expiry and the OS code signature, refuses a manifest version lower than the installed one, stages, and applies through the OS package mechanism. Rollout is staged by device group and percentage with a health gate: the updated core must start, load its cached policy and report healthy to the updater over local IPC within a window (default 15 minutes), or the updater restores the previous package it kept staged; server reachability is reported but not required, so a server outage does not roll devices back. This local rollback is the one path to a lower version and needs no manifest. A release package contains the updater too; the updater replaces itself last and the service manager restarts it, and the core restores the previous updater binary if the new one fails to start. The driver and system extensions follow the same manifest but apply through OS-specific mechanisms: `OSSystemExtensionRequest` from `Ricevanta.app` on macOS, the driver package on Windows, and the core reloading pinned BPF objects on Linux.

## 9. Tamper resistance

Prevention only where the OS provides it, reporting elsewhere. The precondition per OS:

- macOS: the system extension is non-removable only with the MDM `SystemExtensions` payload, so protection depends on Apple MDM enrollment.
- Windows: without ELAM and protected process (v2.0.0) an administrator can stop the service at boot or in safe mode, which the driver cannot report once the core is stopped and the server detects as a missed check-in.
- Linux: root can remove BPF pins, kill the core, clear immutable attributes or change the kernel command line, so BPF LSM self-protection is detection, and prevention would need a locked boot chain (Secure Boot with a signed unified kernel image and lockdown) that the agent only reports (verify).

Configuration protection and uninstall authorization: the enrollment configuration, the local state and the spool are readable and writable only by root or LocalSystem, and the core ignores any local change to its configuration that is not a signed bundle. Uninstalling or stopping the agent through the package manager, the service manager or `Ricevanta.app` requires an uninstall token: a signed command from the server for a named device, or, for an offline device, a one-time code the console derives from the device record that the installer's uninstall path verifies against the device identity. Without the token the uninstall path refuses and reports; on macOS the MDM `SystemExtensions` payload and on Windows the driver's self-protection back the refusal, on Linux it is reporting only (section 9 preconditions). Removal through the MDM channel (Apple MDM remove, OMA-DM unenroll) goes through the same signed-command path.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: rules compiled into the enforcement points keep authorization latency off the IPC path and keep enforcing while the core restarts; one core process keeps identity, policy and the server connection single; the self-watchdog and footprint telemetry turn the 80 MB target into something measured and enforced rather than promised; a separate updater can roll back a broken core.

Trade-offs: a separate updater is one more resident process; Swift shims on macOS add a second language where Apple frameworks require it; metering by thread and by owned structure sizes is approximate; the Linux fallback to a software key weakens identity on hosts without a TPM.

Dependencies: Rust crates `tokio`, `rustls`, `rustls-cng`, `security-framework`, `rusqlite`, `aya`, `endpoint-sec`, `windows-rs`, `tss-esapi`, `cel`, `postcard`, `zstd`, `crc32c`, `blake3`, a TLSH crate; all with rows in `licensing.md`.

Limits: Linux fanotify enforcement lapses during a core restart; Wayland clipboard is unsupported; Safari exposes no downloads API, so Safari downloads are covered by the file-system channel only; tamper resistance and uninstall refusal against a local administrator are reporting on Windows until v2.0.0 and on Linux without a locked boot chain.

Alternatives considered: RocksDB for local state as osquery uses it (rejected: C++ dependency, larger binary, no SQL for the graph); pure-Rust key-value stores such as `redb` or `fjall` (rejected: no SQL, no production users listed); JSON for local IPC (rejected: event volume from the Endpoint Security extension); `cel-cxx` as the CEL runtime (rejected: C++ build chain and cross-compilation limits; `cel` ships the conformance harness); `libbpf-rs` instead of `aya` (not chosen: both are maintained; `aya` keeps the build pure Rust and `libbpf-rs` stays the fallback if CO-RE on the kernel floor misbehaves); updates applied by the core itself (rejected: a broken core cannot roll itself back); a fixed process memory cap that restarts the agent (rejected: loses enforcement and hides which unit was at fault); policy expiry offline (rejected: turns an outage into a loss of enforcement).
