# EDR response actions

The catalogue of EDR response command types: what each does on each OS, how it is authorized, its journal idempotency and reconciliation contract, its undo command and its behaviour while the device is offline. Command signing, dispatch grants, ordering and the action journal are generic and live in `policy-envelope.md` section 7; responder plans from extensions live in `extension-agent-runtime.md` section 6; the reasoning behind the catalogue is in `../design/edr.md` section 7. Decisions: EDR-04, BE-02, AG-05.

## 1. Common rules

- Command types are named `edr.<action>`. The signed payload is the command of `policy-envelope.md` section 7; `params` require per-type schemas under `schemas/commands/edr/`; those files are absent and block command admission (`../analysis.md` section 3).
- Targets are named by stable identity (`../design/lineage.md` section 2): a process by boot session, pid and start time; a file by volume, file identity and the expected SHA-256. Each primitive must bind identity validation and its side effect to the same process or file object, and return `target_changed` on mismatch. A separate PID or pathname check followed by a fresh lookup is insufficient. An unqualified primitive keeps its required platform action blocked (sections 3.1 and 3.2).
- Manual actions arrive as signed commands. Automatic actions come from an `edr` policy action (`kill_process`, `quarantine_file`, `isolate_host`, `block_process`) matched on the agent; the installed bundle authorizes them, they need no dispatch grant, and they use the same journal row under the local uid `auto:<bundle_uid>:<finding_uid>`, so crash recovery is identical.
- Every step that has a side effect writes a progress marker into the journal row with `synchronous=FULL` before and after the side effect. Recovery reads the marker and the observed system state; it never repeats a side effect blindly (AG-05).
- Each outcome is an OCSF remediation event (`ocsf-profile.md` section 1): kill is `process_remediation_activity` Evict, quarantine is `file_remediation_activity` Isolate, restore is Restore, host isolation is `network_remediation_activity` Isolate and un-isolation Restore, blocks are `remediation_activity` Harden, collection and scans are Detect.
- Offline: a command reaches a device only through a live poll and starts only inside its grant window; one that expires undelivered (at most 7 days) is marked undelivered by the server. Installed isolation, blocks and automatic actions keep working offline, and results upload on reconnect.

## 2. Catalogue

| Type | Effect | Protected by default (BE-02) | Undo |
|---|---|---|---|
| `edr.kill_process` | Terminate a process, optionally its descendants | More than 10 devices | None |
| `edr.quarantine_file` | Move a file into the encrypted quarantine store | More than 10 devices | `edr.restore_file` |
| `edr.restore_file` | Return a quarantined file | Always | `edr.quarantine_file` |
| `edr.isolate_host` | Drop all traffic except the allow list | More than 10 devices | `edr.unisolate_host` |
| `edr.unisolate_host` | Remove isolation, widen its allow list or set or shorten its `release_after` | Always | `edr.isolate_host` |
| `edr.kill_and_ban` | Interim hash block, kill every process of that image, optional quarantine, then the hash joins the managed block list | More than 10 devices | Removal from the block list (a weakening change) and `edr.unban` |
| `edr.unban` | Retire an interim hash block | Always | `edr.kill_and_ban` |
| `edr.collect` | Collect a triage package | More than 10 devices | None needed (read-only) |
| `edr.scan` | YARA-X scan of named paths | More than 10 devices | None needed (read-only) |
| `extension.respond` | Execute a validated responder plan | Union of every allowed child action's protection rules, including always-protected actions and the frozen fleet scope | Per step, through the actions above |
| `edr.run_script` | Run an operator script | Always | None |

The "always" entries are additions to the BE-02 default list: each one reduces containment or runs arbitrary code. Publishing a policy whose actions include `isolate_host` or `kill_process` is protected under `policy-envelope.md` section 2.3; block-list additions are not, except the fleet-wide addition of section 3.4; removals are weakening changes.

## 3. Actions

### 3.1 `edr.kill_process`

Params: process identity, `tree` (default false).

| OS | Mechanism |
|---|---|
| macOS | Required identity-bound termination primitive unresolved. `proc_pidinfo` start time or audit-token pid version followed by PID-based `kill(SIGKILL)` performs another lookup and can kill a replacement. The design has no selected and qualified public primitive that binds identity validation and termination to the same process object, so process termination remains a v1.0.0 release blocker. SIP refusal is tested separately after that primitive is selected |
| Windows | `OpenProcess(PROCESS_TERMINATE \| PROCESS_QUERY_LIMITED_INFORMATION)` on the pid; require `GetProcessTimes` to succeed and match the expected creation time, then call `TerminateProcess` on that same handle. A mismatch returns `target_changed`; a failed query never permits termination. Protected-process access refusal returns `os_refused` |
| Linux | `pidfd_open`, compare the start time from `/proc/<pid>/stat` read through the pidfd's process, then `pidfd_send_signal(SIGKILL)` on the same pidfd, which closes the PID-reuse window |

Reconciliation: termination is idempotent on an identity only through a qualified identity-bound primitive. A `running` row after a crash checks whether that identity still exists; absence reconciles to `succeeded` with `target_absent`. Otherwise recovery validates and terminates through the same object-bound primitive, never a fresh PID-based signal after a separate check. With `tree`, descendants are enumerated from the process table and each has its own identity and marker; every sub-step uses that primitive. The macOS blocker covers automatic actions, `kill_and_ban`, quarantine `kill_holders`, recovery and descendant sub-steps. Cancellation has no effect once termination runs.

### 3.2 `edr.quarantine_file` and `edr.restore_file`

Params: file identity, expected SHA-256, `kill_holders` (default false).

The quarantine store is a root-only or SYSTEM-only directory in the agent state directory. Each entry is the file content encrypted with AES-256-GCM under a per-device key in `state.db`, so neither a user nor another security product can execute or rescan it, plus a metadata row: original path, identity, owner, mode or ACL, flags, extended attributes or alternate data streams, timestamps and hash. Defaults, policy-tunable: 512 MB per file, a store of at most 2 GB or 2 % of the volume, entries kept 90 days and then purged with an audit event. A file over the limit or a full store returns `store_full`; kill and block remain available.

| OS | Open and remove |
|---|---|
| macOS | A readable `O_NOFOLLOW` descriptor pins the content source. Copy and pathname removal also require exclusion of content mutation and source-name replacement through the removal. `open`, an identity check and `unlink` alone do not provide that exclusion; the native transaction remains a release blocker until qualified. Files on the signed system volume or protected by System Integrity Protection return `os_refused` |
| Windows | Open with `FILE_FLAG_OPEN_REPARSE_POINT`, compare the 128-bit file ID, copy every data stream, delete with POSIX semantics. A mapped executable cannot be deleted while it runs: with `kill_holders` its processes are killed first; otherwise the driver denies new opens and execution of that file ID and the delete is scheduled for reboot, result `pending_reboot` |
| Linux | Candidate: readable descriptor, exclusive file lease, operation-specific BPF LSM guards and a same-filesystem move before copying, under section 3.2.1. Guard ordering, lease and mapping exclusion, exact caller authorization and recovery must pass on each required kernel/filesystem unit before the transaction is enabled. Linux quarantine remains a release blocker until those proofs exist |

While an entry exists, its hash is in the interim block set of section 3.4, so a re-dropped copy cannot execute.

Markers: `intent` records source and holding identities and names before a move, `secured` records a durable holding entry, `stored` records the encrypted copy after fsync, hash verification and metadata commit, then `removed` and `blocked`. A crash between the move and `secured` can leave either name present. Recovery reinstalls the guards, resolves both recorded names and reacquires content exclusion before proceeding; it never assumes the source is unchanged from the marker alone. Exactly one matching identity resumes the transaction. Before `stored`, missing, duplicate or ambiguous identities become `reconcile_required`; a partial encrypted copy is discarded and a matching holding entry is preserved. After `stored`, removal still needs identity exclusion; absence from both guarded names reconciles a completed removal only if the guard and journal establish that the identity could not escape elsewhere. A substituted entry is always left untouched. No recovery path uses an unchecked pathname deletion.

`edr.restore_file` params: quarantine id, destination `original` or an absolute path. The file is written to a temporary name in the destination directory, its metadata restored, then renamed into place; an existing file is never overwritten, the restored file takes the name `<name>.restored-<id>` instead. Markers: `written`, `renamed`, `unblocked`, `store_deleted`; the store copy is deleted only after `renamed` is durable. The interim block that the quarantine added is retired; a block-list policy entry for the same hash stays and is reported.

### 3.2.1 Linux quarantine candidate and proof obligations

The candidate has these ordered steps. They are a required qualification contract, not a claim that the current BPF or filesystem design supplies every exclusion.

1. Open the source parent and a root-only holding directory on the same filesystem. Record their identities, the source basename, a random holding basename, expected file identity and hash in `intent`. Open the source with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, require a regular file and compare its identity. `O_PATH` cannot supply the bytes to copy.
2. Publish guards for the source and holding entries and the pinned inode. Name guards bind filesystem identity, parent inode and basename; inode guards cover aliases through other mounts. Deny create, link, unlink, rename, attribute changes, open, write, truncate and new mappings that conflict with the transaction. A map update does not drain operations that passed a hook before publication. Qualification must establish which hook runs under which VFS lock and how those in-flight operations are contained.
3. Acquire `fcntl(F_SETLEASE, F_WRLCK)` on the readable descriptor. A qualifying kernel must refuse the lease while another file description, executable reference or file-backed mapping remains, including a mapping whose descriptor is closed. `/proc` enumeration alone cannot establish absence. A conflict returns `in_use`; `kill_holders` may terminate verified holders and retry once, but an unidentified or surviving holder still prevents the transaction. A lease-break signal or `F_GETLEASE` value other than `F_WRLCK` stops the transaction. Guards must keep access denied even if the kernel forces the lease to break; polling the lease before removal is not sufficient exclusion.
4. Require `st_nlink == 1`, capture metadata under the qualified exclusion, and hash through the leased descriptor. A mismatch returns `target_changed`. Move with `renameat2(RENAME_NOREPLACE)` to the holding basename, then fsync both parents and record `secured`. The rename hook must compare the actual source inode and both parent/name pairs while directory locks exclude replacement. A separate `statx` check cannot authorize the move.
5. Encrypt from the same descriptor, verify the stored SHA-256 and record `stored`. The unlink hook must compare the actual holding inode and require a single remaining link while the inode and parent locks exclude link and name changes. This check must also contain a hard-link operation that passed its hook before guard publication. Fsync the holding parent, record `removed`, then retire the transaction guard and lease. A hard-link conflict preserves the held file and reports `multiple_links`; it does not claim complete quarantine.

Every exemption binds the core task's kernel identity and start generation, transaction uid, operation, inode and exact source/destination entries. UID, executable path, PID alone and a blanket Ricevanta-process exemption do not authorize these operations. Existing policy self-exemptions do not apply to the quarantine guard. Guard state remains pinned across a core crash; after reboot, protected holding entries remain unreadable until recovery restores the guard. A filesystem without that protection, lease support or same-filesystem `RENAME_NOREPLACE` cannot run this candidate. An unresolved required filesystem or link case blocks release; `os_refused` is not a substitute for its required support.

### 3.3 `edr.isolate_host` and `edr.unisolate_host`

Params: allow list of remote CIDRs with protocol and port, `release_after` (optional duration). The agent adds the server addresses it resolved for its last connections and the configured agent-endpoint addresses, and the compiler injects the configured addresses into every compiled `isolate_host` action, so automatic isolation from a policy keeps the server reachable; DHCP, loopback and the ICMPv6 neighbour discovery needed for IPv6 links are always allowed. DNS is not allowed unless the operator lists a resolver, so isolated malware cannot tunnel through it, and the core needs no name resolution because the command carries addresses. At most 1,000 entries, the macOS rule limit (verify).

| OS | Mechanism |
|---|---|
| macOS | The Network Extension filter data provider stores the isolation set in its own container and applies `NEFilterSettings` with one allow rule per entry and the default action `drop`; the framework applies the rules to the system. Whether the rules hold while the provider process is not running is unconfirmed (verify); qualification tests it |
| Windows | User-mode WFP: a Ricevanta provider registered without `serviceName`, so the Base Filtering Engine loads its persistent filters at every start whatever the start type of the agent service (`FwpmProviderAdd0` remarks: the engine adds persistent objects of a provider that names a service only when that service is auto-start), a sublayer of maximum weight, persistent hard-block filters at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`, and higher-weight hard-permit filters for the allow list. Boot-time copies of the same filters hold isolation before the Base Filtering Engine starts. A block that clears the action right cannot be overridden by another sublayer |
| Linux | `cgroup_skb/egress` and `cgroup_skb/ingress` programs plus `cgroup/connect4`, `connect6`, `sendmsg4` and `sendmsg6` are attached at agent start to the cgroup v2 root with `BPF_F_ALLOW_MULTI` and pinned in bpffs. Isolation flips one flag in a pinned map and loads the allow list into an LPM-trie map, so it applies atomically, survives a core restart, and after reboot the core restores it before `network-pre.target`. Connects fail with `EPERM` instead of timing out |

Isolation is desired state in `state.db`. Applying it again is a no-op; every 60 s and after each restart the core compares the installed filters, rules or map with the desired state, reinstalls what is missing and reports a removal by a local administrator as a tamper finding. Recovery from a `running` row re-applies the desired state. `release_after` is checked against the monotonic clock and the server's next check-in; expiry un-isolates and reports. A later `edr.isolate_host` on an isolated device may only narrow the allow list and may not set or shorten `release_after`; widening the allow list or setting or shortening `release_after` on an existing isolation is `edr.unisolate_host` with the replacement `allow` or `release_after`. The `release_after` of an approved isolate command is part of the approved fields.

`edr.unisolate_host` removes the filters, rules or map entries and the desired state; with `allow` or `release_after` it replaces those on the existing isolation instead. An isolated device that cannot reach the server stays isolated. Offline release requires a signed release object (`policy-envelope.md` section 7): the operator files an `edr.unisolate_host` request as usual with the nonce the device displays, the approval binds the device uid and that nonce, `jobs` signs the object with the policy signing key in place of a command, the operator types it into the device's local tool, and the agent verifies it against the pinned chain, removes isolation as the command does and stores the object's hash so it is accepted once.

Virtual machine traffic bridged through the host is not covered by host isolation: all three mechanisms filter at the host's sockets, and frames a guest sends through a host bridge never reach them (`../platform-support.md`, OS-imposed limits).

### 3.4 `edr.kill_and_ban` and `edr.unban`

Params: SHA-256, `quarantine` (default true), `tree` (default true). Steps, each a sub-step with markers:

1. Interim block: add the hash to the interim block set in `state.db` and to each enforcement point's verdict cache (`../design/edr.md` section 7.2).
2. Kill every running process whose image hash matches, through section 3.1.
3. Quarantine the image files through section 3.2 when `quarantine` is set.

On a verified success the `detection` module adds the hash to the organization's managed block-list policy, an `edr` policy with `block_process` by hash. The server step runs through the `policy` module's write path with the requester's policy permission and the dry-run count of affected devices. It refuses the hash of an OS-vendor-signed binary or a Ricevanta binary, and the fleet-wide addition is a protected action (BE-02) when the dry-run count shows the hash on more than 10 devices. When the device's installed bundle contains the hash, the agent retires the interim entry. Interim entries are bounded (default 4,096), and an interim entry is retired only when the installed bundle contains the hash or by `edr.unban`; a full set refuses new bans with an alert. `edr.unban` retires an interim entry; removing the hash from the block-list policy is a weakening change under `policy-envelope.md` section 2.3.

### 3.5 `edr.collect`

Params: package name and package parameters. Packages are server resources; the first-party ones are `process-snapshot` (processes with identities, command lines, signers, hashes and sockets), `persistence` (services, scheduled tasks, launch items, cron and systemd units, Run keys), `event-logs` (bounded time ranges of the security channels, the systemd journal and the macOS unified log through `OSLogStore`, verify system-wide access from a daemon), `network-state` (routes, DNS configuration, firewall state) and `file` (one named file).

Bounds, policy-tunable: 100 MB per package (at most 1 GB), 10 minutes, 10,000 files. Raw user content never leaves the device (DLP-02): a `file` request is first classified by `ricevanta-scan` and refused when it is a user document or carries a classification; text artifacts pass the secret and identifier detectors with redaction, as script content does (`ocsf-profile.md` section 3); process memory is never collected.

Upload: zstd parts of at most 5 MB through the artifact path of `../architecture.md` section 3.4, keyed by command uid and part index with a SHA-256 per part and a manifest signed by the device identity key. Collection is read-only, so recovery restarts the package; parts already acknowledged are skipped by key. Cancellation stops collection and the result lists the parts uploaded.

### 3.6 `edr.scan`

Params: paths, `recursive`, `max_files` (default 10,000), `max_bytes` (default 2 GB). `ricevanta-scan` runs the scope's YARA-X rule packs under the limits of `../design/edr.md` section 5.4. Read-only; recovery restarts the scan; matches are findings.

### 3.7 `edr.run_script`

Operator scripts are signed commands, not extensions (`../design/extensions.md` section 4). Params: interpreter (`/bin/sh`, `/bin/zsh`, `/bin/bash`, Windows PowerShell or `pwsh`), the script body (at most 64 KiB, bound by the signature through the canonical params), arguments, identity (`system` or the console user), timeout (default 5 minutes, at most 60). Windows uses a job object and Linux a transient cgroup; qualification must prove descendant containment and termination, including attempted escape, before those mechanisms qualify. A macOS process group does not contain a child that calls `setsid` or changes groups. The design has no selected and qualified macOS mechanism that contains every descendant across those changes and core crashes, so operator-script execution remains a v1.0.0 release blocker on macOS. Standard output and error are capped at 1 MiB each and pass the secret and identifier detectors before upload.

Before launch the journal records the containment identity and ownership needed to recover or stop every descendant. Timeout or cancellation becomes terminal only after the qualified mechanism proves all owned descendants have stopped, including children that detached or outlived the interpreter. Missing ownership or surviving descendants leave `reconcile_required`, not `cancelled` or successful completion. Scripts are not idempotent: after a core crash, the agent never reruns a `running` script; it reconciles containment and reports unknown script completion. An expired command does not erase the containment obligation.

### 3.8 `extension.respond`

The responder produces a plan whose steps call the actions above; validation, persistence and recovery live in `extension-agent-runtime.md` section 6. A step inherits the complete contract of its action. The grant's allowed action set never includes `edr.run_script`.

Before signing `extension.respond`, `jobs` computes the union of the permissions required by every action in the allowed set, over the frozen device and entity scope and each bound parameter envelope. The requester must hold every permission. The parent is protected whenever any permitted child is protected, even if the eventual plan omits that child. Allowing `edr.restore_file`, `edr.unisolate_host` or `edr.unban` always requires their protected approval. Fleet thresholds use the complete frozen target set, not the size of one step.

The approval binds the parent request and device/command uid pairs, immutable package and component digests, recovery epoch, grant generation, allowed actions, entity identities, canonical parameter envelopes, step/byte limits and continue-on-failure mode. Permission and protection decisions come from the native action catalogue, never the module manifest. `jobs` rechecks current requester authority, approval and extension state before signing and each dispatch grant. The core rejects the whole plan before side effects if a step leaves that envelope or lacks its required approval. Widening the action set, scope or parameter envelope requires a new protected request; the wrapper cannot downgrade a child's rule. Exact action-permission mappings and these command/approval schemas remain implementation blockers until their catalogue and fixtures exist.

## 4. Acceptance cases

The verifier fixtures of `policy-envelope.md` section 7 apply to every type. In addition, each type crashes the agent before and after every marker and proves recovery without a repeated side effect; kill and quarantine refuse a reused pid and a replaced file; quarantine and restore round-trip owner, mode, ACL, extended attributes and alternate data streams; isolation holds across a core crash, a reboot and the removal of one filter, and passes only allow-listed traffic in both directions on IPv4 and IPv6; a script interrupted mid-run ends `reconcile_required`.

Termination cases pause after identity validation, exit the target, reuse its PID and prove the replacement survives, including reconciliation, automatic actions and each descendant sub-step. Windows cases cover matching creation time, mismatch, query failure and protected-process refusal with the required handle rights. Script cases fork, call `setsid`, fork again and exit the interpreter before timeout or cancellation; repeat across a core crash. Every owned descendant must stop before terminal cancellation; missing ownership or a surviving descendant must remain unresolved and block qualification.

Linux quarantine must never move or remove a substituted entry. Tests pause competing create, link, unlink and rename operations after their LSM hook and resume them after guard publication; swap both recorded names; race the core's own move and unlink; and attempt read, truncate, descriptor write and mapping access. Include an existing descriptor, duplicated descriptor, shared and private mappings after descriptor close, an executable mapping, a hard link, forced lease downgrade, lease/rename/fsync failures, a substituted core task and an unrelated Ricevanta task. Crash after `intent`, after the move before `secured`, after `secured` before `stored`, and after removal before its marker; reboot with a held plaintext file and prove it remains inaccessible. Run every case on each required kernel/filesystem unit. Missing exclusion evidence keeps the unit in candidate.

## 5. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: identity-bound action contracts prevent a delayed command from hitting a replacement process or file once the native primitive qualifies; block lists are policy, so a ban survives re-imaging and reaches devices that were offline; isolation needs no name resolution and no per-process exemption.

Trade-offs: the interim block duplicates the block-list policy until the next bundle; the encrypted quarantine store costs disk on the endpoint; scripts cannot be recovered after a crash.

Dependencies: the action journal (AG-05), the enforcement points (AG-06), the artifact upload path, `ricevanta-scan` (AG-02); Linux quarantine also depends on active BPF LSM, file leases and same-filesystem `renameat2(RENAME_NOREPLACE)`.

Limits: macOS identity-bound termination and descendant containment for scripts remain required mechanism blockers (sections 3.1 and 3.7); protected Windows processes refuse termination; refusal for SIP-protected macOS processes needs native qualification; a running Windows executable is removed at reboot unless its processes are killed; isolation on macOS depends on the filter rules holding without the provider (verify); a local administrator on Windows can delete the WFP provider and its filters, which the 60 s reconciliation reports as tamper; virtual machine traffic bridged through the host is not covered by host isolation; offline un-isolation needs a signed release object and the nonce shown on the device.

Alternatives considered: per-device block commands (rejected: a re-imaged or offline device misses them); deleting quarantined files at once (rejected: no restore for false positives); Linux `fstatat` followed by `unlinkat` (rejected: the name can be replaced between the check and removal); copying through `O_PATH` (rejected: it is not a readable descriptor); allowing DNS during isolation (rejected: a tunnel for the isolated host); per-process exemptions for the core (rejected: macOS filter rules cannot match a process, and addresses make them unnecessary).

Linux mechanism sources: [file leases and forced breaks](https://man7.org/linux/man-pages/man2/F_GETLEASE.2const.html), [mapping lifetime](https://man7.org/linux/man-pages/man2/mmap.2.html), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [VFS rename/link/unlink ordering](https://github.com/torvalds/linux/blob/master/fs/namei.c), [lease conflict checks](https://github.com/torvalds/linux/blob/master/fs/locks.c), and [`renameat2`](https://man7.org/linux/man-pages/man2/rename.2.html). These APIs establish ingredients, not proof of the composed candidate across all required kernels and filesystems.

Process mechanism sources: [Apple PID-based signaling implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c), [Windows query rights for `GetProcessTimes`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes), and [Apple session and process-group creation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsid.2.html). These sources establish the rejected races and the Windows handle requirement; they do not supply the missing macOS primitives.
