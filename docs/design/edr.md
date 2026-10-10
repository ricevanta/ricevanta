# EDR design

How Ricevanta detects and responds on endpoints: the telemetry sources per OS and which ones run by default, process identity, file integrity monitoring, network telemetry, detection on the agent and the server, alerts and investigations, response actions, threat intelligence and the ATT&CK mapping. The feature list is `../blueprint.md` section 3.2. Event classes and the Sigma and Falco field maps are in `../specs/ocsf-profile.md` (sections 1, 4 and 5); the rule adapter and rule-pack lifecycle in `policy.md`; stable identities in `lineage.md` section 2; the per-action response contracts in `../specs/edr-response-actions.md`. Decisions: EDR-01 to EDR-05, POL-04, AG-01, AG-02, AG-05, AG-06, AG-08, EV-01 to EV-03, POL-02, BE-02, LIN-01 and EXT-03 in `../decisions.md`; conflicts C3, C7 and C9 in `../analysis.md`. This file defines the telemetry source list, response catalogue, authorization and threat intelligence feeds. The required macOS termination and script-containment mechanisms and quarantine transactions remain open in `../specs/edr-response-actions.md`. Claims marked "verify" rest on non-first-party sources or were not confirmed on a first-party page.

## 1. Telemetry

### 1.1 Collection tiers

A source runs only when something consumes it (EDR-02). The compiler derives each scope's collection set from its bundle and ships it in `budgets.json` (`../specs/policy-envelope.md` section 6):

| Tier | Collected when | Uploaded |
|---|---|---|
| Base | Always on an enrolled device | Under the default profile only as findings, lineage and bounded context (`../specs/ocsf-profile.md` section 4) |
| Rule-demanded | A rule, analytic or FIM policy in the bundle names a logsource or path the source serves | Same as base |
| Full | The device group is in the full telemetry profile (EV-01) | Everything collected |

Collection and upload are separate decisions: local Sigma evaluation sees every collected event, while the default profile uploads only findings and their context. The console shows per device which sources run and why.

### 1.2 Sources per OS

"ES" is Endpoint Security, "NE" the Network Extension, "driver" the Windows kernel component (AG-01). Windows ETW provider keywords are read from the installed provider manifest at preflight through the TDH (Trace Data Helper) API, so no keyword value is hard-coded.

| Event | macOS | Windows | Linux | OCSF class | Tier |
|---|---|---|---|---|---|
| Process start, exit, fork | ES `NOTIFY_EXEC`, `NOTIFY_FORK`, `NOTIFY_EXIT` | ETW `Microsoft-Windows-Kernel-Process`, process keyword (verify keyword name) | `tp_btf` on `sched_process_exec`, `sched_process_fork`, `sched_process_exit` | `process_activity` | Base |
| Process access and injection | ES `NOTIFY_GET_TASK`, `NOTIFY_REMOTE_THREAD_CREATE`, `NOTIFY_TRACE` | Driver: `ObRegisterCallbacks` process-handle requests with write, thread-creation or read access to sensitive processes; `PsSetCreateThreadNotifyRoutineEx` for remote threads | BPF LSM `ptrace_access_check` | `process_activity` Open, Inject | Base |
| Privilege change | ES `NOTIFY_SETUID` family, `NOTIFY_SUDO`, `NOTIFY_SU` | Security 4672 | BPF LSM `task_fix_setuid` | `process_activity` Set User ID; `authorize_session` | Base |
| File create, modify, rename, delete | ES `NOTIFY_CREATE`, `NOTIFY_CLOSE` (modified flag), `NOTIFY_RENAME`, `NOTIFY_UNLINK`, `NOTIFY_LINK` | ETW `Microsoft-Windows-Kernel-File` (verify keywords); USN journal for FIM and catch-up | fanotify `FAN_MARK_FILESYSTEM` with `FAN_REPORT_DFID_NAME` and `FAN_REPORT_PIDFD`: `FAN_CREATE`, `FAN_CLOSE_WRITE`, `FAN_RENAME` or `FAN_MOVED_FROM`/`TO`, `FAN_DELETE` | `file_activity` | Base for executables, persistence locations and FIM paths; rule-demanded for the rest |
| File open and read | ES `NOTIFY_OPEN` | Kernel-File create and read events | fanotify `FAN_OPEN`, `FAN_ACCESS` | `file_activity` | Full |
| Permission and attribute change | ES `NOTIFY_SETMODE`, `NOTIFY_SETOWNER`, `NOTIFY_SETEXTATTR`, `NOTIFY_SETACL` | Kernel-File set-information events (verify) | fanotify `FAN_ATTRIB` | `file_activity` | Rule-demanded |
| Executable mapping (library load) | ES `NOTIFY_MMAP` with execute protection | ETW Kernel-Process image keyword | BPF LSM `mmap_file` with `PROT_EXEC` | `module_activity` | Rule-demanded |
| Memory protection change | ES `NOTIFY_MPROTECT` | Not collected: the `Microsoft-Windows-Threat-Intelligence` provider needs an antimalware protected-process consumer (verify), which needs ELAM (v2.0.0, `../platform-support.md`) | BPF LSM `file_mprotect` | `memory_activity` | Rule-demanded |
| Kernel module and driver load | ES `NOTIFY_KEXTLOAD` | ETW image loads in the System process | Tracepoint `module:module_load`; BPF LSM `kernel_read_file`, `kernel_load_data` | `kernel_extension_activity` | Base |
| Network connection | NE filter data provider `handleNewFlow`: endpoints, `sourceAppAuditToken`, `remoteHostname` for flows opened by name | ETW `Microsoft-Windows-Kernel-Network` (verify) | `cgroup/connect4`, `connect6`, `sendmsg4`, `sendmsg6`; tracepoint `sock:inet_sock_set_state` for accepted connections | `network_activity` | Base, aggregated (section 4) |
| DNS query | NE provider reads the query from port-53 flows (verify for UDP flows) | ETW `Microsoft-Windows-DNS-Client` (verify) | `cgroup_skb/egress` parses outbound UDP and TCP port-53 queries | `dns_activity` | Base |
| Registry | None | Driver `CmRegisterCallbackEx` post-notifications with value data | None | `win/registry_key_activity`, `win/registry_value_activity` | Base for persistence keys; rule-demanded for others |
| Services, tasks, launch items, cron, systemd units | ES `NOTIFY_BTM_LAUNCH_ITEM_ADD`, `_REMOVE` | Security 4697 and 4698, System 7045 (verify channel) | fanotify on cron and systemd unit directories | `scheduled_job_activity`; `win/windows_service_activity` | Base |
| Logon and authentication | ES `NOTIFY_LW_SESSION_LOGIN`, `NOTIFY_LOGIN_LOGIN`, `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_SCREENSHARING_ATTACH`, `NOTIFY_AUTHENTICATION` | Security 4624, 4625 | systemd journal entries of `sshd`, `sudo`, `su`, `systemd-logind` | `authentication` | Base |
| Script content | Script file of an `#!` exec (`es_event_exec_t` script field, verify), first 32 KiB | PowerShell 4104 in `Microsoft-Windows-PowerShell/Operational` and `PowerShellCore/Operational`; 4103 rule-demanded | Script path argument of an interpreter exec, first 32 KiB | `script_activity` | Base |
| Other Windows Event Log channels | None | `EvtSubscribe` per channel and event ID that a rule names | None | The semantic class when one exists, else `base_event` with the record in `unmapped` | Rule-demanded |
| OS security verdicts and settings | ES `NOTIFY_XP_MALWARE_DETECTED`, `_REMEDIATED`, `NOTIFY_GATEKEEPER_USER_OVERRIDE`, `NOTIFY_TCC_MODIFY`, `NOTIFY_PROFILE_ADD` | Security 1102 (log cleared); Defender operational channel rule-demanded | None | `detection_finding`; `device_config_state_change`; `event_log_actvity` | Base |

Removable media and mounts are DLP channels (ES `AUTH_MOUNT`, the driver, BPF LSM `sb_mount`); EDR consumes their `peripheral_activity` events through the pipeline.

Per-OS notes:

- macOS: one ES client in the Endpoint Security extension subscribes to the union of the tiers and changes its subscriptions when the bundle changes. Every listed event type exists on the eligible releases (Apple's `es_event_type_t` and per-event pages). The NE filter allows every flow in telemetry mode and records it; it blocks only for isolation and network policies.
- Windows: the core owns one real-time ETW session for the kernel providers and one for PowerShell, sized at 64 KB buffers with at most 32 buffers per session, and reports the session's lost-event count. The baseline that the agent applies through the Audit policy CSP enables Audit Logon (success and failure), Audit Special Logon, Audit Process Creation with the command line, Audit Other Object Access Events and Audit Security System Extension, plus PowerShell script block logging. Microsoft warns that command lines in 4688 are readable by anyone with Security-log access; the baseline states that trade-off, and process telemetry itself comes from ETW whether or not 4688 is on. Event Log subscriptions keep a bookmark per channel in `state.db`, so a restart resumes without loss while the channel retains the records. Sysmon is not used; `service: sysmon` rules evaluate from its channel only where an operator installed it.
- Linux: the eBPF programs are CO-RE objects built with `aya`, using only features of the 5.10 kernel floor (`../platform-support.md`): the BPF ring buffer, `tp_btf`, BPF LSM and `bpf_d_path`; `FAN_RENAME` and `FAN_REPORT_PIDFD` are used where present (5.17 and 5.15; backports to 5.10.220, verify) and `FAN_MOVED_FROM`/`TO` pairs and `/proc` lookups otherwise. Journal entries are read through `sd_journal`, loaded from `libsystemd` at run time. The audit framework is not used, so the agent never changes a host's audit rules.

### 1.3 Normalization

Sensors hand raw records to the core, which builds OCSF 1.9.0 events in the classes above (EV-02, EV-03), enriches them with the process identity and ancestry from the process table (section 2), the user and the bundle in force, and passes them to the matcher before the spool. Fields with no profile mapping go to `unmapped` under its cap (`../specs/ocsf-profile.md` section 3).

### 1.4 Bounded memory and hot sources

| Structure | Default bound | When exceeded |
|---|---|---|
| Kernel queue per source | BPF ring buffer 4 MB; ETW 32 × 64 KB per session; fanotify default queue; ES queue owned by the OS | Drop counted at the source (ring-buffer reservation failure, ETW `EventsLost`, `FAN_Q_OVERFLOW`, ES message sequence gaps, verify) and reported |
| Core channel per source | 4,096 events | Oldest telemetry event dropped and counted; authorization traffic does not use these channels |
| Process table | Live processes plus 8,192 exited entries | Least recently used exited entry evicted |
| File hash cache | 32,768 entries | Least recently used evicted |
| Matcher programs | The policy share of `policy.md` section 9 | Pack throttled, then disabled (AG-08) |
| Indicator set | 4 MB | Server truncates by confidence and recency (section 8.3) |
| Behavioral detector state | 2 MB | Oldest per-process state evicted, counted |

Hot-source control follows AG-08 and `agent.md` section 7: a path or process over its rate is sampled, then muted at the source with the mute reported: `es_mute_path_events` on macOS, a mute entry in a BPF map on Linux, an ETW event filter or a driver-side filter on Windows, and fanotify ignore marks. Authorization rules are never muted, and repeated mutes attributed to one user are a detection (section 5.3).

With every structure at its cap and the channels empty, the EDR structures other than the matcher take about 13 MB at most of the 44 MB core budget (`agent.md` section 6), and the matcher stays within the policy share of `policy.md` section 9; kernel buffers and BPF maps are reported separately (AG-02). The figures are a starting point re-derived from the first measurement.

## 2. Process tree and identity

Processes are keyed by the stable identity of `lineage.md` section 2. At start the core enumerates running processes (`libproc` on macOS, `NtQuerySystemInformation` on Windows, a BPF task iterator on Linux) and then follows the event stream, so the tree is complete from the first event. Each entry keeps the parent and, where the OS distinguishes them, the creator: macOS `original_ppid` and the responsible audit token, the Windows creating process from the process-creation callback, the Linux real parent across `exec`. A finding carries its ancestor chain up to 16 levels and the children seen within the context window, which is how the server shows a tree under the default profile without raw process telemetry.

## 3. File integrity monitoring

FIM is an `edr` policy whose trigger names `file_activity` events on path selectors, with optional registry keys on Windows.

- Baseline: when the policy first installs, the core walks the monitored paths at low I/O priority and records per file the identity, SHA-256, size, owner, mode or ACL digest and extended-attribute digest in `state.db`; at most 200,000 entries per device by default, with the excess reported. SHA-256 is the FIM hash because indicators and other tools use it; lineage computes BLAKE3 separately when it needs content identity.
- Change detection: a close-after-write on a monitored path (ES `NOTIFY_CLOSE` with modified set, Kernel-File close, fanotify `FAN_CLOSE_WRITE`) or a rename, delete or attribute change queues the file; the hasher waits for 2 s without further writes, then streams the file through a fixed 1 MiB buffer, capped at 20 MB/s of reads. Files over 512 MB are compared on metadata and the first and last MiB, and the event says so.
- Catch-up after downtime: Windows replays the USN journal from the stored USN and journal identifier, and a changed identifier or purged records trigger a sweep; macOS replays FSEvents history since the stored event id (verify the history guarantee); Linux has no persistent change journal and fanotify lapses while the core is down, so every core start runs a sweep that compares size, change time and identity and hashes only the files that differ. A weekly verification sweep (policy value) runs everywhere.
- Change events: a `file_activity` event with the previous and new hashes in `file.hashes` and the changed attributes; a `detection_finding` when the policy's action is `alert`.
- Exclusions: path globs and process selectors in the policy, and `Exception` resources. Changes made by Ricevanta's own installer under an MDM command carry that command uid and are recorded as authorized changes rather than suppressed.

## 4. Network telemetry

Each connection is attributed to a process identity at the source: the flow's audit token on macOS, the process id in the ETW event on Windows resolved against the process table by start time, and the current task in the cgroup program on Linux. Locally every connection and DNS query reaches the matcher and the indicator set (section 8.3). For upload, connections aggregate per process identity, remote address, port and protocol per 60 s window with counts and bytes where the source provides them; the context window of a finding carries the unaggregated events. Encrypted DNS (DNS over HTTPS or TLS) sent by an application is not visible as DNS; it appears as a connection. Seeing inside it would need TLS interception, which DLP-01 rejects.

## 5. Detection

### 5.1 Sigma on the agent

The rule adapter (`policy.md` section 5, `../specs/rule-adapters.md` section 3) translates each Sigma rule through the logsource and field map of `../specs/ocsf-profile.md` section 5 into a matcher program (`../specs/rule-adapters.md` section 1): triggers, a predicate tree of typed leaf tests over OCSF attribute paths, and a prefilter literal set. Which modifiers translate natively, which expand at compile time, and the closed list of reason codes for unsupported logsources, fields, modifiers and conditions are defined there; every untranslated rule appears in the pack's `report.json` and in the console per rule and per OS (EDR-01).

The evaluator (POL-04) runs a bundle of N rules in time bounded by the event, not by N:

1. Dispatch by OCSF class and activity: an event meets only the programs whose triggers name its class.
2. Prefilter: one Aho-Corasick automaton per class holds every rule's prefilter literals tagged with their field; one pass over each tagged field of the event, case-folded unless a literal is case-sensitive, yields the candidate rules. Literal hits per field are capped at 4,096, and an event over the cap evaluates every program of its class rather than dropping candidates.
3. Candidates evaluate their predicate trees. Leaf tests are compiled once per bundle: regular expressions through the `regex` crate, which matches in linear time; CIDR tests as prefix tables; numeric and `time` tests as comparisons over the event time in UTC; `fieldref` as an equality between two attributes of the same event.
4. Programs without a prefilter (pure negation, `exists` or numeric tests) run on every event of their class. They are counted per pack against the cost units of `policy.md` section 9, so a pack of them fails at dry run rather than slowing the agent.

Per event the work is the length of the prefiltered fields, the literal hits and the candidate predicate trees. Field values enter the evaluator truncated at 32 KiB, except script content, which the sensor delivers up to 1 MiB for local evaluation only. The rule-count ceiling, the cost units per trigger class, the 20 µs per-event target and the throttling of a pack over budget are in `policy.md` section 9 under AG-08; nothing is dropped silently.

A match emits a `detection_finding` with immutable rule identity `{pack, version, pack_digest, rule_key}` and author (DRL attribution, `../licensing.md`), the matched event and the context of `../specs/ocsf-profile.md` section 4. Sigma rules detect; they do not block. Prevention comes from `edr` policies whose `block_process` rules compile into the enforcement points (AG-06); a Sigma match can trigger an automatic `kill_process` or `quarantine_file` after the fact.

### 5.2 Correlation on the server

Correlation programs (`../specs/rule-adapters.md` section 3: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`) run in the `detection` module on the `jobs` role, sharded by immutable correlation identity `{pack, version, pack_digest, rule_key}` with one lease per shard (BE-03). They consume rule matches, not raw telemetry: the agent tags an event that matches a referenced base rule with its full immutable identity and uploads it (`policy.md` section 4), and `jobs` reads those events through the `events` interface (`events.md` section 3.6), so correlation works under the default profile and across devices (EDR-03). Tags, references, checkpoints, group state, chained findings and late-upload recomputation retain the complete identity; another pack or version with an equal `rule_key` never joins that state. The same engine runs DLP's long-window and cross-device exfiltration counters over `data_security_finding` events (`dlp.md` section 8).

| Type | State per group key | Bound |
|---|---|---|
| `event_count` | Counter per time bucket | Constant |
| `value_count` | Distinct values, counted only up to the condition threshold plus one | Threshold, at most 10,000 |
| `temporal` | Latest match time per referenced rule | Number of rules, at most 64 |
| `temporal_ordered` | Earliest time each prefix of the rule order was satisfied | Number of rules, at most 64 |
| `value_sum`, `value_avg` | Running sum and count per time bucket | Constant |
| `value_percentile` | Value frequencies per group | 10,000 distinct values, then reported as overflowed |

Windows slide over event time in buckets of one hundredth of the `timespan`, and chained correlations consume the findings of other correlations. The group-key bound per rule and its eviction are in `policy.md` section 9. State lives in memory on the shard leader and is checkpointed to PostgreSQL every 10 s. Stored matches are the record of truth: a new leader, or a match that arrives after its window left memory (a device uploading days late), recomputes the affected group from stored matches within `timespan` around that event's time. A correlation match is a `detection_finding` with the related event and finding uids as evidence and the rule's `level`. The roadmap places `event_count` in v0.4.x with EDR and the other types in v0.8.x (`policy.md` section 10, `../roadmap.md`).

### 5.3 Behavioral detections

Analytics that need state across events and are not expressible in Sigma are first-party code in the agent's `edr` module, each a named analytic `ricevanta:<name>` with a version, ATT&CK techniques, thresholds as policy parameters and bounded per-process state:

- Mass file rewrite: a process renaming or rewriting more than N files per window with an entropy rise measured on the first 4 KiB of each rewritten file, read locally and never uploaded.
- Credential store access by an unexpected process: an LSASS handle with read access, reads of the macOS keychain databases or `/etc/shadow` outside an allow list.
- Injection chain: process open with write access, then a remote thread or memory protection change in the target.
- Masquerading: a system binary name running from an unexpected path or without the expected signer.
- Persistence then execution: a new service, task, launch item or unit whose program runs within the window.
- Evasion: log clearing, audit policy change, Ricevanta component tampering, and repeated hot-source mutes attributed to one user (AG-08).
- Beaconing: connections from one process to one destination at regular intervals, scored on interval variance over bounded history.

Server-side analytics use fleet-wide data the agent lacks: first sight of an executable hash in the organization, and rare parent-child pairs across the fleet. The lineage module raises the fan-out detection of LIN-01. Busy-process compaction preserves the maximum source durable sensitivity floor in a process-window summary (`lineage.md` section 3), marks pressure-derived inference and reduces provenance confidence. Reduced confidence never lowers the effective inherited floor or turns protected data into an unclassified result.

### 5.4 YARA-X

YARA-X runs only in `ricevanta-scan` (AG-02); pack compilation, namespaces, modules and the unsupported constructs are in `../specs/rule-adapters.md` section 5. EDR triggers scans in four ways: a new or modified executable or script after its close-after-write, asynchronously; an exec of a file not yet scanned when an `edr` policy declares a YARA-based `block_process`, as a content decision under AG-06 with its deadline and fail mode (ES `AUTH_EXEC`, the driver's process-creation callback, fanotify `FAN_OPEN_EXEC_PERM`); `edr.scan` commands; and scheduled scans. Each file scan runs with `Scanner::set_timeout` at 5 s for asynchronous scans and below the policy deadline for content decisions, the scanner helper's size cap, and memory mapping disabled so a file truncated during the scan cannot fault the helper. The scan-result cache follows the canonical scan-plan identity and coverage contract of `dlp.md` section 2.6 with the selected EDR scan inputs. Unchanged bytes never reuse a result after a selected artifact, configuration, grant generation or recovery epoch changes. A match is a `detection_finding` with immutable rule identity, namespace, file identity, hash and match offsets, never content. YARA-X does not scan process memory, so memory-only implants are left to the behavioral analytics of section 5.3.

### 5.5 Falco rules on Linux

Falco rules translate into matcher programs through the Falco field map (`../specs/rule-adapters.md` section 4) and run in the evaluator of section 5.1 on Linux devices. Coverage follows section 1.2: an `evt.type` that no Linux source in the device's collection set observes is reported per device, and a rule that names one makes that source rule-demanded where a source exists. Falco evaluates rules in order and, by default, the first matching rule wins; Ricevanta evaluates every rule, so one event can raise several findings, and the pack page states that difference.

## 6. Alerts and investigations

### 6.1 Alerts

An alert is a `detection` record that groups findings from Sigma rules, behavioral analytics, YARA-X, correlations and indicator matches.

| Field | Source |
|---|---|
| Severity | OCSF `severity_id` from the rule `level` or the policy `severity`; a correlation's `level` overrides its members |
| Confidence | 0 to 100: the policy's detector confidence, or for Sigma 80 for `stable`, 60 for `test`, 40 for `experimental`; corroborating findings from a different analytic raise it |
| Status | new, acknowledged, in progress, resolved, false positive, suppressed |
| Entities | Device, user, process identities, file identities, remote endpoints |
| ATT&CK | Union of the members' techniques |
| Counts | First and last seen, finding count |

Deduplication: the agent aggregates repeated findings per analytic and object within a window (`events.md` section 2.2) and ingest marks content repeats (`events.md` section 3.3). The server merges a finding into an open alert with the same immutable rule identity, device and primary entity within 1 hour, keeps the first 20 finding references and counts the rest, and caps an alert at 1,000 references. Grouping: findings that share a correlation uid, or a process-tree root on the same device within 15 minutes, join one alert.

### 6.2 Investigations

An investigation is the analyst's case: alerts, notes, tasks, response commands with their results, evidence items, timeline bookmarks, assignee, status and a closing classification. It is created from alerts by an analyst or automatically for `critical` alerts. Every change is an audit event.

Evidence is bounded: the findings and their context windows; artifact packages from `edr.collect` in the blob store (100 MB default, 1 GB at most per package, redacted per DLP-02); YARA match offsets; script content under `../specs/ocsf-profile.md` section 3. Raw user content and process memory are never collected (`../specs/edr-response-actions.md` section 3.5).

### 6.3 Timelines and history

The timeline view and API query two stores: the detection store in PostgreSQL (findings, context, remediation, lineage, inventory changes; 30-day default) and, for devices in the full profile, the raw store (ClickHouse, an external destination or the bounded PostgreSQL investigation set, 7-day default, EV-01). An analyst can place an investigation's devices, at most 50, into the bounded investigation set for 7 days; that change is permission-gated and audited. Every answer states which stores covered which interval and lists gaps from spool drops, mutes, sensor losses and offline periods, so a missing event is not read as an absent one. Retro-hunts over the raw store use the Sigma-to-SQL translator of `backend.md` section 5.

Retention: findings and context 30 days and raw telemetry 7 days (EV-01 defaults); alerts and investigations 1 year by default. An open investigation places a hold on its devices and time range (`events.md` section 5), so its findings, context and raw rows outlive the default retention. Longer history goes to SIEM export.

## 7. Response

### 7.1 Catalogue and authorization

EDR-04 fixes the catalogue; per-action mechanisms, journal markers, undo and offline behaviour are in `../specs/edr-response-actions.md`. Summary:

| Action | macOS | Windows | Linux | Protected (BE-02) |
|---|---|---|---|---|
| Terminate process | Required identity-bound primitive unresolved, release blocker | `TerminateProcess` on a handle with terminate and query rights after a successful creation-time match | `pidfd_send_signal` | More than 10 devices |
| Quarantine and restore file | Encrypted store; native identity exclusion unresolved | Encrypted store, handle-based POSIX delete, reboot delete for running images | Encrypted store; lease, LSM guard and same-volume move candidate | Restore always |
| Isolate and un-isolate host | NE filter rules, default drop | Persistent and boot-time WFP hard filters | cgroup BPF at the cgroup v2 root | Un-isolate always |
| Block hash, path or signer | ES `AUTH_EXEC` | Driver process-creation callback | BPF LSM `bprm_check_security` for paths (Linux has no OS code signature); hashes through fanotify `FAN_OPEN_EXEC_PERM` | Removing a block is a weakening change |
| Kill and ban | Interim hash block, kill, quarantine, then the managed block list | Same | Same | More than 10 devices |
| Collect artifacts | Triage packages, redacted | Same | Same | More than 10 devices |
| `responder` extension plans | `../specs/extension-agent-runtime.md` section 6 | Same | Same | Extension grants and more than 10 devices |
| Operator scripts | Required descendant containment unresolved, release blocker | Signed command; qualified job-object containment | Signed command; qualified transient-cgroup containment | Always |

Every manual action is a signed command under `../specs/policy-envelope.md` section 7. Automatic actions from enforcing `edr` policies run from the installed bundle and journal the same way; publishing a policy with `isolate_host` or `kill_process` is protected. Each command type has a permission of its own, so a role can scan and collect without being able to isolate.

### 7.2 Blocks live in policy

A block is an `edr` policy with `block_process` by hash, path or signer, never a per-device command, so it survives re-imaging and reaches offline devices at their next bundle. Path and signer rules produce point-local candidates; local finality requires the compiler's global conflict-plan proof (`../specs/policy-envelope.md` section 2.2). Hash rules are core-evaluated with a verdict cache in each enforcement point keyed by file identity and change generation: the core fills it from the file hash cache, which hashes executables after their close-after-write, so most execs hit the cache. On a miss the enforcement point asks the core within the deadline and the policy's fail mode applies when it cannot answer. While the core is down, macOS and Windows keep deciding from the cache and apply the policy fail mode on a verdict-cache miss, and Linux hash blocks lapse with fanotify while BPF LSM path rules stay in force (`../platform-support.md`, OS-imposed limits).

## 8. Threat intelligence

### 8.1 Ingestion

The `detection` module ingests, on `jobs` (EDR-05):

- TAXII 2.1 collections: `GET {api-root}/collections/{id}/objects/` with `added_after` set from the last `X-TAXII-Date-Added-Last` header, following `more` until exhausted; HTTP Basic, a bearer token or mutual TLS.
- STIX 2.1 bundles by upload or URL.
- MISP feeds: `manifest.json` plus per-event JSON, or `hashes.csv`, by URL; this parses the published format and links no MISP code (AGPL-3.0).
- Plain lists, one indicator per line, and CSV with a column mapping.
- `enricher` service connectors (EXT-05) for any other source.

Each source has a schedule (default hourly) and honours the publisher's limits, a configured confidence and a TLP marking. Indicators normalize to type (SHA-256, SHA-1, MD5, IPv4, IPv6, CIDR, domain, URL), canonical value, source, confidence, `valid_from`, `valid_until`, `revoked`, markings and ATT&CK references. A STIX `indicator` whose `pattern_type` is `stix` converts when the pattern is a single observation of equality comparisons joined by `OR`; other STIX patterns are reported as unsupported. Patterns of type `sigma` or `yara` become candidate rule packs, published only through the protected rule-pack flow.

### 8.2 Matching placement

The agent matches hashes of executed and newly written executables, connection addresses, DNS names (exact and parent domains) and the URLs the browser extension reports, so detection works offline and a policy can block by indicator through the network and execution enforcement points. MD5 and SHA-1 are computed for executables only when the scope's set holds such indicators. The server matches new indicators retroactively against the last 30 days of stored findings and context, and against the raw store where enabled.

### 8.3 Delivery and bounds

Indicator sets change hourly, which the policy bundle should not, so they travel as signed deltas: `GET /agent/v1/intel?since_epoch=<epoch>&since=<sequence>` returns a DSSE envelope of payload type `application/vnd.ricevanta.intel-delta+json` signed by the policy signing key, naming the organization, `recovery_epoch`, the `scope_id`, the intel set, the base and new sequence inside that epoch and the added and removed indicators. The agent compares the `scope_id` with the one in its installed assignment and refuses a delta for another scope, so a stolen `agent`-role TLS key cannot serve one scope's delta to another scope's device. The bundle names the intel sets a scope receives and their size cap; the agent verifies the chain as for bundles (`pki.md` section 4), installs no delta while its cached CRL is past `nextUpdate`, refuses a lower `(recovery_epoch, sequence)` or an epoch without the verified transition of `../specs/policy-envelope.md` section 6, and fetches a full snapshot when its base is missing or the epoch changes. Check-in reports the installed epoch and sequence, so a device fetches only when the server advanced it. The agent holds SHA-256 as a sorted array, addresses in an LPM trie and domains in a reversed-label trie, within 4 MB by default; above the cap the server keeps indicators an operator pinned, then the highest-confidence, most recent ones, and reports the truncation per scope. Pinned indicators are exempt from truncation, and no source may hold more than half of the set's cap, so a flooding feed cannot evict another source's or an operator's indicators. Indicator expiry and revocation are not weakening changes; detaching a feed from a blocking policy is.

### 8.4 Feeds and licenses

No indicator feed is bundled or preset. The operator adds feed URLs with their own credentials and accepts each source's terms themselves; the product displays no third-party terms. MITRE ATT&CK (`attack-stix-data`) is bundled for the mapping under its terms of use, with the MITRE copyright notice reproduced in `NOTICE` and on the coverage view.

### 8.5 ATT&CK mapping and coverage

The ATT&CK data, technique validation and the coverage matrix belong to the `policy` module (`../specs/rule-adapters.md` section 9, `policy.md` section 7.4). EDR adds three things. Behavioral analytics declare their techniques in their metadata, and YARA rules may declare them in a `mitre_attack` meta field. The EDR coverage view marks a technique as a gap on an OS when its rules need a source that OS cannot serve (section 1.2) and shows findings per technique over the last 30 days. The view exports an ATT&CK Navigator layer file; Navigator is Apache-2.0 and not bundled, and the layer format version is pinned at implementation (verify). The MITRE copyright notice appears in the view and in every exported layer.

## 9. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: sources run only for a consumer, which keeps idle cost near the base tier; local Sigma and indicator matching work offline; the matcher's cost tracks the event, not the rule count; correlation over findings works under the default profile and across devices; blocks and bans live in policy and reach every device; every action names its target by identity.

Trade-offs: correlation sees only the fields projected into findings, so a new correlation needs its base rules recompiled; the interim block duplicates the block list until the next bundle; rule-demanded sources make a rule-pack change alter the device footprint, which the footprint telemetry shows; Windows command-line auditing exposes command lines to Security-log readers.

Dependencies: `aya`, `windows-rs`, `endpoint-sec`, the `regex` and `aho-corasick` crates, `yara-x`, `libsystemd` loaded at run time, the ATT&CK STIX data and the OASIS STIX 2.1 and TAXII 2.1 specifications; all with rows in `../licensing.md`.

Limits: macOS identity-bound termination and descendant containment for operator scripts remain required release blockers (`../specs/edr-response-actions.md` sections 3.1 and 3.7); Windows memory-protection telemetry waits for the Threat-Intelligence provider and ELAM (v2.0.0); encrypted DNS is visible only as connections; Linux FIM catch-up needs a sweep; Linux hash blocks lapse while the core is down; YARA-X does not scan process memory; Falco rules for non-syscall sources are unsupported; macOS isolation depends on filter rules holding without the provider process (verify); macOS and Windows hash blocks apply the policy fail mode on a verdict-cache miss while the core is down.

Alternatives considered: evaluating Sigma per rule in sequence (rejected: cost grows with N); correlation over raw events (rejected: needs the full profile, contrary to C9 and EV-01); Sysmon as the Windows source (rejected: a second product to deploy and configure); the Linux audit framework (rejected: eBPF gives the same events with process context, and the agent would have to change the host's audit rules); the Threat-Intelligence ETW provider at v1.0.0 (rejected: needs ELAM); indicator sets inside the bundle (rejected: hourly churn would recompile and re-download every bundle); bundling community feeds (rejected: their terms forbid it or state none).

## Sources

- Apple: [es_event_type_t](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t), [es_message_t deadline](https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline), [es_new_client](https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:)), [es_mute_path_events](https://developer.apple.com/documentation/endpointsecurity/es_mute_path_events(_:_:_:_:_:)), [es_event_btm_launch_item_add_t](https://developer.apple.com/documentation/endpointsecurity/es_event_btm_launch_item_add_t), [NEFilterDataProvider handleNewFlow](https://developer.apple.com/documentation/networkextension/nefilterdataprovider/handlenewflow(_:)), [NEFilterSettings init(rules:defaultAction:)](https://developer.apple.com/documentation/networkextension/nefiltersettings/init(rules:defaultaction:)), [NEFilterSocketFlow remoteHostname](https://developer.apple.com/documentation/networkextension/nefiltersocketflow/remotehostname), [NEFilterFlow sourceAppAuditToken](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceappaudittoken).
- Microsoft: [command line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing), [about_Logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1), [Audit policy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-audit), [audit policy recommendations](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), [ETW keywords](https://learn.microsoft.com/windows/win32/wes/defining-keywords-used-to-classify-types-of-events), [change journal records](https://learn.microsoft.com/windows/win32/fileio/change-journal-records), [change journal identifier](https://learn.microsoft.com/windows/win32/fileio/using-the-change-journal-identifier), [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex), [PsSetCreateThreadNotifyRoutineEx](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutineex), [filtering registry calls](https://learn.microsoft.com/windows-hardware/drivers/kernel/filtering-registry-calls), [WFP filter arbitration](https://learn.microsoft.com/windows/win32/fwp/filter-arbitration), [WFP object management](https://learn.microsoft.com/windows/win32/fwp/object-management), [WFP operation](https://learn.microsoft.com/windows/win32/fwp/basic-operation), [protecting anti-malware services](https://learn.microsoft.com/windows/win32/services/protecting-anti-malware-services-).
- Linux: [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [libbpf program types](https://docs.kernel.org/bpf/libbpf/program_types.html), [BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html), [lsm_hook_defs.h](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h), [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html), [pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
- Sigma: [rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md), [modifiers appendix](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md), [correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md), [filters](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-filters-specification.md), [taxonomy](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md).
- Falco: [rule basic elements](https://falco.org/docs/concepts/rules/basic-elements/), [falcosecurity/rules](https://github.com/falcosecurity/rules).
- YARA-X: [Scanner](https://docs.rs/yara-x/latest/yara_x/struct.Scanner.html), [YARA-X vs YARA](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/).
- Intelligence: [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html), [MISP feeds](https://www.misp-project.org/feeds/), [CIRCL OSINT feed](https://www.circl.lu/doc/misp/feed-osint/), [abuse.ch terms](https://abuse.ch/terms-of-use/), [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), [attack-stix-data](https://github.com/mitre-attack/attack-stix-data), [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator).
- OCSF: [ocsf-schema 1.9.0](https://github.com/ocsf/ocsf-schema/tree/v1.9.0) (`event_log_activity.json`, `windows_service_activity.json`, `memory_activity.json`).
