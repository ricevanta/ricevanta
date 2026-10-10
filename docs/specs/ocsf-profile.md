# OCSF profile

Which OCSF 1.9.0 classes and attributes each domain emits, the `ricevanta` extension for what OCSF lacks, the event envelope agents upload, and how events are validated. Machine-readable files: `schemas/ocsf/`. Decision: EV-03, building on EV-02.

## 1. Classes per domain

| Domain | Event | Class | `class_uid` | Notes |
|---|---|---|---|---|
| EDR | Process start, stop, injection | `process_activity` | 1007 | Windows 4688 and Sysmon 1, macOS ES exec, Linux BPF `sched_process_exec` all map here |
| EDR | File create, read, write, rename, delete, attribute change | `file_activity` | 1001 | |
| EDR | Connection, listen, DNS | `network_activity`, `dns_activity` | 4001, 4003 | |
| EDR | Registry key and value | `win/registry_key_activity`, `win/registry_value_activity` | 201001, 201002 | Windows extension, uid 2 |
| EDR | Driver and module load | `kernel_extension_activity`, `module_activity` | 1002, 1005 | |
| EDR | Scheduled task, cron, launchd job | `scheduled_job_activity` | 1006 | |
| EDR | Actions on the logging service (log cleared, logging disabled) | `event_log_actvity` | 1008 | Windows 1102 and audit policy changes; spelled this way in the 1.9.0 schema (verify in later versions) |
| EDR | Other Windows Event Log records | The semantic class: 4624 and 4625 to `authentication`, 4672 to `authorize_session`, 4688 to `process_activity`, 4697 and 7045 to `win/windows_service_activity`, 4698 to `scheduled_job_activity`, 4104 to `script_activity`; otherwise `base_event` | 3002, 3003, 1007, 201004, 1006, 1009, 0 | `base_event` carries the record in `unmapped` |
| EDR | PowerShell and shell script blocks | `script_activity` | 1009 | Script content exported up to 32 KiB with truncation attributes (section 3); export can be disabled per scope |
| EDR | Detection | `detection_finding` | 2004 | `finding_info.analytic.uid` identifies the immutable rule version; the extension's `analytic.rule_identity` carries `{pack, version, pack_digest, rule_key}` and `analytic.author` carries DRL attribution |
| EDR | Response action outcome | `remediation_activity`, `file_remediation_activity`, `process_remediation_activity`, `network_remediation_activity` | 7001 to 7004 | |
| EDR | Logon and authentication on macOS and Linux | `authentication`, `authorize_session` | 3002, 3003 | Endpoint Security login events; Linux journal entries of sshd, sudo, su, systemd-logind |
| EDR | Memory protection change | `memory_activity` | 1004 | macOS `NOTIFY_MPROTECT`, Linux BPF LSM `file_mprotect` |
| EDR | macOS privacy permission and profile changes | `device_config_state_change` | 5019 | `NOTIFY_TCC_MODIFY`, `NOTIFY_PROFILE_ADD` |
| EDR | OS anti-malware verdicts | `detection_finding` | 2004 | XProtect through `NOTIFY_XP_MALWARE_*`, Defender channel |
| DLP | Clipboard and removable media | `clipboard_activity`, `peripheral_activity` | 1012, 1010 | Trigger classes for the clipboard and USB channels; clipboard activities are read, write and clear (verify) |
| DLP | Browser upload, download and paste | `http_activity` | 4002 | Emitted by the core from browser-extension decisions; the trigger class for the browser channel |
| DLP | Match and enforcement decision | `data_security_finding` | 2006 | With the `security_control` profile: `action_id`, `disposition_id`, `policy`; the finding is the output of a decision, never a trigger |
| Lineage | Edge | `ricevanta/lineage_activity` | extension | Section 2 |
| MDM | Inventory and software | `inventory_info`, `software_info` | 5001, 5020 | |
| MDM | Configuration change | `device_config_state_change` | 5019 | |
| MDM | Device lifecycle and MDM enrollment | `entity_management` | 3004 | Activities enroll, unenroll, suspend, resume, delete (verify in 1.9.0) |
| MDM | Software, update, lock, wipe, restart, message, diagnostics and script outcomes | `ricevanta/device_management_activity` | extension | Section 2 |
| MDM | Compliance result | `compliance_finding` | 2003 | |
| MDM | Software vulnerability | `vulnerability_finding` | 2002 | |
| MDM | osquery-pack query results | `evidence_info` (Live Evidence Info) | 5040 | Activity Query; `query_info` names the pack and query; rows in the extension's `query_row` (`rule-adapters.md` section 8) |
| PKI | Issue, renew, revoke, expire | `ricevanta/certificate_lifecycle_activity` | extension | OCSF has no PKI class; the `certificate` object is reused |
| RADIUS | Access decision | `authentication` | 3002 | Activity Logon, status success or failure, `status_detail` the reason code; `auth_protocol_id` 9 (EAP) with `auth_protocol: EAP-TLS`, or 99 with `certificate-derived`; `certificate` holds only the exact observed generation; name-only requests omit that object and retain `netid`, `binding = identity_only` and unknown generation in Ricevanta evidence fields (`../design/radius.md` section 10); decision uid as `metadata.correlation_uid` |
| RADIUS | Accounting Start, Interim-Update, Stop | `network_activity` | 4001 | Open, Traffic, Close with `traffic` counters and the terminate cause |
| RADIUS | Disconnect and CoA | `network_remediation_activity` | 7004 | Evict for Disconnect-Request, Other for CoA-Request; `command_uid` is the session-control attempt; retain desired and attempt versions, ACK or NAK with Error-Cause, and proved applied state or `control_unknown`; an obsolete reply cannot establish current success (`../design/radius.md` section 8) |
| Agent | Footprint and health sample | `ricevanta/agent_health_activity` | extension | AG-09 |
| Administration | API and console actions | `api_activity` | 6003 | `actor.user`, `api.operation`, `http_request` |
| Administration | Change of a stored resource, with state before and after | `entity_management` | 3004 | `entity` before, `updated_entity` after (`entity_result` is deprecated in 1.9.0); secrets as fingerprints (`../design/events.md` section 6) |
| Administration | Account, role and group changes | `user_management`, `role_management` | 3007, 3008 | `account_change` and `user_access` are deprecated and never used |
| Pipeline | Spool drop, sequence gap, quarantine, destination state, archive | `ricevanta/pipeline_activity` | extension | `../design/events.md` sections 1 and 4 |
| Server | Start, stop, upgrade | `application_lifecycle` | 6002 | |

Deprecated classes (`security_finding`, `config_state`, `account_change`, `user_access`, the `*_query` classes) are never emitted. Trigger names in policies are `<class>.<activity>` with the activity caption in lower snake case (`policy-envelope.md` section 2.1).

## 2. The `ricevanta` extension

Declared in `schemas/ocsf/extensions/ricevanta/extension.json`; its required `dictionary.json`, `events/` and `objects/` are absent and block event types and validation. Complete them from the table below with fixtures before implementing ingest (`../analysis.md` section 3). OCSF assigns extension uids by registration in the schema repository; Ricevanta uses the development uid 999 (`dev`), which the registry reserves for unregistered extensions, and names the extension `ricevanta`, so no registration is filed. Extension class uids are `uid × 100000 + category × 1000 + class`.

| Addition | Kind | Content |
|---|---|---|
| `lineage_activity` | Class, System Activity | `edge_type`, revision-qualified `source` and `target` (`lineage_node`), `confidence`, `evidence` (event uid plus summary), `inferred`, `summary`, `pressure` and explicit unknown-revision or identity-continuity state (`../design/lineage.md`) |
| `certificate_lifecycle_activity` | Class, Identity and Access Management | `activity_id` issue, renew, revoke, expire; `certificate`, `ca_uid`, `profile`, `requester` |
| `agent_health_activity` | Class, System Activity | per-process `cpu_pct`, `footprint_bytes`, `fd_count`, `event_rates`, budget state per unit (AG-08) |
| `lineage_node` | Object | `kind`, `uid`, `display`; file nodes carry `device_uid`, `observation_namespace`, `file_incarnation`, `content_revision`, native identity hint, continuity state and content hash when known; paths are display observations, never identity (`../design/lineage.md` section 2) |
| `classification_ref` | Object | `scheme_uid`, `label`, `version`, `reference` (optional free text per DLP-03); added to `data_security_finding` and `file` |
| `match_evidence` | Object | `content_hash`, `rule_uid` with immutable `rule_identity` (`pack`, `version`, `pack_digest`, `rule_key`), `offsets` (list of byte ranges) per DLP-02, `coverage`, `inherited_from` (source revision and content hash when known), `sensitivity_floor` (revision identity and compact justification), `type_mismatch`, `warn` (`choice`, `justification`, `timed_out`); added to `data_security_finding`; the redacted snippet itself goes in the core `data_security.pattern_match` |
| `policy_bundle` | Object | `bundle_uid`, `sequence`, `scope_id`; added to `metadata` of every agent event |
| `extension_origin` | Object | Descriptive `id` and `version`; core-assigned `package_digest`, `component`, `component_digest`, installation `recovery_epoch` and `grant_generation` from the active signed bundle, never guest claims; added to `metadata` of every component-caused event (`../design/extensions.md` section 2.6). Ingest requires the current committed epoch and component generation before collector rows become fresh inventory or compliance. Historical telemetry provenance grants no fresh authority. |
| `enforcement_mode_id` | Attribute on classes carrying the `security_control` profile | `enforce`, `monitor`, `fail_open_applied`, `fail_closed_applied`, `unsupported` |
| `author`, `rule_identity` | Attributes on `analytic` | Rule author for DRL attribution and immutable `{pack, version, pack_digest, rule_key}`; the upstream id remains descriptive metadata |
| `policy_activity` | Class, System Activity | `activity_id` evaluated, error, exception_applied, fail_open_applied, fail_closed_applied, command_refused, bundle_installed, bundle_refused, rule_unsupported, unit_throttled, unit_disabled; `policy`, `policy_bundle`, `exception_uid`, `reason` (the policy-health and audit events the specs require) |
| `pipeline_activity` | Class, System Activity | `activity_id` drop, gap, quarantine, destination_state, archive, lookback_overrun; `spool_class`, `stream_epoch`, `sequence_range`, `count`, `bytes`, `reason`, `destination` |
| `device_management_activity` | Class, System Activity | `activity_id` install, update, remove, os_update, lock, unlock, wipe, restart, shutdown, message, collect_diagnostics, run_script; `command_uid`, `channel` (agent, apple_mdm, oma_dm), `status`, `approval_id`, `package` or `script` SHA-256, `reason` |
| `rule_matches` | Attribute on `metadata` | List of `{pack, version, pack_digest, rule_key}` for the base rules of server correlations an agent event matched, so the server counts the exact version without re-evaluating (`../design/policy.md` section 4) |
| `query_row` | Object | Map of osquery column name to string value, with `action` (`added`, `removed`, `snapshot`); added to `evidence_info` |

## 3. Event envelope

Every event, from agent or server:

- `metadata.version` is `1.9.0`; `metadata.product` is `{ name: Ricevanta, vendor_name: Ricevanta, version: <release> }`; `metadata.profiles` lists the profiles applied (`host` on every agent event; `security_control` on findings that carry a decision); `metadata.extensions` lists `ricevanta` and, where used, `win`, `linux`, `macos`.
- `metadata.uid` is a UUIDv7 minted where the event is created; `metadata.correlation_uid` links the events behind one detection or one DLP decision; `metadata.policy_bundle` names the bundle in force.
- `metadata.sequence` is the per-spool-class sequence under the device's stream epoch (`../design/events.md` section 2.3); server events carry a per-replica sequence.
- `time` is epoch milliseconds from the agent's clock; the server adds `metadata.logged_time` at receipt (`../architecture.md` section 7); `metadata.original_time` carries the OS timestamp where it differs.
- `device.uid` is the device record uid; `device.hostname`, `device.os`, `device.type_id` are filled from inventory on the agent.
- `type_uid` is `class_uid × 100 + activity_id`; `severity_id` is set by the emitting policy or `1` (informational) for telemetry.
- Raw user content never appears: DLP evidence follows DLP-02 with the redacted snippet in `data_security.pattern_match` when the policy allows it and hash, rule and offsets in `match_evidence`.
- `script_activity` carries `script.script_content` up to the first 32 KiB, the SHA-256 and byte length of the observed bytes, the complete length when the sensor provides it, and `metadata.is_truncated` when cut. Script blocks are executed code rather than user data, but they embed credentials and identifiers, so the secret and identifier detectors run over the content with redaction before export; a scope's telemetry profile can disable the content export, leaving hash, length and the detection's redacted evidence. Local Sigma evaluation always sees the unredacted buffer before it is discarded.
- `unmapped` holds OS fields the profile does not map, capped at 32 KiB per event with the core `metadata.is_truncated` and `metadata.untruncated_size` set when cut (verify both exist on `metadata` in 1.9.0); the profile grows by mapping fields out of `unmapped`, never by emitting them raw.
- `confidence_score` on the base event carries the policy's detector confidence (blueprint section 4).

The agent uploads NDJSON, one event per line, in zstd-compressed batches with a batch id (`../architecture.md` section 3.4). Server-side events enter the same pipeline.

## 4. Telemetry profiles

The telemetry profiles of EV-01 select classes: the default profile sends findings (2002, 2003, 2004, 2006), remediation outcomes, lineage, agent health, inventory, configuration state, the events any correlation trigger in the scope names, and bounded context, that is the process tree and the file, network and registry events within the window before and after each finding (default 60 s); the full profile sends everything the sensors produce. The spool classes in `../design/agent.md` section 5 map onto these.

## 5. Sigma and Falco logsource mapping

EDR-01 evaluates Sigma on the agent. The mapping from Sigma logsources and field names to OCSF classes and attributes is written with the EDR design in v0.4.x (`../roadmap.md`) and requires `schemas/ocsf/sigma-logsources.yaml`, which is absent and blocks Sigma translation, one entry per `product`, `category` and `service` triple, listing the OCSF class and the field map (for example `Image` to `process.file.path`, `CommandLine` to `process.cmd_line`, `ParentImage` to `process.parent_process.file.path`). Falco requires the absent `schemas/ocsf/falco-fields.yaml` map for its syscall fields; its absence blocks Falco translation (`../analysis.md` section 3). A Sigma rule whose logsource or modifier has no entry is reported with the reason, never silently dropped. Reason codes and per-OS status are defined in `rule-adapters.md` section 2.

## 6. Validation

- The required compiled schema under `schemas/ocsf/compiled/` is absent. Complete the extension contracts, choose an event validator and compile the pinned 1.9.0 release plus the extension with `ocsf-schema-compiler`; add event fixtures before implementing ingest types (`../analysis.md` section 3).
- Go types are generated from the compiled export; the agent's Rust types are generated in-project from the same export, since no Rust crate is known to track 1.9.0 (verify).
- A fixture set of one event per class and activity is validated against the compiled schema in CI with an event validator chosen in v0.1.x (`ocsf-validator` checks schema sources, not events; candidates are `ocsf-toolkit` and a JSON Schema derived from the export, verify); every mapping change adds a fixture.
- Events that fail validation at ingest are stored in a quarantine table with the error and counted in a metric; they are never dropped silently.

## 7. Versioning

`metadata.version` moves only at a minor Ricevanta release with a documented mapping (EV-02). Events written under 1.9.0 are not rewritten; readers accept every 1.x version the server has ever emitted, and the extension version is bumped with the schema it extends.

## 8. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one schema for every domain and for export; attribution, classification references and match evidence travel inside the event; the bundle reference on each event ties every decision to the policy that made it; validation fixtures catch mapping drift in CI.

Trade-offs: PKI, lineage and agent health are extension classes, so SIEMs without the extension see them as unknown classes with valid core attributes; `unmapped` carries OS detail that is not queryable by schema until mapped.

Dependencies: OCSF schema 1.9.0 and `ocsf-schema-compiler` (Apache-2.0), the `win`, `linux` and `macos` native extensions, an event validator to be chosen.

Limits: the `data_classification` profile holds classifier results only, so the category reference needs the extension; `auth_protocol_id` has no EAP-TLS value, so the string field disambiguates; the examples repository's mappings target older schema versions and are guidance only.

Alternatives considered: ECS or a proprietary schema (rejected by the blueprint: OCSF is the canonical format); emitting PKI events as `authentication` with a `certificate` object (rejected: issuance is not authentication, and the activity ids do not fit); carrying lineage inside `detection_finding.evidences` (rejected: edges are not findings and would inflate the finding store); a self-assigned extension uid (rejected: the registry assigns uids and 985 to 998 are taken by other vendors, verify).
