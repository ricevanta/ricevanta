# OCSF profile

The first contract slice fixes four foundation classes, their objects, offline schema generation and decoded-event validation. It supplies no ingest handler, adapter, event producer or authority check. Decision: [EV-03](../decisions.md#ev-03-ocsf-profile-and-extension), under EV-02. The [implementation plan](../plans/ocsf-contracts.md) builds this contract before generated ingest types exist.

## 1. Classes per domain

The table defines the full domain mapping for export selection. Only the four foundation classes in section 1.1 are admitted by this slice's emitted-event validator; the other mappings require the contracts and qualification in [section 5](#5-later-slices-and-dependencies). `extension` means a later-slice class with no allocated class_uid.

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
| PKI | Issue, renew, revoke, expire | `ricevanta/certificate_lifecycle_activity` | 99903001 | OCSF has no PKI class; the `certificate` object is reused |
| RADIUS | Access decision | `authentication` | 3002 | Activity Logon, status success or failure, `status_detail` the reason code; `auth_protocol_id` 9 (EAP) with `auth_protocol: EAP-TLS`, or 99 with `certificate-derived`; `certificate` holds only the exact observed generation; name-only requests omit that object and retain `netid`, `binding = identity_only` and unknown generation in Ricevanta evidence fields (`../design/radius.md` section 10); decision uid as `metadata.correlation_uid` |
| RADIUS | Accounting Start, Interim-Update, Stop | `network_activity` | 4001 | Open, Traffic, Close with `traffic` counters and the terminate cause |
| RADIUS | Disconnect and CoA | `network_remediation_activity` | 7004 | Evict for Disconnect-Request, Other for CoA-Request; `command_uid` is the session-control attempt; retain desired and attempt versions, ACK or NAK with Error-Cause, and proved applied state or `control_unknown`; an obsolete reply cannot establish current success (`../design/radius.md` section 8) |
| Agent | Footprint and health sample | `ricevanta/agent_health_activity` | 99901001 | AG-09 |
| Administration | Authentication | `authentication` | 3002 | Foundation audit; contracts and dependencies in section 5 |
| Administration | API and console actions | `api_activity` | 6003 | `actor.user`, `api.operation`, `http_request` |
| Administration | Change of a stored resource, with state before and after | `entity_management` | 3004 | `entity` before, `updated_entity` after (`entity_result` is deprecated in 1.9.0); secrets as fingerprints (`../design/events.md` section 6) |
| Administration | Account, role and group changes | `user_management`, `role_management` | 3007, 3008 | `account_change` and `user_access` are deprecated and never used |
| Policy | Policy evaluation, exceptions, fail modes, command and bundle outcomes, rule support and unit budgets | `ricevanta/policy_activity` | 99901002 | Foundation activities below; field catalogue owns exact fields and conditions |
| Pipeline | Spool drop, sequence gap, quarantine, destination state, archive | `ricevanta/pipeline_activity` | 99901003 | `../design/events.md` sections 1 and 4 |
| Server | Start, stop, upgrade | `application_lifecycle` | 6002 | |

Deprecated classes (`security_finding`, `config_state`, `account_change`, `user_access`, the `*_query` classes) are never emitted. Trigger names in policies are `<class>.<activity>` with the activity caption in lower snake case (`policy-envelope.md` section 2.1).

### 1.1. Foundation scope and class allocation

The v0.1.x [roadmap](../roadmap.md) needs enrollment, policy installation, resource health and event delivery evidence. This slice admits only these classes. An unsupported class fails validation even if upstream defines it. Category IDs stay upstream values; only class IDs carry the extension offset.

| Class | Category | Local uid | Activities, exact numeric order starting at 1 |
|---|---|---|---|
| `ricevanta/agent_health_activity` | System Activity, 1 | 1 | sample |
| `ricevanta/policy_activity` | System Activity, 1 | 2 | evaluated, error, exception_applied, fail_open_applied, fail_closed_applied, command_refused, bundle_installed, bundle_refused, rule_unsupported, unit_throttled, unit_disabled |
| `ricevanta/pipeline_activity` | System Activity, 1 | 3 | drop, gap, quarantine, destination_state, archive, lookback_overrun |
| `ricevanta/certificate_lifecycle_activity` | Identity and Access Management, 3 | 1 | issue, renew, revoke, expire |

The allocation is permanent within this profile. `class_uid = 999 * 100000 + category_uid * 1000 + local_uid`; `type_uid = class_uid * 100 + activity_id` needs signed 64-bit arithmetic. Activity 0 and 99 are not emitted by these custom classes. Captions capitalize the first word and replace underscores with spaces. The maximum initial type is 9990300104. The checked [field catalogue](../../schemas/ocsf/contract-fields.md) owns field types, presence, bounds, conditions and coverage; do not duplicate them in producer code.

The four custom classes extend `base_event` and set the category explicitly. They do not extend upstream `system`, which requires an actor and device even for a server pipeline diagnostic. Host presence follows section 3. Reuse upstream metadata, product, extension, device, OS, certificate, fingerprint and policy objects through the catalogue's closed projections. Extension objects are not arbitrary maps.

The existing `extension.json` is a declaration, not a complete schema. Dictionary, object/event definitions, compiled output, generator and validators are implementation deliverables, not present implementations. `contract-fields.md` and `examples/` are design inputs. EV-03 fixes uid 999 permanently as the unregistered development namespace; no registration or uid migration is planned. Do not silently substitute another vendor's uid or describe Ricevanta as registered. The [upstream registry](https://github.com/ocsf/ocsf-schema/blob/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/extensions.md) reserves 999 for development; using the name `ricevanta` within that local namespace is Ricevanta policy, not an upstream registration.

## 2. The `ricevanta` extension

The extension table names foundation contracts and required later-slice additions. Foundation class IDs live in [section 1](#1-classes-per-domain); lineage and device-management class IDs remain unallocated. The field catalogue owns foundation fields and objects. Other rows define later-slice content, not fields admitted by this validator.

| Addition | Kind | Content |
|---|---|---|
| `lineage_activity` | Class, System Activity | `edge_type`, revision-qualified `source` and `target` (`lineage_node`), `confidence`, `evidence` (event uid plus summary), `inferred`, `summary`, `pressure` and explicit unknown-revision or identity-continuity state (`../design/lineage.md`) |
| `certificate_lifecycle_activity` | Class, Identity and Access Management | Foundation class; activities in section 1.1, exact fields and conditions in the [field catalogue](../../schemas/ocsf/contract-fields.md#5-activity-specific-fields-and-conditions) |
| `agent_health_activity` | Class, System Activity | Foundation class; activities in section 1.1, exact process, budget and spool measurements in the [field catalogue](../../schemas/ocsf/contract-fields.md#4-health-class) |
| `lineage_node` | Object | `kind`, `uid`, `display`; file nodes carry `device_uid`, `observation_namespace`, `file_incarnation`, `content_revision`, native identity hint, continuity state and content hash when known; paths are display observations, never identity (`../design/lineage.md` section 2) |
| `classification_ref` | Object | `scheme_uid`, `label`, `version`, `reference` (optional free text per DLP-03); added to `data_security_finding` and `file` |
| `match_evidence` | Object | `content_hash`, `rule_uid` with immutable `rule_identity` (`pack`, `version`, `pack_digest`, `rule_key`), `offsets` (list of byte ranges) per DLP-02, `coverage`, `inherited_from` (source revision and content hash when known), `sensitivity_floor` (revision identity and compact justification), `type_mismatch`, `warn` (`choice`, `justification`, `timed_out`); added to `data_security_finding`; the redacted snippet itself goes in the core `data_security.pattern_match` |
| `policy_bundle` | Object | The [field catalogue](../../schemas/ocsf/contract-fields.md#3-extension-dictionary-and-objects) owns its exact fields, including recovery_epoch; section 3 owns source and bundle-presence rules |
| `extension_origin` | Object | The [field catalogue](../../schemas/ocsf/contract-fields.md#3-extension-dictionary-and-objects) owns its exact fields and foundation policy-only placement; core-assigned provenance never grants authority. Fresh collector inventory requires the later committed-grant check in section 5 |
| `enforcement_mode_id` | Attribute on classes carrying the `security_control` profile | `enforce`, `monitor`, `fail_open_applied`, `fail_closed_applied`, `unsupported` |
| `author`, `rule_identity` | Attributes on `analytic` | Rule author for DRL attribution and immutable `{pack, version, pack_digest, rule_key}`; the upstream id remains descriptive metadata |
| `policy_activity` | Class, System Activity | Foundation class; activities in section 1.1, exact fields and conditions in the [field catalogue](../../schemas/ocsf/contract-fields.md#5-activity-specific-fields-and-conditions) |
| `pipeline_activity` | Class, System Activity | Foundation class; activities in section 1.1, exact fields and conditions in the [field catalogue](../../schemas/ocsf/contract-fields.md#5-activity-specific-fields-and-conditions) |
| `device_management_activity` | Class, System Activity | `activity_id` install, update, remove, os_update, lock, unlock, wipe, restart, shutdown, message, collect_diagnostics, run_script; `command_uid`, `channel` (agent, apple_mdm, oma_dm), `status`, `approval_id`, `package` or `script` SHA-256, `reason` |
| `rule_matches` | Attribute on `metadata` | List of `{pack, version, pack_digest, rule_key}` for the base rules of server correlations an agent event matched, so the server counts the exact version without re-evaluating (`../design/policy.md` section 4) |
| `query_row` | Object | Map of osquery column name to string value, with `action` (`added`, `removed`, `snapshot`); added to `evidence_info` |

### 2.1. Upstream pin and acquisition

Pin **OCSF release 1.9.0**, Git tag **`1.9.0`**, commit **`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`**, tree **`e759895035eef590258c37901fadaaafc629ee3d`**. The [tag API](https://api.github.com/repos/ocsf/ocsf-schema/git/ref/tags/1.9.0), [commit API](https://api.github.com/repos/ocsf/ocsf-schema/git/commits/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba) and commit-pinned `version.json` establish the pin. Do not use `v1.9.0`, `main`, an unversioned schema-server export or a floating compiler package.

Only the maintainer's explicit vendor-update operation fetches upstream. In a temporary checkout fetch the tag from `https://github.com/ocsf/ocsf-schema.git`, require the exact commit and tree above, and require `version.json` to contain `1.9.0`. Select root `version.json`, `categories.json`, `dictionary.json`, `LICENSE`, `NOTICE`, and every regular `.json` file below `events/`, `objects/`, `profiles/`, `includes/`, `extensions/` and `metaschema/`. A missing optional directory selects no files. Reject symlinks, submodules, traversal and duplicate paths; never run upstream code or copy its workflows.

Vendor exact bytes under `schemas/ocsf/upstream/1.9.0/`. Task 1 creates `upstream.lock.json` with closed keys `format` (1), `release`, `tag`, `commit`, `tree`, `repository`, and `files`. Each lexically path-sorted file entry has `path`, `bytes`, `git_blob` (40 lowercase hex) and `sha256` (64 lowercase hex). Paths are relative POSIX paths with no empty, dot or parent component. Verify each Git blob as SHA-1 over `blob <decimal byte length>\0` followed by its exact bytes against the pinned tree; then record SHA-256. The review compares the lock inventory with the pinned Git tree. Checks reject missing, extra or changed vendor files, including notice files. Hashes prove correspondence with reviewed source bytes, not trust in a publisher key.

Builds, generator `--check`, Python validation, Go tests and runtime are fully offline for schema data. They read the committed vendor tree and lock, never repair them or resolve a URL. Missing files fail the build. The implementation records actual file hashes, never placeholders or a digest of a rewritten JSON tree. Git archive compression bytes are not pinned because archive encoders can change. The commit/tree pin plus per-file commitments avoids that dependency.

Vendoring is justified by reproducible disconnected builds and immutable validation semantics. Preserve upstream LICENSE and NOTICE, add the notice to distribution attribution, and list the snapshot in the SBOM. The exact source row is in [licensing](../licensing.md). No upstream compiler, validator executable or runtime dependency ships. The in-project generator handles only the explicit projection in this contract; it does not claim to implement every OCSF extension.

## 3. Event envelope and caller boundary

The catalogue defines the exact emitted shape. Every admitted event has the seven required OCSF base fields, UUIDv7 event and correlation identifiers, exact product identity, source sequence and extension metadata. An isolated event uses its own uid as correlation uid; a related event uses its causal operation's uid. A server event has no invented endpoint or policy bundle. Agent events carry the host profile and device record uid. An agent with no installed bundle omits `policy_bundle` and names `bundle_state: absent`; it never fabricates a zero bundle identity.

`metadata.sequence` uses the existing unsigned 64-bit transport range, including zero and MaxUint64. Upstream calls its generic type `integer_t` signed, without a width; this field is an explicit Ricevanta unsigned override required by [body extraction](event-batch-body.md#6-strict-field-extraction-and-line-errors). Other unsigned counters use the same exact decimal token rules. Timestamps are integer epoch milliseconds from 0 through MaxInt64; no clock plausibility claim follows. `metadata.original_time` is an optional upstream string, not a second integer timestamp.

Only emitted events are validated here. `metadata.logged_time`, server enrichment and other undeclared attributes are rejected on this path; the later stored/export event profile must authorize those additions separately. `confidence_score`, script content, findings, raw data and rule matches are later domain fields. Do not leak them through `unmapped`.

For later script events, `metadata.is_truncated` marks content cut at the section 1 limit. The script contract requires the observed bytes' SHA-256 and byte length, the complete length when the sensor provides it, secret and identifier redaction before export, and local Sigma evaluation of the unredacted buffer before discard. Disabling content export retains hash, length and the detection's redacted evidence.

The caller supplies the source as `Agent` or `Server`; no event attribute can select that trust context. A server accepts agent uploads only through `Agent`. Agent source permits health, policy and pipeline activities 1, 6. Server source permits certificate, policy and pipeline activities 2 through 5. Platform restrictions in the catalogue constrain shape, not native support.

The later ingest path must first pass `wire.Decode` and `body.Decode`, retain each raw line and its preliminary binding result, strictly decode the line with `UseNumber`, then call this validator. A map cannot reveal duplicate keys, discarded fields, invalid source UTF-8 or repaired surrogate escapes. [Go UseNumber](https://pkg.go.dev/encoding/json@go1.27.1#Decoder.UseNumber) preserves number tokens but supplies no duplicate-key guarantee. Strict JSON parsing must therefore retain the body spec's whole-tree duplicate/key and encoding checks before map construction. This slice adds no permissive raw-byte shortcut. A caller must never build a map by unmarshalling directly to float64 or first passing through a lossy struct.

Decoded validation neither rebinds device identity nor chooses HTTP status. Schema errors become per-event quarantine only in the future ingest transaction. Body framing failures still reject the batch. Authentication, device equality, positional sequences, provenance grants, replay, enrichment, storage, quarantine persistence and durable acknowledgement keep their existing gates in [events](../design/events.md#3-server-ingestion).

## 4. Telemetry and platform coverage

EV-01 retains default findings, lineage, inventory, configuration state, health and bounded context, with full raw telemetry opt-in. This slice does not change routing, the five spool classes or the lookback window. Health uses findings/state, and policy and agent pipeline diagnostics use audit. Server events do not get an agent spool class.

`coverage` entries describe a missing measurement or deliberately omitted optional field. They never convert a missing required field into success and never grant rule support. All three target configurations, macOS ARM64, Windows x64 and Linux x64, require the four foundation contracts where their emitter applies. Pure JSON fixtures establish data portability only. Native sampling, durability, issuance and enforcement still need [platform qualification](platform-qualification.md).

The field catalogue's closed reason set differs from [adapter report reasons](rule-adapters.md#2-report). A later mapping slice must report every unsupported field and clause per OS; `field_unmapped` and `event_type_unmapped` are not synonyms for sensor failure. Unknown required data rejects the event or uses a specifically defined unknown branch. Never substitute zero, an empty string or an empty successful query result.

## 5. Later slices and dependencies

The following work remains required for v1.0.0 and has no compiled class in this slice. [Section 1](#1-classes-per-domain) owns domain event mappings and class IDs; [section 2](#2-the-ricevanta-extension) owns extension additions. Retain those upstream IDs when later contracts are designed; do not infer support from the vendored inventory.

| Later slice | Classes or artifacts | Dependencies before implementation |
|---|---|---|
| Foundation audit and server lifecycle | [Administration, authentication and Server mappings](#1-classes-per-domain) | Full typed audit payload, authority-journal ordering, before/after redaction, outcome and recovery contracts; lifecycle uses upstream Start/Stop/Update activities, not a new upgrade enum |
| EDR | [EDR mappings](#1-classes-per-domain) | Qualified sensors, response recovery and telemetry privacy; Windows native extension; script hash/length/redaction/truncation contract |
| DLP | [DLP mappings](#1-classes-per-domain); [extension additions](#2-the-ricevanta-extension) | Channel qualification, revision-bound evidence, privacy, warn and fail-mode contracts |
| Lineage | [Lineage mapping](#1-classes-per-domain); [extension additions](#2-the-ricevanta-extension) | Native incarnation and revision identity, continuity, floor recovery and bounded graph contracts |
| MDM | [MDM mappings](#1-classes-per-domain); [extension additions](#2-the-ricevanta-extension) | Per-kind evidence/recovery and command contracts; native inventory worker qualification |
| RADIUS | [RADIUS mappings](#1-classes-per-domain) | Exact-certificate versus identity-only evidence, gateway qualification, desired/attempt control versions and recovery |
| Sigma | `schemas/ocsf/sigma-logsources.yaml`; analytic rule identity and metadata rule matches | EDR emitted fields per OS, matcher/report schemas and immutable rule identities |
| Falco | `schemas/ocsf/falco-fields.yaml` | Linux event coverage, EDR schema and matcher/report contracts |
| osquery | `schemas/policy/osquery-tables.yaml` | MDM inventory snapshots, admitted SQL catalogue, isolated worker and evidence rows |

Full PKI profiles, SAN formats and certificate authorization remain PKI work. The certificate event here carries public observed facts and request identity; it cannot approve issuance. The shared extension-origin shape supports foundation policy evidence only; fresh collector inventory requires a later committed-grant check. No third-party publisher may replace the built-in schema.

## 6. Compiled format and deterministic generator

`schemas/ocsf/profile.json` is the exact, closed projection encoded from the field catalogue. Its only root keys are `format` (1), `profile` (ricevanta-ocsf-1), `classes` and `objects`. classes is a class_uid-sorted array of four closed records with keys name (qualified class name), local_uid, category_uid, class_uid, source_kinds (ordered subset of [agent, server]) and schema (a schema node). objects maps local definition names to schema nodes. Class schema refs use those same definition names. Every data-bearing property node and object/class root has an `x-source` pointer of `path#/attributes/name` or `path#` for a whole source definition; paths are relative to schemas/ocsf, including upstream/1.9.0 or extensions/ricevanta. Custom nodes point into the extension sources. Profile-only restrictions use `x-restriction` text plus the precise schema rule. Constraint-only composition nodes need no source binding. A source binding check rejects type, array, enum, category and required-field drift. A required inherited attribute cannot be removed; a profile may narrow allowed values or require additional fields. The catalogue's unsigned counters explicitly specialize integer_t; pipeline `bytes` and `spool_sample.bytes` also override signed `long_t` to `u64` at those use sites. Both retain a binding to `upstream/1.9.0/dictionary.json#/attributes/bytes` and an explicit `x-restriction`; the native dictionary type remains `long_t`. Narrowing an upstream generic object to a closed local object is permitted without changing its native dictionary type. No other widening is allowed.

Create OCSF-native `dictionary.json`, four files under extension `events/`, and one file per custom object under extension `objects/` from the catalogue. Upstream object augmentations use extension object files with `extends` naming their upstream object. Each new attribute has caption, description and type; object-valued and array attributes name their object type and `is_array`. Native source definitions retain OCSF enum captions and required flags. They describe fields; Ricevanta profile constraints live in `profile.json`. Name collisions with upstream require identical types or the documented unsigned-counter overrides; no silent dictionary override is allowed.

The generator is `schemas/ocsf/generate.py`, standard-library Python 3.14.8. CLI: `python schemas/ocsf/generate.py [--check]`. It reads no environment configuration, network or timestamps. Resolve source inheritance parent-first, then selected profile includes, then the concrete object's attributes. Merge attribute records by key; merge enums by numeric key with a child override, and replace scalar/array metadata. A null attribute removes it. Resolve `$include` only inside the pinned tree, apply only selected profile `host`, and reject cycles, missing refs or ambiguous extension names. Dictionary supplies type and array defaults, then inherited/concrete attributes specialize them. Unknown constructs on a selected dependency are errors, never ignored; unused vendored classes need no compilation. Strip deprecated attributes and reject any selected deprecated source. Check source constraints against the selected projection, including inherited required fields and `at_least_one` groups. The four custom classes intentionally avoid upstream audit-class dependencies. Selected event, object and profile source records use the closed grammar below. Keys are permitted only where the pinned source kind permits them; native extension definitions also pass the pinned metaschemas. Dictionary and type records retain their pinned grammar. Descriptive metadata never becomes an event field.

| Selected source member | Value grammar and compiler action |
|---|---|
| caption, description, name | Strings; name identifies the definition, caption/description are descriptive |
| uid | Nonnegative integer; contributes to class allocation |
| category, extends | Strings; resolve category and parent from the pinned sources |
| profiles | Array of profile-name strings; select only host |
| attributes | Map of attribute names to records or null removals; `$include` is an array of local source-path strings, filtered by profile selection |
| constraints | Closed object with optional `at_least_one` array of attribute-name strings; enforce inherited groups |
| associations | Map of strings to arrays of attribute-name strings; descriptive relationships, no additional event properties |
| observable | Nonnegative integer; descriptive observable identifier |
| references | Array of closed records with required description and url strings; never fetch URLs |
| @deprecated | Closed record with since and message strings and optional superseded_by array of strings; apply the rejection/removal rule above |
| meta | Profile-only string constant `profile`; identifies source kind, never event metadata |
| annotations | Profile-only closed object with optional group string; descriptive grouping, no constraint or include authority |

Attribute records recognize caption, description, group, requirement, type, is_array, enum, observable, references and @deprecated, plus pinned dictionary metadata sibling, source and suppress_checks. String metadata stays descriptive; requirement is required/recommended/optional, type resolves a dictionary type, is_array is boolean, and enum maps numeric strings to records containing caption and optional description, references or @deprecated. caption, description, group, sibling and source are strings; suppress_checks is an array of strings describing upstream lint exceptions and never disables Ricevanta checks. The nested references/deprecation records follow the table. Reject unknown keys at every selected record level, including annotations; do not interpret annotations as schema keywords.

The pinned [host profile](https://github.com/ocsf/ocsf-schema/blob/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/profiles/host.json) has `meta: "profile"` and `annotations: {"group": "primary"}`. Compilation tests must load its exact locked bytes through base_event inclusion, preserve its optional actor and recommended device requirements before Ricevanta narrowing, and compile all Agent branches with required device. Neither meta nor annotations appears in emitted events. Test misspelled root/annotation keys and malformed values as compilation failures. The pinned [dictionary](https://github.com/ocsf/ocsf-schema/blob/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/dictionary.json) binds type_uid and bytes to signed long_t; type_uid retains `x-integer: int64` with structural bounds 0..9223372036854775807 and exact `class_uid * 100 + activity_id` equality in the semantic rule, while source-binding tests must accept both named u64 overrides and reject an unsigned long_t widening at any other use site.

Output `compiled/manifest.json` has closed keys `format` (1), `profile`, `upstream_commit`, `inputs_sha256`, `classes`. `classes` is a numeric-class-sorted array of `{class_uid, path, sha256}`. One `compiled/<class_uid>.schema.json` per class uses JSON Schema Draft 2020-12, `$id` under `https://ricevanta.io/schemas/ocsf/compiled/`, and resolved `$defs`. All `$ref` values are local `#/$defs/<name>` references with no cycles. Every object is closed. A class schema includes source variants and activity branches. Neither `$id` nor `$schema` triggers a fetch.

Supported schema keywords are `$schema`, `$id`, `$defs`, `$ref`, `title`, `description`, `type`, `properties`, `required`, `additionalProperties` (false only), `items`, `minItems`, `maxItems`, `minLength`, `maxLength`, `minimum`, `maximum`, `enum`, `const`, `pattern`, `allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, `else`, plus annotations `x-source`, `x-restriction`, `x-maxBytes`, `x-integer`, `x-sourceKind`, `x-rule`. Types are object, array, string, integer, number and boolean; no null. No general dynamic maps, remote refs, format assertions, defaults, coercion or executable expressions. Patterns are anchored ASCII character classes, literal text, grouping, alternation, bounded repetition, optional groups and repetition of character classes or delimiter-separated groups; no lookaround, backreferences, Unicode classes or ambiguous nested quantifiers; every patterned string also has a byte ceiling. The checker and Go loader reject every unknown keyword before events are accepted.

x-source and x-restriction are strings. x-sourceKind is the string agent or server on a source branch. x-rule is a root-only array of unique rule names in catalogue evaluation order. x-maxBytes is a positive integer. `x-integer` is `uint64` or `int64`; it enforces canonical decimal tokens and exact range in both validators. `x-maxBytes` bounds decoded UTF-8, in addition to JSON Schema character limits where present. `x-sourceKind` marks the root's agent or server branch. `x-rule` names only catalogue cross-field rules: `type_uid`, `bundle_state`, `coverage`, `sequence_range`, `health_identity`, `pipeline_activity`, `policy_activity`, `certificate_activity`, `unmapped`, `truncation`. Implement these fixed rules explicitly, not as a language. JSON Schema handles presence and branches; rules handle equality, ordering, source selection and byte accounting. Every emitted schema contains exactly the rules applicable to its class.

Compute `inputs_sha256` over each input's relative POSIX path in lexical order: UTF-8 path, NUL, ASCII SHA-256 of exact bytes, LF. Inputs are the upstream lock, all its files, limits.yaml, profile.json and all extension JSON files. No generated output, example or generator source participates. Generator semantics belong to format 1; changed semantics need a format bump. Encode outputs with Python `json.dumps(sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False)` plus one LF; array ordering is defined by the catalogue or sorted for set-valued schema arrays. Write atomically only after every check passes. `--check` generates in memory and rejects byte drift, stale/extra outputs and changed embedded copies, without writing. Do not call this encoding JCS or reuse it for signatures.

Copy the compiled files byte-for-byte into `server/internal/events/ocsf/schema/` for `go:embed`. The generator owns both copies; a Go drift test compares them. Go never loads schemas from the working directory. The manifest digest detects accidental drift; the reviewed source/build is the trust anchor. A database row, extension package or console request cannot install a new schema.

## 7. Exact Go API, budgets and errors

Create `server/internal/events/ocsf`, importing the standard library and the existing `eventid` package only. The package has no import edge to body, wire, policy, database or HTTP code.

```go
package ocsf

type Source uint8
const (
    Agent Source = iota + 1
    Server
)
const (
    MaxDepth = 32
    MaxNodes = 16384
    MaxObjectFields = 128
    MaxArrayItems = 1024
    MaxStringBytes = 32768
    MaxTotalBytes = 1048576
)
func Validate(event any, source Source) error
var (
    ErrSource = errors.New("ocsf source")
    ErrBudget = errors.New("ocsf budget")
    ErrDecoded = errors.New("ocsf decoded value")
    ErrVersion = errors.New("ocsf version")
    ErrClass = errors.New("ocsf class")
    ErrShape = errors.New("ocsf shape")
    ErrConstraint = errors.New("ocsf constraint")
)
```

Accept only exact dynamic types `map[string]any`, `[]any`, `string`, `bool`, `json.Number`; nil is a decoded JSON value but never schema-valid. Reject typed nil maps/slices, aliases, pointers, structs, all Go numeric types including float64 and int64, invalid UTF-8 in keys/strings, and malformed number tokens. No reflection, user methods, implicit `json.Marshaler` calls or coercion. Callers must not mutate concurrently; immutable shared validation and concurrent calls are supported. Return no normalized tree; never mutate input.

Bounded preflight is iterative. Root depth is 1; increment for each nested container. Count every container and scalar as one node, keys only in total byte accounting. Check len(map), len(slice) and string length before sorting or traversing. Walk map keys in byte order and array indices in increasing order; visit repeated aliases each time. Cycles reach MaxDepth or MaxNodes and return ErrBudget. Total bytes are the sum of all decoded key/string bytes and number-token bytes plus one per bool/null and two per container, checked with remaining-budget subtraction. This is a work bound, not wire length or a promise about memory already allocated by the caller. Do not marshal an unbounded object to measure it. A global max-array value does not loosen a catalogue list bound.

`json.Number` tokens have at most 64 bytes. A longer token returns ErrBudget before token syntax checks, including when the token is valid JSON; this preflight failure precedes ErrVersion. The ceiling bounds work, so ErrDecoded is reserved for malformed tokens within the ceiling. Integer schemas require `0` or `[1-9][0-9]*` for unsigned, and `0` or `-?[1-9][0-9]*` for signed. Number schemas in this slice admit nonnegative decimal fractions with 1 through 6 fractional digits, or the unsigned integer spelling; no exponent or negative zero. Validate their rational value exactly with bounded integer arithmetic or `math/big`, not float64. These lexical restrictions are Ricevanta emission rules. Token syntax violations return ErrDecoded; a well-formed JSON exponent or fraction at an integer field reaches ErrShape. Bool is never an integer.

Stop at the first failed stage; within a stage return only that sentinel:

1. Invalid source enum: ErrSource, without inspecting the event.
2. Preflight: on each node, budget checks precede dynamic-type/UTF-8/JSON-number checks; first defect in the bounded ordered walk yields ErrBudget or ErrDecoded. Number-token length overflow yields ErrBudget; malformed tokens within the cap yield ErrDecoded. Both beat later version/class checks. No precedence is promised over unvisited nodes.
3. Missing/nonobject root or metadata, missing/nonstring metadata.version, missing/non-number class_uid: ErrShape. A validly typed version other than `1.9.0` is ErrVersion before class dispatch. Noncanonical/nonintegral/overflow class_uid is ErrShape; a representable unselected ID is ErrClass.
4. Apply the selected schema for the caller source. Missing/unknown/wrong-case members, wrong types, null, required/enum/range/pattern/list violations or forbidden source branch: ErrShape. Schema traversal order need not affect the sentinel. Schema byte limits also return ErrShape, not the global preflight ErrBudget.
5. Apply all fixed semantic rules in their catalogue order: ErrConstraint. Both UUID fields use eventid.Parse but expose only ErrConstraint, without wrapping eventid sentinels. Bad type_uid and bad UUID have the same primary sentinel. Error text contains no event data, values, paths or unknown keys.

Embedded schemas are trusted build artifacts, but the private loader validates their grammar, refs and manifest before use. Use `sync.Once` to initialize an immutable validated schema; a malformed embedded artifact is a build defect and `Validate` returns a private wrapped error, with no success or panic. Expose no public loader or runtime override. Tests require all supported event failures to match exactly one exported sentinel using `errors.Is`.

Required combined defects: invalid source plus cyclic map yields ErrSource; wrong version plus unknown class yields ErrVersion; unknown class plus unknown field yields ErrClass; unknown nested key plus bad type_uid yields ErrShape; oversize single string plus bad version yields ErrBudget; valid shape with wrong source context yields ErrShape. A lost duplicate key in a caller's map is undetectable, not proof of strict input admission. Tests document that limit.

## 8. Python checks, fixtures and verification

Implement `schemas/ocsf/validate.py` and `test_validate.py` with Python 3.14.8, `jsonschema==4.25.1` and `PyYAML==6.0.3`. Pin the installed transitive validation closure too: attrs==26.1.0, jsonschema-specifications==2025.9.1, referencing==0.37.0, rpds-py==2026.6.3 and typing-extensions==4.16.0. The primary adds these exact pins to the shared design requirements during implementation; no cryptography dependency is needed. Follow [Draft 2020-12 validation](https://json-schema.org/draft/2020-12/json-schema-validation) and the [pinned Python validator API](https://python-jsonschema.readthedocs.io/en/v4.25.1/validate/). Use `Draft202012Validator.check_schema`, an offline local-reference registry, custom keyword checks and the fixed semantic rules. Preserve number spelling with token wrapper classes, reject duplicate decoded keys and invalid source encoding before constructing trees, and distinguish bool from integer. A normal `json.load` plus schema validation cannot prove the full contract. Source checks also validate native extension definitions against the vendored OCSF metaschemas. No remote resolver is permitted, including on errors.

`examples/` contains four complete positive emitted events, one per custom class, and vectors.json carries accepted boundaries and rejected emitted-event mutations from the catalogue's vector table. They are design vectors, not evidence that a producer exists. Task 2 expands them into fixtures with `{name, source, event_json, expected_error}` in `fixtures/events.json`; `event_json` is a JSON string to preserve numeric tokens and intentionally malformed spellings. Parser-only invalid cases live in a separate fixture group and do not claim a Go Validate sentinel. The Python and Go fixture loaders must enforce the strict token contract. Body fixtures under `schemas/events/v1/` remain preliminary identity vectors, not OCSF-positive events; do not rewrite them to claim otherwise.

Required positive coverage: every custom activity; both sources where allowed; every target OS; absent and installed bundle; all coverage/unmapped reasons in eligible paths; all optional fields; exact uint64 maximum sequences and counters; lowest/highest severity; truncation; recovery epoch and grant generation boundaries; renew with predecessor. Cross-platform fixture variants change only documented OS/metric fields. One event per activity must pass both validators, including cross-field checks.

Required negative coverage: one deletion per required field at every object level; unknown/wrong-case property at every level; invalid enum/type/null; wrong category/class/type triple; unknown profile, extension uid/version or extra extension; malformed UUID/digest/identifier; token 1.0, 1e0, -0 and uint64 overflow; mixed valid and invalid optional objects; source mismatch; forbidden server enrichment; every activity condition; overlapping coverage entries and present fields marked absent; invalid range order; present zero-valued measurements with coverage claiming absence; fake bundle state; unknown/truncated unmapped fields without reasons; forbidden raw text; cyclic and aliased Go trees.

For every numeric, byte, depth, node, field and list bound, test limit-1, limit and limit+1; include multibyte strings whose character count fits but byte count fails. Test reordered input objects for identical acceptance/errors, local-reference cycles, unknown schema keywords, altered vendor bytes, extra/missing files, unresolved source fields, deterministic regeneration under two `PYTHONHASHSEED` values, and embedded-copy drift. A schema-only positive with wrong type_uid must fail both semantic validators. The type_uid vectors at MaxInt64-1 and MaxInt64 pass the structural range but return ErrConstraint for unequal class/activity values; MaxInt64+1 returns ErrShape before semantic checks.

`FuzzValidate` decodes bounded bytes with UseNumber and the strict test decoder, selects either source, and asserts no panic, no input mutation and stable repeated results. Seed every shared vector. Native Go tests add caller misuse, aliases and cycles which JSON cannot express. No local timed fuzz or race runs; CI owns `-race` and `-fuzz=^FuzzValidate$ -fuzztime=60s -parallel=2` plus the three-OS matrix. These tests establish portable validation, not OS telemetry qualification.

## 9. Threat trace and limits

| Attacker | End-to-end result within this slice |
|---|---|
| Stolen enrollment token | Schema validation cannot redeem the token or issue a certificate. If PKI later admits a device, its valid-looking events remain untrusted claims; PKI-02 and authenticated device binding must constrain admission. |
| Compromised agent host | Can fabricate every measurement, uid and provenance field for its uploads. Strict shapes and bounded work reject malformed trees, but valid claims gain no policy, identity or grant authority. Caller source cannot come from the payload. |
| Compromised console session | Cannot replace embedded schemas through configuration. Server-source validation still grants no right to write audit events, approve actions or issue certificates; authz and journal gates remain mandatory. |
| Rogue extension publisher | Cannot add a class or keyword at runtime. Can request or forge descriptive provenance through a compromised host; current core-assigned digests, epoch and grant generation must be verified by future admission. |
| Network position | No schema fetch exists to redirect at runtime. mTLS protects uploaded bytes in the later handler. Hashes and schema validity neither authenticate events nor stop valid replay. |
| Database writer without signing keys | Cannot change schemas embedded in the binary, but can forge or alter stored schema-valid events. This validator supplies no storage integrity, signature or audit-chain proof. |
| Server restored from backup | Loads its binary's fixed profile; validation restores no authority counters or freshness. BE-12 sealed restore must gate consumers. Replayed events can remain schema-valid. |

Benefits: a small shared vocabulary, exact rejection behavior, bounded offline checks and independently testable fixtures before producers or ingest. Trade-offs: a deliberately closed subset rejects otherwise valid OCSF events; explicit projection and native sources require drift checks; vendoring costs repository space; lexical numbers restrict third-party emitters. A source claim can lie even after every check passes.

Alternatives rejected: live schema-server export introduces network trust and availability; compiling every domain forces unresolved contracts into this slice; a general Go JSON Schema library adds a runtime dependency; accepting unknown properties hides typos and data leakage; hand-coded per-class Go checks drift from the compiled schema; generated Go/Rust types are premature before fixtures pass. Native source projection plus a small compiled-schema interpreter shares structure while keeping authority out of validation.

## 10. Unresolved questions and review focus

Choices below are defaults for this slice, not requests to stop work. Changing one needs a reviewed contract change.

- Keep domain mappings in section 1 with five columns and extension additions in section 2 with three columns; reject moving or reshaping those tables because the export validator parses that layout. Lineage and device-management IDs remain unallocated pending their own contracts.
- Keep type_uid bound to signed `long_t` with structural range 0..MaxInt64 and semantic equality; reject `u64` widening because the largest allocated value, 9990300104, fits signed 64-bit arithmetic and the pinned dictionary provides no reason to widen.
- Should future stored/export schemas admit enrichment through a separate entry point? Keep this validator emission-only; reject a caller-controlled enrichment flag.
- Should later class additions use a new profile revision or a minor OCSF upgrade? Keep profile format/revision separate from metadata.version; reject same-revision behavior changes.

Review focus:

- Exact release/tree verification and offline failure, including extra files and notices.
- Complete custom field definitions and no escape through coverage, provenance or unmapped.
- Full-width counters, including spool bytes, type_uid arithmetic and byte versus character bounds; 63/64/65-byte number tokens and version precedence.
- Source context, no invented device/bundle, and no claim that schema validity proves authority.
- Source projection, exact pinned host metadata grammar, inherited requirements, compiled drift and Python/Go semantic parity.
- No generated types or deferred-domain admission before their own reviewed contracts.
