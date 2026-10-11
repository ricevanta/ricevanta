# Foundation OCSF field catalogue

This catalogue defines the closed emitted-event projection for `ricevanta-ocsf-1`. The [profile](../../docs/specs/ocsf-profile.md) owns source acquisition, compilation, errors and trust boundaries. All paths below are event-relative unless an object is named. These are implementation inputs, not a claim that schemas or producers exist.

## 1. Notation and common rules

`!` means required. `?` means optional, absent rather than null. All other fields are forbidden, including undeclared upstream optional fields. Empty objects are allowed only when a table explicitly permits them. Bounds include both endpoints. Every string is valid UTF-8 with no code points U+0000 through U+001F or U+007F. No normalization, trimming or case folding occurs. Fixed literals are case-sensitive. Descriptive text must be producer-authored and must contain no raw content, credentials or free-form OS error message; schema validation cannot prove that privacy property.

| Type | Exact accepted values |
|---|---|
| `u64` | JSON integer token 0 through 18446744073709551615 |
| `positive` | u64 excluding 0 |
| `time` | JSON integer token 0 through 9223372036854775807, epoch milliseconds |
| `text(n)` | Nonempty UTF-8 string, at most n decoded bytes |
| `id` | text(256); opaque identity, no stronger upstream identity semantics implied |
| `token` | 1..128 ASCII bytes matching `[a-z][a-z0-9_.-]*` |
| `digest` | Exactly 64 lowercase hexadecimal characters, SHA-256 bytes without a prefix |
| `uuid7` | `eventid.Parse` canonical lowercase UUIDv7 contract |
| `version` | 1..64 ASCII bytes matching `[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?`; a descriptive release string, not a version comparator |
| `percent` | Nonnegative JSON decimal, at most 6 fractional digits, value 0..100 |
| `spool` | `raw`, `context`, `lineage`, `findings`, `audit` |
| `bool` | JSON true or false |

Patterns above are full-string matches. Compile the common control-character ban as an additional pattern on every string schema, including unconstrained descriptive text; combine it with field patterns using allOf. This also excludes final LF from dollar-anchor matching. Counter zero means a known zero, not unavailable data. Decimal integer tokens use the profile's lexical rules. Lists retain producer order unless the table requires a unique key; they never silently deduplicate. Every root field listed here uses its table's type, even when upstream's dictionary offers a wider generic type.

## 2. Common event and upstream projections

| Object | Fields |
|---|---|
| Every event | `activity_id!` class enum; `category_uid!` exact class category; `class_uid!` class constant; `type_uid!` signed `long_t`, JSON integer 0..9223372036854775807 (`x-integer: int64`), exact class/activity value enforced by the semantic type_uid rule; `severity_id!` integer 0..6; `time!` time; `metadata!` metadata; `device?` device; `unmapped?` unmapped; `message?` text(1024); `status_id!` enum 0 unknown, 1 success, 2 failure |
| `metadata` | `version!` constant `1.9.0`; `uid!` uuid7; `correlation_uid!` uuid7; `sequence!` u64; `product!` product; `profiles!` list; `extensions!` list of exactly one extension; `policy_bundle?` policy_bundle; `bundle_state?` enum `absent`, `installed`; `extension_origin?` extension_origin; `coverage?` 1..512 coverage_entry; `is_truncated?` constant true; `untruncated_size?` positive; `truncation?` truncation; `original_time?` text(128) |
| `product` | `name!` constant `Ricevanta`; `vendor_name!` constant `Ricevanta`; `version!` version |
| `extension` | `name!` constant `ricevanta`; `uid!` string constant `999`; `version!` constant `1.9.0` |
| `device` | `uid!` id; `hostname!` text(253); `type_id!` enum 0, 1 server, 2 desktop, 3 laptop; `os!` os; `labels?` 0..32 text(128); `groups?` 0..64 group |
| `group` | `name!` text(128); `uid?` id |
| `os` | `name!` text(128); `type_id!` enum 100 Windows, 200 Linux, 300 macOS; `version?` text(128); `cpu_architecture!` enum `arm64`, `x64` |
| `certificate` | `issuer!` text(2048); `serial_number!` 2..40 lowercase hex characters, even length; `subject?` text(2048); `uid!` id; `fingerprints!` list of exactly one fingerprint; `created_time!` time; `expiration_time!` time |
| `fingerprint` | `algorithm_id!` constant 3 (SHA-256); `value!` digest |
| `policy` | `uid!` id; `version!` version |

The extension object's uid is a string because upstream inherits it from `_entity`. The extension declaration's uid remains numeric 999. Do not confuse those two files. Device type values and OS values come from the pinned dictionary/object records. `cpu_architecture` reuses the upstream string dictionary entry and is added to the OS object by the Ricevanta extension. All other entries in this table project upstream object members except the metadata additions named in section 3. `policy.version` is descriptive policy version evidence.

For Agent: `device`, `bundle_state` and profiles equal to `["host"]` are required. macOS must carry arm64; Windows and Linux must carry x64. For Server: device, bundle_state and policy_bundle are forbidden and profiles must equal `[]`. Server deployment OS is not the endpoint platform; no OS is inferred from a certificate's subject device. No native extension is declared because these four classes use no native extension field.

Required base fields and category/type arithmetic are checked for every event. Require `certificate.created_time < certificate.expiration_time`, but never compare either with the local clock. Expiry evidence may arrive late. A revoked certificate still has its observed public identity. Never include PEM, key material, CSR bodies, SANs or enrollment tokens in this slice.

`metadata.original_time` retains the source's bounded textual timestamp when different from time. Upstream [metadata](https://github.com/ocsf/ocsf-schema/blob/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/objects/metadata.json) defines untruncated size as event kilobytes while the dictionary describes generic bytes. The object-specific meaning wins: use decimal kilobytes, rounded up from `truncation.original_event_bytes`. This decimal-unit choice is Ricevanta policy. Do not store bytes in that upstream field.

## 3. Extension dictionary and objects

Every field below that is absent from the upstream dictionary gets a Ricevanta dictionary entry. Reused names inherit the upstream type if compatible. Event-specific enums and integer ranges specialize the field at its use site. Use OCSF `integer_t` for bounded/u64 integer attributes, `long_t` for type_uid, `timestamp_t` for time, `float_t` for percent, `boolean_t` for bool and `string_t` for other scalars; the compiled profile owns exact integer widths and lexical restrictions. Object names below are their OCSF type names except unmapped, which is a compiled local definition over upstream generic object. Keep the native unmapped dictionary type as object; do not create a conflicting native unmapped type. Each list uses its item type and `is_array: true`.

| Object or metadata addition | Exact fields and rules |
|---|---|
| `policy_bundle` | `bundle_uid!` id; `sequence!` positive; `scope_id!` digest; `recovery_epoch!` positive. Sequence is the assignment counter within the recovery epoch, independent of metadata.sequence and spool stream_epoch. |
| `extension_origin` | `id!` text(253), `version!` version, `package_digest!` digest, `component!` token, `component_digest!` digest, `recovery_epoch!` positive, `grant_generation!` positive. `id` is dot-separated ASCII segments, each `[a-z][a-z0-9-]*`, with at least two segments. |
| `coverage_entry` | `path!` text(256), canonical JSON Pointer into a declared optional measurement; `reason!` enum from section 6. No free text, source value or executable expression. |
| `truncation` | `original_event_bytes!` positive; `original_unmapped_bytes!` u64; `omitted_entries!` positive. Only unmapped may be truncated in this slice. |
| `process_sample` | `uid!` id identifying a process lifetime, never a PID alone; `name!` token; `pid!` u64 up to 4294967295; `cpu_pct?` percent; `footprint_bytes?` u64; `footprint_metric!` enum `phys_footprint`, `private_working_set`, `pss`; `fd_count?` u64; `handle_count?` u64; `event_rates!` 0..128 event_rate |
| `event_rate` | `source!` token; `count!` u64. Count is the events observed during the containing sample's interval, not an estimated per-second float. Unique source within each process. |
| `budget_sample` | `unit!` token; `state!` enum `normal`, `throttled`, `disabled`; `memory_bytes?` u64; `memory_limit_bytes!` positive; `cpu_pct?` percent; `cpu_limit_pct!` percent excluding zero; `window_ms!` positive up to 3600000. Unique unit within health event. |
| `spool_sample` | `spool_class!` spool; `bytes!` u64; `oldest_unsent_ms?` u64; `dropped_segments!`, `dropped_records!`, `dropped_bytes!`, `upload_errors!` u64; `last_ack_sequence?` u64; `stream_epoch!` positive. Unique spool_class. All counters are cumulative within stream_epoch. |
| `sequence_range` | `first!` u64; `last!` u64. first <= last. A claimed range need not have the same count as a pipeline event's count unless section 5 says so. |
| `requester` | `kind!` enum `device`, `user`, `service`; `uid!` id. Refers to the requesting principal, not proof of authorization. No token or session secret. |
| `unmapped_entry` | `field!` enum `os_error_code`, `sampler_backend`, `native_event_code`; `index!` integer 0..127; `reason!` enum `field_unmapped`, `value_unmapped`; `value!` 1..256 ASCII bytes matching `[A-Za-z0-9_.:-]+`. |
| `unmapped` | `entries!` 1..128 unmapped_entry, unique (field, index) pair. Only allowlisted diagnostic tokens survive. No dynamic keys or nested source object. |

`metadata.bundle_state` and `metadata.coverage` are new dictionary attributes, as are `metadata.truncation` and the object-valued additions. `extension_origin` is permitted only on policy activity. Agent extension-origin events require an installed policy bundle, and the two recovery_epoch values must match; that equality still proves no current grant. Server extension-origin events retain all provenance fields but make no bundle claim. Other foundation classes forbid extension_origin.

An installed bundle requires exactly one policy_bundle; absent forbids it. Server policy events identify a candidate through `candidate_bundle_uid`, not metadata.policy_bundle. An agent's metadata.policy_bundle always describes the assignment in force, even when reporting refusal of a different candidate. A bundle_installed event names the installed bundle as its candidate. Privacy policy can omit descriptive data only where the schema provides absence; it cannot remove required identity fields and retain a valid event.

## 4. Health class

`agent_health_activity` has activity_id 1, status_id 1 and severity_id 1. It is Agent-only. In addition to common fields, require `interval_ms` (positive <= 3600000), `processes` (1..64 process_sample), `budgets` (0..128 budget_sample), `spools` (exactly five spool_sample). Optional `kernel_bytes` is u64; missing kernel measurement needs coverage. Process uid is unique within the event. No sample asserts an idle-memory or enforcement guarantee.

CPU percentage is CPU time divided by elapsed interval and logical processor count, multiplied by 100. It is normalized to 0..100 rather than one-core percentages above 100. Metric implementations and their cross-OS accuracy require native verification. Footprint names follow [agent section 6](../../docs/design/agent.md#6-memory-budget); verify the native sampling API during its own slice. Do not compare different footprint metrics as identical resident bytes.

| Platform | Required metric tag | Measurement presence |
|---|---|---|
| macOS ARM64 | phys_footprint | cpu_pct, footprint_bytes and fd_count present or individually covered; handle_count forbidden |
| Windows x64 | private_working_set | cpu_pct, footprint_bytes and handle_count present or individually covered; fd_count forbidden |
| Linux x64 | pss | cpu_pct, footprint_bytes and fd_count present or individually covered; handle_count forbidden |

For each omitted eligible measurement in processes or budgets, require exactly one coverage entry. Budget memory_bytes/cpu_pct may be absent with a reason; budget limits may not. Empty event_rates means no registered source for that process, not sampling failure; when any registered source cannot be measured, omit the health event and emit policy error with reason measurement_failed. No disabled unit silently disappears from budgets. Each spool measurement follows this exhaustive table. A present measurement has no coverage entry; every permitted absence has exactly one entry. Sampler failure means sensor_unavailable, permission_denied or collection_failed, as defined in section 6.

| Spool measurement and condition | Presence | Reason when absent |
|---|---|---|
| bytes, dropped_segments, dropped_records, dropped_bytes, upload_errors, stream_epoch | Required; zero is allowed except for stream_epoch | None; a sampler failure prevents this health event and requires policy error measurement_failed |
| oldest_unsent_ms, bytes = 0 | Forbidden; an empty spool has no oldest age | not_applicable only |
| oldest_unsent_ms, bytes > 0, age measured | Required u64, including zero | None |
| oldest_unsent_ms, bytes > 0, age unavailable | Absent | Sampler failure only |
| last_ack_sequence, acknowledgement measured, for any bytes value | Required u64, including zero | None |
| last_ack_sequence, no acknowledgement observed in stream_epoch, for any bytes value | Absent | not_observed only |
| last_ack_sequence, acknowledgement state unavailable, for any bytes value | Absent | Sampler failure only |

Conditional spool measurement presence and absence reasons are checked by the coverage rule and return ErrConstraint on failure; missing required spool fields return ErrShape. The validator accepts either permitted absence reason for last_ack_sequence because the event cannot prove whether an acknowledgement exists. It does not infer that state from spool bytes. Reject the alternative of allowing only not_observed, which would mislabel a sampler failure as an empty acknowledgement history.

## 5. Activity-specific fields and conditions

All fields in each class's union below are forbidden on the other classes. Each row's required/optional field list is exhaustive for its activity, in addition to common fields. `reason` is required except on health. It is a closed token, never a free-text exception. status_id describes the observed operation outcome, not transport acceptance.

Policy union: `policy` policy, `exception_uid` id, `command_uid` id, `candidate_bundle_uid` id, `rule_uid` id, `unit` token, `reason` enum. Agent and Server may emit policy; metadata rules still differ by source.

| Policy activity id | Required fields | Optional fields | Allowed reason; status_id |
|---|---|---|---|
| 1 evaluated | policy | none | completed; 1 |
| 2 error | none | policy, unit | evaluation_failed, measurement_failed, query_failed; 2 |
| 3 exception_applied | policy, exception_uid | none | exception_active; 1 |
| 4 fail_open_applied | policy | unit | timeout, resource_limit, sensor_unavailable; 2 |
| 5 fail_closed_applied | policy | unit | timeout, resource_limit, sensor_unavailable; 2 |
| 6 command_refused | command_uid | policy | invalid_signature, expired, stale_epoch, scope_mismatch, replay, unsupported; 2 |
| 7 bundle_installed | candidate_bundle_uid | none | installed; 1 |
| 8 bundle_refused | candidate_bundle_uid | none | invalid_signature, stale_epoch, scope_mismatch, replay, unsupported; 2 |
| 9 rule_unsupported | rule_uid | policy | unsupported; 2 |
| 10 unit_throttled | unit | policy | resource_limit; 2 |
| 11 unit_disabled | unit | policy | resource_limit, repeated_failure; 2 |

Bundle-installed is Agent-only and requires metadata.bundle_state installed and equal candidate/bundle uid. Other policy activities allow either source. Rule uid is a local descriptive identity here; immutable pack/rule matching and adapter reports are a later slice. Never use this event to claim a translated Sigma, Falco or osquery rule.

Pipeline union: `affected_device_uid` id, `spool_class` spool, `stream_epoch` positive, `sequence_range` sequence_range, `count` u64, `bytes` u64, `reason` enum, `destination` id, `destination_state` enum healthy/degraded/failed/lagging, `archive_uid` id, `quarantine_uid` uuid7, `event_uid` uuid7.

| Pipeline activity id | Source | Required fields | Optional fields | Allowed reason; status_id |
|---|---|---|---|---|
| 1 drop | Agent | spool_class, stream_epoch, count, bytes | sequence_range | corrupt, capacity, rejected, lookback_overrun; 2 |
| 2 gap | Server | affected_device_uid, spool_class, stream_epoch, sequence_range, count | none | sequence_gap; 0 |
| 3 quarantine | Server | affected_device_uid, quarantine_uid, count | event_uid | schema_invalid, device_binding, extension_binding, event_id, sequence, json; 2 |
| 4 destination_state | Server | destination, destination_state | none | recovered, retrying, dead_letter, paused, lag; 1 if healthy, otherwise 2 |
| 5 archive | Server | destination, archive_uid, count, bytes | none | completed, failed; 1 for completed, 2 for failed |
| 6 lookback_overrun | Agent | count, bytes | none | lookback_overrun; 2 |

Every pipeline count is positive. Quarantine count is exactly 1. quarantine_uid is a server-minted identity for the quarantine record. Optional event_uid refers to the rejected event only when strict extraction produced a valid unambiguous UUIDv7; invalid JSON or an invalid identifier must not require or invent one. Gap count must equal last-first+1 and the difference must be below MaxUint64; range 0..MaxUint64 cannot fit and fails. Drop ranges, when known, use the same equality; corrupted unknown ranges must be omitted, not invented. A lookback ring loss may use drop reason lookback_overrun or activity 6, but only one record for the same loss; correlation_uid links the affected finding. No recursive quarantine event is emitted for a rejected pipeline event within this validator.

Destination-state reason mapping is exact: healthy/recovered, degraded/retrying or dead_letter, failed/paused or retrying, lagging/lag. Archive success describes verified archive evidence from its producer, not proof supplied by the schema. `affected_device_uid` is required on activities 2 and 3, has type id, and is forbidden on other pipeline activities. It identifies the affected device without asserting the server itself is that device.

Certificate union: `certificate!` certificate, `ca_uid!` id, `profile!` token, `requester!` requester, `request_uid!` uuid7, `reason!` enum; `prior_certificate_uid?` id. Server-only. Activity 1 issue: reason issued and status 1; 2 renew: renewed and status 1, prior_certificate_uid required and different from certificate.uid; 3 revoke: reason revoked and status 1; 4 expire: reason expired and status 1. Other activities forbid prior_certificate_uid. These events describe completed transitions only. Failed issuance belongs to the future administrative audit contract, not a fabricated issued certificate. The profile token records the issuing service's profile name, including private agent identity and standard ACME issuance. It is descriptive, never an allowlist of issuance authority; certificate constraints and authorization remain owned by PKI.

## 6. Coverage, unmapped and truncation rules

`coverage.path` is a JSON Pointer with canonical decimal array indices (0 or nonzero digits without leading zero). Allowed paths are omitted process cpu_pct/footprint_bytes/platform-appropriate descriptor count, budget memory_bytes/cpu_pct, spool oldest_unsent_ms/last_ack_sequence, and root kernel_bytes. The containing array element must exist. No wildcard, escaped alias or absent parent is allowed. A path occurs once, points to an absent eligible field and never relaxes a required field. coverage is omitted when there are no missing measurements. It is allowed on health only.

| Reason | Exact meaning and permitted use |
|---|---|
| not_applicable | Empty spool has no oldest age, or kernel accounting does not apply to this host configuration |
| not_observed | No acknowledgement in this stream; only last_ack_sequence |
| sensor_unavailable | Eligible sampler lacks its required platform facility; never a permanent support exemption |
| permission_denied | Eligible measurement was denied by the OS |
| collection_failed | Eligible measurement attempt failed |
| privacy_filtered | Optional kernel accounting intentionally suppressed by the telemetry policy; no other required health metric may use it |

The spool table in section 4 owns spool presence and reason rules. Sampler failure reasons apply to the other eligible measurement paths; platform-forbidden descriptor fields must simply be absent and cannot receive coverage. `not_applicable` never excuses macOS/Windows/Linux required support. A producer reports missing measurements rather than fake zero values. Validation cannot detect a producer lying with an ordinary numeric zero.

Unmapped reasons describe retained diagnostic values: field_unmapped means no dedicated typed destination, value_unmapped means a known source enum value has no profile enum. Both require the same allowlisted field and bounded value. Index distinguishes repeated observations of the same diagnostic field; it supplies no authority. Unmapped is permitted only on policy errors and health samples. It never carries file contents, commands, user text, raw record bodies, keys or arbitrary source dictionaries. Policy coverage and adapter report reasons remain separate contracts.

Measure unmapped as compact ASCII JSON with keys sorted, separators `,` and `:`, no spaces or LF; admitted unmapped keys and values need no escaping. Its encoded size must be <=32768 bytes. Producers remove complete entries from the end until the cap fits and never cut a token. Retained entries remain a nonempty prefix or unmapped is omitted. Set all three metadata truncation fields together, never false or a partial triple. Require original_unmapped_bytes >32768, omitted_entries >0, original_event_bytes >= original_unmapped_bytes and untruncated_size = ceil(original_event_bytes/1000), computed without overflow. If no truncation occurred, all three fields are absent. Truncation fields do not authorize a still-oversize retained object or unknown property. The original byte counts are source claims; validation checks their consistency only.

## 7. Semantic rule order and vectors

After schema checks, evaluate: type_uid/category/activity equality; uuid7 fields; bundle_state and provenance epoch; coverage; sequence_range; health uniqueness/metric tags; pipeline_activity; policy_activity; certificate_activity; unmapped byte cap; truncation. All semantic failures use ErrConstraint. Source branch and activity-specific presence/enum/status constraints belong to schema checks and return ErrShape. Compiled rule names follow the profile's fixed list; UUID checks are included in type_uid, which runs first.

The four files in `examples/` are complete positive vectors for Linux health, agent bundle installation, agent spool drop and server certificate issue. Clone them for the activity and boundary matrix specified in the plan; never treat these four alone as full conformance coverage. Literal digest `a` repeated 64 times is synthetic evidence, not a computed certificate digest. No vector claims actual certificate verification.

| Mutation to the named example | Expected Go result |
|---|---|
| health: delete device | ErrShape |
| health: add processes[0].cpu_pct = 0 while its missing path remains covered | ErrConstraint |
| health: set os.cpu_architecture to arm64 with Linux type_id | ErrShape |
| health: spools[0].bytes = 18446744073709551615, oldest_unsent_ms = 0, remove its oldest-age coverage | Accept |
| health: same populated spool, bytes = 18446744073709551616 | ErrShape |
| health: bytes = 1, oldest age absent, its reason = collection_failed | Accept |
| health: last acknowledgement absent, its reason = collection_failed, bytes = 0 or 1 (nonempty oldest age covered by collection_failed) | Accept |
| health: bytes = 1, oldest age absent with not_applicable | ErrConstraint |
| health: bytes = 0, oldest age absent with collection_failed | ErrConstraint |
| health: bytes = 0, oldest_unsent_ms = 0 with its coverage removed | ErrConstraint |
| health: last acknowledgement absent with not_applicable | ErrConstraint |
| health: bytes = 1, oldest_unsent_ms = 0 and last_ack_sequence = 0, remove both coverage entries | Accept |
| health: bytes = 1, either absent measurement lacks coverage (other has collection_failed) | ErrConstraint |
| policy: sequence token 18446744073709551615 | Accept |
| policy: sequence token 18446744073709551616 | ErrShape |
| policy: sequence token 1e0 or 1.0 | ErrShape |
| policy: sequence token `1` followed by 62 or 63 zeroes (63 or 64 bytes) | ErrShape |
| policy: either token above plus metadata.version = 2.0.0 | ErrVersion |
| policy: sequence token `1` followed by 64 zeroes (65 bytes), with version 1.9.0 or 2.0.0 | ErrBudget |
| policy: metadata.version = 2.0.0 plus class_uid = 1 | ErrVersion |
| policy: class_uid = 1 plus unknown root member | ErrClass |
| pipeline: type_uid = 9990100302 | ErrConstraint |
| pipeline: type_uid = 9223372036854775806 (MaxInt64-1) | ErrConstraint |
| pipeline: type_uid = 9223372036854775807 (MaxInt64) | ErrConstraint |
| pipeline: type_uid = 9223372036854775808 (MaxInt64+1) | ErrShape |
| pipeline: bytes = null plus wrong type_uid | ErrShape |
| certificate: issuer absent | ErrShape |
| certificate: validate with Agent source | ErrShape |
| certificate: created_time equals expiration_time | ErrConstraint |

`examples/vectors.json` encodes these mutations as complete event_json strings, including both integer-token failures, the spool presence/reason cases and each number-token boundary/version combination. It uses the fixture container from plan task 2. Coverage-reason mismatches return ErrConstraint; token overflow returns the preflight sentinel defined by the profile.

The implementation must also prove the upstream bindings, including required issuer/serial, extension uid string, metadata product/version, host/device requirements with the exact pinned host profile's meta/annotations, and the two bytes u64 overrides in profile section 6. Unknown schema annotations must fail compilation; a typo cannot silently disable a constraint.
