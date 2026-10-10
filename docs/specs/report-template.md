# Report template

`ReportTemplate` is a closed, declarative resource for reports, dashboard panels and extension content format `report`. This slice publishes its machine-readable authoring contract and source catalogue, and specifies a decoded-template validator. Decision: BE-11. [The plan](../plans/report-template.md) assigns implementation and review; the Python checker and Go package are not implemented by this design.

The contract files under [`schemas/report/v1alpha1/`](../../schemas/report/v1alpha1/) are `report-template.json` (JSON Schema 2020-12), `catalogue.schema.json`, `catalogue.json` and `fixtures/templates.json`. The catalogue is the sole field inventory: 12 sources, each field's type, nullability, operators, grouping, aggregations and exact read permission. Schema acceptance alone cannot resolve references, check value compatibility or authorize a read.

## 1. Boundaries and choice

Use a standard-library Go leaf package with an embedded catalogue and fixture drift checks against Python. No SQL, script, CEL, template interpolation, HTML, arbitrary field paths, joins or caller-defined sources exist. Display strings are plain text; punctuation resembling markup remains text and must never be interpreted. The console renderer belongs to [console section 5.10](../design/console.md#510-dashboards-and-reports).

Included: closed schemas, typed catalogue, positive and negative fixtures, a Python schema and semantic check, and Go validation of an already decoded resource. Run execution, query translation, persistence, parameter submission, schedules, dashboard storage, rendering and extension admission remain separate slices. Section 4 names their inputs and outputs only. Pure validation grants no authority and does not establish platform support; full applicable support remains required on macOS ARM64, Windows x64 and Linux x64.

Installed toolchains: Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 with pnpm 11.18.0. Runtime dependencies: Go standard library only. Python uses the existing exact pins `jsonschema==4.25.1` and `PyYAML==6.0.3`; neither cryptography nor an added timestamp library is needed. Node tests regex parity. No dependency, licensing, build or workflow change belongs to this slice.

## 2. Resource contract

The JSON Schema owns local required fields, closed objects, disjoint variants, enums, patterns and count bounds. No field is silently dropped or coerced. Defaults describe interpretation without modifying the input [S1]. The wire loader must separately cap raw bytes at 65536 and reject duplicate keys, invalid UTF-8, YAML aliases, nonstring keys and multiple documents before decoding. This package cannot recover information lost by a permissive decoder [S2].

| Field | Meaning and constraints |
|---|---|
| Root | Exactly `apiVersion: ricevanta.io/v1alpha1`, `kind: ReportTemplate`, `metadata`, `spec` |
| `metadata` | Required DNS-label `name`, 1..63 ASCII bytes, unique per organization at admission; optional single-line `description`, 0..1024 Unicode scalars. `rv-` names are first-party and read-only at admission; offline validation accepts them. No labels, annotations, uid, revision or status |
| `spec.title`, KPI `label` | Exactly `en` and `vi`, each 1..256 Unicode scalars, single-line plain text |
| Heading/text `text` | Exactly `en` and `vi`, each 1..4096 scalars; TAB, CR and LF allowed. Other C0 controls and DEL forbidden. Extra locales need a reviewed contract extension |
| `parameters` | Optional array, 0..16 entries, unique names; each has `name`, `type`, optional `default`; only `enum_list` requires `field` |
| `datasets` | 1..10 entries: `name`, `source`, `filter`, `measures`; optional `group_by`, `order_by`, `limit` |
| `filter` | 0..32 keys including reserved `time` and `device_groups`; all predicates AND together; one operator per ordinary field |
| `group_by` | If present, 1..3 distinct groupable source fields; absent means a single aggregate row |
| `measures` | 1..8 named measures. `count` forbids `field`; every other function requires an allowed source field |
| `order_by` | If present, 1..11 distinct output fields, each `{field, desc?}`; absent `desc` means false |
| `limit` | Integer 1..10000, absent means 100; limits result rows, never the footprint needed to authorize those rows |
| `layout` | 1..64 blocks; names and field references are case-sensitive and never normalized |

Parameter, dataset, measure and field identifiers use `[a-z][a-z0-9_]{0,31}` across the whole string. Source ids use dot-separated identifiers as constrained by the schema. Names are unique within each parameter list, dataset list and dataset measure list. Measure aliases must not collide with any field in their source. Output columns are exactly `group_by` fields followed by measure aliases; filters do not create output columns. Unused parameters and datasets are allowed and still fully validated.

### 2.1 Parameter and operand types

| Parameter type | Default domain | Permitted reference sites |
|---|---|---|
| `time_range` | One of `last_24h`, `last_7d`, `last_30d`, `last_90d`, `this_month`, `previous_month`, or `{start,end}` | Reserved `time`, or `between` on a timestamp field |
| `device_groups` | `all` or 1..64 distinct device-group names using metadata name grammar | Reserved `device_groups` only |
| `enum_list` | 1..64 distinct members of the exact `source/field` enum named by `field` | `in` or `not_in` on that same source and field only |
| `string` | Plain single-line string, 0..256 scalars | `eq` or `prefix` on a catalogue `string` field only |

A parameter reference is exactly `{param: name}`. Missing defaults are valid definitions and require explicit values from a later run request; no value is inferred. Defaults must pass their declared type even when unused. No default contains a reference. Forward references to parameter definitions work. The validator checks declarations and sites, not submitted run values or group existence.

Timestamps use the project's strict RFC 3339 subset: exactly `YYYY-MM-DDTHH:MM:SSZ`, year 0001..9999, valid Gregorian calendar, seconds 00..59, uppercase T/Z, no offsets or fractions. Reject leap seconds and year zero. Absolute ranges require start < end; field `between` endpoints may be equal. Relative ranges remain symbolic, never read the clock here. The later resolver fixes one UTC evaluation instant per run; month presets use UTC calendar months [S4]. No maximum absolute interval is claimed; runtime query cost limits remain necessary.

Ordinary scalar literals are strings, finite numbers within +/-9007199254740991, or booleans. Null literals are forbidden. An ordinary field accepts scalar equality shorthand, `{param: name}` equality shorthand, or a one-key operator object. `eq`, `gte`, `lte` and `prefix` take one scalar or reference. `in`/`not_in` take a distinct list of 1..64 scalars or a reference. `between` takes exactly two scalars or a reference. `exists` takes only a literal boolean. Unknown operators and two-key operator objects fail structurally.

| Field type | Type-compatible operators, further restricted by the field's catalogue list |
|---|---|
| `string` | eq, in, not_in, prefix, exists; string values only |
| `enum` | eq, in, not_in, exists; exact catalogue members only |
| `boolean` | eq, exists; booleans only |
| `integer`, `number` | eq, in, not_in, gte, lte, between, exists; numeric values, integral for integer |
| `timestamp` | eq, gte, lte, between, exists; valid timestamps, or time_range at between |

Both literal endpoints must have the field's type and be ascending. A list cannot mix field types. `exists` tests non-null presence; all other operators, including `not_in`, are false for missing/null values. Prefix means literal case-sensitive prefix, never regex or wildcard. Equality compares typed values without case folding; negative numeric zero equals zero. An empty string is a valid string literal; empty lists never mean all.

Every source accepts reserved `time` and `device_groups`; absent keys mean no requested time restriction and all currently authorized entities respectively. `all` requests no narrower group selection and never expands authority. `time` uses `time_field`, with start inclusive and end exclusive. Explicit predicates on that time field AND with the reserved range. For organization-only sources a group filter cannot narrow the required organization authority; the later run resolver must require effective scope all regardless of supplied groups.

### 2.2 Measures and layout

`count` counts selected rows. Field aggregations ignore nulls; `count_distinct` returns an integer, including zero for no values. All field types may admit count_distinct. Only numeric fields admit sum, min, max, avg, p50 and p95. Integer sum/min/max preserve integer type; number sum/min/max and all avg/p50/p95 produce number. Empty sum/min/max/avg/p50/p95 produces null. Percentiles require a later query contract for interpolation; validation only checks the allowed function. Counts on a multirow source are row counts, not implicit distinct entities; each catalogue field description fixes any expansion grain.

| Block | Semantic checks after its schema branch passes |
|---|---|
| heading, text | Localized plain text only; no dataset or interpolation |
| kpi | Existing ungrouped dataset and existing measure; its output is numeric |
| table | Existing dataset and 1..11 distinct output columns; source fields outside group_by are unavailable |
| chart | `y` names a measure; `x` names a group_by field. `series`, when present, names a different group_by field |

Charts have exactly the group dimensions they consume: one for x without series, two for x/series. `stacked_bar` and `heatmap` require series; `pie` forbids series; line/area require timestamp x. Other x and series types may be any groupable type. All measures are numeric or nullable numeric; chart rendering must handle null without fabricating zero. Layout references never reach another dataset implicitly.

The positive `dlp-category` fixture is the authoring example. It includes all four parameter types, en/vi text, ungrouped KPIs, a category/channel chart and a table. Keeping the example in the corpus avoids duplicating a resource in prose.

## 3. Source catalogue and immutable delivery

`catalogue.json` has exactly `format_version: 1`, positive uint32 `revision`, and 1..64 `sources`. Each source has `id`, `owner`, `read_permission`, `scope`, `footprint`, `conditional_reads`, `time_field`, `row_aggregations: [count]` and 1..64 `fields`. Each field has `name`, `type`, `nullable`, `filterable`, `groupable`, `operators`, `aggregations`, `description`, and `values` only for enum. Source ids and field names are unique and strictly ascending by ASCII bytes. Capability lists have no duplicates; their order has no semantic meaning. Empty operators means filterable false and vice versa.

The schema restricts type/operator/aggregation compatibility. Semantic checks require a non-null timestamp time_field, no field named `time` or `device_groups`, and the exact source bindings below. The shipped set is exactly these 12 sources, with the complete fields in the snapshot. New fields or sources require a reviewed snapshot and revision increase; removing or retyping a field, shrinking an enum or changing a binding requires a new contract version. Unknown revisions are not negotiated by a template.

| Source | Owner | Base read permission | Footprint rule |
|---|---|---|---|
| devices | devices | mdm.devices.read | devices |
| devices.software | mdm | mdm.inventory.read | devices |
| mdm.compliance | mdm | mdm.compliance.read | devices |
| edr.alerts | detection | edr.alerts.read | devices |
| edr.response_actions | detection | edr.response.read | devices |
| dlp.findings | dlp | dlp.findings.read | devices |
| lineage.edges | lineage | lineage.edges.read | lineage_endpoints |
| pki.certificates | pki | pki.certificates.read | certificate_profile |
| radius.authentications | radius | radius.authentications.read | radius_attribution |
| agents.versions | devices | mdm.versions.read | devices |
| agents.health | events | events.health.read | devices |
| audit.events | audit | audit.events.read | organization |

Every base permission has scope device_group except audit.events.read, which has scope organization. Only pki.certificates has a conditional read: `infrastructure_certificate` adds `pki.infrastructure.read` with scope organization. Authoritative profile classification determines this condition, never template filters, device_uid nullability or caller claims. Do not require infrastructure access for a purely device-certificate selection and do not use device access to expose infrastructure rows. Before aggregation, the later query compiler must prove a device-only selection from authoritative profiles or require the conditional permission for the selected infrastructure domain, even when that domain returns zero rows. A caller-supplied filter cannot itself prove the classification. Refuse unresolved domains rather than silently dropping unauthorized rows. This follows [permission catalogue section 3](permission-catalogue.md#3-scope-and-composed-requirements); permission names remain unchanged.

Footprint obligations passed to later source adapters:

- devices: immutable device uid of every contributing row, even when grouped or excluded from the output projection.
- lineage_endpoints: immutable source and target entity uids and their device bindings, checked on both ends; unresolved access is a refusal, never a hidden-neighbor count.
- certificate_profile: immutable certificate uid, authoritative profile classification and device binding, plus the conditional permission whenever the authorized query domain includes infrastructure, even without a contributing row.
- radius_attribution: immutable authentication uid and provable device binding; an unbound or rejected identity without that proof requires scope all under radius.authentications.read.
- organization: organization uid and required all scope, even for zero-row counts. Scoped zero-row runs still record every base permission used.

The catalogue contains no source rows, snippets, raw matched content, fingerprint originals, credentials, private keys or escrow secrets. Its field descriptions define normalized reporting projections, not claims that module adapters or SQL mappings exist. Those adapters must verify value mappings, enum coverage, row grain and entity bindings before execution; an unmapped value is a reported adapter failure, never a dropped row or invented success.

Go embeds a byte-identical copy at `server/internal/events/reportvalidate/catalogue.json`, as an unexported string. Embed paths are package-relative [S5]. No environment path, database replacement, HTTP fetch, exported arbitrary-catalogue loader or extension catalogue registration exists. The private loader caps embedded bytes at 1048576, container depth at 16 and values plus keys at 32768 before materializing catalogue state. It checks embedded syntax, shape, capabilities, ordering and binding table; any failure returns ErrCatalogue without a partial catalogue. Tests compare exact bytes with the canonical file and check every binding against the active permission catalogue. Runtime validation uses only this immutable catalogue.

## 4. Later consumer inputs and outputs

These are requirements for separate slices, not APIs or storage formats implemented here. Do not implement consumers that depend on an unreviewed query, authorization or footprint-storage contract.

| Consumer | Inputs | Outputs and authorization obligations |
|---|---|---|
| Strict API/GitOps/content loader | Bounded bytes; authenticated operation or verified extension package ownership | Duplicate-free decoded tree; run this schema/semantic contract. Preserve signed extension bytes; content format is exactly report, with one ReportTemplate per content file |
| Template admission | Valid tree, immutable catalogue revision, current caller and ownership | Stored immutable template revision; enforce rv- ownership and operation permission. Schema validity supplies neither extension trust nor write authority |
| Parameter resolver/query engine | Template revision, submitted values, defaults, one UTC instant, current operator scope | Typed fully resolved parameters and module-owned dataset requests. Revalidate submitted types and bounds, resolve groups, enforce source permissions before counts, apply 60-second dataset timeout and row limits. No cross-module table reads |
| Source adapter/run writer | Resolved dataset, current authority, immutable source revision | Typed rows plus complete immutable contributing entity footprint and every permission/scope condition used. Bind template/catalogue revisions, resolved parameters, runner, result digest and footprint digest to one immutable run; no mutable names as proof |
| Run read/list/download/cache | Authenticated reader, committed current authority and immutable run | Return metadata or rows only with events.reports.read and every recorded source permission plus current coverage of the whole footprint. Missing/deleted/unresolvable entities deny the whole result. Recheck for ranges, retries, exports and cached panels; private blobs have no bypass URL |
| Schedule | Template revision, parameter values, UTC cron, notifier refs, current owner | Execute with owner's current run/source rights; disabled owner or lost rights pauses with audit. An editor becomes the runner. Notifiers receive a link, never rows |
| Dashboard/renderer | Authorized run, locale, declarative layout | Plain text, numeric series, CSV/JSON dataset export and browser print output under console section 5.10; cache keys include operator, current authority version and footprint digest |
| Retention | Installation setting, immutable runs | Default 90-day retention; expiration removes result availability, never changes authorization proof |

A stolen or stale source description cannot act as an authority receipt. Future run readers must check current permission metadata and committed grants, not merely replay the strings returned by this validator. BE-12 restore fencing remains mandatory. Already delivered copies remain in the reader's custody.

### 4.1 Operator action bindings

This library and its local tests introduce no network operation or privileged operator action. Pure offline validation and listing bundled schema metadata have a reasoned exemption: they process caller-owned content and static product metadata, access no installation data and change no authority. A server validation route is not introduced. The integration operations named here retain these exact catalogue bindings; selectors use the permission catalogue's operation notation.

| Action or selector | Permission or composed requirement |
|---|---|
| getReportCatalogue | events.report_catalogue.read; metadata only |
| listReportTemplates | events.report_templates.read |
| createReportTemplate; api:update-report-template; api:delete-report-template | events.report_templates.create; events.report_templates.update; events.report_templates.delete respectively |
| createReportRun | events.reports.run plus every base and applicable conditional source read and current scope |
| getReportRun; listReportRuns; api:download-report-dataset | events.reports.read plus current source reads and complete footprint coverage |
| listReportSchedules; api:delete-report-schedule | events.report_schedules.read; events.report_schedules.delete respectively |
| createReportSchedule; updateReportSchedule | events.report_schedules.create; events.report_schedules.update respectively, plus events.reports.run and source checks |
| listDashboards; updateDashboard | events.dashboards.read; events.dashboards.update respectively; rendering or preview adds run-read/run and source checks |
| createExport#non-audit; createExport#audit for report data | events.exports.create for non-audit; audit.events.export and audit.events.read for audit; both retain report and source checks |
| Extension content admission | Existing extensions.packages.install or extensions.packages.upgrade operation, protected admission and content ownership; validation grants no package or report write authority |

GitOps applies the same create/update/delete operation checks. A dry run grants no extra visibility. Extension content reaches the existing admission pipeline, not an unbound import action. Browser print of already authorized rows adds no server operation. A future new endpoint, ownership transition or report action needs its own coverage entry. This slice does not edit schemas/permissions/; its source-digest refresh remains separate permission-catalogue maintenance.

## 5. Exact Go API

Package `github.com/ricevanta/ricevanta/server/internal/events/reportvalidate`:

```go
package reportvalidate

type Catalogue struct { /* unexported immutable state */ }
type ConditionalRead struct { Condition, Permission, Scope string }
type SourceRequirement struct {
    Source, Permission, Scope, Footprint string
    ConditionalReads []ConditionalRead
}
type Result struct {
    Name string
    CatalogueRevision uint32
    Sources []SourceRequirement
}
type Error struct { Path, Rule string; Cause error }
func Builtin() (*Catalogue, error)
func (c *Catalogue) Revision() uint32
func (c *Catalogue) JSON() []byte
func Validate(resource map[string]any, catalogue *Catalogue) (Result, error)
func (e *Error) Error() string
func (e *Error) Unwrap() error
var (
    ErrCatalogue = errors.New("report catalogue unavailable")
    ErrInput = errors.New("report input")
    ErrLimit = errors.New("report limit")
    ErrEnvelope = errors.New("report envelope")
    ErrSchema = errors.New("report schema")
    ErrSemantic = errors.New("report semantic")
)
```

Builtin initializes once without panic or I/O; repeated calls may share immutable state. Nil/zero Catalogue has Revision 0, JSON nil, and cannot validate. JSON returns detached bytes. Result is zero on every error; on success Name copies metadata.name, CatalogueRevision identifies the snapshot, and Sources contains each used source once in ASCII order, with detached conditional-read slices. Requirements include unused datasets. They describe obligations, never effective grants, resolved entities or authorization.

Every error is *Error with Unwrap for errors.Is and fields for errors.As [S3]. Error() is exactly `report validation <rule>`; it excludes paths and submitted strings to avoid logging attacker-controlled map keys. Path is a diagnostic-only RFC 6901 pointer [S6], empty at root; callers must not log Path blindly. Rule is one fixed token from section 6. No raw values enter errors. Calls do not mutate, normalize, insert defaults, resolve external references or retain input aliases. The caller must not mutate an input concurrently; independent inputs and shared Catalogue support concurrent calls.

## 6. Input domain, limits and deterministic errors

Only map[string]any, []any, string, bool, nil and finite float64 belong to the decoded Go domain. Numbers have absolute value at most 9007199254740991; integer fields require zero fractional part. Strings and keys require valid UTF-8. Nested typed nil maps/slices, native ints, json.Number, pointers, structs, custom marshalers, NaN and infinities are ErrInput. Root nil is allowed through preflight and fails ErrEnvelope. Never invoke custom methods. Cycles exhaust depth without recursion panic; shared subtrees count once per occurrence.

Preflight limits: 16 container levels including root, 8192 values plus object keys, 131072 raw UTF-8 bytes across keys/strings. At each value, charge its node, check container depth and type, then test raw string byte length before scanning UTF-8; validate finite numeric values directly. An oversized string returns budget even if its UTF-8 is invalid. An object key charges one node and its valid UTF-8 bytes immediately before its value. Before sorting keys, reject an object if twice its entry count exceeds the remaining node budget, or the sum of its key byte lengths exceeds the remaining raw-string budget; both errors report that object path. This length precheck does not charge the keys twice. Reject an array if its element count exceeds the remaining node budget. Traverse objects in byte order and arrays in numeric index order. The first preflight failure wins: ErrInput/input or ErrLimit/budget at the encountered path. At overflow before descent report the container path; oversized strings report the string path. Use saturated counters, not input-sized serialization or reflection calls.

After preflight compute a conservative encoded charge: null 4, booleans 4/5, numbers 24, strings 2 plus UTF-8 bytes with quote/backslash charged 2 and each C0 scalar charged 6; containers add brackets and each comma/colon. Object keys are charged strings. Charge >65536 is ErrLimit/bytes at root. The charge is not a hash or raw JSON length. Exact vectors: null=4, true=4, 0=24, empty object=2, empty string=2, `"ế"`=5, `[0]`=26, `{"a":0}`=30, and the string containing quote, backslash and LF=12.

Validation stages stop at the first failing stage:

1. Nil/zero catalogue: ErrCatalogue/catalogue at root, even with invalid input. Builtin internal failures also use that error without exposing catalogue data.
2. Preflight domain and traversal bounds, then encoded charge, as defined above.
3. Envelope: exact root fields, apiVersion/kind, metadata rules and object spec. ErrEnvelope/envelope. Wrong or missing spec contents wait for stage 4.
4. Structural spec: mirror report-template.json, selecting variants by type, `param` presence or operator key under the dispatch rules below before child checks. ErrSchema/schema. JSON Schema does not implement the following semantic stages.
5. Duplicate named parameters/datasets/measures and order_by fields: ErrSemantic/unique, at the second name/field. Measure/source field collision waits for output checks.
6. Resolve every parameter enum field, dataset source, filter field/param, group_by field, measure field and layout dataset: ErrSemantic/reference, at the missing reference. Resolution covers all branches before any type checks.
7. Enum parameter field types, calendar and range order, enum defaults, operator membership, literal/parameter types, field aggregation membership and groupability: ErrSemantic/compatibility at the parameter field, operand, default, fn or group_by entry. An `enum_list` declaration whose resolved field is not enum reports its `field` path, even when unused or without a default; skip its dependent enum-default checks. Missing fields remain stage 6 reference failures. Operator membership failures point to the condition; typed-operand failures point to its operand, list errors to the offending element. Literal reversed between points to element 1, absolute range order to end. Invalid absolute instants point to start/end.
8. Output aliases, order_by output fields, layout output fields and shape: ErrSemantic/output. Alias collision reports measure name; missing layout output reports its reference; wrong KPI grouping and wrong chart dimension count report block dataset, wrong x/series role reports x/series. Chart time requirement reports x.

Within stages 3..8 compare location sequences, parent first, string keys by UTF-8 bytes, array indices numerically. Missing properties report their intended child path; unknown properties report their own path. At one location use required, forbidden, type, enum/const, range/length, pattern, branch order; do not surface speculative errors from inactive variants. Apply the following structural dispatch before child checks; selected branches follow the ordinary missing/forbidden rules.

- An ordinary condition object containing `param` selects the reference branch, even with operator keys or an invalid `param` value. Other keys are forbidden; compare their paths with any invalid `param` path using the location order above. Without `param`, the object must have exactly one key and that key must be a known operator to select its operator branch; zero, multiple or unknown keys report the condition path.
- At scalar-or-reference and list-or-reference operand sites, every object selects the reference branch. An absent `param` reports the intended `/param` child; a wrong type or invalid identifier reports `/param`; extra keys report their own child paths. Nonobjects select the literal branch. `exists` accepts only a boolean and never selects a reference branch.
- At reserved `time`, an object containing `param` selects the reference branch; every other object selects the absolute-range branch. At reserved `device_groups`, every object selects the reference branch. Defaults never select a reference branch.

For example, `channel: {eq: browser, param: p}` returns `ErrSchema/schema` at `/spec/datasets/0/filter/channel/eq`. `channel: {eq: {}}` returns the same sentinel/rule at `/spec/datasets/0/filter/channel/eq/param`.

Semantic ties use the order of rules in the numbered stage. Unknown source or dataset suppresses dependent semantic checks, not checks in other branches. Python returns the same sentinel/path/rule, not jsonschema's library text.

## 7. Fixtures and checks

`fixtures/templates.json` is an array of closed records `{id, structural, accepted, sentinel, path, rule, document}`. Ids are unique lower-kebab-case ASCII. Success has empty diagnostic strings. Structural means pure Draft202012Validator acceptance; accepted means all stages with Builtin. Every record embeds a complete template; no patch interpreter or external retrieval is needed. The implementer may add reviewed cases, never change expectations merely to agree with Go.

The planned `validate.py` provides `validate_template(document) -> list[dict]` with zero or one `{sentinel,path,rule}` and `check_catalogue(document) -> list[str]` with integrity failures. It runs independent schema validation, checks every fixture expectation, validates embedded examples, checks the exact source set and every active permission binding against schemas/permissions/v1/catalogue.json, and fails for missing/extra files, duplicate keys, nonfinite numbers or off-tree references. Only two schemas are registered locally; every $ref and fragment must resolve without network access. Semantic errors follow section 6 rather than oneOf diagnostic order.

The Go package's private catalogue loader checks the full shape and source binding table without a schema interpreter. Tests compare bindings with the permission JSON, including owner, scope, active status and grant role. No runtime authz import is needed. Catalogue tests mutate unknown/retired/misspelled permissions, swapped owner/scope/footprint, removed conditional permission, non-timestamp time_field, duplicate/unsorted ids, enum values, invalid capability/type pairs, unknown properties and missing fields. All must refuse the catalogue or fail the cross-catalogue drift test before consumer use.

Required generated tests in both implementations extend the compact corpus:

- All 12 sources and every field/operator/aggregation capability; each incompatible pairing; all six chart variants; every parameter type, with absent and explicit defaults; every reserved filter form.
- Each count/length bound at 0, 1, cap, cap+1; exact encoded charges 65536/65537 with schema-valid bilingual text; multibyte/control escapes, integers versus booleans and numeric zero; preflight node/depth/raw-string limits separately.
- Missing and unknown properties in every closed object; mixed reference/operator selectors, malformed references and reference-first dispatch; non-enum parameter fields with absent and explicit defaults; union overlap; trailing LF in identifiers; missing en/vi; nulls; duplicate names; cross-source enum parameters; unknown references; count with field; measure alias collision; non-output sort/column; grouped KPI; chart dimensions and timestamp x.
- Calendar leap/non-leap February, impossible month days, equal/reversed ranges, forbidden offsets/fractions/leap second/year zero; missing/null operator behavior remains a query-engine test, not proof from this validator.
- Combined defects: nil catalogue plus malformed input -> catalogue; overcharge plus bad kind -> bytes; bad apiVersion plus bad filter -> envelope; structural defect plus duplicate name -> schema; duplicate name plus unknown source -> unique; unknown field plus wrong default -> reference; incompatible aggregate plus invalid layout output -> compatibility.
- Direct Go hostile values, invalid UTF-8, aliases, cycles and custom marshalers; deterministic repeat errors, no mutation, detached results and no error-string leakage. Pure JSON fixtures cannot encode these Go-only cases.

TestFixtureDrift uses runtime.Caller to locate the corpus, fails if absent, asserts structural expectations through Python separately and full expectations via Go, errors.Is/errors.As and zero Result. TestBuiltinDrift compares exact catalogue bytes. FuzzValidate decodes bounded JSON and checks determinism, no panic, zero results on error and no mutation. FuzzBudget compares charge to an independent oracle on bounded trees. Ordinary tests execute seed corpora [S7]; timed fuzz and race runs belong to CI only. Two independent temporary scripts recompute published vectors before design handoff.

## 8. Security trace and review focus

The trust path is bounded bytes -> strict decoder -> schema/semantic checks -> authorized immutable admission -> authorized module query -> result plus immutable footprint -> current-authority read. This slice supplies only checks and catalogue obligations. No signature, execution or current-grant proof follows from acceptance.

| Attacker | What the attacker gets and what still blocks escalation |
|---|---|
| Stolen enrollment token | Can attempt enrollment under enrollment restrictions; token is not an operator principal. Validator has no enrollment route and grants no report permission |
| Compromised agent host | Can lie about observed inventory and telemetry. Fixed projections exclude secrets but cannot establish truth; source adapters need authenticated provenance and authoritative entity bindings |
| Compromised console session | Can submit bounded valid templates under the victim's rights. Closed fields prevent query/code injection through this language; current source rights, footprint checks and session controls must still fence data reads and writes |
| Rogue extension publisher | Can supply report text and bounded filters, never executable content or a source/permission override. Package verification, trust, ownership and protected admission remain required; a signed report is not a data grant |
| Network position between agent and server | Can delay/drop data; validation does not authenticate traffic. Existing TLS and signed package paths protect their own bytes; report freshness and provenance remain source responsibilities |
| Database writer without signing keys | Can replace template, result or footprint rows. Embedded catalogue prevents a database-supplied permission mapping, but this validator cannot detect a valid malicious row replacement. Immutable revision/result/footprint integrity and committed-authority checks must be designed before storage consumers |
| Server restored from backup | Can recover stale valid templates, runs and permissions. Static validation cannot revive authority. BE-12 sealing and reconciliation plus current checks must precede admission, queries and reads; unresolved integrity denies availability |

Review focus: field and alias confusion cannot expose unprojected data; catalogue metadata never replaces grants; PKI conditional access and both lineage endpoints survive aggregation; every non-table path keeps footprint checks; bounded decoded input cannot trigger unbounded sorting or traversal; structural and semantic validators agree without sharing the same bug; plain-text labels cannot become markup or interpolation.

Benefits: offline review and extension delivery share one language, exact source permissions travel with validation results, and bounded pure checks need no live services. Trade-offs: hand-written Go duplicates schema logic and requires drift tests; normalized source projections need later module mapping qualification; strict bilingual labels and UTC timestamps restrict authoring flexibility. Dependencies: BE-11, the permission catalogue, strict byte loading, current-authority evaluation and reviewed source/footprint contracts. Limits: no runtime query safety, aggregate precision, row authenticity, footprint integrity or restore guarantee is established here.

Alternatives: a generic Go JSON Schema dependency reduces shape duplication but not semantic checks and adds a dependency; dynamic source registration admits unreviewed permission mappings; SQL/script templates cross module and authority boundaries; group names as historical footprints lose entity identity. All are rejected for this slice. The selected decoded validator follows the [MDM resource pattern](mdm-resource-schemas.md).

## 9. Unresolved questions

- How should mixed reference/operator selectors choose diagnostics? This slice chooses reference-first dispatch whenever `param` is present and rejects operator-first or condition-level rejection so all reference sites use the same closed-object rules.

- Should locale support grow beyond en/vi? This slice chooses exactly the two product locales and rejects arbitrary tags until a bounded localization contract exists.
- Should report timestamps accept offsets or fractions? This slice chooses whole-second UTC and rejects decoder-dependent normalization; a later version can widen the grammar deliberately.
- Which module mappings prove every normalized enum, row grain and field projection? This slice chooses an explicit snapshot and rejects execution until adapters verify the mappings.
- Which percentile interpolation, numeric overflow and immutable footprint storage contracts will execution use? This slice validates function selection and names the required outputs; it rejects guessed query semantics and mutable group-name proofs.
- Should untrusted offline catalogues be accepted? This slice chooses the embedded reviewed snapshot and rejects runtime replacement; future CLI/server compatibility needs its own authenticated negotiation contract.

## Sources

- [S1: JSON Schema 2020-12 Validation](https://json-schema.org/draft/2020-12/json-schema-validation): structural keywords, string lengths and default annotations.
- [S2: Go encoding/json](https://pkg.go.dev/encoding/json): decoded types and duplicate-key/UTF-8 caveats.
- [S3: Go errors](https://pkg.go.dev/errors): errors.Is, errors.As and Unwrap.
- [S4: RFC 3339](https://www.rfc-editor.org/rfc/rfc3339): timestamp syntax; the narrower accepted subset is a Ricevanta choice.
- [S5: Go embed](https://pkg.go.dev/embed): package-relative embedding.
- [S6: RFC 6901](https://www.rfc-editor.org/rfc/rfc6901): diagnostic pointer escaping.
- [S7: Go fuzzing](https://go.dev/doc/security/fuzz/): seed corpus and fuzz targets.
