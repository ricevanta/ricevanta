# Extension admission contracts

The exact Go API, canonical digests, reason codes, schemas and fixtures for [extension admission](extension-admission.md). That document owns the decision model and the recovery fence; this one owns the machine-readable surface that implementation and review check against. Decision: EXT-09.

## 1. Package and dependencies

Create `server/internal/extensions/admission` in `github.com/ricevanta/ricevanta/server` with Go 1.27.1 and only the standard library plus three in-module packages: `extensions/loader` (for `FromPackage`), `extensions/manifest` (validation and options) and `signing/ed25519key` (key admission). No database, network, clock, filesystem, JSON Schema runtime, DSSE call or YAML parser belongs here. The loader is a qualified leaf; this package is a leaf above it. Nothing in `extensions/` imports `policy`, `authz` or `platform`.

## 2. Exact Go API

```go
package admission

type Evidence struct {
    ID, Version, PublisherFingerprint string
    PackageSHA256, ManifestSHA256, EnvelopeSHA256 [32]byte
    Requires map[string][]string // kind -> interfaces, as validated
    Components []Component       // sorted by Name, names unique
}

type Component struct {
    Name, Kind, Interface, Format string
    Slots []string      // console-module only
    Requested Values    // the manifest capabilities in grant-value shape
}

type Values struct { // exactly one field set, selected by Kind and Interface
    Content          *struct{}
    BrowserAdapter   *BrowserAdapterValues
    AgentModule      *AgentModuleValues
    ConsoleModule    *ConsoleModuleValues
    ServiceConnector *ServiceConnectorValues
}

type Snapshot struct { // scoped to one id, version, approval and the referenced registrations
    RecoveryEpoch            uint64
    ApprovalPolicyDisabled   bool
    ApprovalPolicyGeneration uint64
    FirstStart               bool           // first-start setup still open
    AutomaticReleaseFloor    string         // journal maximum reserved-id version; empty before any such prepare
    ReleaseVersion           string         // version of the release manifest verified at start; empty without one
    ProjectKey               string         // fingerprint of the project key compiled into the binary
    ServedInterfaces         []string
    TrustList                []TrustEntry   // every entry, including revoked and retired, with Generation
    Revocations              []Revocation   // this id's id-level record and this version's record
    RevocationGeneration     uint64         // this id's revocation writes and removals
    Ownership                *Ownership     // this id's record
    Tombstones               []Tombstone    // this version's and the installed version's
    Install                  *Install       // this id's install with Enabled, Generation, Targets and grant records
    Registrations            []Registration // the registrations the components reference
    DisclosureProfiles       []string       // the reviewed profiles the request names
    DeviceGroups             []string       // the requested group uids that exist
    ConsumedApprovals        []string       // the presented approval uid, if consumed
}

type Request struct {
    Source      Source
    Requester   string
    GrantUpdate bool      // a grant or target write on the installed version
    Grants      []Grant
    Targets     Targets   // DeviceGroups, AllDevices, Console, Jobs
    Approval    *Approval // nil, Operator, SingleAdministrator or ReleaseFixed
}

type Verdict struct { Component string; OK bool }

type Decision struct {
    Outcome        Outcome   // Admit, ApprovalRequired, IdenticalRetry, Reject
    Operation      Operation // Install, Upgrade, Reinstall, GrantUpdate; set only on Admit and ApprovalRequired
    Stage          Stage     // the failing stage, set only on Reject
    Reasons        []Reason  // sorted by Code then Subject; set on Reject and on ApprovalRequired from a release-fixed approval
    ClosureDigest  string    // "sha256:<hex>", set only on Admit and ApprovalRequired
    RequestDigest  string    // set only on Admit and ApprovalRequired
    Intent         *Intent   // non-nil only on Admit
}

type Reason struct { Code Code; Subject string }

type Intent struct {
    Operation        Operation
    ApprovalKind     ApprovalKind // Operator, SingleAdministrator, ReleaseFixed; the audit event records it
    TombstoneCreate  bool
    ReleaseFloorRaise string      // irreversible maximum at prepare; empty when unchanged
    OwnershipCreate  bool         // irreversible reservation at prepare, retained on abort
    Enabled          bool         // the install's enabled state after commit
    Grants           []string     // component names, sorted; the coordinator allocates generations
    Targets          Targets      // canonical: DeviceGroups sorted
    RegistrationBind []Binding    // the id's complete binding set after commit, sorted by component; unnamed bindings are released
    ApprovalConsume  string       // approval or exemption uid; empty for release-fixed
}

func FromPackage(p loader.Package, options manifest.Options) (Evidence, error)
func Decide(e Evidence, s Snapshot, r Request, v []Verdict) Decision
func ParseSnapshot(data []byte) (Snapshot, error)
func ParseRequest(data []byte) (Request, error)
func ParseGrantRecord(data []byte) (GrantRecord, error)
func ParseResource(data []byte) (Resource, error)
func ClosureDigest(e Evidence, s Snapshot, r Request) (string, error)
func RequestDigest(e Evidence, s Snapshot, r Request, op Operation) (string, error)

var (
    ErrEvidence = errors.New("extension admission evidence")
    ErrJSON     = errors.New("extension admission JSON")
    ErrShape    = errors.New("extension admission shape")
    ErrField    = errors.New("extension admission field")
    ErrGrant    = errors.New("extension admission grant")
)
```

`Decide` never returns an error and never panics: a malformed input is a `Reject` at stage `input`. It does not retain or mutate its inputs; callers may share immutable values across concurrent calls. A `Reject` and an `IdenticalRetry` leave `Operation`, `ClosureDigest`, `RequestDigest` and `Intent` zero, even when the rejecting stage ran after the digests could have been computed; the vectors record exactly that. The remaining field types (`TrustEntry` with `Retired` and `Generation`, `Revocation`, `Ownership`, `Tombstone`, `Install` with `Enabled`, `Generation` and `Targets`, `GrantRecord`, `Registration` with `RecoveryEpoch` and `Bound {ID, Component, State}`, `Grant`, `Targets`, `Approval`, `Binding`, `Resource`, the five `*Values` structs) mirror the schemas in section 5 field for field, with `uint64` for the decimal-string fields, `[32]byte` for digests, and JSON `null` for an empty `ReleaseVersion`, `AutomaticReleaseFloor` or `ReleaseFloorRaise`. Registration `recovery_epoch` is required and uses the existing decimal-string `uint64` shape. `Approval` carries `Approver` for the operator kind and `Principal` for the single-administrator kind.

`FromPackage` validates `p.Document` with `manifest.Validate` under the supplied options with `AllowReservedID` forced to true (reserved-id authority is the `namespace` stage's decision), requires `p.PublisherFingerprint` to equal the document's `metadata.publisher.key`, requires all three digests to be nonzero, then projects the typed fields; it never re-reads bytes. Any failure is `ErrEvidence`. A grant update loads the stored package blob through the loader again under the key its tombstone names, so its evidence is as fresh as an install's; that key may have been retired since (extension-admission section 3). `Decide` repeats the cheap checks on the typed `Evidence` it receives and reports `input.evidence` when any fails: zero digest, id outside the manifest grammar, fingerprint outside `sha256:` plus 64 lowercase hex, components unsorted or with a repeated name, a kind and interface pair the manifest schema does not define, a `Values` field that does not match the kind, or `Requires` that differs from the components' kinds and interfaces. A hand-built `Evidence` therefore cannot skip what `FromPackage` proved.

The `Parse*` functions decode the JSON shapes of section 5 with the strict profile the permission catalogue uses: bounded input (`16 << 20` bytes for a snapshot, `2 << 20` for a request or resource, `1 << 20` for a grant record), depth at most 16, at most 65,536 JSON values for a snapshot, 32,768 for a request or resource and 1,024 for a grant record (objects, arrays and scalars; member names are not counted), exact fields, decoded duplicate-key rejection, invalid UTF-8 and lone surrogates rejected, integer tokens without fraction, sign or exponent, and every string constraint from the schema applied in Go. Input over its byte bound returns `ErrJSON` before decoding, and the lexer returns `ErrJSON` at the first value past the value cap, before allocating it, so allocation stays proportional to the cap rather than to arbitrary array lengths. The largest schema-valid instances hold 17,808 values (request), 17,809 (resource), 274 (grant record) and 59,839 (snapshot); every array is then at its schema maximum, so no schema-valid instance holds more. The bounds are over input bytes, and producers (the coordinator, GitOps tooling, the fixture generator) emit the compact encoding: no insignificant whitespace and an escape only where JSON requires one. In that encoding every schema-valid instance fits its bound. Constructed capacity witnesses with the longest interface names and `false` wherever a boolean is free: a request of 1,264,586 bytes and a resource of 1,266,858 bytes (64 `export-destination` connector grants of 64 outbound tuples with 253-byte hosts, the largest grant kind at 19,127 bytes, ahead of browser adapters at 13,450 and collectors with 16 maximal Windows roots at 7,186, plus 1,024 device groups), a grant record of 19,994 bytes, and a snapshot of 7,348,790 bytes (1,024 trust entries with 16 maximal prefixes and 128 four-byte display-name characters, an install with 64 maximal connector grant records, 64 maximal registrations, 1,023 prior owners and 1,024 device groups). Registration epochs and the release floor occupy 65 scalar values and at most 2,717 bytes of the snapshot. These are shape-capacity bounds, not runtime allocation measurements. Each byte bound keeps more than 700 KB of headroom. Phase order is `ErrJSON` (lexical and size), `ErrShape` (fields and types), `ErrField` (patterns, enums, bounds, uniqueness), then `ErrGrant` (grant kind, interface and value-shape agreement). They exist for fixtures, GitOps and the future coordinator; a parsed value proves shape, never authority.

Error text names a field path at most. It never contains publisher-controlled strings, fingerprints, digests or uids.

## 3. Digests

Both digests are `"sha256:"` plus lowercase hex of SHA-256 over the JSON Canonicalization Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)) encoding of the objects below: no whitespace, object members sorted by UTF-16 code units of their names (section 3.2.3), arrays in the stated order, integers as plain decimals, strings escaped per section 3.2.2.2. Every string these objects contain is ASCII by schema (ids, names, hex, uuids, enum names, interface names, versions, root paths; the trust entry's display name is not in either object), so the encoder is a small sorted-key emitter with no float, no non-ASCII and no HTML escaping. Go's `encoding/json` escapes `<`, `>`, `&`, U+2028 and U+2029 by default and sorts map keys ([encoding/json](https://pkg.go.dev/encoding/json@go1.27.1#Encoder.SetEscapeHTML)); the package does not use it for digests and instead emits from the typed structs, so no map order or escaping choice can change a digest.

Closure object, computed after the `grant` stage:

```json
{"profile":"ricevanta-extension-admission-closure-v1",
 "recovery_epoch":"3","approval_policy_disabled":false,"approval_policy_generation":"1",
 "release":null,"automatic_release_floor":null,
 "id":"com.example.rules","version":"1.0.0",
 "trust_entry":{"fingerprint":"sha256:...","generation":"1","prefixes":["com.example"],"project_publisher":false,"revoked":false,"retired":false},
 "covering":["sha256:..."],
 "revocations":[],
 "revocation_generation":"0",
 "ownership":null,
 "tombstone":null,
 "install":null,
 "registrations":[],
 "served_interfaces":["ext.ricevanta.io/content/v1"],
 "disclosure_profiles":[],
 "device_groups":["017f22e2-79b0-7cc3-98c4-dc0c0c0739a0"]}
```

- `prefixes`, `covering` (fingerprints of every non-retired entry whose prefixes cover the id), `prior_owners`, `served_interfaces`, `disclosure_profiles` and `device_groups` are sorted bytewise. `revocations` holds the snapshot's records sorted by their JCS bytes. `registrations` holds each referenced registration as `{id, recovery_epoch, registration_generation, os, bound}` sorted by `id`, with `bound` null when absent.
- `automatic_release_floor` is the snapshot floor for a reserved id and null for other ids. It binds every reserved-id request regardless of source, so a concurrent floor advance stales an operator approval. It never decreases, so it needs no separate generation.
- `release` is `{first_start, release_version}` for a `server-image` request, with `release_version` null on an unsigned build, and null for every other source, so a server release never stales an operator's pending approval.
- `ownership` is `{id, owner, prior_owners, ownership_generation}` or null. `tombstone` is the full record for the version under decision or null. `install` is `{version, package_sha256, state, enabled, generation, targets, grants}` or null, where `targets` is canonical (device groups sorted) and `grants` lists `{component, recovery_epoch, grant_generation, values}` sorted by component.
- `served_interfaces` lists the required interfaces; the `interface` stage already proved each is served. `disclosure_profiles` lists the profiles the request's collector grants name.

Frozen request object:

```json
{"profile":"ricevanta-extension-admission-request-v1",
 "id":"...","version":"...","publisher":"sha256:...",
 "package_sha256":"<hex>","manifest_sha256":"<hex>","envelope_sha256":"<hex>",
 "recovery_epoch":"3","operation":"install","source":"upload","requester":"<uuid>",
 "grants":[{"component":"rules","kind":"content","interface":"ext.ricevanta.io/content/v1","values":{}}],
 "targets":{"device_groups":["<uuid>"],"all_devices":false,"console":false,"jobs":false},
 "closure":"sha256:..."}
```

`operation` is one of `install`, `upgrade`, `reinstall` and `grant_update`, so a grant update and an install of the same proposal have different digests. `grants` is sorted by component; `device_groups` is sorted; inside each grant's `values`, and inside the closure's install grant values, every set-valued array is in canonical order (strings bytewise, objects by their JCS bytes; extension-admission section 4). The approval binds `request_digest` and `recovery_epoch`; nothing else in the approval is hashed, and the approver changes nothing in the request. The first corpus case records `closure_digest` `sha256:c76da84b001eabfaa264cabf18c18df05192946b98182f8d2cb2e31250c69052` and `request_digest` `sha256:8a04711e8837aa35020c9e1467a0332a4a4df1255e014e9da75894ec0e6fd94e` for the inputs it embeds; the Go encoder must reproduce every recorded digest.

## 4. Reason codes

Codes are `<stage>.<name>`. The subject makes a reason unique within a decision and names what the console shows; it never carries publisher display text.

| Stage | Code | Subject |
|---|---|---|
| `input` | `input.evidence`, `input.snapshot`, `input.request` | empty |
| `key` | `key.unknown`, `key.invalid`, `key.revoked`, `key.retired` | publisher fingerprint |
| `namespace` | `namespace.reserved`, `namespace.prefix` | id |
| `revocation` | `revocation.id` | id |
| `revocation` | `revocation.version` | version |
| `tombstone` | `tombstone.manifest`, `tombstone.package`, `tombstone.publisher`, `tombstone.grants`, `tombstone.targets`, `tombstone.not_installed` | version |
| `ownership` | `ownership.owner`, `ownership.assignment_required` | id |
| `interface` | `interface.unserved` | interface |
| `component` | `component.verdict_missing`, `component.verdict_failed`, `component.registration_unknown`, `component.registration_epoch`, `component.registration_os`, `component.registration_names`, `component.registration_native_host`, `component.registration_bound`, `component.registration_duplicate` | component name |
| `targets` | `targets.device_groups_required`, `targets.device_groups_forbidden`, `targets.all_devices`, `targets.console`, `targets.jobs`, `targets.retired_key` | empty |
| `targets` | `targets.unknown_group` | device-group uid |
| `grant` | `grant.missing`, `grant.extra`, `grant.kind`, `grant.registration`, `grant.exceeds`, `grant.profile`, `grant.roots`, `grant.retired_key` | component name |
| `approval` | `approval.release_fixed`, `approval.release_operation`, `approval.release_rollback`, `approval.targets_changed`, `approval.epoch`, `approval.digest`, `approval.separation`, `approval.exempt_unavailable`, `approval.exempt_principal`, `approval.consumed` | empty |
| `approval` | `approval.widened` | component name |

Within a stage every applicable reason is reported once per `(code, subject)`, so `Decide` returns at most 1,029 reasons: the `targets` stage with 1,024 unknown groups and five other codes is the largest, and the vectors schema caps `expected.reasons` at that number; `targets.all_devices` covers both `all_devices` beside device groups and `all_devices` from a source other than `server-image` that a grant update does not keep from its install. `targets.retired_key` and `grant.retired_key` mark a grant update under a retired key that would reach new targets or widen a component; `grant.retired_key` is evaluated only when the stage's other checks pass. Across stages the first failing stage wins. `approval.release_operation`, `approval.release_rollback`, `approval.widened` and `approval.targets_changed` are the codes that accompany a non-reject outcome: a release-fixed request that needs an operator returns `approval_required` with them. `approval.release_fixed` is a reject evaluated before them, so it never appears with them. A valid release-fixed request below the automatic release floor returns only `approval.release_rollback`, before operation-specific reasons. `component.registration_epoch` names each adapter referencing an older registration; a future registration epoch is `input.snapshot`. No grant or approval can bypass that component-stage rejection, and identical retries return only after this stage.

Permission mapping for the coordinator: `install` and `reinstall` use `extensions.packages.install`, `upgrade` uses `extensions.packages.upgrade`, and `grant_update` uses `extensions.grants.update`, the catalogue's permission for grant or target writes on an installed version without a package change, including the request a `tombstone.grants` or `tombstone.targets` rejection points to. Every grant in a request is covered by the same approval, and enabling uses `extensions.packages.enable`. `uploadExtension` (`extensions.packages.upload`) stages bytes and runs the loader only; the preview run of `Decide` that returns `approval_required` with its digests runs under the operation's own permission, so a principal without `extensions.packages.install` learns neither the closure digest nor the request digest. Approvals are decided under `authz.approvals.approve` by a different, freshly authenticated account. A single-administrator exemption is no decision: the coordinator records it from the committed setting under the requester's own operation permission ([console design section 3.2](../design/console.md#32-approval-queue)). Server-image first-start installs, unwidened upgrades and recovery re-assertion at or above the journaled automatic release floor, using current-epoch registrations, run under the system principal and the release authority that the coverage manifest's `offline-recovery` exemption names; a server-image request that returns `approval_required` is decided by an operator under `authz.approvals.approve`. No new catalogue name is needed.

## 5. Schemas

All schemas use [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation) with every object closed (`additionalProperties: false`, an applicator keyword defined in the core vocabulary), `uniqueItems` where sets are meant, inclusive `minimum` and `maximum`, and patterns anchored with the absolute end assertion the sibling schemas use. They live under `schemas/extension/v1alpha1/` beside the manifest schema, which the design CI inventory requires to be registered pair by pair in `scripts/ci/validate_contracts.py`.

| Schema | Fixture | Content |
|---|---|---|
| `extension-resource.schema.json` | `extension-resource/schema-cases.json` | The GitOps kind `Extension`: `metadata.name` is the id; `spec.version`, `spec.source.sha256` (the package digest; `url` optional for air-gapped applies), `spec.grants` (one grant per component), `spec.targets`, `spec.enabled` |
| `capability-grant.schema.json` | `capability-grant/schema-cases.json` | One committed grant record: `extension_id`, `version`, `package_sha256`, `recovery_epoch`, `grant_generation`, `approval` (`operator` with `request_digest`, `approval_uid`, `approver`, `recovery_epoch`; `single-administrator` with the same fields but `principal` for `approver`; or `release-fixed` with `release_version`) and `grant` |
| `admission-vectors.schema.json` | `admission-vectors.json`, `admission-vectors/schema-cases.json` | The corpus envelope: `evidence` (decoded document and three digests), the decision-scoped `snapshot`, `request`, `verdicts`, `expected` |

The grant shape (`$defs/grant`) is one closed object per kind and interface: `component`, `kind`, `interface` and kind-specific `values` bounded by the manifest ceilings (4096 pages, 10^9 fuel, 60,000 ms, 64 policy names per OS, 23 operations per slot, 64 outbound tuples, 16 roots). Collector `roots` are a `oneOf` by OS: `macos` and `linux` take an absolute POSIX path, `windows` a drive-rooted backslash path. Both forms share a segment grammar that excludes `.` and `..`, forbids a leading or trailing space and allows interior spaces; a Windows segment also never ends in a period. A path holds at most 256 bytes. `disclosure_profile` is a lowercase dotted id of at most 128 bytes. The Go decoders apply exactly these rules and nothing more, so Go acceptance equals schema validity for every instance.

`uint64` fields are decimal strings whose pattern admits exactly `0` through `18446744073709551615` without leading zeros, generated as a digit-by-digit alternation so JSON Schema and Go agree on overflow. The targets object carries `device_groups` (at most 1,024), `all_devices`, `console` and `jobs`. The snapshot carries `approval_policy_disabled` with `approval_policy_generation`, `first_start`, `release_version` (a version or null), `project_key`, a trust entry's `retired` flag and `generation` and a display name of at most 128 characters without C0 or C1 controls or DEL, at most two `revocations` with the id's `revocation_generation`, at most two `tombstones`, a single `ownership` and `install` (or null) where the install carries `enabled` and `generation`, at most 64 referenced registrations each with an optional `bound {id, component, state}`, and at most one `consumed_approvals` entry. `prior_owners` is a set of at most 1,023 fingerprints, one fewer than the trust-list cap. The request carries `grant_update`.

The shared `$defs` (`id`, `name`, `version`, `digest`, `fingerprint`, `uint64`, `uuid`, `targets`, and `grant` in the two schemas that carry grants) are byte-identical across the three files, and the three approval shapes are identical between the grant schema and the vectors schema. JSON Schema cannot reference a sibling file without a resolver the CI checker does not configure, so the copies are deliberate and `TestSchemaDefsIdentical` in the Go package fails when they drift. Embedded `document` and grant objects inside the vectors are typed `object` in the vectors schema; the Go tests validate each document with `manifest.Validate` and each grant with `ParseGrantRecord` or the grant decoder, and the generator validated them against `manifest.schema.json` and `capability-grant.schema.json` before publication.

The GitOps resource is not the package manifest: `spec.components`, `files` and `spec.requires` are invalid in it, and the manifest's `spec.source`, `spec.targets` and `spec.grants` are invalid there. `ricevanta apply` resolves `spec.source.sha256` to an uploaded or fetched package, runs the loader and admission, and turns the result into the approval request of [extension design section 2.2](../design/extensions.md#22-install-flow). A changed `spec.version` or `spec.source.sha256` is an install, upgrade or reinstall request. A changed `spec.grants` or `spec.targets` on an installed version is a grant-update request (`grant_update: true`) through the same stages, so the manifest bound, the `all_devices` rule and the closure-bound approval apply to it. `all_devices: true` is schema-valid but `Decide` rejects it on every source except `server-image`, which a GitOps apply never is, unless a grant update keeps it from an install that already targets all devices. `spec.enabled: false` installs without enabling; `spec.enabled: true` also requests the separate enable action once the install commits.

## 6. Fixtures

`admission-vectors.json` holds 170 cases: 38 `approval_required`, 29 `admit`, 4 `identical_retry` and 99 `reject`. Fixture keys are the deterministic test keys the loader corpus uses (seeds `00..1f`, `20..3f` and `40..5f`; the identity point stands for an inadmissible key); their fingerprints are SHA-256 of the raw public bytes. Package, manifest and envelope digests are synthetic SHA-256 values labelled by id, version and variant; admission compares digests and never needs the bytes. File digests use the loader corpus's `abc` vector. The project publisher entry, `io.ricevanta.browser-chrome` and `io.ricevanta.sigma-core` are fixture identities, not the shipped first-party key or components.

The generator checks that all 55 reason codes appear, every approval kind admits, and rejects and identical retries record no operation, digest or intent. The recipes assert these paths, whose stage behavior the Go tests and independent review must establish:

- Install, admit with a full intent, identical retry, identical bytes with different grants or targets, reinstall after uninstall, upgrade, rollback to an accepted version, recovery-pending reinstall, prior-owner reinstall and rollback after transfer, and a retired prior owner that still resolves.
- Grant update: approval required, admit, not installed, `all_devices` introduced from GitOps refused, and a value above the manifest request; an operator narrowing of a fleet-wide first-party adapter that keeps all devices, with its admit, and a retarget of that install to device groups; under a retired key a narrowing with its admit and a move from all devices to device groups, a widened grant and an added device group refused, and a revoked key refused.
- Single-administrator exemption admit, an operator approval still accepted under the exemption, the exemption refused while policies are enabled, for another principal and for a server-image request, and stale after the setting changed or was toggled back.
- First-start install with an empty device-group snapshot, `all_devices` and the enabled intent; equal-grant upgrade; release version mismatch; upgrade that keeps narrowed targets or a disabled install; widened upgrade, the upgrade that starts from the committed operator narrowing, and targets restored to all devices returning `approval_required`; the operator approval of a widened release proposal keeping `all_devices`; reinstall and new-version install after an operator uninstall, a recovery that meets a new release through the upgrade case, a development build (development label, no running release, first start closed) refused a release-fixed approval and its proposal with the operator admit, a purged project key not re-created, and a first-party id new after first start with its operator approval; recovery re-assertion and its narrowed-target variant; release-fixed refused for a non-project key and for an upload.
- Approvals stale after an unrelated revocation, after a revocation added and removed, after a key revoked and unrevoked, and after the install was disabled and enabled again; `all_devices` refused on an upload; a revoked covering entry still requiring assignment and a retired one not covering; multi-reason stages sorted; a lookalike id (`io.ricevantaevil`) accepted; a registration held by a `recovery_pending` install not blocking and the rebind intent; key revocation hiding a later tombstone mismatch.
- One vector for each part of the thirteen snapshot rules, each intended to trip that rule alone, and for each request rule.
- Prepare/abort/retry: retained ownership and tombstone without an install, a consumed stale approval, a fresh reinstall approval, a different publisher refused after retirement, and a first-start release prepare aborted with its floor retained.
- Registration recovery: old-epoch re-assertion, rebind and identical retry refused; a fresh protected current-epoch registration write permits re-assertion; equal registration renewal stales an approval; future registration epoch refused.
- Release floor: older mixed-version replica and restored image require an operator, operator-approved rollback retains the higher floor, same-version recovery below the floor still needs an operator, another id's strictly higher floor applies while equality still reaches the operation rules, concurrent floor advance stales approval, null or low floors beside reserved tombstones fail input, and numeric/prerelease ordering stays bounded.
- Two adapters naming one registration in a package, unbound, held by a `recovery_pending` install and unknown; identical retries unchanged by the order of policy names or outbound tuples and an approval digest unchanged by the order of policy names; upgrades that drop an adapter, move it to another registration or rename it while keeping its registration, with their binding sets.

Each case embeds complete inputs so the Go test needs no shared state. The schema-cases files hold schema-level positives and negatives for the resource (33 cases), the grant record (20) and the vectors envelope (40), including bounds at ceiling plus one, `uint64` lexemes with a leading zero and one above the maximum, `release-fixed` with a digest, an operator approval with `principal` and an exemption with `approver`, a `..` and a `.` segment, a `windows` root with a POSIX path and a `linux` root with a drive path, leading and trailing spaces, Windows segments ending in a period (`C:\Data.`, `C:\Secret. .\x`, `C:\...`), a 257-byte root, an uncatalogued console operation, a device group that is not a UUIDv7, a trust display name with a C0 control character, U+0085 or U+009B, a null release version accepted, a missing project key, 1,029 expected reasons accepted and 1,030 refused, 1,024 prior owners, three tombstones, two consumed approvals and every required snapshot and request field missing. Registration epochs cover missing fields, integer tokens, leading zeroes and overflow; release floors and intent advances cover missing, null and invalid version values.

Run `python3 -B schemas/extension/v1alpha1/generate_admission.py` from the repository root in the existing pinned validator environment. The sibling `admission_vector_recipes.py` is the source: each recipe names an earlier base and exact field replacements, with expected decisions written as design assertions. The generator independently computes all 67 closure/request digest pairs, resolves named approval references and preserves deliberate literal stale digests. It validates embedded documents and grants, all 93 schema cases, reason and approval-kind coverage, and the S-04 below-floor and equality witnesses before writing `admission-vectors.json`. Schemas and schema cases are reviewed inputs, not generated outputs. The `--check` option compares generated bytes without writing. Regeneration needs no existing output file, Git history, temporary input, network or Go output. The fixture expectations are design assertions, not proof that the Go stages or the blocked journal reducers implement them; independent review and the plan's stage and reducer tests remain required.

## 7. Required tests

- `TestVectors`: every corpus case through `FromPackage`-equivalent projection (`manifest.Validate` on the document, then the typed evidence), `ParseSnapshot`, `ParseRequest` and `Decide`; exact outcome, operation, stage, reasons, digests and intent including approval kind, ownership reservation, release-floor advance, enabled state, targets and registration bindings, and zero values where section 2 says so.
- `TestSchemaCases`: the three schema-cases files through the matching `Parse*` function; `valid` must agree with Go acceptance for every case. There is no exception list; a disagreement is a review finding.
- `TestSchemaDefsIdentical`: shared `$defs` and the approval shapes equal across the schema files read from `../../../../schemas/extension/v1alpha1/`.
- `TestStageIsolation`: for each adjacent stage pair, a combined defect returns only the earlier stage; permuting components, grants, verdicts and snapshot arrays leaves every decision and digest unchanged.
- `TestDigests`: the JCS emitter against RFC 8785 Appendix B style vectors for the value kinds used (sorted keys, nested arrays, escapes of `"` and `\`, control characters, integers), and against every recorded corpus digest.
- `TestBounds`: generation and epoch at 0, 1 and `MaxUint64`, 20-digit lexemes above the maximum, 64 components, 1,024 device groups, 16 roots, 1,023 prior owners, each `*Values` numeric field at request value, request plus one and request minus one, the maximal request, resource, grant record and snapshot of section 2 accepted by the parsers, each of them one byte over its bound (padded with a space) rejected with `ErrJSON`, and an input of small values one past each value cap rejected with `ErrJSON` while total allocation stays within a fixed multiple of the cap.
- `TestReviewRegressions`: the prepare/abort snapshots of S-01, registration epoch and retry guards of S-02, and release order, global floor, restore and mixed-version cases of S-03, including the S-04 strict-below and equality boundary. Assert an operator rollback never emits a lower floor, and a release-fixed request below the floor never emits an intent. Executable journal replay and crash tests remain with the blocked coordinator.
- `TestEvidenceChecks`: each `input.evidence` condition from section 2 on a hand-built `Evidence`.
- `TestNoAliasing`: inputs mutated after `Decide` do not change the returned decision; returned slices are independent copies.
- `FuzzDecide`: arbitrary JSON bytes through `ParseSnapshot` and `ParseRequest` plus a fixed valid evidence set; assert no panic, deterministic results, and that `Admit` implies every stage invariant checked independently (owner or prior-owner rule, subset rule, digest equality, approval kind preconditions, the release-fixed operation cases, the system-principal rules, consumption). Before an `IdenticalRetry` oracle branch returns, independently recheck current registration authority; the later admit-path checks cannot cover it. Permit `approval.release_rollback` among the `ApprovalRequired` reasons. `FuzzParse` on each parser asserts no panic and one sentinel per failure. Timed fuzzing runs in CI only.

## 8. Limits of these contracts

These contracts prove decisions over supplied facts. They do not supply the facts: the journal projection, writer fence, generation allocation, approval request storage, exemption records, approval expiry, binding, target and enabled-state writes and blob publication belong to the blocked coordinator. They do not qualify any OS mechanism, and nothing here reduces the v1.0.0 obligations on macOS ARM64, Windows x64 or Linux x64. Browser-registration canonical targets, disclosure profiles, the console bridge catalogue and connector contracts remain the absent schemas `analysis.md` section 3 lists; an admitted component of those kinds is admitted, not runnable.
