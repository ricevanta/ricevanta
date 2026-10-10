# CEL variable declarations

`variables.json` binds policy conditions to one versioned declaration catalogue. The contract supplies the editor, compiler and agent with identical names, types, presence rules and bounds. `server/internal/policy/celdecl` loads that catalogue with the Go standard library. This slice specifies the package; it does not implement it or qualify CEL execution. Decision: POL-08.

## 1. Authority, versions and files

The [CEL profile](cel-profile.md) owns the admitted language and evaluation semantics. [Policy envelope section 6](policy-envelope.md#6-compiled-bundle-and-device-assignment) owns bundle authentication. The declaration grammar is [declarations.schema.json](../../schemas/cel/v1/declarations.schema.json); [variables.json](../../schemas/cel/v1/variables.json) is the canonical catalogue. The [fixture manifest](../../schemas/cel/v1/fixtures.json) names full declaration inputs, their schema result and their Go error.

Every declaration has exactly these top-level members:

| Member | Value and purpose |
|---|---|
| `format_version` | Integer `1`, the JSON encoding revision |
| `profile` | Exactly `{"id":"ricevanta-cel-1","version":1}`; the integer repeats the profile suffix deliberately, so inconsistent identity/version pairs fail |
| `declaration_version` | Integer `1`, the immutable catalogue revision |
| `ocsf_version` | String `1.9.0`, matching the OCSF profile |
| `objects` | Named, closed record shapes |
| `variables` | All 14 top-level declarations, indexed by name |
| `domains` | Domain, expression context and sorted variable-name arrays |

Object member order and JSON whitespace have no meaning. The canonical file uses two-space indentation and one final LF for repository readability; loaders accept equivalent member ordering and string escapes. Array order is significant. All names and enum values are case-sensitive. No `$schema`, comments, paths, imports, remote references, default values or extension members occur in a declaration input.

A supported tuple of format, profile, declaration and OCSF versions identifies one exact decoded catalogue, including documentation, bounds and array order. A loader rejects any other content under that tuple. Every catalogue edit, including an additive variable, wider limit, changed presence rule or documentation correction, increments `declaration_version`; revisions are positive integers, never product versions. An encoding change increments `format_version`. An admitted-language change follows the CEL profile's own version rule. An OCSF change changes `ocsf_version` and `declaration_version` together.

Revision 1 accepts only the tuple above. Future binaries may explicitly retain multiple catalogues; no range, fallback, automatic downgrade or remote schema discovery is permitted. A new declaration revision requires compiler/editor/agent compatibility evidence before publication. Bundles contain the full catalogue, including domains absent from their policies. The compiler must validate the shipped catalogue and compile with that same tuple. Declaration revisions are compatibility keys, not replay counters or authority epochs.

## 2. Exact type encoding

A type is an object tagged by `kind`. Each row permits only the listed members; all listed members are required. References name an entry in `objects`; they are not JSON Schema references.

| Kind | Encoding | CEL meaning |
|---|---|---|
| Primitive | `{"kind":"bool"}`, `int`, `double`, `null`, `timestamp`, or `duration` in the same shape | Corresponding CEL type; `int` is signed 64-bit and `double` is binary64 |
| String | `{"kind":"string","max_length":4096}` | CEL string; limit counts Unicode scalar values |
| List | `{"kind":"list","element":{"kind":"int"},"max_items":64}` | Homogeneous CEL list |
| Map | `{"kind":"map","key":"string","value":{"kind":"int"},"max_entries":64}` | Homogeneous string-keyed CEL map |
| Object | `{"kind":"object","name":"device"}` | Closed JSON record, represented at evaluation as a string-keyed map |
| JSON value | `{"kind":"json"}` | Declaration-only union of admitted JSON values, described below |

`uint`, `bytes`, `dyn`, `any`, protobuf messages, wrappers, enums, CEL object constructor types, opaque types, unions, nullable wrappers and CEL optional types have no encoding. A string such as `list(string)` is not a type. Unknown tags and tag-specific extra members fail. `null` is a type only in `{"kind":"null"}`; JSON null in place of a type fails. No revision-1 field uses the null type, but the grammar defines it for future catalogues.

`json` covers null, bool, signed int, double, string, lists of JSON values and string-keyed maps of JSON values. It excludes timestamps and durations until a source schema projects them. It is not permission to use CEL's `dyn` conversion or excluded language features. It occurs only at the schema-backed paths in section 3. The later compiler must narrow every accessed field or column using its source schema, and refuse unresolved field access or an unbounded comprehension. A generic map declaration alone cannot pass that gate.

Timestamp and duration tags describe CEL values, not their JSON serialization. They are neither strings nor protobuf-message declarations. The activation adapter owns validated conversion from source data; OCSF epoch-millisecond fields project to timestamp plus an `int` `_ms` sibling as the profile requires. The catalogue adds `device.compliance_time_ms`, `certificate.not_before_ms` and `certificate.not_after_ms`. `now` is an injected timestamp, with no raw source sibling. This loader never parses runtime timestamps or durations.

An object definition contains `doc` and `fields`. Each field and variable entry contains `type`, `presence`, `doc`, and optionally `values`. `values` is a nonempty, ordered, distinct list of allowed strings, only on a string type; it is a runtime value constraint, not a CEL enum. Object names and field names use `[a-z][a-z0-9_]{0,63}`. Object references must exist and the object graph must be acyclic, including references under list elements and map values. Unused objects are refused by exact catalogue comparison.

| `presence` | Meaning for a field within a present parent |
|---|---|
| `required` | The activation must supply the field with the declared type |
| `optional` | The field may be absent; absence is never encoded as null or a default |
| `network` | Required in `network`, absent in other domains; used only by `user.source` |
| `exact` | Required for `certificate.binding == "exact"`, absent for `identity_only` |

Variables use only `required` or `optional`. `user` is absent in system context; `session` is absent when DLP has no session. The compiler must account for missing top-level bindings without inventing a nullable user or assuming `has(user)` is a valid CEL presence test. Runtime activation and safe missing-binding tests belong to the compiler slice. Within a present map, `has(certificate.serial)` retains the profile's meaning.

The later compiler must prove exact-certificate access paths, including aliases and indexed access, as [profile section 5](cel-profile.md#5-variables-per-domain) requires. A plain `has` test cannot create authenticated evidence. No declaration check proves that a certificate belongs to a request.

## 3. Complete domain catalogue and source gates

The canonical file is the sole list of individual field encodings, documentation and bounds. The following cross-check accounts for every variable in profile section 5. `condition` and `exception` are contexts in every domain; MDM also has `query` and `collector`.

| Variable | Domains and context | Type and source |
|---|---|---|
| `event` | edr, dlp, lineage, pki, network; both contexts | `map(string,json)` from the OCSF trigger class |
| `device` | All contexts | Object `device`; `os` is `map(string,json)` from OCSF OS |
| `user` | All contexts | Object `user`, absent for system context |
| `session` | dlp; both contexts | Object `session`; its `user` is the same user object |
| `match` | dlp; both contexts | Object `match`, including rule identities, categories and inherited evidence |
| `destination` | dlp; both contexts | Object `destination`, removable device and sync account objects |
| `activity` | dlp; both contexts | Object `activity`, with all five counters typed `int` |
| `certificate` | network; both contexts | Object `certificate`, with exact-only fields and raw time siblings |
| `gateway` | network; both contexts | Object `gateway` |
| `access` | network; both contexts | Object `access`; `nas_port_type` is `int` |
| `state` | mdm; all four contexts | `map(string,json)` from the baseline kind |
| `rows` | mdm; query and collector only | `list(map(string,json))` from query columns or collector result schema |
| `item` | mdm; exception only | Object `item`, with `baseline` and `id` |
| `now` | All contexts | Timestamp injected by the engine |

Every domain includes `device`, `user` and `now`. A context not listed in the catalogue is invalid, not an alias for `condition`. MDM exceptions receive `state` and `item`, not rows from an unrelated check. Conditions in DLP exceptions are scheduled only once their required context exists, as the envelope requires.

Concrete choices for fields whose profile table gives no scalar encoding: names and identities use strings; labels and groups use lists of strings; confidence uses double; counts use int; `destination.app` is an application identity string; `destination.account` has `account` and `tenant` strings; removable vendor/product identifiers use strings so leading zeroes survive. `session.user` uses the user object, not an unrelated principal string. `match.inherited` contains optional `revision` and `content_hash`; an empty inherited object preserves the fact that a floor applies while source evidence is unavailable.

The remaining schema-backed paths are `event`, `device.os`, `state`, each `rows` element and `match.inherited.revision`. Their declared type is exact, but their field-level schemas remain consumer gates in [analysis section 3](../analysis.md#3-missing-specifications). No field from those maps may silently acquire `dyn` semantics in a published condition.

All explicit list/map/string bounds are activation ceilings, not truncation instructions. The adapter must fail evaluation when a value exceeds a bound unless the owning source contract explicitly defines a safe truncation. Existing source limits remain authoritative when tighter. JSON-value subtrees have ceilings of 16 nested list/map containers, 1,024 entries per map, 10,000 elements per list, 32,768 scalar values per string, and 65,536 total value nodes per subtree. These ceilings bound data; the compiler must still apply the profile's expression cost ceiling.

`device.labels`, `device.groups`, `user.groups` and `match.rules` match `schemas/ocsf/limits.yaml`. The proposed `match.categories` ceiling is 256. That file has no `match.categories` entry and still has `match.regulations`; do not interpret regulations as categories. Align and review the source limit before enabling compilation over categories. Rows use a 10,000-row ceiling; the query/collector contract must establish an equal or tighter bound. These gates do not block the pure declaration loader.

## 4. Go API and ownership

Module: `github.com/ricevanta/ricevanta/server`, Go 1.27.1, no new dependencies. Package: `server/internal/policy/celdecl`. The package copies the reviewed canonical JSON into an embedded `variables.json`; a test compares that copy byte for byte with the schema asset. It embeds no JSON Schema and imports no other server package. Schema validation in Go is the explicit contract below, not a general JSON Schema engine.

```go
package celdecl

const MaxBytes = 262144

func Parse(data []byte) (*Document, error)
func Load(r io.Reader) (*Document, error)

type Document struct { /* private validated catalogue */ }
func (d *Document) Snapshot() Catalogue
func (d *Document) Environment(domain, context string) ([]Variable, error)

type Catalogue struct {
    FormatVersion int `json:"format_version"`
    Profile Profile `json:"profile"`
    DeclarationVersion int `json:"declaration_version"`
    OCSFVersion string `json:"ocsf_version"`
    Objects map[string]Object `json:"objects"`
    Variables map[string]Entry `json:"variables"`
    Domains map[string]map[string][]string `json:"domains"`
}
type Profile struct {
    ID string `json:"id"`
    Version int `json:"version"`
}
type Object struct {
    Doc string `json:"doc"`
    Fields map[string]Entry `json:"fields"`
}
type Entry struct {
    Type Type `json:"type"`
    Presence string `json:"presence"`
    Doc string `json:"doc"`
    Values []string `json:"values,omitempty"`
}
type Type struct {
    Kind string `json:"kind"`
    Name string `json:"name,omitempty"`
    Key string `json:"key,omitempty"`
    Element *Type `json:"element,omitempty"`
    Value *Type `json:"value,omitempty"`
    MaxLength int `json:"max_length,omitempty"`
    MaxItems int `json:"max_items,omitempty"`
    MaxEntries int `json:"max_entries,omitempty"`
}
type Variable struct {
    Name string
    Entry Entry
}
```

The exported structs are detached views, not a second unchecked construction path. `Snapshot` returns a recursive copy. `Environment` returns deep-copied entries sorted by variable name for the exact domain/context pair. An unsupported domain/context pair returns `(nil, ErrDomain)`, including an unknown domain, an unknown context or a context unavailable in that domain. It does not resolve object references or validate runtime bindings. A nil or zero `Document` returns a zero `Catalogue` from `Snapshot` and `(nil, ErrDocument)` from `Environment`; `ErrDocument` takes precedence over `ErrDomain` for every pair. Concurrent read-only calls are safe. Caller mutation of any returned map, slice or type pointer cannot affect the document or another result. Successful documents retain no aliases into input bytes.

`Parse` returns `(nil, err)` on every failure. `Load` reads at most `MaxBytes+1` bytes, then uses the same parser. If the extra byte exists it returns `ErrSize`, even when the reader also returns an error. Otherwise a read error other than the exact value `io.EOF` returns `ErrRead`, wrapping both that sentinel and the original cause for `errors.Is`; data returned with `io.EOF` is processed. A wrapped EOF returns `ErrRead`. A nil reader returns `ErrRead`. Typed-nil or panicking reader implementations are the caller's responsibility. `Load` does not close the reader. The caller owns deadlines and concurrency admission; the byte cap does not stop a stalled reader.

No `Validate(Catalogue)` or file-path API is exposed. A caller wanting to validate a modified snapshot serializes it and calls `Parse`; same-version changes fail. Runtime callers cannot install their own trusted catalogue.

## 5. Errors, bounds and precedence

Each declaration failure matches exactly one package sentinel through `errors.Is`. Except for `ErrRead`, do not wrap decoder errors as additional public classifications. Error messages may include a JSON Pointer or byte offset, never declaration values or document strings; callers must not depend on message text. Sentinel text is fixed:

```go
var (
    ErrRead = errors.New("cel declarations read")
    ErrSize = errors.New("cel declarations size")
    ErrJSON = errors.New("cel declarations json")
    ErrDuplicateKey = errors.New("cel declarations duplicate key")
    ErrShape = errors.New("cel declarations shape")
    ErrVersion = errors.New("cel declarations version")
    ErrProfile = errors.New("cel declarations profile")
    ErrOCSF = errors.New("cel declarations ocsf version")
    ErrName = errors.New("cel declarations name")
    ErrType = errors.New("cel declarations type")
    ErrLimit = errors.New("cel declarations limit")
    ErrDomain = errors.New("cel declarations domain")
    ErrReference = errors.New("cel declarations reference")
    ErrCycle = errors.New("cel declarations cycle")
    ErrCatalogue = errors.New("cel declarations catalogue")
    ErrDocument = errors.New("cel declarations document")
)
```

Run complete phases in this order, not validation interleaved with map iteration. Within a phase all defects share its sentinel, so no path-order guarantee is needed.

1. Byte size greater than `MaxBytes`: `ErrSize`. A bounded lexical preflight also returns `ErrSize` at the first container opener beyond depth 64 or token beyond 32,768. Root container depth is 1; each container opener/closer, key and scalar is one token. Escaped delimiters inside strings are not tokens. If malformed syntax prevents reaching a later cap, that later cap has no precedence; the byte-size check always runs first.
2. Strict JSON syntax, one value followed only by JSON whitespace, valid UTF-8, no BOM, no unpaired UTF-16 surrogate escapes: `ErrJSON`. Empty input fails. Number tokens anywhere must use `0` or a nonzero decimal digit followed by digits, with no sign, fraction or exponent; this is a declaration syntax restriction, not a runtime numeric restriction. Thus `1.0`, `1e0` and `-0` fail even though JSON Schema treats them as integers. Do not convert numbers through float64.
3. Duplicate decoded object keys anywhere: `ErrDuplicateKey`. Scan the whole syntactically valid document; `"name"` and `"na\u006de"` collide. A later syntax defect wins over an earlier duplicate.
4. Root, profile, objects, object definitions, entries, variables and domains have the required members, case-sensitive known names and JSON container/scalar categories: `ErrShape`. Empty required dictionaries, missing fields, unknown members outside type objects, bad documentation characters, invalid presence spelling, and malformed `values` arrays also belong here. The complete `type` subtree is deferred to phase 9. Version fields must be number tokens here; profile id and OCSF version must be strings. Domain keys and context lists are deferred to phase 11, but `domains` must be an object.
5. Unsupported `format_version` or `declaration_version`: `ErrVersion`.
6. Wrong profile id or profile version: `ErrProfile`.
7. Wrong OCSF version: `ErrOCSF`.
8. Bad object, field, variable or object-reference name syntax: `ErrName`. Reference names are checked here only when `kind` is `object` and `name` is a string; other type defects belong to phase 9. Domain-list names belong to phase 11.
9. Invalid type grammar, missing tag-specific bounds, wrong bound JSON categories, unknown kind, extra type member, `values` on a non-string type, or `network`/`exact` on a variable: `ErrType`. Integer bounds outside their allowed ranges wait for phase 10. A missing referenced object waits for phase 12.
10. Declaration limits: `ErrLimit`. At most 64 objects, 64 fields per object, 64 variables; docs contain 1..1,024 Unicode scalar values and no U+0000..001F or U+007F; enum lists contain 1..32 distinct strings of 1..64 scalar values. String bounds are 1..32,768; list bounds 1..10,000; map bounds 1..1,024. Type nesting is at most 16, counting the root type as 1 and list/map child edges, before following object references. Oversized decimal bounds fail this phase without integer overflow. Empty docs/enum strings and empty enum arrays fail here; enum duplicates fail phase 4.
11. Exactly six domain keys; required `condition` and `exception`; only MDM may also have `query` and `collector`, both required for MDM: `ErrDomain`. Lists contain 1..64 valid identifier strings in strictly increasing ASCII order. Missing/extra contexts, duplicate or unsorted names and invalid list categories return this error.
12. Undefined object references anywhere or undefined variables in domain lists: `ErrReference`.
13. Cycles in the full object graph, including unreachable definitions: `ErrCycle`. Use visiting/visited marks; never recursively expand referenced shapes without a bound.
14. Any decoded difference from the embedded canonical catalogue: `ErrCatalogue`. Compare typed values structurally after validation; do not compare raw JSON, hashes or map iteration order. This catches changed domain membership, narrowed/widened types, presence, bounds, docs, fields and valid-but-unsupported shapes.

The lexical preflight is bounded work, not a second general JSON implementation: track strings and escapes to count containers/tokens, then use `encoding/json` tokens with `UseNumber` and explicit surrogate validation. Go's decoder accepts duplicate names, case-insensitive struct matches and replacement of invalid string encodings; direct struct unmarshalling alone cannot enforce this contract ([Go JSON documentation](https://pkg.go.dev/encoding/json)). The implementer may use a single bounded token parser if it preserves the phase precedence and strict string checks.

JSON Schema 2020-12 validates structure, type variants and local bounds. It cannot detect duplicate lexical keys, enforce raw-byte/token/depth caps, distinguish integer spellings, resolve catalogue references, prove acyclicity, require sorted lists or compare the catalogue with trusted bytes. The fixture manifest therefore records schema validity separately from loader success. A schema pass is never authorization to compile.

## 6. Required vectors and fuzzing

All 48 persisted fixtures in the manifest are required Go test vectors. `valid` and `valid_reordered` succeed. Every failure must return a nil document and the exact manifest sentinel with `errors.Is`. Schema-valid negative fixtures deliberately exercise semantic validation beyond JSON Schema. `null_primitive` and `duration_primitive` prove those grammar kinds reach catalogue comparison; they do not add revision-1 variables. Schema-invalid fixtures cover each missing MDM-only context, each forbidden query/collector context in the other five domains, both forbidden variable presence values, and trailing U+000A in entry and object documentation.

The implementer adds generated byte-level tests, without committing malformed JSON as `.json` files:

- Input length 0, 1, `MaxBytes` and `MaxBytes+1`; pad canonical JSON with spaces for the successful exact-byte boundary. Oversize plus malformed JSON returns `ErrSize`.
- JSON depths 64 and 65 and token counts 32,768 and 32,769, using otherwise legal arrays; the within-cap root-array input returns `ErrShape`, the over-cap input `ErrSize`. Include strings containing escaped braces, backslashes and quotes.
- Trailing value, garbage, BOM, invalid UTF-8 and isolated high/low surrogate escapes return `ErrJSON`; paired surrogate escapes and literal supplementary-plane characters in docs reach `ErrCatalogue` when they change canonical text.
- Duplicate keys at root, object, field and type levels; escaped duplicate spellings; duplicate plus trailing syntax defect returns `ErrJSON`; duplicate plus wrong version returns `ErrDuplicateKey`.
- Unknown top-level member plus wrong version returns `ErrShape`; wrong version plus wrong profile returns `ErrVersion`; wrong profile plus wrong OCSF returns `ErrProfile`; wrong OCSF plus bad identifier returns `ErrOCSF`; bad identifier plus bad type returns `ErrName`.
- Bad type plus oversized bound returns `ErrType`; oversized bound plus bad domain returns `ErrLimit`; bad domain plus unresolved reference returns `ErrDomain`; missing reference plus cycle returns `ErrReference`; cycle plus changed catalogue returns `ErrCycle`.
- Every excluded kind (`uint`, `bytes`, `dyn`, message, enum, wrapper, optional, nullable, opaque); malformed map/list/object variants; wrong-case keys; null versus absent members; enum duplicates and enum on an int.
- Limits at maximum and maximum plus one: objects, fields, variables, docs, enum count/length, type depth, list/map/string bounds. Valid noncanonical boundary inputs end in `ErrCatalogue`; excessive limits return `ErrLimit`. Use 1,024 supplementary-plane scalars to distinguish rune count from byte count. Enforce byte cap separately.
- All supported `Environment` pairs succeed. Unknown domains, unknown contexts and unavailable pairs such as `("edr", "query")` return a nil slice and match only `ErrDomain` through `errors.Is`. Nil and zero documents return a nil slice and match only `ErrDocument` for both supported and unsupported pairs. Check exact-only fields, time siblings, nested rule identities and inherited source metadata; no certificate leakage to EDR, no rows in MDM exceptions.
- Reader short reads, `(n>0, EOF)`, `(n>0, custom error)`, no-progress reader, nil reader and `MaxBytes+1` with a custom error; preserve `errors.Is` for the read cause. Bound no-progress reads at 100 consecutive `(0,nil)` returns, then `ErrRead` wrapping `io.ErrNoProgress`; any positive read resets that count.
- Returned snapshot/entry mutation, nested pointer and slice mutation, repeated/concurrent reads, nil/zero document, and input-byte mutation after parse.

`FuzzParse` seeds the complete fixture corpus plus malformed bytes; assert no panic, nil result on error, and on success a snapshot equal to the trusted catalogue whose JSON re-parses successfully. `FuzzLoad` varies chunk size and error position over fuzzed bytes; clean readers agree with `Parse`, erroring readers obey size/read precedence, and no read exceeds the cap. Both targets use bounded memory and never invoke CEL.

## 7. CEL integration handoff

A later slice maps primitive kinds to the corresponding `cel.*Type`, lists to `cel.ListType`, and maps to `cel.MapType(cel.StringType, valueType)`. It registers each selected variable with `cel.Variable` or `cel.VariableWithDoc`. Objects lower to string-keyed maps with a heterogeneous value type; `json` uses internal `cel.DynType` only behind schema narrowing and profile checks. These API names and signatures are documented on [pkg.go.dev](https://pkg.go.dev/github.com/google/cel-go/cel#VariableWithDoc); `Declarations` is deprecated in that documentation. `cel.ObjectType` refers to externally defined types, so it is not the encoding for Ricevanta's JSON records.

The profile pins cel-go `v0.32.0`; the fetched package page reports `v0.31.0`, and the version-specific v0.32.0 page could not be fetched. **Verify** the pinned API before implementing integration; do not silently change the pin. This loader does not add cel-go or protobuf to `server/go.mod`.

Map types do not express closed heterogeneous fields or evidence conditions. The integration must retain the object graph alongside CEL declarations, enforce field types through accesses, indexes, comprehensions and aliases, reject unresolved dynamic access, prove evidence availability, supply source-specific size estimates, validate activation values and cross-check Rust results. It must enforce boolean condition results, profile syntax/functions, cost and absent-variable semantics. Optional/protobuf registration must stay disabled. These are reviewed compiler/activation tasks, not promises made by a successful loader result.

## 8. Trust boundary

The bounded parser treats every input as hostile. The embedded catalogue prevents a signed or unsigned input from changing a known revision's meaning. It authenticates no sender and verifies no signature. Later bundle admission first verifies assignment, archive digest, manifest signature and member size/hash, then loads declarations and prepares all consumers before installation. Error reporting exposes classifications and positions only; the editor renders docs as text, never markup.

| Attacker or failure | What the attacker gets and where the boundary holds |
|---|---|
| Stolen enrollment token | No declaration authority. Enrollment cannot choose a trusted catalogue; enrollment authorization remains a separate contract. |
| Compromised agent host | Can lie about local activation data and bypass its own process. Cannot change the server catalogue or signed bundle for other devices. Loader validation does not make host evidence trustworthy. |
| Compromised console session | Can submit changes within that session's authority and attacker-controlled text. Parser caps bound each declaration; catalogue comparison rejects semantic edits. Policy authorization, protected approval and signing still gate publication. |
| Rogue extension publisher | Can package hostile content, but cannot add declaration kinds, fields or contexts under revision 1. Import validation and operator grants remain required before core compilation. No schema URL or code executes during loading. |
| Network position between agent and server | Can deny service or replay bytes. Bundle authentication blocks changed declaration bytes; assignment epoch/sequence checks block replay. A loader alone supplies neither guarantee. |
| Database writer without signing keys | Can corrupt stored policies or blobs and cause refusal. Catalogue comparison catches declaration drift; signed member hashes prevent altered bundles from installing. A database value cannot replace the embedded catalogue. |
| Server restored from backup | Can expose an older supported catalogue or stale bundles. Version compatibility alone cannot detect rollback; sealed restore and the independent journal's epoch/floors remain required. No declaration-version increment substitutes for recovery authorization. |

Reader deadlines and aggregate parser concurrency belong to callers. Metadata contains no secrets. This slice has no network, filesystem-path traversal, database mutation, signing, enrollment or policy enforcement API. It claims no new support evidence for macOS ARM64, Windows x64 or Linux x64; all remain required by the blueprint.

## 9. Benefits, trade-offs, dependencies and unresolved questions

The contract removes ambiguous declaration syntax and gives all consumers one bounded catalogue. Stable sentinels make combined-defect tests deterministic. A standard-library loader can ship independently of missing runtime schemas.

Strict revision equality requires a catalogue release for even a doc correction and embeds a small copy in the server; byte-equality tests keep that copy honest. Full catalogues repeat unused domains in bundles. These costs buy explicit compatibility and prevent declaration injection under a known revision.

Alternatives rejected: serialized protobuf declarations couple JSON to cel-go and admit excluded types; treating all records as unrestricted `map(string,dyn)` loses field/evidence checking; custom CEL object types need runtime providers on both sides; null/optional wrappers conflict with the profile; caller-supplied catalogues let untrusted declarations widen the environment; accepting additive same-version changes makes compatibility depend on load order. Using only JSON Schema misses lexical and graph checks. Implementing the compiler here crosses unresolved schema and conformance gates.

Dependencies are the existing profile, OCSF limits and source contracts, the bundle verification contract and Go 1.27.1. Design-fixture validation uses Python `jsonschema==4.25.1`; no runtime package depends on Python. [JSON Schema validation](https://json-schema.org/draft/2020-12/json-schema-validation) supplies local constraints; semantic checks are Ricevanta rules.

Unresolved questions for consumer review, with the choices used by this slice:

- Can the source-schema owners confirm the selected app string, nested session user, account/tenant object and string media identifiers? The catalogue uses these explicit projections; opaque strings for every object were rejected because they hide fields.
- Can the OCSF owner adopt the proposed 256 categories and retire or explain `match.regulations` before category compilation? Unbounded categories were rejected because cost must be finite.
- Can query/collector schemas guarantee at most 10,000 rows and the generic JSON ceilings, with tighter source bounds where needed? Unbounded result types were rejected; value enforcement stays with those consumers.
- Can the compiler prove closed-map field types, missing top-level bindings and exact-certificate access through aliases on both runtimes at the pinned versions? Plain map type checking was rejected because it loses these constraints; compilation remains blocked pending that review.
- Which concrete source-schema revisions and digests bind the five schema-backed paths, including lineage revision identity and certificate serial/fingerprint formats? This slice chooses typed JSON maps and retained evidence tags instead of inventing absent source schemas; consumers cannot publish unresolved accesses.
