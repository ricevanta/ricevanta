# Extension package manifest

This contract defines `extension.yaml`, its decoded shape and a pure Go validator. It does not admit an installation. EXT-08 records the representation choice. [The plan](../plans/extension-manifest.md) requires independent review before implementation.

## 1. Scope and dependencies

The contract supplies field grammar, identity and version spelling, file commitments, component declarations, requested capability ceilings and reserved package names. The schema uses [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation). [The manifest schema](../../schemas/extension/v1alpha1/manifest.schema.json) owns the field inventory, required fields, enums and individual bounds. Sections 3 through 6 own the semantic checks that JSON Schema cannot express. Neither artifact alone is the complete contract.

The package is `server/internal/extensions/manifest`, in `github.com/ricevanta/ricevanta/server`, using Go 1.27.1 and only its standard library. No runtime JSON Schema interpreter, code generator, database, filesystem access, network call, archive reader or DSSE call belongs in this package.

The installed toolchain is Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0. Rust and Node are not dependencies of this Go slice. The later YAML loader uses exactly `go.yaml.in/yaml/v3` v3.0.4, recorded in [licensing](../licensing.md). This plan does not add that module to `server/go.mod`.

Later slices own:

- Bounded archive and YAML loading, signature verification and file-byte digest checks, the install flow and the GitOps `extension-resource.json` resource.
- Publisher trust-list admission, canonical Ed25519 key checks, revocation, global id ownership, protected publisher-key transfer and permanent immutable id/version tombstone storage.
- Browser adapter and browser-registration schemas, canonical OS targets, exclusive write ownership and OS reserved namespaces.
- Capability-grant schemas, approval, recovery epochs, generations, compilation and revocation propagation.
- Content validators, WIT schemas, collector disclosure profiles, console catalogue and binding schemas, connector contracts and their qualification gates.

Those are implementation dependencies of their consumers, not v1.0.0 scope reductions. Full support remains required on macOS ARM64, Windows x64 and Linux x64.

## 2. YAML and signed bytes

`extension.yaml` remains YAML, with DSSE type `application/vnd.ricevanta.extension-manifest+yaml`. JSON syntax is also valid within the restricted YAML profile. The decoded JSON fixtures are data-model examples, not a change to the payload type. No manifest canonicalizer exists: comments, indentation and line endings remain signed bytes. A semantically equal reserialization has different manifest bytes and cannot replace an accepted id/version.

The later loader must preserve the exact bounded payload bytes and require equality between the archive's `extension.yaml` and the verified DSSE payload. It calls the shared primitive with `dsse.TypeExtensionManifest` from caller intent. The claimed publisher fingerprint and DSSE `KeyID` never select authority by themselves. The caller selects a currently authorized, non-revoked key and verifies the unchanged DSSE payload before any YAML token scan, decoding or validation. After decoding that verified payload once, the caller checks that `metadata.publisher.key` equals `sha256:` plus lowercase SHA-256 of that key's 32 raw public bytes. This is not a certificate fingerprint. `KeyID` remains an opaque hint under [the DSSE profile](dsse-envelope.md); the upstream [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) defines signing over pre-authentication encoding, not reserialized content.

The YAML loader is deliberately a later slice. Its required preconditions are:

1. Read at most 1,048,576 payload bytes; reject invalid UTF-8, a byte-order mark and more than one document. One optional document start/end marker is permitted; a second empty document is not.
2. Check the original verified YAML bytes with a bounded, token-aware scan that rejects every explicit tag, including bare `!`, shorthand tags and verbatim tags on mappings, sequences and scalars. Distinguish tag tokens from `!` inside comments, quoted strings, block scalars and plain scalar content; a substring or regular-expression search is insufficient. Decode into `yaml.Node` once, not directly into a struct or map. Accept mappings, sequences, strings, booleans and decimal unsigned integers only. Reject anchors, aliases, merge keys, explicit tags, nulls, floats, timestamps, binary scalars and non-string mapping keys. Node inspection alone cannot enforce the tag ban: [the pinned parser](https://github.com/yaml/go-yaml/blob/v3.0.4/decode.go) treats bare `!` like an omitted tag and does not set `TaggedStyle`.
3. Reject duplicate mapping keys after scalar decoding, including escaped spellings, before forming a Go map. Do not apply implicit defaults, case folding or YAML scalar coercions. Boolean text is exactly `true` or `false`; integer text is `0` or `[1-9][0-9]*`. Quoted numbers remain strings and fail numeric fields.
4. Enforce the tree limits below, then preserve each integer lexeme as `json.Number`. Map keys remain case-sensitive. Retain the original payload separately for signatures, digests and tombstones.

The [YAML specification](https://yaml.org/spec/1.2.2/) distinguishes representation from presentation. [The pinned Go YAML API](https://pkg.go.dev/go.yaml.in/yaml/v3@v3.0.4) exposes nodes and also documents compatibility coercions. `KnownFields` alone does not implement this profile. Loader tests must prove the preconditions and bound parser allocations before any production consumer relies on them.

## 3. Identity, metadata and namespace

`metadata.id` has 2 through 16 lowercase ASCII DNS labels, each 1 through 63 bytes, and at most 253 bytes including dots. Labels start and end with a letter or digit and contain only letters, digits and hyphens. No trailing dot, wildcard, underscore, Unicode, normalization or DNS lookup is allowed. The id is an installation identity, not proof that the publisher controls a domain.

The exact id `io.ricevanta` and descendants beginning `io.ricevanta.` are reserved. `io.ricevantaevil.rules` is not a descendant. The validator refuses reserved ids unless the trusted caller sets `AllowReservedID`; the caller may set it only after verifying the project publisher's current authority. An id prefix in the manifest, publisher display name or matching claimed fingerprint cannot set that option. Other publisher prefix matching and ownership checks belong to the trust slice. Component names are local to this package and confer no global namespace ownership.

Versions follow the lower-case, no-build-metadata profile of [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html): three decimal numbers without leading zeroes, an optional dot-separated prerelease, and at most 128 bytes total. Numeric prerelease identifiers have no leading zeroes. Alphabetic prerelease text uses only `a` through `z` and hyphens. Reject `v1.2.3`, ranges, build suffixes and uppercase. Compare identity by exact accepted version string, never by SemVer precedence. Do not parse numeric identifiers into a machine integer; the string length bounds them. A tombstone for `1.0.0-rc.1` is distinct from `1.0.0`.

The schema fixes a fingerprint to `sha256:` and 64 lowercase hex digits and a file digest to 64 lowercase hex digits without the prefix. All-zero digests are syntactically valid; matching actual bytes is a later gate. The validator never infers key validity from a fingerprint.

Publisher names are display-only, 1 through 128 Unicode scalar values without C0 or C1 controls. Other manifest strings use the schema's ASCII grammar. URLs are display metadata: HTTPS, a lowercase dotted DNS host, optional decimal port, path and query; no credentials, fragment, IP literal or network fetch. After the schema grammar, reject hosts above 253 bytes, hosts accepted by `net/netip.ParseAddr`, ports above 65535 and malformed percent escapes. URL validity does not make a destination safe to fetch.

`metadata.license` is required, at most 256 ASCII bytes. The schema checks its alphabet; the Go validator checks the following bounded SPDX expression syntax. This is grammar validation, not recognition of every license-list identifier or legal approval. The later license-policy slice must check identifiers and license texts before distribution.

```text
expr    = term *(" OR " term)
term    = factor *(" AND " factor)
factor  = simple [" WITH " exception] / "(" expr ")"
simple  = identifier ["+"] / ["DocumentRef-" ref ":"] "LicenseRef-" ref
identifier = 1*(ALPHA / DIGIT / "-" / ".")
exception  = identifier
ref        = 1*(ALPHA / DIGIT / "-" / ".")
```

Operators are uppercase with one space on each side. Nesting is at most 8. `AND`, `OR`, `WITH`, `NONE` and `NOASSERTION` are not identifiers. A token beginning `LicenseRef-` or `DocumentRef-` must use the reference production; it cannot fall back to an ordinary identifier. `+` applies only to an ordinary license identifier. `WITH` cannot follow a parenthesized expression or a license reference. These are Ricevanta restrictions on [SPDX expressions](https://spdx.github.io/spdx-spec/v2.3.1/SPDX-license-expressions/).

## 4. File commitments and references

Every `files[]` record commits one regular file path, SHA-256 and uncompressed byte size. Zero-length files are valid. The schema's per-file ceiling is 1,073,741,824 bytes. The validator's default aggregate ceiling is 67,108,864 bytes; the trusted caller may set a positive ceiling up to the per-file ceiling. These limits concern listed file bytes. A later archive reader must separately account for the manifest, envelope, tar headers, padding and compressed bytes under its archive budget.

Paths use lowercase ASCII and `/`, with at most 240 bytes. Each segment starts with a letter or digit; remaining characters are letters, digits, `.`, `_` or `-`. Additionally, a segment is at most 63 bytes, cannot end with `.`, and its stem before its first dot cannot be `con`, `prn`, `aux`, `nul`, `com1` through `com9`, or `lpt1` through `lpt9`. These are a portable package naming restriction, not a claim of safe OS extraction.

Reject root paths `extension.yaml` and `envelope.json` and their descendants in the listing. Reject repeated paths and any file/directory prefix collision, such as `a/b` with `a/b/c`. No path cleanup, Unicode normalization, percent decoding, case folding or separator conversion is allowed. Absolute paths, `..`, empty segments, backslashes, drive letters, alternate streams and trailing separators fail the grammar.

Each component has an explicit `files` array. Its `file`, `entry` and `row_schema` references, when required by its kind, must occur in that array. Each component path must occur once in the package listing. Each listed path has exactly one component owner, except paths beneath `attestations/`, which have no component owner. A component cannot claim an attestation. A console mount can therefore use its own explicit file set without exposing another component's assets. File order carries no extraction authority.

The validator checks declared ownership, not archive members or file contents. It does not open a path, check a module header, parse a row schema or compute a component digest. Archive extraction still needs no-link, no-alias, size and hash checks. Future component identity must bind the descriptor and all owned files; this slice does not choose a component digest encoding.

## 5. Components and requested capabilities

The schema is closed at every object. Unknown fields, kinds, interfaces, formats, capability names and enum values fail. No field is ignored as an extension point. The GitOps `Extension` resource uses the same outer kind name but has a different contract; `spec.source`, `spec.targets` and `spec.grants` are invalid here.

`spec.requires` maps each used kind to a nonempty unique array of exact interfaces. Its keys and values must equal the sets derived from all components, with no missing or unused value. Arrays permit a classifier and collector, or two connector contracts, in one package. Requirement order is immaterial. A known spelling does not prove the running server serves the interface; the later installer checks its served catalogue.

| Kind | Manifest declaration | Boundary left to a later slice |
|---|---|---|
| `content` | One format, entry file and empty capability object | Validate the content against that format's schema |
| `browser-adapter` | Adapter file, one registration id, requested policy names and native-host use per declared OS | Intersect adapter, registration and grant; reject OS reserved targets and overlapping owners |
| `agent-module` | One exact WIT interface, module file, memory pages, fuel and deadline | Link imports, enforce budgets and validate outputs on the agent |
| `console-module` | Entry, explicit asset files, bridge version, slots and operation names | Reviewed safe-operation catalogue, slot mapping, current operator permissions and qualified document binding |
| `service-connector` | One contract interface, deployment descriptor file and DNS host/port/transport destination tuples | Descriptor and image-digest validation, registration and network policy |

A package uses multiple connector components for multiple contracts. The server never executes a deployment descriptor. Console operation names come from the design's candidate list; accepting a name here does not make the absent bridge catalogue available. Slots and operations are package-wide upper bounds; a later grant maps operations to individual slots.

All agent requests require positive `memory_pages`, `fuel_per_call` and `deadline_ms`, capped respectively at 4096 pages, 1,000,000,000 fuel and 60,000 ms. These are product ceilings, not recommended grants or promised resident-memory limits. Effective values may be lower under bundle policy. Parser requests also declare bounded MIME types; policy chooses which types it routes to the parser.

Collector requests require every broker and output maximum in the schema and a `row_schema` file. `max_bytes_per_file <= max_input_bytes` and `max_open_handles <= max_read_requests`. Roots, disclosure profiles and telemetry projections are grant data, absent here. A collector manifest cannot authorize a filesystem read.

Responder requests include the schema's exact child action set, maximum entities, parameter bytes, plan steps and plan bytes. `edr.run_script` and recursive `extension.respond` are excluded. Command-bound entity identities, parameter envelopes and the permission/approval union remain required under [the runtime contract](extension-agent-runtime.md#6-responder-plan-and-recovery).

Browser declarations accept only OS keys `macos`, `windows` and `linux`, at most 64 unique policy names per OS and an explicit native-host boolean. They cannot express a registry key, plist domain, filesystem target, policy value, update URL or native-host manifest. A registration id is only a reference, including when it names a first-party registration. Registration authorization, canonical targets and generated values remain mandatory.

## 6. Exact Go API and error precedence

```go
package manifest

type Options struct {
    AllowReservedID    bool
    MaxTotalFileBytes uint64 // Zero selects DefaultMaxTotalFileBytes.
}

const (
    MaxManifestBytes = 1 << 20
    MaxTreeDepth = 16
    MaxTreeNodes = 65536
    DefaultMaxTotalFileBytes uint64 = 64 << 20
    HardMaxTotalFileBytes uint64 = 1 << 30
)

func Validate(document any, options Options) error

var (
    ErrOptions = errors.New("manifest options")
    ErrTree = errors.New("manifest decoded tree")
    ErrShape = errors.New("manifest shape")
    ErrField = errors.New("manifest field")
    ErrReserved = errors.New("manifest reserved id")
    ErrDuplicate = errors.New("manifest duplicate")
    ErrPath = errors.New("manifest path")
    ErrLimit = errors.New("manifest file total")
    ErrRequires = errors.New("manifest interface requirements")
    ErrReference = errors.New("manifest file reference")
    ErrCapability = errors.New("manifest capability relation")
    ErrLicense = errors.New("manifest license expression")
    ErrURL = errors.New("manifest URL")
)
```

Accept only exact dynamic types `map[string]any`, `[]any`, `string`, `bool` and `json.Number`. Nil values, typed nil containers, aliases with distinct defined Go types, all floats and native integer types fail. `json.Number` must contain the canonical unsigned decimal spelling above, at most 20 digits and fit `uint64`. The use of an untyped tree preserves absent, unknown and wrongly typed fields; a typed struct would discard evidence before this validator could reject it. Tests load decoded JSON fixtures using `json.Decoder.UseNumber`, never the default `float64` representation documented by [encoding/json](https://pkg.go.dev/encoding/json).

`Validate` returns nil only for complete structural validity. It does not mutate, retain, normalize or fill in the input. Calls with separate immutable trees are concurrent-safe. The caller must not mutate a tree during validation. No context parameter is needed for bounded, local computation. Errors wrap exactly one listed sentinel with `%w`; callers use `errors.Is`. Error text may name a schema field but must not include publisher-controlled values. No public structured error or stable message suffix is promised.

Run these stages over the whole document in order. A later-stage defect cannot mask an earlier-stage defect, regardless of map iteration order. Multiple errors in one stage return the same sentinel.

| Order | Check | Error |
|---|---|---|
| 1 | Configured total ceiling exceeds the hard ceiling | `ErrOptions` |
| 2 | Unsupported dynamic type, invalid UTF-8, malformed number, nil, or tree budget | `ErrTree` |
| 3 | Object/array/scalar type at a field, missing or unknown key, unknown kind, or unknown agent interface needed to select a branch | `ErrShape` |
| 4 | All schema constants, enums, patterns, string lengths, array lengths, object cardinality (`minProperties`), numeric bounds and array `uniqueItems` | `ErrField` |
| 5 | Reserved package id without caller authority | `ErrReserved` |
| 6 | Repeated component name or package file path, including unequal objects with equal identity | `ErrDuplicate` |
| 7 | Extra segment rules, reserved root filenames and file/directory collisions | `ErrPath` |
| 8 | Listed size sum exceeds the effective ceiling | `ErrLimit` |
| 9 | Requirement sets differ from component interface sets | `ErrRequires` |
| 10 | Missing references, shared or unowned files, or component-owned attestations | `ErrReference` |
| 11 | Collector cross-field limits | `ErrCapability` |
| 12 | SPDX expression syntax or nesting limit | `ErrLicense` |
| 13 | URL host, port and percent-escape checks | `ErrURL` |

The tree budget counts each container, key and scalar as one node and every key/string/number's UTF-8 byte length toward `MaxManifestBytes`. Root depth is one; only containers increase nesting depth. Reject a map or array whose immediate length exceeds the remaining node budget before iterating it. Incremental checked counters stop traversal at the first exceeded budget. Cycles therefore terminate with `ErrTree` by depth or node count without unbounded recursion. A byte payload's length and this decoded budget are separate checks; this API cannot measure bytes it did not receive.

Apply schema string limits by Unicode scalar count, including ASCII fields. Reject invalid UTF-8 before counting. Implement numeric comparisons without `float64`. Add file sizes by checking `size > ceiling - total` before addition. Do not sort caller-owned arrays. Equality for `uniqueItems` is structural; array order matters and map key order does not. All numbers have canonical unsigned spelling, so equal numbers have equal lexemes. Avoid quadratic pairwise comparisons: index structural encodings with sorted map keys, or collision-resolved hashes, for `uniqueItems`. Such internal encodings never replace signed payload bytes. The final newline must never pass a pattern because `$` can match before a line terminator in some engines; the schema uses an explicit absolute-end assertion, and Go checks the whole value.

## 7. Security path and limits

The future admission path is bounded byte loading, authorized DSSE verification over unchanged payload bytes, the token-aware YAML check and one payload decode, decoded validation, verified-key/fingerprint and id-prefix binding, exact file hash/size checks, committed ownership and tombstone checks, then approved grants and publication under the recovery fence. This order follows [the shared DSSE contract](dsse-envelope.md#8-responsibilities-and-attacker-paths): verify exact bytes before parsing the payload once. Reserved-id permission derives from the verified key's current project-publisher authority; the caller sets `AllowReservedID` only from that authority before decoded validation. No successful return from this API skips any later gate.

| Attacker | What this slice prevents | What the attacker still gets or requires |
|---|---|---|
| Stolen enrollment token | Cannot encode trust, grant or ownership fields into a manifest | Token grants no publisher authority; enrollment controls and install authorization remain separate |
| Compromised agent host | Cannot turn submitted malformed declarations into admitted structure | Can lie about local execution and possess local artifacts; agents still consume organization-signed bundles, never publisher manifests as authority |
| Compromised console session | Cannot bypass grammar, bounds or namespace checks through submitted fields | Can submit otherwise valid requests within session rights; independent approval and trust administration must stop unauthorized install or grant changes |
| Rogue extension publisher | Cannot request unknown capabilities, alias paths, change type spelling or cross reserved package names through this API | Can sign malicious but structurally valid code and choose arbitrary claimed hashes; signature, file-byte checks, grants and runtime isolation are all still required |
| Network position between agent and server | Cannot make a changed spelling silently normalize to accepted identity | Can replay an unchanged structurally valid manifest; DSSE, TLS, assignments and current authority provide authenticity and replay controls |
| Database writer without signing keys | Cannot manufacture a structurally valid document that itself grants execution | Can replace rows with other valid documents; rechecking signed bytes, independent authority and tombstones must reject substitution or revival |
| Server restored from backup | Deterministic validation does not silently rewrite ids, versions or fingerprints | Old revoked bytes remain structurally valid; the restore stays sealed until journal, key custody, ownership, revocation and permanent tombstones reconcile |

A fingerprint is only a digest commitment. Trust-list key admission must call the shared [Ed25519 key admission](ed25519-key-admission.md) validator, which rejects non-canonical, small-order and mixed-order public keys, before DSSE verification can be treated as authentication. This manifest validator neither accepts a public key nor repairs that gap.

## 8. Fixtures, boundaries and fuzzing

[fixtures.json](../../schemas/extension/v1alpha1/fixtures.json) contains complete decoded manifests, explicit caller options, schema validity and expected Go sentinels. [fixtures.schema.json](../../schemas/extension/v1alpha1/fixtures.schema.json) checks the corpus envelope. Each manifest runs against the manifest schema even when a semantic rejection is expected. A schema-valid negative demonstrates why schema-only admission is insufficient. Public-key bytes in the digest vector are test data, not a trusted or proven admissible key. File vectors commit the exact UTF-8 strings, without a newline. Their bytes are opaque test content, not valid examples of each component format.

Recompute every digest vector with Python `hashlib`, then an independent Go `crypto/sha256` program. The checker also matches every file digest and publisher fingerprint in positive fixtures. No signature vector is invented here; DSSE byte/signature vectors remain in `schemas/dsse/v1/`.

Required in-memory vectors supplement the corpus:

- Every allowed kind, agent world, connector contract, content format, slot and operation. Accept `listDeviceSoftware`; reject `getDeviceSoftware` with `ErrField`, both alone and beside the accepted spelling. A mixed package contains multiple worlds and connector contracts; requirement arrays must exactly match their union.
- Every numeric minimum/maximum, one below and one above; counts 0, 1, cap and cap+1; string lengths cap-1, cap and cap+1. Check 4096 listed files and 64 components independently with short valid data.
- Tree depths 15, 16 and 17; nodes 65535, 65536 and 65537; aggregate text bytes 1,048,575, 1,048,576 and 1,048,577. Use unknown subtrees to test budget precedence before shape rejection. Include map and slice cycles, nils, invalid UTF-8, huge containers and defined Go alias types.
- `json.Number` values `0`, `1`, `18446744073709551615`, overflow, `-0`, `01`, `1.0`, `1e0`, `+1` and a million digits. Valid lexical values still face field bounds. Float64, NaN and infinities return `ErrTree`.
- Zero-length file with the empty digest vector; default total at cap-1, cap and cap+1; explicit smaller and larger totals; `MaxUint64` total option; multiple files whose sum crosses the ceiling.
- Reserved `io.ricevanta` and descendants under both options; lookalikes `io.ricevantaevil.rules` and `com.io.ricevanta` are ordinary ids. The options must never be loaded from the document.
- All portable reserved stems with suffixes; 63/64-byte segments; root-file descendants; shared assets, unowned assets, attestations claimed by components and missing entry/row-schema references.
- SPDX simple, `+`, `AND`, `OR`, parentheses, `WITH`, local and document license references; dangling operators, empty refs, forbidden reference suffixes and depths 8/9. Metadata URLs include escaped paths, malformed escapes, IP literals, 253/254-byte hosts and port 65535/65536.
- Empty `spec.requires` and browser `capabilities.os` objects return `ErrField` at stage 4. Each empty object combined with a reserved id still returns `ErrField`; combined with an unknown key it returns `ErrShape`.
- Pairwise defects across every adjacent stage, plus reordered object keys. Identical duplicate objects fail stage 4 (`uniqueItems`); unequal records with the same path fail stage 6. Error messages never contain supplied secrets or control characters.

`FuzzValidate` decodes arbitrary bounded JSON bytes using `UseNumber`, ignores JSON syntax failures, and calls `Validate` with arbitrary options. Assert no panic, deterministic sentinel, input unchanged and equal results after map-key reordering. Seed from every small corpus manifest. Direct graph mutation tests cover values and cycles that JSON cannot encode. Raw YAML fuzzing belongs to the loader slice. [loader-vectors.json](../../schemas/extension/v1alpha1/loader-vectors.json), checked by [its schema](../../schemas/extension/v1alpha1/loader-vectors.schema.json), supplies raw UTF-8 YAML for that slice, not inputs to `Validate`. `accept` means the loader and decoded validator must accept the complete manifest; `reject-explicit-tag` means the loader must reject before decoded validation. The tag vectors cover mappings, sequences and scalars, including bare `!`, with untagged controls and literal-exclamation controls. These vectors do not qualify the absent production loader or its allocation bounds.

## 9. Assessment and review focus

Benefits: explicit files and closed capability objects let a small leaf validator reject ambiguous package identities and over-budget declarations before stateful admission. Shared fixtures expose the distinction between schema and semantic validity.

Trade-offs: the map API requires exact dynamic types and a strict upstream decoder. YAML needs a dependency and loader qualification. Lowercase filenames and versions exclude otherwise portable-looking packages; authors must rename files and prerelease labels. Requirement arrays are more verbose than one interface string per kind.

Alternatives considered: JSON-only YAML would avoid a YAML dependency but reject ordinary indented manifests promised by EXT-01. A handwritten YAML parser would add an unnecessary untrusted-input parser. A typed struct with permissive decoding would erase unknown keys. Accepting build metadata would permit versions with equal SemVer precedence but different tombstone identities. A general JSON Schema runtime would add a Go dependency without supplying cross-reference or authority checks.

Review focus:

- Whole-tree error precedence, closed branch selection and `errors.Is` behavior match the corpus.
- Bounds apply before large traversal or arithmetic, including direct cyclic Go values.
- No normalization merges ids, version strings or package paths; no case-insensitive struct decoding occurs.
- Schema-valid semantic failures remain failures in Go, including shared files and unused requirements.
- Caller namespace options cannot become publisher-supplied authority; cryptographic key validity is a separate gate.
- No accepted declaration enables an unresolved browser, collector, responder, console or connector consumer.

## 10. Unresolved questions

The selected defaults govern this slice; these questions do not permit implementers to widen acceptance without review.

- Should publisher feedback justify build metadata or uppercase prerelease text, instead of the selected lowercase, no-build profile?
- Should real package measurements justify raising the selected 64 MiB default or any capability ceiling, instead of the bounded defaults?
- Can the later YAML loader prove its byte, node, depth and allocation bounds with v3.0.4, or does that evidence require a separately reviewed parser pin?
- Which reviewed license catalogue will resolve SPDX identifiers and custom license texts before distribution, beyond the selected grammar-only check?
