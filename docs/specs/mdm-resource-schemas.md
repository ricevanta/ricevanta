# MDM resource schemas

This slice defines authoring validation for `Baseline`, `SoftwarePackage` and `DeviceGroup`, including all 17 Baseline kinds. It supplies JSON Schema 2020-12 contracts, fixture checks and a standard-library Go validator for decoded resources. The schemas, fixtures and Python design checks are published under `schemas/policy/v1alpha1/`. The Go consumer remains implementation work under [the plan](../plans/mdm-resource-schemas.md). Decision: MDM-10.

[Baseline](baseline.md) owns convergence, approval bindings and compliance. [MDM design](../design/mdm.md) owns native mechanisms. [Policy envelope](policy-envelope.md) sections 1, 6 and 8 own the resource envelope, bundles and GitOps. Validation grants no permission to publish, deploy, execute or accept evidence.

## 1. Boundaries and choice

Use hand-written Go validation with fixture drift tests against Python JSON Schema validation. The package imports only the standard library. The small closed resource vocabulary, explicit error precedence and decoded-input API fit direct validation. The cost is maintaining two structural implementations; section 8 makes disagreement a failing check. A Go JSON Schema library would reduce duplicated structural code but still need custom byte, uniqueness, path and cross-field checks, a pinned dependency and license review. It is rejected for this slice; no licensing row is needed.

Included: three resource schemas; 17 per-kind schemas; all named platform variants; positive, negative and combined-defect fixtures; additive `validate.py` and `test_validate.py` changes; `server/internal/mdm/resourcevalidate` and its tests. No existing Policy or Exception acceptance rule changes.

Later slices: revision-bound item evidence, required-set and grace-episode schemas; every evidence-recovery record in [MDM evidence recovery](mdm-evidence-recovery.md), including query consumption, native status, escrow acknowledgements and retirement authorization. This slice supplies no authority journal, native adapter, CEL or SQL compiler, reference resolver, canonical revision hasher, transport parser, runtime enforcement or compliance computation. Those consumers must complete their own review and qualification gates.

Installed tools: Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 with pnpm 11.18.0. Go and Python implement validation; Node checks schema-pattern parity in ECMAScript Unicode mode. Retain the design check pins `jsonschema==4.25.1`, `PyYAML==6.0.3`, `rfc3339-validator==0.1.4`, `six==1.17.0`. No added dependency, build file or CI change is needed.

## 2. Schema layout and common rules

All paths in this section are relative to `schemas/policy/v1alpha1/`:

| File | Purpose |
|---|---|
| `mdm-common.schema.json` | Shared definitions only; title `MDMCommon`, never a resource dispatch target |
| `baseline.schema.json` | Baseline root; title `Baseline`; OS and kind dispatch |
| `software-package.schema.json` | SoftwarePackage root; title `SoftwarePackage` |
| `device-group.schema.json` | DeviceGroup root; title `DeviceGroup` |
| `baseline/<kind>.json` | Settings object for each exact kind in section 3; title equals kind |
| `fixtures/mdm/manifest.json` | Complete fixture inventory, structural and full results |
| `fixtures/mdm/{valid,invalid}/*.json` | Whole authoring resources, never isolated settings |

Every schema has `$schema: https://json-schema.org/draft/2020-12/schema` and an `$id` equal to `https://ricevanta.io/schemas/policy/v1alpha1/` plus its path. Resolve only registered local schemas; no file, HTTP or dynamic retrieval. Use `$ref`, `oneOf` for disjoint tagged variants and `if`/`then` for OS restrictions. Close every object with `additionalProperties: false`, except the expressly named maps and native payload JSON below. Unknown resource kinds, item kinds, properties and variant fields fail. A `default` is documentation, not mutation by the validator [S1, S2].

The notation below is normative: `T(n)` is a string of 1 through n Unicode scalar values, `T0(n)` permits empty, `I(a,b)` is an integer inclusive of both bounds, `B` is boolean, `?` means optional. All unmarked fields are required. Arrays state inclusive length bounds; sets additionally prohibit duplicate values. Null is refused except inside native JSON. Strings and object keys must be valid UTF-8 without surrogate code points. NUL is forbidden outside native JSON. Control characters U+0000 through U+001F and U+007F are forbidden in strings outside native JSON, except multiline content, rules, queries, expressions and CSP xml, which permit tab, CR and LF. Identifiers, paths, URI strings, arguments and single-line values have no control-character exception.

`Name` is a full-string ASCII DNS label of 1..63 bytes: lowercase letters, digits and internal hyphens, starting and ending alphanumeric. Use `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(?![\s\S])` in schema patterns; Go checks the same language without lookahead. `Hash` is exactly 64 lowercase hex characters. `Version` is T(128), excluding exactly U+0000..U+0020, U+007F, U+0085, U+00A0, U+1680, U+2000..U+200A, U+2028..U+2029, U+202F, U+205F, U+3000 and U+FEFF, in addition to the scalar-validity rule. This fixed whitespace and control set applies in every language; do not use a language whitespace predicate or `\s` to classify Version scalars. Version is an opaque vendor version, not SemVer. `Groups` is a set of 1..64 Names. `Args` is 0..64 T0(4096) strings, each passed as one argument, never a shell command.

Roots require exactly `apiVersion: ricevanta.io/v1alpha1`, the resource's `kind`, `metadata` and `spec`. Reject `status`, uid, revision, approval and recovery fields in authoring input. Server response decoding is outside this API. Metadata uses `policy.schema.json#/$defs/metadata`, with a stricter Name intersection and scalar-valid keys; keep its labels, annotations and description limits. Add maxLength 256 to metadata map keys. Do not change the existing metadata definition. Empty labels and annotations are allowed.

`mdm-common.schema.json` owns definitions for these primitives, `metadata`, `groups`, `nativeJSON`, `duration`, `posixPath`, `source` and `signature`. Native JSON recursively accepts null, boolean, strings, finite numbers, arrays and string-keyed objects. Each native object/array has at most 256 entries; each native string/key has at most 16,384 scalars. Its total bounds come from section 7. Native dictionaries remain vendor-defined data, never extra Ricevanta fields.

Canonical base64 uses the standard alphabet and pattern `(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?` across the whole string, with maxLength 16384; nonempty variants require minLength 4. Re-encoding decoded bytes must reproduce the input, including zero pad bits.

Duration is integer zero `0` or a string matching `[1-9][0-9]{0,5}(s|m|h|d)` across the entire value, with at most 2,592,000 seconds (30 days). Negative values, leading zeroes, compound durations and whitespace spellings are refused; decoded numeric zero, including negative zero, is accepted as an integer under section 7. The semantic layer checks converted seconds without overflow. Grace defaults to `24h`, except critical severity defaults to integer `0`; explicit nonzero critical grace is refused.

## 3. Baseline and per-kind settings

`spec` requires `os: macos|windows|linux` and `items` (1..2,000 entries). Optional fields: `allowedGroups: Groups`, `minOsVersion: Version`. Apply-capable kinds require allowedGroups; check-only baselines forbid it. This depends on kind capability even for a report policy. Items require `id: Name`, `kind`, `settings`, `required: B` and `severity: informational|low|medium|high|critical`; optional fields are `grace`, `authority` and `references`. Item ids must be unique. No script kind exists.

`references` is 0..16 closed objects with `framework: T(64)`, `id: T(128)`, `document?: T(128)`, `version?: T(64)`. No benchmark prose field exists; license-aware publication review still owns detecting copied text. `authority` is `native|agent`: windows.csp permits both and defaults to native; apple kinds permit only native; all other kinds permit only agent except os_update and encryption, which default to native on macOS and agent elsewhere. Explicit authority must match these choices. The baseline's OS supplies that context to the otherwise standalone settings schema.

Each per-kind file carries `x-ricevanta-effect: apply|check` and `x-ricevanta-protected-publication: true|false`. Exactly check.query and check.collector use check/false; every other kind uses apply/true. These annotations classify capability; an author-supplied `protected`, `effect` or approval flag is rejected. Tests compare annotations with the Go classification table. A false annotation never exempts a required-compliance weakening diff from [Baseline section 5](baseline.md#5-authoring).

### 3.1 macOS and Windows

| Kind | OS | Required settings and optional fields |
|---|---|---|
| `apple.declaration` | macos | `identifier: T(255)`, `type: T(255)`, `payload: nativeJSON object`; identifier and type are dot-separated ASCII segments `[A-Za-z0-9_-]+` with at least two segments. Type starts `com.apple.`. Reject top-level server token or status fields. |
| `apple.profile` | macos | `identifier: T(255)` with the same identifier grammar; `payloads`: 1..64 nativeJSON objects. Each payload requires `PayloadType: T(255)` and `PayloadIdentifier: T(255)` with that grammar. Payload identifiers are unique. No XML, base64 profile, external URL, CMS wrapper or enrollment profile input. PayloadType must start `com.apple.`. |
| `windows.csp` | windows | `locUri: T(2048)`, `format: int\|bool\|chr\|xml\|b64`, `value`. URI starts `./Device/Vendor/MSFT/` or `./User/Vendor/MSFT/`, with nonempty ASCII segments `[A-Za-z0-9_.-]+`, no `.` or `..` segment, percent, query or fragment. `int` uses I(-2147483648,2147483647), `bool` B, `chr` T0(16384), `xml` T(16384), `b64` canonical padded base64 of 1..12288 decoded bytes. |
| `windows.registry` | windows | `hive: HKLM`, `view: 32\|64`, `key: T(1024)`, `name: T0(256)`, `type: string\|expand-string\|multi-string\|dword\|qword\|binary`, `value`. Key is backslash-separated nonempty printable ASCII segments without slash, dot segments or leading/trailing spaces. Refuse case-insensitive `SOFTWARE\Policies` and descendants, including explicit `SOFTWARE\WOW6432Node\Policies`; refuse every explicit WOW6432Node segment, using view instead. Values: string/expand-string T0(16384), multi-string 0..256 T0(1024), dword I(0,4294967295), qword decimal string `0\|[1-9][0-9]{0,19}` at most 18446744073709551615, binary canonical base64 of 0..12288 bytes. |
| `windows.service` | windows | `name: T(256)` without slash or backslash, `startType: automatic\|automatic-delayed\|manual\|disabled`, `state: running\|stopped`. Disabled plus running is refused. No executable path, account, password or arbitrary service creation. |

Reject `PayloadType` values `com.apple.mdm`, `com.apple.security.scep` and `com.apple.security.pkcs12` in apple.profile. These belong to enrollment or secret-handling contracts. Native publication must validate all payloads against an independently pinned Apple catalogue, generate required UUIDs and transport fields, and refuse unrecognized or unsafe combinations. That compiler is a later slice, not permission to send unvalidated native payloads. CSP publication likewise requires a reviewed URI/type/edition catalogue for both namespaces, qualified user-context binding for User settings, and a qualified effective-state reader for authority agent. XML is bounded text here; parsing, entity refusal and CSP semantics belong to that compiler. The first-party catalogues describe the native data model [S5, S6]; this document does not claim full vendor-payload validation.

### 3.2 Linux

`PosixPath` is an absolute path of 2..4096 ASCII bytes, using printable non-space characters except backslash; no repeated slash, trailing slash, `.` or `..` segment. This is a lexical restriction, not proof of ownership or protection against links. `Account` is `[a-z_][a-z0-9_-]{0,31}`. Path restrictions apply before host lookup.

| Kind | Required settings and optional fields |
|---|---|
| `linux.dconf` | `key: PosixPath`, `value: T0(16384)` containing one single-line GVariant spelling, `locked: B`. Agent generates the database and profile entries; no file-path field. GVariant parsing is a native-compiler obligation. |
| `linux.polkit` | `rules: T(16384)` multiline JavaScript. No path field; output path derives only from item id under Baseline section 2. Always protected; validation does not execute or sandbox rules [S7]. |
| `linux.sysctl` | `key: T(255)` with full grammar `[a-z0-9_]+(\.[a-z0-9_-]+)+`, `value: T(1024)` single-line. No `/proc` path or command field. |
| `linux.systemd` | `unit: T(255)`, `state?: enabled\|disabled\|masked`, `dropIn?:` object defined below. Require at least state or dropIn. Unit is `[A-Za-z0-9_:@.-]+\.(service\|socket\|timer\|target\|path\|mount\|automount\|swap\|slice)` across the full string, no leading dot or `..`, at most one `@`, and no empty template instance. No slash, escape or wildcard. |
| `linux.pam` | `pwquality?:` object with `minlen?: I(6,128)`, `minclass?: I(0,4)`, `maxrepeat?: I(0,128)`, `enforceForRoot?: B`; `faillock?:` object with `deny?: I(1,100)`, `failIntervalSeconds?: I(1,86400)`, `unlockTimeSeconds?: I(0,604800)`, `evenDenyRoot?: B`, `rootUnlockTimeSeconds?: I(1,604800)`. Each supplied object is nonempty; require at least one. evenDenyRoot true requires rootUnlockTimeSeconds. No module, stack, path or command fields. |
| `linux.file` | `path: PosixPath`, `content: T0(16384)` multiline, `mode: 0400\|0440\|0444\|0600\|0640\|0644` as strings, `owner: Account`, `group: Account`. All paths are strictly below `/etc/`; refuse `/etc/pam.d`, `/etc/ricevanta` and their descendants. Only whole regular files owned by the agent; no link or special-file discriminator. |
| `linux.repository` | `manager: apt\|dnf\|zypper\|flatpak`, `name: Name`, `url: HTTPS`, `key: {sha256: Hash, fingerprint: Fingerprint}`; `suite: T(128)` and `components: set 1..32 T(64)` required only for apt. No trusted flag, insecure mode, key URL, command or authentication secret. |

`dropIn` requires `name: Name`, `sections`: 1..8 objects `{name: Unit|Service|Socket|Timer|Path|Mount|Automount|Swap|Slice|Install, directives: 1..128 objects {name: T(64), value: T0(4096)}}`. Directive names match `[A-Za-z][A-Za-z0-9]*`; values are single-line and cannot end with backslash. Section names are unique; directive order and duplicates are preserved because repeated directives and empty resets have meaning. Agent renders section headers, `name=value` lines and `90-ricevanta-<item id>-<name>.conf`. No raw unit body or caller-chosen output path. Native compiler must check directives against the unit type. Commands in directive values remain executable configuration, hence protection [S8, S9].

`HTTPS` is T(2048), absolute lowercase `https://` with ASCII DNS host or canonical IPv4, optional port 1..65535, and optional path/query; no userinfo, fragment, whitespace, backslash or percent encoding in the authority. DNS names are lowercase labels of 1..63 letters/digits/internal hyphens, at most 253 bytes total, without a trailing dot; IPv4 uses four decimal octets 0..255 without leading zeroes. Hosts containing only digits and dots must be canonical IPv4. Ports have no leading zeroes. In path/query each percent escape has exactly two hex digits; forbid encoded slash, backslash, percent and control bytes in paths, and refuse dot segments after one percent-decode. Empty path is allowed. It is an input constraint, not an SSRF defense: the later fetcher enforces origin allowlists, DNS/IP checks on every redirect and private-address policy. `Fingerprint` is exactly 40 or 64 uppercase hex characters. Keys refer to uploaded immutable key bytes, never secret key material.

A raw file can still alter authentication or execute code despite nonexecutable mode. The native writer must resolve links, aliases and existing ownership, reject special files and collisions with dedicated kinds, and use an approved create/replace/remove transaction. These are runtime gates; lexical acceptance cannot bypass them. Full Linux support still requires qualified native execution on each eligible distribution.

### 3.3 All-platform kinds

| Kind | Required settings and optional fields |
|---|---|
| `software` | `package: Name`, `ensure: present\|absent\|latest`, `removeOnUnassign?: B` default false. No caller-supplied URL, version override or install arguments. |
| `check.query` | `query: T(4096)` multiline SQL, `expect: T(4096)` CEL. Structural validation checks strings only; read-only SQL/table/function and CEL checks remain required under [rule adapters section 8](rule-adapters.md#8-osquery-packs-osquery). |
| `check.collector` | `ref: T(256)` matching `ext/<extension id>/<component>`; extension id uses `[a-z0-9][a-z0-9.-]*`, component `[a-z0-9][a-z0-9_-]*`; `expect: T(4096)` CEL. Optional `input: nativeJSON object`. No inline module, capability, grant or path. Resolution must require a currently enabled collector and validate input against its manifest schema and disclosure grant. |
| `os_update` | `platform: macos\|windows\|linux`, `maintenance`, `reboot`, and platform settings below. platform must equal baseline os. |
| `encryption` | `platform: macos\|windows\|linux`, `enabled: true`, `escrow: true`; on Linux also `existingLuks2Root: true`, `tpm2: true`. Other platforms forbid those Linux fields. No recovery key, route deletion, unlock, decryption or rotation command. |

`maintenance` requires `timezone: T(128)` and `slots`: 1..14 objects `{days: set 1..7 of mon|tue|wed|thu|fri|sat|sun, start: HH:MM, durationMinutes: I(1,1440)}`. HH is 00..23 and MM 00..59. Timezone is `device`, `UTC` or a slash-separated ASCII IANA-shaped name with segments `[A-Za-z0-9_+-]+`, no dot segments. Syntax does not prove a zone exists; the native planner verifies it against the endpoint database. Overlapping slots form a union; midnight wrap is allowed. Clock gaps/folds and scheduling belong to that planner.

`reboot` requires `notify: duration`, `maxDeferrals: I(0,100)`, `deadline: duration`; deadline must be positive and notify must not exceed deadline. These are relative periods, not timestamps. Native scheduling maps them to [MDM design section 6](../design/mdm.md#6-os-update-management).

| os_update platform | Additional fields, all required except marked optional |
|---|---|
| macos | `targetVersion: Version\|latest`, `targetBuild?: Version`, `deferrals: {majorDays: I(0,90), minorDays: I(0,90), systemDays: I(0,90)}`, `automaticDownload: B`, `automaticInstall: B`, `notifications: B`. targetBuild requires targetVersion other than latest. |
| windows | `productVersion: Version`, `targetRelease: Version\|latest`, `qualityDeferralDays: I(0,30)`, `featureDeferralDays: I(0,365)`, `qualityDeadlineDays: I(0,30)`, `featureDeadlineDays: I(0,30)`, `graceDays: I(0,7)`, `activeHours: {start: I(0,23), end: I(0,23)}` with unequal values. |
| linux | `class: security\|all`, `includeFlatpak: B`. No arbitrary package-manager flags or timers. |

The numeric windows and deferral bounds are Ricevanta authoring limits, not assertions that every native release accepts every value. Verify each mapping in native-adapter qualification. Encryption accepts desired state only; the escrow, lock and retirement blockers in the owning designs remain in force.

## 4. SoftwarePackage

`spec` requires `os`, `format`, `name: T(256)`, `version: Version`, `source`, `signature`, `detection`, `allowedGroups: Groups`, `installArgs: Args`, `uninstallArgs: Args`, `reboot`, `interaction`. Optional `retrySafe: B` defaults false and is allowed only for exe. Version cannot be `latest`; the software item's latest choice resolves to an immutable approved package before deployment. Repository metadata and name are not approval identities.

`source` is exactly one of `{type: blob, blobKey: T(1024), sha256: Hash, size: I(1,9007199254740991)}` or `{type: repository, manager: apt|dnf|zypper|flatpak|homebrew|winget, ref: Name, package: T(256)}`. Blob keys are relative slash-separated `[A-Za-z0-9_.-]+` segments without dot segments, repeated/leading/trailing slash. They are opaque store identifiers, never paths to open on the server. Repository ref resolves to an approved repository configuration; package identifiers have no whitespace and cannot begin with hyphen. Hash and size describe blob bytes, not repository metadata.

| OS | Format | Source | Signature type unless explicit none | Detection type |
|---|---|---|---|---|
| macos | pkg | blob | developer-id | bundle |
| macos | homebrew-formula, homebrew-cask | repository/homebrew | checksum | package, bundle respectively |
| windows | msi | blob | authenticode | msi |
| windows | msix | blob | msix | msix |
| windows | exe | blob | authenticode | uninstall |
| windows | winget | repository/winget | authenticode or msix | uninstall or msix respectively |
| linux | deb | blob or repository/apt | none for blob; openpgp for repository | package |
| linux | rpm | blob or repository/dnf or repository/zypper | openpgp | package |
| linux | flatpak | repository/flatpak | openpgp | package |

`signature` variants are closed: `{type: developer-id, teamId: [A-Z0-9]{10}}`, `{type: authenticode, subject: T(1024)}`, `{type: msix, publisher: T(1024)}`, `{type: openpgp, fingerprints: set 1..16 Fingerprint}`, `{type: checksum, sha256: Hash}`, or `{type: none, reason: T(1024), allowUnsigned: true}`. None is an explicit exception requiring protected approval on every format; it never disables an OS-mandated signature check. No exception permits hash substitution. Blob deb must explicitly use none. Checksum pins Homebrew artifact bytes; it does not assert publisher identity. The later resolver freezes repository artifacts and integrity inputs before approval.

`detection` variants: `{type: bundle, identifier: T(255), version: Version}` with the Apple identifier grammar; `{type: msi, productCode: GUID}` where GUID is uppercase hex `8-4-4-4-12` within braces; `{type: msix, family: T(255), version: Version}`; `{type: uninstall, hive: HKLM, view: 32|64, key: T(256), version: Version}` where key is one printable ASCII segment without slash/backslash; `{type: package, name: T(256), version: Version}`. Version, when present, must equal spec.version; package detection name must equal source.package for repository sources, otherwise spec.name. No regex, script or CEL detection variant. `family` and package name forbid whitespace and leading hyphen.

`reboot` is `{mode: none|required}` or `{mode: exit-code, codes: 1..32 objects {code: I(0,4294967295), reboot: B}}`. Codes are unique; mapping does not declare installer success. `interaction` is `{mode: silent}` or `{mode: defer-while-running, processes: set 1..64 T(256)}`; process names are basenames without slash/backslash or controls. Deferral counts and deadlines come from the applying update/reboot policy, not an implicit infinite wait. Native installation and success-code semantics remain owned by the software executor slice.

## 5. DeviceGroup

`spec` has only `members?: set 1..20000 Names` and `selector?:` closed object with `matchLabels?: map 1..16 T0(63)`, `matchExpressions?: 1..16 expressions`, `os?:` closed nonempty map of macos/windows/linux to T0(16). Require members or selector. Empty group means a valid selector matching no devices; `{}` and empty arrays do not mean all devices. Selector is nonempty and every label key is T(63) without controls.

An expression is `{key: T(63), operator: In|NotIn|Exists|DoesNotExist, values?: set 1..64 T0(63)}`. In/NotIn require values; Exists/DoesNotExist forbid values. Label strings use exact case-sensitive equality. In requires the key and membership in values. NotIn requires the key and absence from values; DoesNotExist expresses absent keys. Duplicate expression objects are refused. OS map keys are OR; a value is the minimum version, empty means any version. Version ordering belongs to the platform resolver, not lexical comparison.

Static members and selector matches are unioned; all populated selector fields and expressions are ANDed. Static members need not meet the selector. No nested groups, CEL, inventory expressions, uid, include/exclude or group references. Device names resolve within the organization at compilation. Membership changes, whether manual or derived, still pass the approval and weakening checks in Baseline section 5 and policy-envelope section 2.3. Schema validity cannot make a group an authorization grant.

## 6. Exact Go API

Package `github.com/ricevanta/ricevanta/server/internal/mdm/resourcevalidate`:

```go
package resourcevalidate

type Result struct {
    Kind string
    Name string
    RequiresContentApproval bool
    ApplyItemIDs []string
}

type Error struct {
    Path string
    Rule string
    Cause error
}

func Validate(resource map[string]any) (Result, error)
func (e *Error) Error() string
func (e *Error) Unwrap() error

var (
    ErrInput = errors.New("mdm resource input")
    ErrLimit = errors.New("mdm resource limit")
    ErrEnvelope = errors.New("mdm resource envelope")
    ErrSchema = errors.New("mdm resource schema")
    ErrSemantic = errors.New("mdm resource semantic")
)
```

Result is zero on error. On success Kind and Name copy the root fields; ApplyItemIDs holds apply-capable ids in input order. RequiresContentApproval is true for SoftwarePackage and apply-capable Baseline, false otherwise. False requires the caller to evaluate weakening diffs, not skip authorization. Nil ApplyItemIDs represents no apply items. Errors support errors.Is through Unwrap and errors.As to *Error. Error() is `mdm validation <rule> at <path>` and never includes input values, native content, queries, arguments or secrets. Root path is empty; other paths use RFC 6901 escaping.

Validate accepts only the ordinary decoded JSON tree: map[string]any, []any, string, bool, nil and finite float64. JSON integers are float64 values with zero fractional part; bound all numbers to absolute value at most 9007199254740991. A nil root map fails the envelope check; nested nil maps and nil slices are ErrInput because decoded JSON null is nil, not a typed container. No structs, pointers, typed slices, json.Number, native int or custom marshalers. Callers using Decoder.UseNumber must convert with exact range checks before entry. Native vendor integers beyond this range need a reviewed representation; qword already uses decimal text. No input mutation, default insertion, sorting, hashing, reference lookup or retained map/slice aliases. Callers must not mutate the tree concurrently. Calls on independent inputs are concurrency-safe.

Defaults in section 3 affect interpretation only. The later canonical revision compiler must materialize those same defaults and immutable bindings before RFC 8785 hashing under Baseline section 5; Validate returns no approved or compiled bytes. Go's decoder can accept duplicate keys and replace malformed UTF-8 [S3]; a future raw decoder must reject those before constructing this tree. This package cannot recover discarded duplicate keys.

## 7. Validation order and resource bounds

Apply stages in order; stop at the first failing stage. Within a stage, inspect objects by byte-lexicographic key order and arrays by numeric index. For structural errors compare locations as sequences of string keys/numeric indices, parent before child; compare string keys by UTF-8 bytes and indices numerically; at one location check required fields (missing keys sorted), forbidden fields, type, enum/const, range/length, pattern, then branch constraints. Select nativeJSON branches by JSON type. Select tagged branches by kind, platform, type, format or mode before comparing child errors; an invalid discriminator reports its field and suppresses speculative errors from unmatched branches. A missing field reports its intended child path; a forbidden field reports its own path. The Go sentinel is stable; library diagnostic text is not.

1. Input scan: unsupported Go type, invalid scalar text, nonfinite or out-of-range number gives ErrInput, rule `input`. Traverse depth first; stop before descending beyond 32 container levels (root is level 1), counting over 100000 values plus object keys, or cumulative raw UTF-8 string/key bytes over 2097152: ErrLimit, rule `budget`. These preflight failures follow traversal order, even if a later branch has invalid input. Bounded traversal also stops cyclic maps/slices; no panic or custom method call.
2. Size accounting after that scan: charge null 4, booleans 4/5, each number 24, each string its quotes plus UTF-8 bytes with quote/backslash charged 2 and each control U+0000..001F charged 6, arrays/objects their brackets, commas and colons. Object keys count as strings. Refuse a whole resource charge over 1048576, then each Baseline settings charge over 65536 in item order: ErrLimit, rule `bytes`. This conservative JSON budget avoids serialization differences; it is not a revision hash. The later compiler separately enforces the 1 MiB actual compiled Baseline cap.
3. Envelope: require exactly the four root fields, recognized apiVersion/kind and valid metadata. Errors use ErrEnvelope, rule `envelope`; malformed spec contents wait for stage 4. Root missing/nonobject spec is an envelope error. Wrong apiVersion and kind report their own paths; an unknown root property reports that property, never the empty root path.
4. Structural validation: types, required/forbidden fields, enum/const, count and string limits, patterns, disjoint variants, platform restrictions and conditional fields from sections 2..5. Errors use ErrSchema, rule `schema`. Whole-string pattern matching must reject trailing LF. Native JSON is bounded and typed as section 2 specifies.
5. Semantic validation in this fixed order: duplicate item ids or named entries (`unique`); duration conversion and critical/reboot comparisons (`duration`); path/URI rules and registry exclusions (`target`); canonical base64 and qword range (`encoding`); cross-field equality and relations (`relation`). All use ErrSemantic. At each rule choose the first location under the same ordering. Return the offending duplicate's second location, not the first entry.

Schema expresses every local structural constraint, including set uniqueness via uniqueItems. Semantic-only rules are duplicate ids/payload identifiers/section names/exit codes, aggregate budgets, duration seconds/comparisons, decoded URI/path segment exclusions, registry exclusions, base64 canonical bytes, qword numeric bound and field-to-field relations. Relation errors report `settings/platform`, service `settings/state`, macOS update `settings/targetBuild`, Windows update `settings/activeHours/end`, or package `spec/detection/name` and `spec/detection/version`, beneath the corresponding resource/item path. Document those gaps in each affected schema's description. Python runs both structural and semantic validation for MDM; generic Draft202012Validator success alone is not full acceptance. No format keyword silently stands in for these rules.

## 8. Fixtures, drift and vectors

Keep the existing Policy/Exception fixtures and their expected-errors.json entries unchanged. Add MDM failures to that index under `mdm/invalid/<name>.json`, using the existing field-array format; the MDM manifest additionally records full error sentinels and rules. The new manifest is an array of closed records `{file, structural, accepted, sentinel, path, rule}`. file is `valid/<name>.json` or `invalid/<name>.json`; structural and accepted are booleans; success uses empty sentinel/path/rule, failure uses the exact sentinel name and Go path/rule. Load manifest and fixture JSON with duplicate-key and nonfinite-number rejection before validation. Every fixture appears once; directory placement must equal accepted. Unknown/missing/extra files, malformed entries or duplicate names fail. file permits only the named directory and a lowercase ASCII basename matching `mdm-[a-z0-9-]+[.]json`; no path traversal or symlinks. Structural records mean pure JSON Schema result on a valid JSON tree; budget-only defects can be structural true.

`validate.py` adds `validate_mdm(document) -> list[dict]`, returning zero or one `{sentinel,path,rule}` record, under sections 6..7. Keep schema validation as an independent structural check. Load exactly the manifest of 23 schema paths (21 new plus Policy and Exception); reject extra schema files in this subtree. Register common and per-kind schemas recursively but dispatch only the five resources Policy, Exception, Baseline, SoftwarePackage and DeviceGroup. Require every expected schema by explicit filename, id, title and annotation. Check all `$ref` targets and fragment existence at startup; reject missing, duplicate-id or off-tree references before fixtures. Reject reference cycles except the explicit nativeJSON self-reference, which the instance budget bounds. Flatten schema error contexts for diagnostics; MDM error precedence comes from the ordered contract, not the first oneOf error.

Validate YAML resource fences from policy-envelope.md and this document. This document supplies the MDM authoring examples for the published contract. Require at least one example per dispatch kind across those files. Report unknown kinds and missing discriminator fields with the existing diagnostics. YAML loading must reject duplicate keys, nonstring map keys, aliases and nonfinite numbers; do not change existing Policy/Exception schema semantics.

Go TestFixtureDrift loads the manifest and every fixture by a path anchored from runtime.Caller, not the working directory. It asserts acceptance, errors.Is, errors.As fields, zero result on failure and classifications on success. It does not shell out or fetch schema files. Python separately asserts the same expectations and pure schema results. Both checks must pass in the same review. Generated boundary tests in both languages cover caps too large for small checked-in files; no fixture is accepted solely because both implementations agree.

Required fixture families (names are lower-kebab-case, prefixed `mdm-`):

- One minimum and one populated Baseline for every per-kind branch; all common kinds on all three OSes; both CSP authorities and Device/User namespaces; every CSP/registry value type; each PAM branch, systemd state/drop-in/both, repository manager, update platform, zero/default/explicit grace and optional references.
- User CSP fixtures cover all five formats, including `chr` at `./User/Vendor/MSFT/Policy/Config/ADMX_Desktop/Wallpaper` [S10]. Both namespaces reject first-suffix `.` and `..` segments; malformed User scope, empty segments, percent escapes, queries and fragments fail. Version fixtures reject each excluded range endpoint, including U+0085 and U+FEFF, and accept adjacent allowed scalars plus a four-byte scalar. Generated tests check every excluded scalar and each shared Version field.
- Every SoftwarePackage table row/source/signature/detection combination, explicit none, retrySafe exe, both interaction modes and all reboot modes; cross-product mismatches, unsigned without reason/true, source union overlap, bad hash/size, detection mismatch and latest resource version must fail.
- Static, selector and union groups; every expression operator; multiple OS keys; absent/empty selector fields, duplicates and operator/value mismatch fail. Group fixture validation does not claim to execute membership.
- Remove each required field and add one unknown field at every closed object; null/wrong scalar type; unknown kind/OS; wrong OS/kind pairing; protected=false injection; missing apply allowedGroups; forbidden check-only allowedGroups; metadata/status injection; trailing LF on names, hashes and references.
- Invalid executable modes `0755`, `04755`, numeric 420; raw unit replacement; directive newline/backslash continuation; registry Policies aliases, WOW6432Node, slash and case variants; `../`, encoded traversal, file symlink discriminator, PAM arbitrary stack, repository disable-verification flag; no input gains an unprotected classification.

Exact semantic and precedence vectors:

| Mutation from an otherwise valid resource | Expected |
|---|---|
| Item id repeated at index 1, even with different settings | ErrSemantic, unique, `/spec/items/1/id` |
| Critical item grace `1s`; explicit integer 0 | ErrSemantic duration; accept respectively |
| Grace `720h`; `721h` | Accept; ErrSemantic duration |
| qword `18446744073709551615`; `18446744073709551616` | Accept; ErrSemantic encoding |
| CSP b64 `YQ==`; `YR==`; `YQ`; `YQ==\n` | Accept; ErrSemantic encoding for pad bits; ErrSchema for the last two |
| Baseline settings charge 65536; 65537 | Accept if otherwise valid; ErrLimit bytes at that settings path |
| Resource charge 1048576; 1048577 | Accept if otherwise valid; ErrLimit bytes at root |
| Whole charge too large plus unknown kind | ErrLimit bytes, root |
| Wrong apiVersion plus wrong settings type | ErrEnvelope envelope, `/apiVersion` |
| Duplicate item id plus unknown settings field | ErrSchema schema, unknown field path |
| Duplicate item id plus forbidden registry path | ErrSemantic unique, duplicate id path |
| Windows activeHours start equals end plus invalid base64 in another item | ErrSemantic encoding before relation |

Test lengths 0, 1, cap, cap+1; item counts 0, 1, 2000, 2001; one ASCII, four-byte scalar and escaped-control settings budgets; integer limits, fractional floats, negative zero, bool-as-integer confusion, NaN, infinities, unsupported types and cycles. Two independent scripts must recompute generated boundary charges and vector results before review. Number charge is always 24: `{}` charges 2, `{"a":0}` charges 30, `{"x":"é"}` charges 10, and `{"x":"\n"}` charges 14. These are budget vectors, not canonical serialized byte lengths.

FuzzValidate consumes bytes decoded by encoding/json into map[string]any and checks no panic, no mutation, repeatable result/error fields, zero result on failure and no false protected classification for accepted apply kinds. Malformed raw JSON is a decoder seed, not a promised decoder contract. FuzzBudget constructs nested trees from bytes, including cycles and unsupported values through explicit selector bytes; assert bounded return, ErrInput/ErrLimit precedence and exact charges against a simple independent test oracle. Bound each run to 5 seconds and parallelism 2 [S4].


### 8.1 Authoring examples

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Baseline
metadata: {name: linux-settings}
spec:
  os: linux
  allowedGroups: [managed-linux]
  items:
    - id: forwarding
      kind: linux.sysctl
      required: true
      severity: high
      settings: {key: net.ipv4.ip_forward, value: "0"}
```

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: SoftwarePackage
metadata: {name: example-package}
spec:
  os: linux
  format: deb
  name: example-package
  version: "1.0"
  source:
    type: blob
    blobKey: packages/example.deb
    sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    size: 1
  signature: {type: none, reason: Internal unsigned package, allowUnsigned: true}
  detection: {type: package, name: example-package, version: "1.0"}
  allowedGroups: [managed-linux]
  installArgs: []
  uninstallArgs: []
  reboot: {mode: none}
  interaction: {mode: silent}
```

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: DeviceGroup
metadata: {name: managed-linux}
spec:
  selector:
    matchLabels: {managed: "true"}
    os: {linux: ""}
```

## 9. Security trace and review focus

The trust path is authoring bytes -> strict decoder -> schema plus semantic checks -> native/CEL/SQL and reference compilation -> protected diff and committed approval -> signed revision and assignment -> verified native/agent application -> separately verified evidence. This slice implements only the middle input checks and classification. Rejecting malformed values or classifying an item is never an approval receipt.

| Attacker | What the attacker gets and where this slice stops |
|---|---|
| Stolen enrollment token | Can attempt enrollment within the token's existing restrictions; cannot turn a validated Baseline into publication authority. Enrollment redemption and device binding remain elsewhere. |
| Compromised agent host | Can submit lies about local state and inventory, and violate local enforcement. Valid groups or settings do not authenticate those claims; signed evidence and inventory-driven expansion checks remain required. |
| Compromised console session | Can submit valid polkit, systemd, file or installer bytes within its request rights. Derived classification prevents author flags from suppressing approval; exact content, target and weakening checks remain the publisher's responsibility. |
| Rogue extension publisher | Can package syntactically valid checks or apply items, not confer a collector grant or group scope. Extension trust, disclosure and native validation remain mandatory; check-only required-set weakening still needs approval. |
| Network position between agent and server | Can delay/drop traffic; schema shape proves neither integrity nor freshness. Existing TLS, signatures, immutable hashes and assignment checks bind delivered resources. |
| Database writer without signing keys | Can replace stored resource rows and group names. Validation accepts well-formed replacements but grants no authority; publishers must reload approved immutable revisions and frozen targets from committed authority before signing. |
| Server restored from backup | Can expose stale valid resources and groups. Schema acceptance does not reset counters, reopen consumed approvals or award fresh grace. BE-12 keeps publication sealed until journal reconciliation and an authorized epoch transition. |

Review focus: no unknown kind or field becomes an escape hatch; no cross-platform payload reaches a different native channel; no privileged config is classified check-only; no optional unsigned flag bypasses a mandatory OS check; no group union or dynamic membership becomes approval; no defaults or mutable references enter an approved digest without compiler normalization; no pure schema success is reported as executable or evidence validity.

Benefits: one explicit authoring contract and review corpus for API, GitOps and compiler callers; protected configuration is visible in machine-readable schemas. Trade-offs: two validator implementations and deliberately opaque vendor payloads need maintained drift and native-catalogue gates. Dependencies: the existing envelope metadata and design validators, plus later native/reference/CEL/SQL compilers and authority checks. Limits: no endpoint behavior, ownership, signature trust or recovery guarantee follows from passing these tests.

Alternatives: a generic Go schema engine loses the dependency trade-off in section 1; free-form settings lose type and platform boundaries; an author-controlled protected flag cannot enforce classification; intersection of members and selector makes static membership unexpectedly conditional and is rejected in favor of union. Duration, update bounds and schema-only native payloads are explicit choices, not inferred vendor promises.

## 10. Unresolved questions

- Should future scale evidence require groups larger than 20000 members? This slice chooses the fleet-sized cap and rejects unbounded arrays.
- Should a later slice replace hand-written validation with a pinned Go JSON Schema engine? This slice chooses standard-library code and mandatory drift checks.
- Which immutable native catalogues and qualified adapters admit each Apple payload, CSP URI, systemd directive and update value? This slice chooses bounded native data plus a blocking compiler check, rejecting schema success as execution permission; verify those mappings before native implementation.
- Which group matching behavior should the product expose for missing labels? This slice chooses NotIn requiring existence and static/selector union; implicit absent-key matches and intersection are rejected.

## Sources

- [S1: JSON Schema 2020-12 Core](https://json-schema.org/draft/2020-12/json-schema-core): references and annotations.
- [S2: JSON Schema 2020-12 Validation](https://json-schema.org/draft/2020-12/json-schema-validation): type, uniqueItems and default vocabulary.
- [S3: Go encoding/json](https://pkg.go.dev/encoding/json) and [errors](https://pkg.go.dev/errors): decoded values, duplicate-key/UTF-8 caveats and errors.Is/errors.As.
- [S4: Go testing fuzzing](https://pkg.go.dev/testing#hdr-Fuzzing): fuzz targets and corpus execution.
- [S5: Apple device-management schemas](https://github.com/apple/device-management) and [S6: Microsoft CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/): native catalogue ownership; verify per-setting qualification.
- [S10: Microsoft ADMX Desktop Wallpaper](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-desktop#wallpaper): User namespace and `chr` format.
- [S7: polkit authorization rules](https://polkit.pages.freedesktop.org/polkit/polkit.8.html): executable JavaScript and privilege decisions.
- [S8: systemd unit source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml) and [S9: service source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml): structured drop-ins and executable service directives.
