# CEL profile

The subset of the Common Expression Language that policy conditions may use, chosen so that `cel-go` on the server and the `cel` crate on the agent parse and evaluate every admitted expression identically. Profile name: `ricevanta-cel-1`. Machine-readable list, with the pinned cel-spec and crate versions: `schemas/cel/ricevanta-cel-1.yaml`. Decision: POL-03, building on SH-02 and POL-01.

## 1. Admitted language

| Area | Admitted | Excluded, and why |
|---|---|---|
| Types | `bool`, `int`, `double`, `string`, `list`, `map` with `string` keys, `null`, `timestamp`, `duration` | `uint` and `bytes`: OCSF events need neither, and mixed-sign arithmetic is a runtime difference to avoid; protobuf messages, wrappers and enums: the data is JSON |
| Literals | Decimal and hex `int`, `double`, quoted and raw strings, lists, maps | `u` suffix; byte strings; triple-quoted strings (fewer parse surfaces) |
| Operators | `! -`, `* / %`, `+ -`, `< <= > >= == !=`, `in` on lists and maps, `&& ||`, `? :`, field access, indexing | Mixed numeric operands: `int` and `double` are never compared or combined without an explicit conversion, since the runtimes differ on cross-type comparison defaults |
| Macros | `has`, `all`, `exists`, `exists_one`, `filter`, `map` with one variable and without the filter argument | The three-argument `map`, two-variable comprehensions, `optional` types and `?.`, `bind`, `block`: the Rust runtime skips most or all of their conformance cases |
| Functions | `size`, `contains`, `startsWith`, `endsWith`, `matches`, `string`, `int`, `double`, `bool`, `timestamp`, `duration`, `getFullYear`, `getMonth`, `getDayOfMonth`, `getDayOfWeek`, `getHours`, `getMinutes`, `getSeconds` in UTC only | Time-zone arguments: local time makes a condition evaluate differently per device; `getMilliseconds`: its conformance case `timestamps::duration_converters::get_milliseconds` is on the Rust runtime's ignored list |
| Whitespace | YAML parsing produces the expression string; the compiler lexes and validates those exact scalar contents without rewriting them. Spaces, tabs and line breaks outside tokens are lexical whitespace; whitespace inside quoted or raw string literals remains data. The Rust runtime ignores the cel-spec `parse::whitespace` and `parse::comments` cases, so the server parses every condition with both runtimes at validation and rejects a condition the two parse differently (`../design/policy.md` section 2.2, POL-05) | Comments inside expressions |

Extension functions enter the profile only when both runtimes pass the corresponding cel-spec file in CI (section 4). Candidates in order: the strings extension (`lowerAscii`, `upperAscii`, `trim`, `replace`, `split`, `join`, `indexOf`, `substring`), then the math extension (`greatest`, `least`). Until admitted, a condition that uses them is rejected at validation.

## 2. Semantics pinned

- Integer overflow, division by zero and remainder by zero are errors, not wraparound.
- Strings compare by Unicode code point; `size` counts code points.
- `matches` patterns use the subset of syntax that Go RE2 and the Rust `regex` crate evaluate identically: literal characters, `.`, explicit character classes and ranges (`[0-9]`, `[A-Za-z0-9_]`, `[ \t\r\n]`) and their negations, anchors `^` and `$`, repetition (`* + ? {n,m}`), alternation, non-capturing groups and the `(?i)` flag. Forbidden: the shorthand classes `\d`, `\D`, `\w`, `\W`, `\s`, `\S` and the boundaries `\b`, `\B`, because the engines assign different sets to them; Unicode classes `\p{...}`; lookaround and backreferences; named groups. Patterns are literals of at most 256 characters with repetition counts at most 1,000 ([Go regexp syntax](https://pkg.go.dev/regexp/syntax)), never built at evaluation time; the agent registers its own `matches` function over a pattern cache filled at bundle install, since the `cel` crate's built-in compiles the pattern on every call. The conformance fixtures include Unicode digits and spaces to prove the two engines agree.
- `now` is a variable injected by the engine with the event time, never a function call.
- OCSF time fields are epoch milliseconds in JSON; the variable environment exposes them as CEL `timestamp` values, with the raw integer available as `<field>_ms`.
- An evaluation error (missing field without `has`, overflow, bad conversion) makes the policy outcome `error`; for enforcement policies `error` takes the declared fail mode and is reported as an event; for detections it suppresses the alert and raises a policy-health event.
- Map keys are strings; `in` on a map tests keys.

## 3. Cost

The server validates every condition with `cel-go`'s checker cost estimate (`checker.Cost`, with its own constants) against a ceiling of 100,000, and runs with a runtime `CostLimit` of ten times the estimate as a guard. The Rust runtime has neither a checker nor a cost limit, so the agent enforces size only: the compiler guarantees at most 4,096 characters, 500 AST nodes and comprehension nesting of 2, and every list a comprehension iterates has a declared maximum length (`schemas/ocsf/limits.yaml`), so the server's estimate bounds the agent's work.

## 4. Conformance in CI

Both runtimes run the cel-spec simple test suite at the pinned spec version for the files `basic`, `comparisons`, `conversions`, `fp_math`, `integer_math`, `lists`, `logic`, `macros`, `string` and `timestamps`, minus the cases the profile file lists as excluded (those exercising `uint`, `bytes`, time zones, `getMilliseconds` and protobuf types). In those files the Rust runtime's ignored list, at its harness's pinned cel-spec v0.25.3, holds 73 cases: 59 in `comparisons::eq_wrapper`, 13 protobuf-message and dynamic-JSON-null cases in `comparisons::eq_literal` and `comparisons::ne_literal`, and `timestamps::duration_converters::get_milliseconds`; `string_ext` and `math_ext` have none. Any failure fails the build. The extension files `string_ext` and `math_ext` run as well; an extension is admitted when both runtimes pass it in full. `fields` and `plumbing` are not run because they rest on protobuf messages (verify); `parse`, `dynamic` and `type_deduction` cover syntax the profile admits but are partly ignored by the Rust runtime, so Ricevanta's own fixture suite below covers that syntax instead. The spec, crate and `cel-go` versions pinned in the profile file are verified at the first CI run; a crate upgrade reruns the suite before the pin moves.

A second suite is Ricevanta's own: every example condition in the specs and every condition in the first-party rule packs is evaluated by both runtimes over the same fixture events, and the outputs are compared byte for byte.

## 5. Variables per domain

The compiler validates each condition against a declared environment and ships `variables.json` in the bundle. [The declaration contract](cel-declarations.md) defines the version tuple, exact JSON type encoding, closed object fields, presence rules and loader; its canonical catalogue and fixtures live in `../../schemas/cel/v1/`. Source-schema and runtime integration gates in that contract remain prerequisites for compiler, editor and agent consumers.

| Variable | Domains | Type |
|---|---|---|
| `event` | edr, dlp, lineage, pki, network | The OCSF event of the trigger class |
| `device` | all | `uid`, `name`, `os`, `labels`, `groups`, `state`, `compliant` (server: stored state is `compliant` or `grace`; agent: the signed compliance statement combined with local results, `baseline.md` section 4.4), `compliance` (`compliant`, `grace`, `noncompliant`, `unknown`), `compliance_time` |
| `user` | all | `uid`, `name`, `groups`, `source` (`certificate`, `device_link`; network only); absent for system context |
| `session` | dlp | `uid`, `user`, `interactive`, `remote` |
| `match` | dlp | Detector results: `classification`, `confidence`, `rules` (list of immutable `{pack, version, pack_digest, rule_key}` identities), `reference`, `count` (distinct values or records of the deciding category), `categories` (list of `{id, confidence, count}`, maximum length in `schemas/ocsf/limits.yaml`), `coverage` (`complete`, `truncated`, `encrypted`, `corrupt`, `unsupported`, `pending_ocr`), `inherited` (source revision identity and content hash when known, absent when no durable sensitivity floor applies), `type_mismatch` (bool) |
| `destination` | dlp | `kind` (`removable`, `cloud_sync`, `browser`, `network`, `clipboard`), `host`, `managed`, `app`, `device` (`vendor_id`, `product_id`, `serial`, `encrypted`) for removable media, `account` (sync client account and tenant) |
| `activity` | dlp | Per-user sliding-window counters of classified transfers: `removable_bytes_1h`, `removable_files_1h`, `uploads_10m`, `upload_bytes_10m`, `blocked_10m` (`../design/dlp.md` section 8) |
| `certificate` | network | String keys `identity`, `kind`, `profile`, `binding` (`exact`, `identity_only`); exact-only string keys `serial`, `fingerprint`, `issuer`, and CEL `timestamp` keys `not_before`, `not_after` |
| `gateway` | network | `name`, `profile`, `labels` |
| `access` | network | `method` (`eap_tls`, `certificate_derived`), `medium` (`vpn`, `wired`, `wireless`), `ssid`, `nas_port_type`, `calling_station`, `tls_version` |
| `state` | mdm | The device's current configuration state for desired-state policies |
| `rows` | mdm (`check.query` and `check.collector` items) | List of maps with string keys, the query or collector result |
| `item` | mdm (exceptions) | `baseline`, `id` of the item an `mdm` exception tests |
| `now` | all | `timestamp` of the event, or of evaluation for `state` |

Network certificate evidence is a map with the declared keys, not a CEL optional type. Name-only requests set `binding = "identity_only"`; the exact-only keys are absent, so `has(certificate.serial)` is false, never a null, empty string or another inventory generation. Exact bindings come from EAP-TLS or a gateway profile qualified to bind this request to the authenticated certificate (`../design/radius.md` sections 3 and 6). The [declaration contract](cel-declarations.md) retains these field types and evidence availability in `variables.json`.

The compiler records generation-evidence needs and proves the path condition for every exact-only field access, including indexes and aliases. An exact-binding guard may prove that a field is unreachable on a name-only route; otherwise publishing or admitting a policy on that route fails. Dynamic access whose evidence need cannot be proved is refused. Gateway creation or a policy-scope change reruns that check against every reachable method. At runtime, missing or ambiguous required evidence rejects with `certificate_binding_unknown` before an accept; another policy cannot bypass the failure. Fixtures cover both renewal generations, name-only and exact routes, guarded and unguarded field access, dynamic keys and runtime evidence loss. Serial and fingerprint formats and the compiler evidence proof remain implementation blockers in `../analysis.md` section 3.

## 6. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: a policy that validates on the server evaluates the same way on every endpoint; conformance is a CI gate, not a promise; the server's cost estimate and the agent's size limits together keep an expression from stalling an authorization callback.

Trade-offs: excluding `uint`, optionals and two-variable comprehensions removes some expressiveness that `cel-go` alone would offer; forbidding `\d` and `\w` makes patterns longer; UTC-only accessors push local-time rules into the MDM design.

Dependencies: cel-spec (Apache-2.0) at the pinned version, `cel-go`, the `cel` crate (POL-01).

Limits: the Rust runtime's ignored-test list is the practical boundary; when it shrinks, the profile can widen, never the reverse within a version.

Alternatives considered: a full CEL environment with per-runtime feature flags (rejected: a condition would pass on one side and fail on the other, which is C8); rewriting `\d` and `\w` to ASCII classes in the compiler instead of forbidding them (not chosen for v1alpha1: a silent rewrite hides the difference from the author; it can be added later as an explicit option); a custom expression language (rejected: CEL has a specification, a conformance suite and two maintained runtimes); Rego or Cedar (rejected: no Rust runtime with a conformance suite for Rego, and Cedar is an authorization language rather than an event predicate language).
