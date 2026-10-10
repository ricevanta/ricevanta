# ExportDestination schema and decoded validation

The authoring schema in `schemas/export/v1alpha1/export-destination.json` defines typed configuration for all ten adapters in [event export](event-export.md). The Go validator specified here checks decoded resources without resolving secrets, compiling CEL, contacting a destination or authorizing a change. Decision: EV-10. Implementation tasks: [the plan](../plans/export-destination-schema.md).

## 1. Scope and authorities

[The policy envelope](policy-envelope.md) sections 1 and 8 own the resource envelope and GitOps workflow. [Event export](event-export.md) sections 2 to 12 own adapter protocols. [The events design](../design/events.md) section 4 owns filtering, repeats, export logs, delivery and replay. This document owns configuration spelling, bounds and validation. The schema owns each field's structural constraint; this document defines its meaning and the Go validation stages.

Artifacts in this slice are the schema, `fixtures.schema.json`, `fixtures.json`, this spec and its plan. The Python runner, design CI step and Go package are implementation deliverables. No delivery or API admission implementation belongs to this slice.

Later slices must define the S3 immutable export plan, destination configuration revision, replay namespace, staged payload, manifest and verification receipt schemas, with mismatch and crash-recovery fixtures. They must bind resolved secret revisions as well as the approved configuration. The authority journal, protected configuration publication, secret-resolution contract, connector registration and CEL compiler remain separate gates. A valid resource does not close any of those gates.

Later schema paths under `schemas/export/v1alpha1/` are `s3-export-plan.json`, `destination-revision.json`, `s3-replay-namespace.json`, `s3-staged-payload.json`, `s3-manifest.json` and `s3-verification-receipt.json`. These are handoff names, not implemented contracts. Delivery, S3 registration qualification and crash recovery remain separate implementation slices.

The scope keeps every blueprint destination required for v1.0.0. Portable validation does not establish macOS ARM64, Windows x64 or Linux x64 delivery support.

## 2. Resource and defaults

The resource has exactly `apiVersion`, `kind`, `metadata` and `spec`. The constants are `ricevanta.io/v1alpha1` and `ExportDestination`. `status`, server-assigned uid, revision, approval, replay and receipt fields are not author input. A future read API keeps those in its response envelope and submits only the authoring resource for validation.

All objects are closed except the bounded metadata maps and OTLP header-reference map. Field names are case sensitive. Unknown properties, explicit nulls, wrong JSON types and duplicate array elements fail. Optional means omitted, never null. `metadata.name` and references use the same 1 to 63 character lowercase label grammar. Labels, annotations and description follow the schema's explicit size and key limits. Metadata is descriptive and must never contain a secret value.

Exactly one adapter block is required, named by `spec.type`: `elasticsearch`, `opensearch`, `splunk_hec`, `syslog`, `otlp`, `loki`, `sentinel`, `kafka`, `s3` or `connector`. Unknown blocks and multiple blocks fail even when `enabled` is false. Disabled resources receive every validation check.

Validation does not insert defaults, rewrite strings, sort arrays or change the input. Omitted fields have the effective values below. A future approved-configuration compiler materializes these values before hashing a configuration revision; it must not let binaries choose different defaults for frozen work. JSON Schema `default` is annotation, not a mutation contract ([validation vocabulary](https://json-schema.org/draft/2020-12/json-schema-validation)).

| Common field | Effective default and meaning |
|---|---|
| `enabled` | `true`; destination lifecycle stays protected under BE-02 |
| `filter.classes` | `[]`, every class in the export profile |
| `filter.deviceGroups` | `[]`, every group; nonempty values name groups in the current organization |
| `filter.origins` | `[agent, server, extension]`; an empty list fails |
| `filter.minSeverity` | `informational`; captions are `unknown`, `informational`, `low`, `medium`, `high`, `critical`, `fatal`, `other` |
| `filter.condition` | Empty string, no CEL predicate; at most 4096 Unicode characters |
| `projection.drop` | `[]`, no removed fields |
| `repeats` | `first_and_summary`; `all` is the only alternative |
| `audit`, `archive` | `false`; only S3 accepts `archive: true` |
| `batch.maxEvents` | 1000; integer 1 through 10000 |
| `batch.maxBytes` | Per-adapter table below; integer 1024 through 67108864; Sentinel has a tighter maximum |
| `batch.maxDelay` | `5s`, except S3 `300s`; integral seconds `1s` through `300s` |
| `inflight` | 2; integer 1 through 16 |
| `tls` | System certificate roots, no pin, no client certificate and endpoint host as server name |

Default `batch.maxBytes`: Elasticsearch and OpenSearch 5000000; OTLP 4000000; S3 67108864; all others 1000000. These are Ricevanta configuration defaults, not claims about provider quotas. `batch.maxBytes` bounds encoded batch preparation; adapter envelope and compression limits still apply at delivery. S3 flushes only at whole export-log objects as required by its protocol. A delivery implementation must specify oversize-source handling and staging budgets, not infer that the configuration proves a process memory cap. At the largest settings, `inflight × maxBytes` is 1073741824 bytes before other overhead.

The schema permits `audit: true` on every adapter because the event-export contract does. The audit-export slice must define how each adapter carries records, checkpoints and exact evidence without ordinary projection invalidating verification. This schema defines no audit wire encoding and does not certify an immutable audit anchor. S3 archive selection ignores the filter but uses the projection, as [events section 5](../design/events.md#5-retention-holds-and-archive) requires.

A complete resource, with omitted fields taking the stated effective defaults:

```json
{
  "apiVersion": "ricevanta.io/v1alpha1",
  "kind": "ExportDestination",
  "metadata": {"name": "soc-splunk"},
  "spec": {
    "type": "splunk_hec",
    "endpoint": "https://splunk.example.com:8088",
    "credentialRef": "soc-splunk-token",
    "filter": {"classes": ["detection_finding", "data_security_finding", "authentication"]},
    "projection": {"drop": ["unmapped"]},
    "repeats": "first_and_summary",
    "splunk_hec": {"mode": "event", "sourcetype": "ricevanta:ocsf", "index": "security", "requireAck": true}
  }
}
```

## 3. Selection and projection

`$defs.class` is the finite class-name list drawn from [the OCSF profile](ocsf-profile.md) sections 1 and 2, including `ricevanta/policy_activity`. Extension names retain their prefix, for example `ricevanta/lineage_activity` and `win/registry_key_activity`. Spool classes such as `raw` and deprecated names are not event class names. The literal `event_log_actvity` follows the profile spelling. Updating the profile requires updating this enum and its all-classes fixture; CI checks that relationship.

An empty `classes` list selects all profile classes, including classes added in a compatible resource revision. It does not admit an unregistered extension class. A nonempty list selects exactly those names. Arrays are sets for matching but preserve author order. Each list is unique and bounded by the schema. A nonempty device-group selection excludes events without a matching bound device. Group existence and scope are admission checks, not schema checks.

The severity threshold compares OCSF numeric severity values: unknown 0, informational 1, low 2, medium 3, high 4, critical 5, fatal 6 and other 99. This is a filter comparison, not a claim that `other` describes a worse incident than `fatal`. Origin filtering uses server-bound provenance, never an extension's self-assertion. The CEL text is opaque here; passing length validation is not CEL admission. Compilation, event-field declarations, Boolean result type and the profile's cost checks must pass before activation.

`first_and_summary` exports the first occurrence and the agent summary, suppressing records with the server's `repeat_of` marker. `all` exports every stored finding. Neither option reconstructs occurrences already folded on the agent. No count, duration or threshold is part of `repeats`.

Projection paths are lowercase snake-case fields separated by dots, with at most 16 segments and 256 characters. No wildcards, indices, escaping or case folding exists. A missing path is a no-op. Traversal through arrays applies the remaining path to each object element; scalars are unchanged. The final named field is removed from each matched object. Removing a parent removes its subtree. Protect `metadata`, `metadata.uid`, `metadata.version`, `class_uid`, `time` and every descendant of the protected leaf paths. Thus neither dropping `metadata` nor inventing `metadata.uid.value` evades identity preservation. Field existence against compiled OCSF remains a later semantic check; the schema can reject only syntax and protected paths.

## 4. Secrets and transport configuration

A secret reference is a string matching `[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?` over the entire string. It identifies one server-held secret record in the current organization. No provider scheme, path, fragment, query, environment expansion, key selector or inline material is accepted. The resource cannot choose another organization or a historical secret revision.

`credentialRef` identifies a typed record appropriate to the selected authentication mode: API key, basic username/password pair, HEC token, bearer token, AWS credential set, S3 access-key pair, Entra certificate/private-key pair or client secret, SASL username/password pair, or OAuth token-provider configuration. This slice specifies the expected kind, not those secret records' schemas. `tls.caRef` resolves a CA bundle; `tls.clientCertificateRef` resolves a certificate chain and private key. Every OTLP `headers` value is a secret reference, including a header whose resolved value is not confidential. No literal header values are accepted.

Resolution occurs only in `jobs`, after the current organization, resource revision, BE-02 approval, recovery epoch and secret-kind checks succeed. Freeze the selected immutable secret revision in the delivery plan. On missing, denied, revoked, incompatible or unrecoverable material, pause admission or delivery; never use an empty credential, an ambient fallback or the latest revision in an existing plan. A secret rotation is a protected effective credential change and cannot silently broaden a running destination. Workload identity is explicit configuration, not a fallback after secret failure. Its provider qualification remains part of the delivery slice.

Validation performs none of that resolution and logs no input. Syntactic references cannot prove that arbitrary user text is free of copied secrets. Metadata, conditions, identifiers and endpoints must not contain secret values; authorization and safe authoring paths must enforce that operational rule. The closed schema removes credential-value fields and URL credential carriers rather than claiming content-based secret detection.

HTTPS endpoints are origins with an optional proxy base path; adapters append their fixed protocol route. No userinfo, query, fragment, percent escape, backslash, whitespace or scheme-relative form is accepted. Each path segment starts with an ASCII alphanumeric, underscore or hyphen, so `.` and `..` segments fail. A trailing slash is allowed. The host is lowercase ASCII DNS-style labels or bracketed lowercase IPv6 in pure hexadecimal form; embedded IPv4 IPv6 spellings and zone identifiers are excluded. International names require their ASCII form. Ports are 1 through 65535 without leading zeros. HTTPS may omit the port; syslog and Kafka require an explicit port. DNS resolution and reachability are not validated. The 2048-character endpoint limit does not establish a valid DNS wire name.

Syslog uses `tls://host:port` or `udp://host:port` without a path. Kafka lists `host:port` brokers and has no `endpoint`. Connector transport lives in its registration and forbids resource `endpoint`, `tls` and `credentialRef`. All other adapters require HTTPS. OTLP transport defaults to gRPC even though the endpoint uses the HTTPS spelling; the adapter takes host, port and base path from that value.

TLS defaults to system-root verification. `caRef` replaces the root set; `pinSha256` selects an exact lowercase 64-hex SHA-256 end-certificate fingerprint, not an SPKI hash. They are mutually exclusive. A pin selects the pinned-peer trust mode from event-export section 2; delivery must still enforce the configured server name and certificate lifetime. `serverName` overrides the name used for verification and SNI. There is no verification bypass. TLS configuration on UDP fails. Syslog UDP is the sole unencrypted mode and remains lossy. The validator does not establish TLS safety or control DNS rebinding, redirects, environment proxies or server-side request forgery; outbound authorization and connection-time target checks are required in the delivery design.

## 5. Adapter parameter blocks

All fields not marked required are optional. Exact character limits and closed enums live in the schema. Authentication is required wherever listed; omitting it must never choose ambient credentials.

| Block | Required fields | Optional fields and effective defaults |
|---|---|---|
| `elasticsearch` | `auth`: `api_key`, `basic`, `mtls` | `namespace: default` |
| `opensearch` | `auth`: `basic`, `mtls`, `sigv4` | `namespace: default`; `sigv4` additionally requires `region`, `service` (`es` or `aoss`), `credentialSource` (`secret` or `workload`); those fields fail in other modes |
| `splunk_hec` | None; credential always required | `mode: event` (`raw` alternative), `sourcetype: ricevanta:ocsf`, optional `index`, `requireAck: true` |
| `syslog` | `transport`: `tls` or `udp` | `facility: 16`; `maxMessageBytes: 65536` for TLS or 1180 for UDP; TLS permits 480 through 1048576, UDP 480 through 1180 |
| `otlp` | `auth`: `mtls`, `bearer`, `headers` | `transport: grpc` (`http` alternative), `body: map` (`json_string` alternative); `headers` required only for header auth |
| `loki` | `auth`: `basic` or `bearer` | Optional `tenant` supplies `X-Scope-OrgID`: 1 to 128 ASCII characters, an alphanumeric first character, then alphanumerics, `.`, `_` or `-`; colons fail ([Loki restrictions](https://grafana.com/docs/loki/latest/operations/multi-tenancy/#restrictions)); `timestamp: metadata.logged_time` (`time` alternative), `labels: []` adds only `ocsf_category` or `os`, `maxLineBytes: 262144` |
| `sentinel` | `cloud`: `public`, `usgovernment`, `china`; `tenantId`, `clientId`, `dcrImmutableId`; `auth`: `certificate` or `client_secret` | Fixed stream and table from event-export section 9; no override. `batch.maxBytes` cannot exceed 1000000 |
| `kafka` | `brokers` (1 through 16); `auth`: `mtls`, `scram_sha_256`, `scram_sha_512`, `plain`, `oauthbearer` | `topic: ricevanta.ocsf`; one optional final `.{category}` or `.{class}` placeholder; `key: device.uid` (`metadata.uid` alternative); `compression: zstd` (`lz4`, `snappy`, `gzip` alternatives) |
| `s3` | `bucket`, `region`, `auth`: `access_key` or `workload` | `prefix: ""`, `forcePathStyle: false`, `encryption.mode: none`; alternatives `sse_s3`, `sse_kms`; only `sse_kms` requires and allows `kmsKeyId` |
| `connector` | `registrationRef` | `timeout: 30s`; integer seconds 1 through 300 |

`credentialRef` is required for every authentication mode except `mtls`, `workload`, OTLP `headers`, syslog and connector, which forbid it. `mtls` requires `tls.clientCertificateRef`. Other TLS adapters may also present a client certificate alongside their configured credential. Header names are lowercase ASCII and exclude the schema's transport-controlled names and every `grpc-` prefix for both OTLP transports; values are references only. Header auth may use `authorization`, but cannot override host, framing, content encoding or the [reserved gRPC namespace](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md).

S3 prefix segments never start with a dot; leading, trailing and doubled slashes fail. The empty prefix is valid. KMS key identifiers are identifiers, not encryption key material. S3 output format is fixed NDJSON with zstd by event-export section 10. Kafka template expansion must separately enforce the broker's topic constraints at delivery. UDP's 1180-byte cap chooses a conservative profile over larger datagrams; delivery must still avoid fragmentation on the actual path. Provider-specific bucket restrictions, region existence, IAM permissions, endpoint/cloud agreement and certificate validity require qualification, not a schema success.

## 6. Go API and deterministic errors

Use Go 1.27.1 and its standard library in `server/internal/events/exportdest`. No Go JSON Schema dependency is added. Keep module `github.com/ricevanta/ricevanta/server` and its existing `go 1.27.1` directive. The package validates the ordinary decoded JSON tree without first unmarshalling into structs that discard unknown fields.

```go
package exportdest

func Validate(resource any) error

var (
    ErrInput       = errors.New("export destination decoded input")
    ErrLimits      = errors.New("export destination input limits")
    ErrResource    = errors.New("export destination resource envelope")
    ErrAdapter     = errors.New("export destination adapter selection")
    ErrCommon      = errors.New("export destination common fields")
    ErrParameters  = errors.New("export destination adapter parameters")
    ErrCombination = errors.New("export destination field combination")
)
```

Errors are exactly one of these sentinels. Callers use `errors.Is`; wrapping with `%w` in a caller preserves identity. No input value, property name, reference, CEL text or endpoint appears in an error. This intentionally omits field-level error APIs until a reviewed redaction contract exists. The function returns nil on success, never mutates or retains input, performs no I/O, uses no global mutable state and is safe for concurrent calls on separately owned inputs. Callers must not mutate a tree during validation.

Input values use only `map[string]any`, `[]any`, `string`, `bool`, finite `float64` and nil, as returned by `encoding/json.Unmarshal` into `any`. Typed structs, integer Go values, `json.Number`, typed-nil containers and nonfinite floats return `ErrInput`. Strings and keys must be valid UTF-8. Integer schema fields accept integral float64 values, including decoded `1.0` and `1e0`, but never booleans or fractions. All admitted integer bounds are exactly representable in float64. Nil is a decoded JSON null and reaches the relevant structural stage, which rejects it where the schema requires another type.

Before constructing the tree, a future decoder must reject duplicate keys, invalid Unicode, trailing documents and oversized source input. Go's default decoder replaces duplicate keys and malformed Unicode, so this API cannot detect those lost distinctions ([encoding/json](https://pkg.go.dev/encoding/json)). The validator must not be advertised as a byte parser. A future YAML caller must disable aliases and reject duplicate keys and non-JSON values, then supply this tree representation.

Validation order is normative:

1. Bounded preflight: root depth is 0; reject a node at depth 13, more than 8192 nodes or more than 262144 total UTF-8 bytes across all string values and object keys with `ErrLimits`. Count each visited value, including containers and null, as one node. Count shared subtrees on each occurrence. Cycles terminate at the depth bound. At most 8192 entries from any container may be visited; reject a container length above 8192 immediately. A node/depth limit wins before checking that node's type; unsupported types return `ErrInput`. For a string, check its byte length against the remaining budget before scanning UTF-8; excess bytes return `ErrLimits`, otherwise invalid UTF-8 returns `ErrInput`. For a map, check container length first, then sum all key byte lengths against the remaining budget using overflow-safe subtraction, before scanning or sorting keys. Excess key bytes return `ErrLimits`; otherwise any invalid UTF-8 key returns `ErrInput`. Charge those key bytes once, sort the bounded keys, then visit children in key order. Visit arrays by index; stop at the first child defect. Do not stringify unsupported types.
2. `ErrResource`: check root object, its exact keys and constants, required metadata and spec, metadata shape and values. Require spec to be an object but defer its keys. No other stage runs on failure.
3. `ErrAdapter`: reject unknown spec keys, missing or unknown type, a missing selected block or any nonselected block. A present block's wrong value type belongs to step 5.
4. `ErrCommon`: validate present common fields against their base schema, including all filter, TLS and projection constraints. Do not enforce cross-field requirements here. `endpoint` may pass the common HTTPS or syslog grammar before step 6 compares the scheme with the selected adapter.
5. `ErrParameters`: validate the selected block against its `$defs` schema, including its internal conditional rules, header references, numeric limits and required fields.
6. `ErrCombination`: apply every `spec.allOf` rule not covered by step 3: required/forbidden endpoint, exact endpoint scheme, TLS-on-UDP refusal, credential mode and client-certificate requirements, archive restriction and Sentinel's batch-byte cap.

Preflight limits protect decoded work and are not JSON Schema keywords. Each schema-valid resource within those budgets must pass Go validation; the byte admission layer may reject a larger source representation. Preflight bounds permit an at-most-8192-key sort only after key bytes fit the aggregate budget, before structural rejection. A larger valid annotations map can hit the aggregate byte limit; that is an explicit API bound, not a schema/Go drift exception to conceal in tests.

Go mirrors schema predicates with small hand-written field validators, using whole-string matching and explicit numeric checks. JSON Schema patterns end with `(?![\s\S])` to exclude a final newline. [Go regular expressions](https://pkg.go.dev/regexp/syntax) do not support lookahead; implement an equivalent `\z` end anchor and an explicit `grpc-` prefix rejection, never copy the pattern unchanged. Match Unicode string lengths by rune count and preflight bytes by UTF-8 byte length. No schema interpreter or embedded schema is required at runtime.

## 7. Fixtures, boundaries and CI

`fixtures.json` carries version 1 and cases with `id`, `valid`, `resource` and, only for a negative case, `error` naming the exact Go sentinel. `fixtures.schema.json` validates the manifest shape; negative resources deliberately do not validate against the resource schema. IDs must be unique. The fixture runner must load the resource schema by its exact filename, not discover only `*.schema.json` and miss `export-destination.json`.

The shared cases cover each adapter, supported trust and authentication branches, class selection, repeats, projection ancestry, inline credential carriers, newline suffixes, ports, IPv6, bounds and combined defects. `valid-selection` contains the complete class enum. Negative cases pin `ErrResource` before `ErrAdapter`, then `ErrCommon`, `ErrParameters` and `ErrCombination`. Go tests add preflight-only values that JSON fixtures cannot encode: cycles, typed nil, nonfinite floats, invalid UTF-8, unsupported types and precise aggregate-budget edges.

Required generated test vectors extend the checked-in cases without updating expected output from the implementation: every enum member and one unknown; every optional field omitted and null; every required field removed; every numeric or length bound at min minus one, min, max and max plus one; unique-array duplicates; unknown properties at every closed object; every authentication mode's missing and forbidden references. Include reference lengths 0, 1, 63 and 64; a newline after 63 characters; every protected projection leaf, its ancestors and descendants; header case and reserved names; syslog bounds 479, 480, 1180, 1181, 65536 and 1048577; S3 nonempty and empty prefixes; each Kafka compression and both template variables; each Sentinel cloud and both credential kinds.

Go-only precedence tests combine an over-depth tree with bad kind; unsupported type with bad kind; bad kind with bad adapter; bad adapter with a common error; a common error with a parameter error; a parameter error with missing credentials. Node counts 8192/8193, depths 12/13 and aggregate bytes 262144/262145 receive exact expected sentinels. Cycles return `ErrLimits`, not a panic. Add a map with 8192 keys sharing an over-budget common prefix and require rejection before sorting; combine oversized keys with invalid UTF-8 and require `ErrLimits`. Test a bounded invalid key against an unsupported child and require `ErrInput` before child traversal. Numeric vectors include negative zero, 1.0, 1e0, fractions, `math.MaxFloat64`, NaN and infinities. Prove input nonmutation by a deep copy on accepted and rejected cases; prove errors do not contain a synthetic canary placed in every attacker-controlled string and key.

`FuzzValidate` decodes bounded arbitrary JSON into `any`, then calls Validate twice. Assert deterministic error identity, no panic, unchanged input and only declared sentinels. Seed it from every shared case and valid boundary resource. `FuzzDecoded` maps bytes into bounded Go trees and deliberately injects unsupported values, cycles and invalid strings; assert preflight precedence and termination. Timed fuzzing runs in CI for the duration `instructions/testing.md` lists for every target; ordinary test runs execute the seed corpus.

The planned sibling Python runner uses `jsonschema==4.25.1`, the existing design requirement pin. It checks both metaschemas, unique fixture IDs, every resource outcome, an exact all-classes comparison and every complete JSON/YAML ExportDestination example in the two specs. It uses only local references and cannot fetch schemas. Its tests reject a missing file, empty case list, duplicate ID, missing adapter coverage, wrong expectation, missing error name and broken schema reference. Go's `TestFixtureDrift` loads the same manifest and compares accept/reject and `errors.Is` for every case; it does not regenerate expected results. CI runs Python validation before Go tests. No Python error text is made part of the Go API.

## 8. Security boundary and attacker outcomes

The mechanism is closed structural validation plus bounded work and reference-only credential slots. Apply it to an untrusted decoded tree, report only a sentinel, and pass no secret or network authority to the validator. Future admission then compiles CEL, checks referenced objects, approves the effective revision and publishes through BE-12 before `jobs` resolves a secret or sends data. Every unresolved downstream gate remains closed.

| Attacker | Capability within this slice and required boundary |
|---|---|
| Stolen enrollment token | May attempt endpoint enrollment under the enrollment protocol; gains no destination-write or secret-read authority. Schema validation never interprets that token as an export credential |
| Compromised agent host | Can send hostile event content; cannot select the server's export configuration or resolve its references. Ingest must bind event provenance separately; a selected destination can still receive false telemetry |
| Compromised console session | Can propose a schema-valid attacker endpoint or silence export. Validation cannot distinguish intent; BE-02 approval and the exact revision's authorization must precede activation |
| Rogue extension publisher | Can propose content or a connector, but a registration reference grants no capability. Installation, grants and live registration/epoch checks must pass before a connector sees the selected event data |
| Network position between agent and server | Can interfere with traffic; the resource schema supplies no channel authentication. Existing mTLS and signed authority contracts must prevent configuration substitution; delivery separately verifies destination TLS |
| Database writer without signing keys | Can store a valid malicious destination or change a secret reference. Structural validity cannot authorize it; `jobs` must verify current published authority and secret revision before use. BE-12's unresolved gate blocks relying on database validity |
| Server restored from backup | Can contain valid but revoked endpoints, credentials and revisions. The validator still accepts their shape; sealed recovery must reconcile the live authority head and epoch before any export resumes. S3 replay cannot reuse an output namespace by resource name |

No error exposes input, but a valid secret name is still metadata requiring access control in API responses. Transport checks do not imply approval to reach a private or public address. Syntax validation supplies no signature, tenant isolation, anti-replay, retention authorization, checkpoint integrity or delivery guarantee.

## 9. Benefits, trade-offs, dependencies and alternatives

Benefits: one finite contract covers every adapter, refuses accidental plaintext credential fields, and supports offline GitOps checks. The Go package needs no network, database, CEL runtime or third-party library. Shared vectors make both implementations reviewable before delivery exists.

Trade-offs: hand-written validation duplicates schema predicates. Fixture drift tests alone cannot prove equivalence for all resources, so mutation tests and independent adversarial review are required. Strict spellings exclude alternate URI forms, IPv4-embedded IPv6 addresses, arbitrary Kafka templates and large UDP messages. Defaults stay separate from validation, which makes caller duties explicit but requires an approved configuration compiler.

Dependencies: existing JSON Schema draft 2020-12 design tooling and the OCSF/CEL profile documents; Go 1.27.1 standard library. Existing design packages are pinned in `.github/requirements-design.txt`; this slice adds none and needs no licensing row. Installed toolchains are Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0. Rust and Node are not used by this slice.

Alternative: a Go JSON Schema library would reduce duplicated predicates but add a runtime dependency and schema loading behavior for a small closed kind. Choose hand-written validation with cross-language fixtures and bound tests under `instructions/go.md`. Alternative: permissive maps with arbitrary credential objects would make adapters easier to extend but accept misspelled fields and inline secrets. Alternative: validation plus connection testing would conflate syntax with authority and require secret access; keep them separate.

## 10. Review focus and unresolved questions

Review focus:

- Every adapter and documented authentication mode has a typed branch and required reference checks.
- Defaults, null refusal and stage precedence agree between Go and Python, including disabled destinations.
- Parent projection removal and alternate spellings cannot remove protected identity fields.
- Secret-like header and URL carriers fail without echoing input; reference validity never grants authority.
- The schema can pass while CEL, registration, secret resolution, TLS, S3 recovery or authorization remains blocked.
- Budget limits, Unicode lengths, cycles and numeric values cannot panic or bypass validation.

Questions for independent review, with the selected answer in force for this candidate:

- Should the runtime use hand-written checks with fixture drift tests, as selected, or justify a pinned Go JSON Schema dependency?
- Should the strict endpoint spellings and UDP cap stay as selected, or should a separately reviewed URI profile admit IPv4-embedded IPv6, zone identifiers or larger datagrams?
- Should omitted defaults stay an approved-configuration compiler duty, as selected, or should a separate normalization API own them?
- What exact secret-record and revision-publication contracts will authorize runtime resolution without allowing rotation or restore to revive stale authority?
- How will non-S3 adapters carry exact audit evidence under the later audit-export contract?

Sources fetched for new library and standard claims: [JSON Schema validation vocabulary](https://json-schema.org/draft/2020-12/json-schema-validation), [Go encoding/json](https://pkg.go.dev/encoding/json), [Go errors and errors.Is](https://pkg.go.dev/errors), [Go regular expression syntax](https://pkg.go.dev/regexp/syntax), and [JSON Schema core](https://json-schema.org/draft/2020-12/json-schema-core). Adapter protocol claims remain in [event export section 14](event-export.md#14-sources). Provider workload-identity support, actual receiver size limits and the profile's OCSF class spellings against the compiled 1.9.0 schema remain **verify** before delivery; no provider support claim is established by these fixtures.
