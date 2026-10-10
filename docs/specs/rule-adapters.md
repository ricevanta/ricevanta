# Rule adapters

What each rule adapter accepts, what it produces, what it refuses and how it is tested: the matcher program shared by the event formats, the per-rule report, and one section per source format (Sigma, Falco, YARA and YARA-X, Presidio-style recognizers, Gitleaks-style patterns, osquery packs) plus MITRE ATT&CK as a taxonomy. The adapter framework, the rule-pack lifecycle and evaluation cost are in `../design/policy.md`; the `RulePack` resource is in `policy-envelope.md` section 5; Sigma and Falco logsource and field maps are owned by `ocsf-profile.md` section 5. Decisions: EDR-01, POL-04 to POL-07. Claims marked "verify" rest on a repository file or page that was not fully confirmed.

## 1. Matcher program

Sigma and Falco rules translate into one intermediate form, the matcher program, so the agent runs one evaluator for both (POL-04). Required machine-readable schema: `schemas/policy/v1alpha1/matcher.json`, absent and blocking compiler/evaluator interoperability (`../analysis.md` section 3). A pack's `compiled/matcher.json` holds one entry per translated rule:

| Field | Content |
|---|---|
| `identity` | Resolved immutable `{pack, version, pack_digest, rule_key}`; scope compilation attaches the verified manifest digest to the pack-local template, which carries `rule_key` and no self-hash (`policy-envelope.md` section 6); the key is the Sigma upstream `id` or Falco rule name |
| `source` | Format, file path, upstream id, line |
| `title`, `severity`, `author`, `license`, `mitre`, `status` | Carried from the source; `license` defaults to the pack's record |
| `triggers` | OCSF `<class>.<activity>` list from the logsource map, with the OS set per trigger |
| `predicate` | Boolean tree, below |
| `output` | Finding message template with OCSF field substitutions |
| `cost` | Static cost units (`../design/policy.md` section 9) |
| `prefilter` | Literal set the compiler derived: the rule can match only events containing one of these literals in the named fields |

Predicate nodes are `and`, `or`, `not` and leaf tests over one OCSF attribute path, typed by the compiled OCSF schema: `eq`, `prefix`, `suffix`, `contains`, `glob` (`*` and `?` with backslash escape), `regex`, `cidr`, `num` (`lt`, `lte`, `gt`, `gte`, `eq`, `neq`), `exists`, `fieldref` (equality with another attribute), `in` (literal set), `time` (UTC part of a timestamp: minute, hour, day, week, month, year) and `keyword` (any string attribute the logsource map lists as full text). Each string test carries `case: insensitive | sensitive` and an optional transform (`lower`, `upper`, `basename`, `length`). Values are literals fixed at compile time; nothing is computed from the event except the tested attribute. A list attribute matches when any element matches, or every element under `all`. A missing attribute makes a leaf false, except `exists: false`.

Regular expressions in a program use the syntax of the Rust `regex` crate, which has no look-around and no backreferences ([regex crate](https://docs.rs/regex/latest/regex/)); every pattern is compiled by `ricevanta-rulec` at import (POL-05), and its size is bounded by the crate's compiled-size limit.

## 2. Report

Every adapter writes `report.json` beside its output. One entry per source rule:

```json
{ "rule": "proc_creation_win_susp_whoami", "status": "translated",
  "os": { "windows": "supported", "macos": "not_applicable", "linux": "not_applicable" },
  "reasons": [ { "code": "field_unmapped", "os": "linux", "detail": "OriginalFileName", "location": "detection.selection" } ] }
```

`status` is `translated` (the rule compiles for at least one OS it targets), `unsupported` (for none) or `excluded` (disabled at the source, status-filtered or license-blocked). Per OS, a rule is `supported` only when every logsource, field, modifier and function it uses is supported there; an adapter never drops a clause, since dropping one leg of an `and` widens a rule and dropping one leg of an `or` narrows it. The required report schema, `schemas/policy/v1alpha1/report.json`, is absent and blocks compiler/console report interoperability (`../analysis.md` section 3). The reason-code list to encode is: `syntax_error`, `logsource_unmapped`, `field_unmapped`, `event_type_unmapped`, `modifier_unsupported`, `operator_unsupported`, `regex_unsupported`, `placeholder_undefined`, `keyword_unsupported`, `source_unsupported`, `module_unsupported`, `external_undefined`, `include_outside_pack`, `slow_pattern`, `validator_unknown`, `ner_required`, `table_unmapped`, `column_unmapped`, `function_unsupported`, `evented_table_unsupported`, `extend_unresolved`, `git_context_unsupported`, `license_blocked`, `status_excluded`, `cost_exceeded`, `attack_unknown`. Warnings (`context_without_lemma`, `relaxed_regex`, `output_field_unmapped`, `denylist_ignored`, `deprecated_technique`) leave a rule supported and are listed with it. The console lists every entry with its reason, per rule and per OS (`../design/policy.md` section 8).

## 3. Sigma

Input: Sigma rules, filters and correlation rules in YAML, written against the [Sigma rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) 2.1.0 with its [modifiers](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md), [correlation](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md) and [filters](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-filters-specification.md) specifications. The pinned specification version requires the absent `schemas/policy/v1alpha1/adapters.yaml` contract, which blocks reproducible adapter builds (`../analysis.md` section 3); a rule declaring a later major version is refused with `syntax_error`.

Targets: single-event rules become matcher programs evaluated on the agent; correlation rules become server correlation programs in the `detection` module (EDR-01). The required logsource and field map, `schemas/ocsf/sigma-logsources.yaml`, is absent and blocks Sigma translation (`ocsf-profile.md` section 5).

| Construct | Translation |
|---|---|
| `title`, `id`, `author`, `license`, `level`, `tags`, `status`, `fields`, `falsepositives`, `references`, `related` | Metadata; `level` maps one to one onto severity; `attack.t*` tags become `mitre`; `author` is carried to every match (DRL attribution) |
| `logsource` (`product`, `category`, `service`) | One map entry per triple gives the OCSF triggers and OS set; no entry is `logsource_unmapped` |
| Selections: maps (AND of fields), lists of maps (OR), value lists (OR) | `and`, `or` and `in` nodes; string comparison is case-insensitive unless `cased` |
| Wildcards `*`, `?` and the escape `\` | `glob`, or `prefix`, `suffix`, `contains` where the pattern allows |
| Keyword selections (values without a field) | `keyword` over the attributes the map marks as full text for that logsource (Windows Event Log message, script content); none is `keyword_unsupported` |
| `condition`: `and`, `or`, `not`, parentheses, `1 of`, `all of`, wildcard selection names, `them` | Boolean tree; `|` aggregations and `near` from Sigma 1.0 are `syntax_error` with a pointer to correlation rules |
| `null` value | `exists: false` |
| Filters (`filter` documents with `rules`, `selection`, `condition`) | Compiled into each referenced rule as `and not`; listed in the rule's report entry |

Modifiers, all from the appendix:

| Group | Modifiers | Translation |
|---|---|---|
| Generic | `all`, `startswith`, `endswith`, `contains`, `exists`, `cased`, `neq` | Native leaf tests |
| String | `windash` | Expanded at compile into the permutations of `-`, `/`, en dash, em dash and horizontal bar |
| Regular expression | `re` with `i`, `m`, `s` | `regex` with the matching inline flags; look-around, backreferences and possessive or atomic groups are `regex_unsupported` |
| Encoding | `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide` | Expanded at compile into literal alternatives, the encoding modifiers applied before `base64` or `base64offset`; an encoding modifier without a base64 modifier is `modifier_unsupported`, since OCSF attributes hold decoded text |
| Numeric | `lt`, `lte`, `gt`, `gte`, `neq` | `num` |
| Time | `minute`, `hour`, `day`, `week`, `month`, `year` | `time`, in UTC only, matching the CEL profile |
| IP | `cidr` | `cidr`, IPv4 and IPv6 |
| Specific | `expand`, `fieldref` | `expand` substitutes the organization's placeholder values (a `policy` setting, one list per placeholder name), and an undefined placeholder is `placeholder_undefined`; `fieldref` is `fieldref` |

Correlation types: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg` and `value_percentile`, with `rules`, `group-by`, `timespan`, `condition` (`gt`, `gte`, `lt`, `lte`, `eq`, `neq`), `aliases` and `generate`. The specification's own type list names only the first four while it defines all seven in sections (verify against the next specification release); the adapter accepts all seven. The compiler resolves every correlation reference to `{pack, version, pack_digest, rule_key}`. The agent tags matches with that full identity (`../design/policy.md` section 4); late events remain matches of that version even after publication changes. Identical rule names in concurrent versions cannot satisfy each other. The correlation program retains its resolved identities for its event window and supported late-upload horizon; `generate: false` suppresses the base rule's own finding.

Rules with `status: deprecated` or `unsupported` are `excluded` with `status_excluded` from wildcard detector references and translated when a policy names them.

Fixtures: SigmaHQ ships regression samples in `regression_data/`, referenced from a rule's `regression_tests_path`, each with an expected `match_count` ([regression test runner](https://github.com/SigmaHQ/sigma/blob/master/tests/regression_tests_runner.py)); the samples are Windows event captures (verify the format for every sample), which `ricevanta-rulec` converts to OCSF with the agent's own Windows Event Log normalizer before running the rule. How many rules carry samples was not confirmed. Rules without a sample need a project fixture to count as tested.

## 4. Falco

Input: Falco rules files from [falcosecurity/rules](https://github.com/falcosecurity/rules), Apache-2.0, in the format of the [Falco rules documentation](https://falco.org/docs/concepts/rules/): `rule`, `macro`, `list`, `required_engine_version`, `required_plugin_versions` and the `override` section with `append` and `replace`. Target: matcher programs on the Linux agent through the required second logsource map, `schemas/ocsf/falco-fields.yaml`, absent and blocking Falco translation (`ocsf-profile.md` section 5). The adapter resolves macros, lists and overrides across the pack's files before translation.

| Construct | Translation |
|---|---|
| `source: syscall` or absent | Translated |
| Any other `source` (`k8s_audit` and plugin sources) | `source_unsupported` |
| `evt.type` and `evt.dir` | OCSF triggers through the field map, such as `execve` and `execveat` to `process_activity.launch`; an event type the Linux sensors do not emit is `event_type_unmapped`; Ricevanta events are completed operations, so `evt.dir = <` holds and `evt.dir = >` is `event_type_unmapped` |
| Fields `proc.*`, `fd.*`, `user.*`, `group.*`, `evt.*` | Through the field map; a field without an entry, including every `k8s.*` and `container.*` field the map omits, is `field_unmapped` |
| `and`, `or`, `not`, `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `intersects`, `pmatch`, `contains`, `icontains`, `startswith`, `endswith`, `glob`, `iglob`, `exists`, `regex` | Native; `regex` is RE2 in POSIX mode in Falco and is recompiled by `ricevanta-rulec` |
| `bcontains`, `bstartswith` | `operator_unsupported`: OCSF carries no raw byte buffers |
| Transformers `tolower`, `toupper`, `basename`, `len`; `val()` | Leaf transforms; `val()` is `fieldref` |
| Transformer `b64`; modifier `oneof` | `operator_unsupported` (`oneof` semantics, verify) |
| Modifiers `anyof`, `allof` | `in` and `all` |
| `exceptions` | `and not` per exception tuple |
| `enabled: false` | `excluded` |
| `skip-if-unknown-filter: true` | Ignored: an unknown field is reported like any other |
| `priority` | `emergency`, `alert`, `critical` to critical; `error` to high; `warning` to medium; `notice` to low; `informational`, `debug` to informational |
| `output` | Template; a field without a map entry renders `<NA>` with `output_field_unmapped` |
| Tags | `maturity_*` is recorded; `mitre_*` and `T*` tags become `mitre` |

A `required_engine_version` above the version the field map was written against is a pack warning, and rules still translate field by field. The first-party Falco pack takes the `maturity_stable` rules, which are the ones Falco ships in `falco_rules.yaml` ([rules maturity framework](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md)).

Fixtures: falcosecurity/rules ships no per-rule test events; its CI validates rules files against a Falco image. Project fixtures are OCSF events per rule. `event-generator` actions run in the Linux qualification lab, not as fixtures.

## 5. YARA and YARA-X

Input: YARA rule sources. Target: YARA-X in `ricevanta-scan`; the bundle carries the sources and the agent compiles them, because the YARA-X documentation gives no compatibility statement for serialized rules across versions (verify) and agents of three minor releases share a server (AG-04). `ricevanta-rulec` compiles each pack at import with the same YARA-X version as the agent of that release.

- Each pack compiles into its own namespace, so equal rule names in two packs do not collide.
- The compiler runs with relaxed regular-expression syntax, so YARA 4 escapes compile, and records `relaxed_regex` on each affected rule. The incompatibilities on the [differences page](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/) that relaxed syntax does not cover (an unescaped `{`, base64 patterns under 3 characters, mixed base64 alphabets, rule-name wildcards in `of`, negative array indexes, decimal-only hex jump bounds, duplicate modifiers) surface as compile errors, reported per rule as `syntax_error` with the compiler message.
- A slow pattern is an error, not a warning: such a rule is `slow_pattern`, because DLP content decisions run inside a deadline.
- Modules: `pe`, `elf`, `macho`, `dotnet`, `dex`, `lnk`, `crx`, `math`, `hash`, `string` and `time` are built into the agent's YARA-X. `console` is built but discards output. Rules importing `cuckoo`, `magic`, `vt` or any other module are `module_unsupported`: no sandbox report, libmagic or VirusTotal metadata exists on an endpoint, and Magika supplies the file type.
- External variables: `filename`, `filepath`, `extension` and `filetype` (the Magika label) are defined; any other external is `external_undefined`.
- `include` resolves only inside the pack's `rules/` directory; anything else is `include_outside_pack`.
- Process memory scanning is not implemented in YARA-X ([YARA-X vs YARA](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/)); Ricevanta scans files and extracted content only.

Scanner limits per scan: `Scanner::set_timeout` below the policy deadline, `max_matches_per_pattern` at 1,000, and the scan size cap of the scanner helper.

Fixtures: community YARA repositories rarely ship samples, and live malware is never committed. Project fixtures are synthetic files that exercise each rule's strings and conditions; a rule with no fixture is shown as untested.

## 6. Presidio-style recognizers (`pii`)

Input: recognizer YAML in the shape Presidio's registry loads ([Presidio](https://github.com/data-privacy-stack/presidio), MIT; the project moved from `microsoft/presidio` to `data-privacy-stack/presidio`): a `recognizers` list whose entries carry `name`, `supported_entity`, `supported_language` or `supported_languages`, `patterns` (`name`, `regex`, `score`), `context`, `deny_list`, `deny_list_score`, `enabled`, `type`, `class_name` and `country_code`, with the registry's `global_regex_flags`. Ricevanta adds two optional keys per entry, `validator` and `invalidator`, each naming a built-in from the scanner's fixed catalogue (Luhn, IBAN mod 97, and the Vietnamese identifier checks in `dlp-detectors.md` section 1). Target: detectors in `ricevanta-scan` with the `regex` crate, an `aho-corasick` keyword pass for deny lists, and `match.confidence` from the score.

- Regular expressions: Presidio compiles with the third-party Python `regex` module and defaults the flags to `DOTALL | MULTILINE | IGNORECASE` ([pattern_recognizer.py](https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern_recognizer.py)). The adapter records the source flags and Unicode version and accepts only semantics covered by the pinned compatibility fixtures; naming both engines Unicode-aware does not prove equal character sets or case folding. The translation uses explicit source character sets where needed and refuses an unrepresented class, flag or boundary with `regex_unsupported`. Look-around, backreferences, atomic groups, possessive quantifiers, `\G`, recursion, fuzzy matching and named lists are also `regex_unsupported`.
- Validation: Presidio's `validate_result` and `invalidate_result` are Python methods ([pattern_recognizer.py](https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern_recognizer.py)), so they never travel; a `type: predefined` entry maps through a table of `class_name` values to built-in validators (`CreditCardRecognizer` to Luhn, `IbanRecognizer` to mod 97), and an unmapped class is `validator_unknown`. Custom validation code arrives only as an extension `classifier` module (EXT-03).
- Recognizers that need a named-entity model (the spaCy, Stanza and transformers recognizers) are `ner_required`: AI and NLP are an optional backend workload (blueprint section 7), not an agent function.
- Context: Presidio's default enhancer raises the score by 0.35 with a floor of 0.4 when a context word appears within 5 words before the match, comparing lemmas ([lemma_context_aware_enhancer.py](https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/context_aware_enhancers/lemma_context_aware_enhancer.py); whether the factor is added or multiplied, verify). The scanner applies the same window, factor and floor to lower-cased words without lemmatization and reports `context_without_lemma` once per pack.

Fixtures: Presidio's tests are Python test modules per recognizer under `presidio-analyzer/tests/`; they are ported by hand into project fixtures for every recognizer a first-party pack adopts.

## 7. Gitleaks-style patterns (`secrets`)

Input: a Gitleaks TOML configuration ([gitleaks](https://github.com/gitleaks/gitleaks), MIT) at the format of its README: `[[rules]]` with `id`, `description`, `regex`, `secretGroup`, `entropy`, `keywords`, `path`, `tags`, `[[rules.allowlists]]` (`description`, `condition` `OR` or `AND`, `paths`, `regexes`, `regexTarget` `match` or `line`, `stopwords`, `commits`) and composite rules `[[rules.required]]` (`id`, `withinLines`, `withinColumns`); global allow lists; and `[extend]` with `useDefault`, `path` and `disabledRules`. The shipped default configuration uses a singular `[allowlist]` table while the README documents `[[allowlists]]` (verify); the adapter accepts both. Target: detectors in `ricevanta-scan`.

- Regular expressions: Gitleaks uses Go's `regexp`. The adapter parses its syntax tree, including escapes within bracket classes and quoted literals, before translating; textual substitution is forbidden. Go's exact sets are `\d = [0-9]`, `\w = [0-9A-Za-z_]` and `\s = [\t\n\f\r ]`, excluding vertical tab ([Go syntax](https://pkg.go.dev/regexp/syntax)). Emit these explicit sets and Unicode-mode complements `[^0-9]`, `[^0-9A-Za-z_]` and `[^\t\n\f\r ]`; complements must consume complete UTF-8 characters. Preserve bracket unions and negations by emitting the parsed rune set, rather than embedding a replacement fragment in brackets. Go ASCII word boundaries use Rust `(?-u:\b)` and `(?-u:\B)`. Never use Rust `(?-u:\s)`, which includes vertical tab, or byte-mode complements, which violate string-regex UTF-8 safety ([Rust regex](https://docs.rs/regex/latest/regex/)). `\Q...\E` emits escaped literal nodes. Source flags, Unicode property ranges and case folds must match the pinned Go version; an unsupported semantic construct is `regex_unsupported`, even if Rust compiles it.
- `keywords` feed the scanner's `aho-corasick` prefilter; `entropy` is the Shannon entropy of the secret group, as in Gitleaks; `path` matches the file path.
- Allow-list `commits` need Git history, which the endpoint channels do not have: the entry is ignored with `git_context_unsupported` as a warning, which makes the rule stricter, never weaker.
- `[extend] useDefault` resolves against a pack the import names as its base; without one it is `extend_unresolved`. `path` outside the pack is refused.
- A match has confidence 1.0, since the format carries no score; tuning is through allow lists and `Exception` resources.

Fixtures: Gitleaks keeps true-positive and false-positive samples beside each rule in its Go generator (`cmd/generate/config/rules/*.go`), not in the TOML; the first-party secrets pack ports them by hand with attribution. Adapter fixtures compare Go and Rust match spans and capture groups on vertical tab, form feed, non-ASCII digits and spaces, `\D`, `\W`, `\S`, ASCII boundaries, escaped backslashes and bracket classes containing positive and negated escapes. Run the same cases through detection and allow lists; a translated allow list must not suppress a value that its Go source rejects.

## 8. osquery packs (`osquery`)

Input: osquery query packs ([configuration](https://osquery.readthedocs.io/en/stable/deployment/configuration/)): pack `platform`, `version`, `shard`, `discovery` and `queries`; per query `query`, `interval`, `platform`, `version`, `snapshot`, `removed`, `shard` and `denylist`, plus the undocumented `description` and `value` annotations the repository's example packs use. The example packs in the osquery repository are marked not maintained, so the first-party pack is authored in-project. Target: the agent's inventory tables, whose names and columns follow osquery's table schemas, queried under the isolated execution and resource contract below (`../design/mdm.md` section 3; POL-06).

- Table map: `schemas/policy/osquery-tables.yaml` is the required machine-readable list, absent and blocking query validation, of the tables `../design/mdm.md` section 3 collects, with their columns and platforms, generated from the `specs/*.table` files of a pinned osquery release (Apache-2.0 option of `Apache-2.0 OR GPL-2.0-only`) and the platform each spec directory declares (`posix` is macOS and Linux, `linwin` Linux and Windows, `macwin` macOS and Windows) ([genwebsitejson.py](https://github.com/osquery/osquery/blob/master/tools/codegen/genwebsitejson.py)). A table outside the map is `table_unmapped`; a column outside it is `column_unmapped`. The map grows table by table with the MDM collectors and with tables that extension `collector` modules declare.
- SQL: one `SELECT` statement in SQLite syntax, including joins, subqueries and aggregates over mapped tables. `ricevanta-rulec` prepares each statement against empty mapped tables with an authorizer that refuses writes, `ATTACH`, `PRAGMA` and temporary objects, records every table, column and function read, and fails a statement SQLite itself rejects.
- Functions: the admitted catalogue covers SQLite core functions and the osquery [SQL additions](https://osquery.readthedocs.io/en/stable/introduction/sql/) (`concat`, `concat_ws`, `split`, `regex_split`, `regex_match`, `inet_aton`, `version_compare`, `sha1`, `sha256`, `md5`, `community_id_v1`, `to_base64`, `from_base64`, `conditional_to_base64`, `in_cidr_block` and math functions) only after each has a bounded implementation entry. The entry states argument sizes, work bound and output allocation bound. Unknown or unbounded functions are `function_unsupported`; file access and extension loading are never admitted. `regex_match` and `regex_split` use cached Rust patterns under explicit pattern, input and output caps.
- Evented `*_events` tables are `evented_table_unsupported`: event data is OCSF telemetry evaluated by `edr` policies.
- `interval` has a floor of 300 seconds by default, a budget value; `shard` selects devices by a hash of the device uid; `discovery` queries gate the pack per device; `denylist: false` cannot exempt a query from resource governance and is reported as `denylist_ignored`.

An `osquery` pack runs on every device of the scopes it is published to; no policy references it, since `mdm` policies carry no detectors (`policy-envelope.md` section 2.1). Results: a scheduled query emits OCSF `evidence_info` (Live Evidence Info, class 5040, activity Query) with `query_info` naming the pack and query, differential `added` and `removed` rows unless `snapshot` is set, and each row in the `ricevanta` extension's `query_row` object (`ocsf-profile.md` section 2). Compliance checks are `check.query` items of a `Baseline` (`baseline.md`), which carry their own SQL; `ricevanta-rulec` validates that SQL against the same table map and function set, and the `mdm` module turns results into `compliance_finding` events.

### 8.1 Execution bounds

The same contract governs scheduled queries, pack discovery and baseline `check.query`. A separate on-demand query process evaluates a bounded immutable inventory snapshot with no writable database handle, network access, credentials or ambient file access. At most one query process runs per device; at most eight requests wait, with excess requests refused and reported. A 100 ms monotonic deadline covers queueing, snapshot transfer, prepare, functions, stepping, serialization and cleanup. The supervisor terminates and reaps an overdue process and rejects late output. A progress handler also aborts after 10^6 virtual-machine steps, but a long function call can run between callbacks, so the handler is not the time or memory boundary ([SQLite callbacks](https://www.sqlite.org/c3ref/progress_handler.html)).

| Bound | Default hard ceiling |
|---|---|
| SQLite `LENGTH`, including any value and encoded row | 64 KiB |
| SQLite `SQL_LENGTH`, `COLUMN`, `EXPR_DEPTH`, `COMPOUND_SELECT` | 16 KiB, 64, 100, 8; a baseline keeps its smaller 4,096-character SQL cap |
| SQLite `ATTACHED`, `VARIABLE_NUMBER`, `TRIGGER_DEPTH`, `WORKER_THREADS` | 0; no attached databases, bind parameters, triggers or auxiliary SQL threads |
| SQLite heap per query process | 32 MiB hard heap limit; soft limits are insufficient |
| Total query-process memory | 64 MiB, charged to the agent's active helper budget |
| Function argument, generated value and allocation | 64 KiB each; length-producing functions check requested size before allocation |
| Results | 1,000 rows, 64 columns, 64 KiB per encoded row and 1 MiB total |

Apply connection limits before preparation, retain the inventory-only authorizer, disable extension loading and disk spill, and bound every custom function's work and scratch memory. SQLite's [connection limits](https://www.sqlite.org/limits.html) and [hard heap limit](https://www.sqlite.org/c3ref/hard_heap_limit64.html) constrain SQLite; the process cap also covers Rust functions and serialization. Large `zeroblob`, `randomblob`, formatting, concatenation and splitting requests must fail before creating an oversized intermediate value.

A timeout, allocation failure or result-cap breach returns a named query error, never an empty or partial successful result. A baseline records `unknown`, not passing; a scheduled query preserves its previous differential snapshot and emits policy health; failed discovery never grants compliance or silently turns off health reporting. Import and runtime use the same function catalogue and limits. The native process launcher, sandbox, aggregate-memory accounting, kill/reap flow and per-function catalogue remain implementation blockers until qualified on all three OS targets (`../analysis.md` section 3). No claim of a 100 ms hard bound rests on SQLite callbacks alone.

Fixtures: per query, row fixtures per referenced table in `rows/<table>.json` and expected rows. Negative cases include `length(hex(zeroblob(100000000)))`, a long function without progress callbacks, cross joins, recursive expansion, result overflow and a custom regex/split function exhausting its allocation cap. The core must continue serving enforcement within its budget while the query fails.

## 9. MITRE ATT&CK

ATT&CK is a taxonomy, not a pack format. The `policy` module loads the Enterprise STIX 2.1 bundle from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) at a pinned version, shipped with the server release and replaceable by an operator upload. It validates every `mitre` value in policies and translated rules (`attack_unknown`), follows `revoked-by` relationships with a `deprecated_technique` warning, and feeds the coverage matrix (`../design/policy.md` section 7). The [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) grant a royalty-free license provided every copy reproduces MITRE's copyright designation and the license, so the notice ships in `NOTICE` and on the coverage view.

## 10. Upstream tooling

| Tool | License | Use |
|---|---|---|
| pySigma, sigma-cli | LGPL-2.1 ([pySigma LICENSE](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE), [sigma-cli LICENSE.txt](https://github.com/SigmaHQ/sigma-cli/blob/main/LICENSE.txt)) | Reference only, neither run nor linked: they are Python and convert rules into backend queries through processing pipelines, while Ricevanta needs an evaluator over OCSF |
| `bradleyjkemp/sigma-go` | MIT | Not used: its last release predates Sigma 2.x correlation and filters (verify) |
| osquery `specs/*.table` | Apache-2.0 option | Build time: generates the table map |
| Gitleaks generator samples | MIT | Ported by hand into fixtures for the first-party secrets pack |
| SigmaHQ `regression_data/` | DRL 1.1 with the rules | Fixtures, converted by `ricevanta-rulec` |
| ATT&CK STIX data | MITRE terms | Runtime dataset in the server |

No adapter calls upstream tooling at runtime.
