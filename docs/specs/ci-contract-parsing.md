# CI catalogue string representation

Use literal TOML strings for eligible `console-unit.tests` values in `scripts/ci/targets.toml`, preserving the complete parsed catalogue. This is a data representation change. The [CI hardening contract](ci-hardening.md), its [policy evaluation lifetime](../plans/ci-hardening.md#task-3a-reuse-selected-inventory-within-one-cache-check) and [Python failure diagnostics](../plans/contract-validation.md#failure-diagnostics) remain authoritative. The [implementation plan](../plans/ci-contract-parsing.md) requires independent design approval before implementation.

## 1. Purpose and evidence

Repeated catalogue parsing is required at independent validation boundaries. Reduce work inside the existing parser by choosing equivalent string syntax, without reducing those boundaries. [The source-bound native profile](https://github.com/ricevanta/ricevanta/actions/runs/38870370042) records 880 complete TOML parses for the selected policy test and 1,652 for the selected receipt test. `parse_basic_str` consumes 13.528 s and 25.720 s of its own profiled time, respectively. These are diagnostic measurements, not normal-job deadlines or promised savings.

The pinned [CPython 3.14.8 parser](https://github.com/python/cpython/blob/v3.14.8/Lib/tomllib/_parser.py) walks basic-string characters in Python. Literal parsing searches for the closing delimiter, checks forbidden characters and slices the result. That source difference supports qualifying this bounded change. It does not establish an end-to-end speedup. YAML parsing remains outside this scope.

The evidence's 88 complete policy checks retain three classification inventory loads per check under Task 3A. Other independent inventory and fuzz catalogue reads remain separate. This change preserves every public loader call, file read, TOML parse, mutation, assertion and failure boundary; only the parser's internal string branch changes. It adds no cache, parser, dependency, workflow or runtime API.

## 2. Eligible values and exact scope

Only the two string tokens of each ordered pair in the unique `selected` entry with `id = "console-unit"`, field `tests`, may change spelling. Preserve every pair, including repeated pairs, and its position. All other bytes, including field names, table headers, IDs, commands, comments, whitespace, array punctuation, line endings, budgets, skips and other targets, remain unchanged.

Obtain each token's decoded value from the public `tomllib` API under the local proof input contract in section 4. Do not decode with JSON, `unicode_escape`, manual escape substitution or a different TOML library. [TOML's string rules](https://toml.io/en/v1.0.0#string) distinguish escape-decoding basic strings from literal strings, which retain their contents. Eligibility is a property of the decoded value, not its raw backslash spelling.

Apply these rules in order:

1. Only an existing one-line basic string token is a candidate. Leave existing supported literal tokens unchanged. A multiline basic string is outside the supported row grammar and aborts the transformation. Refuse malformed TOML before rewriting anything.
2. Require every decoded character to be printable ASCII, U+0020 through U+007E inclusive. The empty string qualifies. Leave any value containing a control character, DEL or non-ASCII character in its original spelling. This deliberately excludes legal TOML tabs and Unicode rather than introducing new raw Unicode through a reader with an implicit encoding.
3. If the value contains no apostrophe, emit one apostrophe, the exact decoded value and one apostrophe.
4. Otherwise require no three consecutive apostrophes and no apostrophe at either end. Emit three apostrophes, the exact decoded value and three apostrophes, all on one physical line. Values with one or two internal apostrophes qualify; edge apostrophes remain unchanged to avoid ambiguous closing runs.
5. Parse the candidate token with the same `tomllib` and require exactly the same `str` value. A mismatch or parse error aborts the candidate change; it never authorizes a fallback rewrite.

Double quotes, backslashes and text such as `\n` or `\u0041` inside a decoded value are retained literally. An actual decoded newline or Unicode character is ineligible. An escape such as `\u0041` in a basic token decodes to ASCII `A` and may become literal `A`; it must not become literal backslash-u text. Never add, trim, wrap or normalize string content. Triple delimiters here do not permit a multiline body, initial-newline trimming or line continuation.

The conservative ASCII and quote-edge rules are intentional limits, not a complete TOML serializer. Ineligible values remain valid basic strings. No minimum conversion count or fixed console inventory count is an acceptance condition.

## 3. Transformation and refusal

Use a task-local, standard-library verifier/converter in the coordinator's scratchpad, outside production imports and authoritative CI. It is a review artifact, not a new installed tool or catalogue loader. Keep its source, hashes, invocation and results with the implementation evidence.

Start from exact raw source bytes and record their SHA-256. Require strict UTF-8, LF line endings and the expected unambiguous catalogue structure before conversion. Refuse a CR, ambiguous span, unexpected syntax or a changed baseline hash without writing a candidate. This restriction applies to the one-time conversion, not to production TOML acceptance.

Locate the unique target and its `tests` array by source spans, then verify the spans against the full parsed model. The supported row grammar is one pair per physical line, exactly two one-line string tokens separated by a comma, with existing indentation, brackets and optional trailing comma. A conservative lexical recognizer may locate basic-token spans and preserve recognized literal tokens; it must account for escaped quotes and backslashes. It does not interpret escape semantics. Reject an unrecognized row or a mismatch between source row positions and parsed pairs instead of guessing or partially rewriting the file.

Replace only eligible token spans, from the decoded values. Preserve every other byte and every ineligible token. Do not serialize the complete model, sort entries, deduplicate, shorten titles, omit large expectations, change escape content or regenerate inventory from a test run. Run the complete equality and scope proof below before publishing the candidate. Reapplying the conversion to its own output must make no byte changes.

No runtime code changes are required. `run_selected.load_targets` continues to parse an explicit UTF-8 `read_text`; `inventory.fuzz_targets` continues to parse its existing `read_text` result. Unknown IDs, malformed files, missing files and invalid rows encounter the same production validation and exception handling. No result or failure is retained between independent reads. Failures that occur before loading still occur before loading.

## 4. Paired equality proof

The local pure proof uses CPython 3.14.8 without claiming CI admission. Before running it, the coordinator freezes the absolute invoked executable path, resolved executable path and SHA-256, Python implementation/version, and the actual imported `tomllib` package and module paths and SHA-256 values. Include `__init__.py`, `_parser.py` and `_re.py`; compare their exact source bytes with the official [CPython v3.14.8 sources](https://github.com/python/cpython/tree/v3.14.8/Lib/tomllib) and retain the source URLs, hashes and equality result. A version string alone is insufficient. A module/source mismatch requires a different verified input or design review, not an unrecorded parser substitution.

Use the frozen executable with `-I -S -B`, standard-library imports only, and [`-X pycache_prefix=<fresh-empty-scratchpad-directory>`](https://docs.python.org/3.14/library/sys.html#sys.pycache_prefix) so existing bytecode caches cannot substitute for the checked module source. Record the actual loaded module locations, interpreter flags, bytecode-cache prefix and effective text-reader encodings. Recheck the resolved executable and module identities against the frozen values at the start and end of every proof invocation. Missing, changed or unexpected identities invalidate the result. Do not run bootstrap admission with an overridden host identity or weaken any production admission check.

Compare complete original and candidate raw-source snapshots in that same interpreter, using the same parser, reader form and effective encoding on both sides of each pair. Exercise both actual reader forms, `Path.read_text(encoding='utf-8')` and `Path.read_text()`, followed by `tomllib.loads`. Do not compare a generated expected model against the candidate alone. Do not pre-normalize, strip, sort or deduplicate input or parsed output. Record both source hashes and each verification result. [The public TOML API](https://docs.python.org/3.14/library/tomllib.html) defines returned Python types and parse errors.

This local result proves parsed-model equality for the recorded inputs. It proves no payload integrity, native environment admission, performance or deadline qualification. The local host need not match a supported bootstrap runner; native CI still uses its unchanged admitted environment and remains required under section 5.

The comparison recursively requires exact Python type at every node, identical dictionary key iteration order, identical list lengths and element order, and exact scalar values. Strings compare by exact characters. Every duplicate occurrence remains at its original index. Ordinary dictionary equality, sets, counters, sorted JSON and a hash of a normalized model are insufficient. The verifier supports the catalogue's `dict`, `list`, `str`, `int` and `bool` types; an unexpected type stops the proof for design review rather than silently coercing it.

Independently prove that every changed byte belongs to an eligible token span under section 2 and that all other bytes match. Model equality alone cannot detect removed comments or formatting outside scope. Record changed/refused token counts as observations, never authority to discard unmatched rows. Require equality on each reader and no newly introduced non-ASCII bytes. Existing unchanged non-ASCII source remains byte-identical.

Keep the pair of raw snapshots and verifier available to the independent reviewer. After a rebase, conflict resolution or concurrent source change, regenerate from the new baseline and repeat the complete proof. Equality of an earlier pair does not qualify another head.

### Composition with console inventory work

The [console execution-proof plan](../plans/ci-hardening.md#task-4-prove-selected-tests-fuzzing-and-nested-harness-execution) owns inventory meaning. An independently reviewed console content correction establishes its own exact counts and multiplicities. Apply this representation change to that correction's final bytes, or retain explicit separate content and representation stages with separate evidence. The immediate representation-stage input and output must be completely equal under section 4.

Do not bless a stale inventory merely because its representation proof passes. Do not combine a semantic inventory refresh with this transformation's equality claim. The integration evidence must bind the final content baseline, representation output and tested head. Console execution must still prove every expected instance, including repeated names, under its own contract.

## 5. Verification and qualification

Pure checks exercise empty strings, spaces, double quotes, backslashes, trailing backslashes, escaped basic quotes, literal backslash-n versus decoded LF, ASCII Unicode escapes, non-ASCII Unicode escapes and raw Unicode. Cover internal single/double apostrophes, runs of three or more apostrophes, leading/trailing apostrophes, tab, CR, LF, CRLF, NUL, DEL, Unicode line separators and invalid Unicode escapes. Eligible values round-trip exactly; ineligible values remain byte-identical. Malformed TOML and unsupported source shape abort before a write.

Negative controls must catch a naive delimiter-only swap that preserves escaped quote/backslash text, ASCII Unicode escapes converted without decoding, newline trimming, normalization of Unicode, deletion of one duplicate pair, row reordering, type substitution such as `true` for `1`, dictionary key reordering and an edit outside allowed spans. Parse rejection and semantic inequality are distinct expected outcomes. A no-op control passes equality; a valid eligible conversion also passes. These tests verify the verifier, not a new production conversion path.

Local work is limited to syntax, pure representation controls and paired source checks. Run no helper suite, policy mutation workload, native qualification, profiling or performance loop locally for this slice. Keep existing tests unchanged. CI runs the complete policy and receipt mutation suites, helper discovery, closure admission and selected-test proof on the final source. Do not omit a check, assertion or probe to fit a deadline.

Native CI qualification retains the 10-minute `ci-contracts` job and 30-minute bootstrap jobs, with full helper execution on Linux x64, Windows x64 and macOS ARM64. Preserve all cold admission, corruption, foreign-identity and compiler probes, receipts and failure diagnostics. Require complete exact-head logs, job outcomes, durations and the final PR integration head's successful `ci-required`. A green diagnostic selector or local equality result cannot substitute for these gates. Claim a runtime improvement only when comparable native evidence supports it; claim a timeout correction only after the full required jobs pass within their unchanged deadlines.

## 6. Trust boundary and trade-offs

The path remains reviewed source bytes, admitted interpreter and unchanged loaders, complete policy and selected-test validation, same-run receipts, `ci-required`, independent review and landing. The representation proof constrains this edit; it does not authenticate candidate-controlled source or replace any step on that path. No endpoint content, credentials or external service enter the transformation.

| Attacker | Outcome in this slice |
|---|---|
| Stolen enrollment token | No catalogue, validator or CI authority is granted. Enrollment controls remain separate. |
| Compromised agent host | Cannot supply an authoritative catalogue or receipt through this transformation. Candidate source still needs review and CI. |
| Compromised console session | Gains no source-write, parser or receipt capability from literal encoding. |
| Rogue extension publisher | Cannot add or remove expected tests through a representation-only proof. Extension trust controls remain unchanged. |
| Network position between agent and server | Gains no new protocol or catalogue input. Existing transport and receipt bindings remain required. |
| Database writer without signing keys | Database content is not input to the transformation and grants no CI signature or receipt authority. |
| Server restored from backup | Cannot reuse stale CI evidence or bypass exact-head qualification; server recovery controls are unchanged. |

Benefit: eligible large strings take the pinned parser's literal branch while preserving all independent validations. Trade-offs: mixed TOML string styles and a deliberately conservative conversion leave some parsing cost intact; triple-quoted one-line values need careful review. Dependencies are the identity-checked local Python standard library for the pure proof and the unchanged admitted Python and catalogue readers in native CI. No new license, account or vendor program is required, and no OS mechanism or v1.0.0 support scope changes.

Alternatives: leaving all values unchanged avoids a data diff but leaves the measured cost; broader literal conversion increases boundary cases without being needed for the largest eligible strings; a TOML serializer could alter unrelated source; a shared parse cache could hide mutations; a faster parser adds a dependency and compatibility surface; YAML optimization is a separate question. These alternatives are outside this bounded change. There is no guaranteed speedup until native qualification supplies evidence.
