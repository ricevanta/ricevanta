# OCSF Contracts Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task by task after the design gate. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build the pinned foundation OCSF sources, deterministic compiled schemas, emitted-event fixtures, Python checks and a standard-library Go decoded validator.

**Architecture:** A reviewed vendor snapshot and closed Ricevanta field projection generate four schemas and an embedded copy. Python and Go execute the same structural schemas and explicit semantic rules. Neither validator performs admission or grants authority.

**Tech Stack:** Go 1.27.1; Python 3.14.8; jsonschema 4.25.1; PyYAML 6.0.3. No new Go dependency or OCSF runtime fetch.

**Spec:** [OCSF profile](../specs/ocsf-profile.md), with [field catalogue](../../schemas/ocsf/contract-fields.md) and its four design examples. Read both before each task.

## Global constraints

- An independent Sol xhigh reviewer (`gpt-6.1-sol`, `xhigh`) must approve the spec, field catalogue, examples and plan before product code starts. Approval applies to the reviewed bytes, not an earlier draft.
- A separate Sol medium implementer (`gpt-6.1-sol`, `medium`) owns the code paths. The designer and design reviewer do not implement this slice.
- Astra xhigh (`gpt-6-astra`, `xhigh`) reviews the full slice once, after the last code task and before integration, and confirms fixes, because a model never reviews code it wrote. Include an adversarial pass for source loading, schema interpretation, untrusted decoded trees and numeric/resource boundaries.
- The primary agent owns Git operations and integration. Workers never add, commit or push. Copy reviewed documents into the implementation worktree. Keep other slices in separate worktrees; at most six Codex jobs across all slices.
- Tasks are sequential because each consumes the preceding task's schema and fixtures. Do not run concurrent edits in the same worktree or change another worker's files.
- Installed toolchains are Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 with pnpm 11.18.0, and Python 3.14.8. Rust and Node are not used by this slice. Keep `server/go.mod` at Go 1.27.1; no toolchain directive or dependency change.
- Keep design tooling at jsonschema==4.25.1 and PyYAML==6.0.3. Existing design pins rfc3339-validator==0.1.4 and six==1.17.0 remain unchanged. Pin the installed transitive validation closure exactly as listed in spec section 8. No cryptography use or new package is required.
- Pin OCSF to the exact tag, commit and tree in spec section 2. The vendor operation is the only schema network operation. All ordinary checks must work offline.
- Tests fail first for the intended missing behavior, then the implementer adds the least code that passes. Record the failing and passing commands. A bad fixture or import-path typo is not the intended red result.
- Local checks are formatting, focused tests and vet. Race, timed fuzz, extended tests and native matrix runs belong to CI; read their results before integration. No local fuzzing or race runs.
- No handlers, transport changes, producers, generated ingest/Rust types, adapters, database writes or deferred-domain admission. The authority journal and native qualification gates remain blocked.
- A failed source assertion is a design conflict. Stop that dependent task, report the exact upstream path/value, and obtain author correction and independent confirmation. Do not relax the schema or silently copy another release.

## Review focus

- Upstream byte pinning must reject a changed, missing, extra or symlinked file and must retain licensing notices; task 1 tests each case.
- Metadata extension uid is string `999`, source declaration uid is integer 999, and type_uid exceeds uint32; tasks 1 and 3 test these distinctions and preserve the permanent unregistered allocation.
- Missing measurement reasons must not excuse required fields or convert failure into a zero reading; tasks 2 and 3 exercise the exact spool presence/reason table and all other coverage branches.
- Decoded maps cannot prove strict JSON or sender authenticity; task 3 tests the boundary without adding a raw-byte admission API.
- Python and Go must reject the same full-width numeric, byte-boundary and cross-field defects; tasks 2 and 3 consume identical vectors and task 4 checks parity.
- Future classes and extension packages must not expand runtime validation; tasks 1 and 3 reject unknown classes, schema keywords and override attempts.

## Ownership and outputs

| Path | Owner and purpose |
|---|---|
| `schemas/ocsf/upstream/1.9.0/`, `upstream.lock.json` | Implementer: exact schema snapshot and byte commitments |
| `schemas/ocsf/extensions/ricevanta/` | Implementer: declaration consistency checks, dictionary, four native event files and custom/augmented object files |
| `schemas/ocsf/profile.json`, `profile.schema.json` | Implementer: closed field projection and its authoring schema |
| `schemas/ocsf/generate.py`, `test_generate.py` | Implementer: offline generator, vendor verification and drift checks |
| `schemas/ocsf/compiled/` | Generated, never hand-edited |
| `schemas/ocsf/fixtures/events.json`, `fixture.schema.json` | Implementer: emitted-event and parser fixture containers |
| `schemas/ocsf/validate.py`, `test_validate.py` | Implementer: strict fixture loading, JSON Schema checks, semantic rules and negative tests |
| `server/internal/events/ocsf/validate.go`, `schema.go`, `rules.go` | Implementer: public API, private schema interpreter, semantic rules |
| `server/internal/events/ocsf/schema/` | Generated byte-identical embed copy |
| `server/internal/events/ocsf/validate_test.go`, `schema_test.go`, `fuzz_test.go` | Implementer: shared vectors, private loader and caller-boundary tests |
| `NOTICE`, `.github/requirements-design.txt`, `.github/workflows/design.yml`, `.github/workflows/server.yml`, `instructions/testing.md` | Primary integration: attribution, scoped CI checks, fuzz target inventory; no worker edits |

The design author changes none of the implementation or CI paths. `limits.yaml` remains authoritative for existing per-field caps; task 1 reads it without widening its values. It includes later-domain and CEL paths that are not selected by this projection. Preserve those entries and label their absence from compiled events as deferred, not a broken reference. Add no fabricated CEL environment binding.

### Task 1: Pinned sources and deterministic compilation

**Consumes:** Spec sections 1 through 6, field catalogue and licensing row.

**Produces:** `generate.py` command with `--check`; exact native sources; `profile.json`; four schemas and manifest; embedded-copy bytes. Private Python interfaces: `verify_vendor(root: Path) -> None`, `compile_profile(root: Path) -> dict[str, bytes]`, `check_outputs(root: Path, outputs: dict[str, bytes]) -> None`. Errors raise ValueError with static error codes and no source values.

- [ ] Write `test_generate.py` tests `test_vendor_pin`, `test_vendor_inventory`, `test_source_bindings`, `test_pinned_host_profile`, `test_bytes_unsigned_overrides`, `test_unknown_construct`, `test_inheritance`, `test_compiled_grammar`, `test_determinism`, `test_embed_drift`. Include altered bytes, path traversal, symlink, missing NOTICE, extra vendor file, duplicate decoded source keys, missing source reference, inheritance/ref cycle, wrong array type, removed inherited required field, enum conflict, unsupported keyword and unselected native class.
- [ ] In the source tests, compile the exact locked host.json through base_event with meta/annotations intact; assert profile requirements before narrowing, required device in Agent branches, and no leaked metadata fields. Reject unknown/malformed root and annotation keys. Bind pipeline bytes and spool_sample.bytes to dictionary long_t, accept only their explicit u64 overrides, and reject an unlisted long_t widening.
- [ ] Run `python -m unittest discover -s schemas/ocsf -p test_generate.py -v`. Require failure because generator interfaces are absent.
- [ ] Perform the vendor operation in `/tmp`; require tag/commit/tree equality. Generate the lock from exact selected Git blobs. Copy only selected data and license files. Have the primary add distribution NOTICE attribution from the vendored notice before accepting this task. Compare SHA-256 with an independent hashlib pass, not the generator helper.
- [ ] Create dictionary/object/event definitions from the catalogue. Use exact class filenames `agent_health_activity.json`, `policy_activity.json`, `pipeline_activity.json`, `certificate_lifecycle_activity.json`. Require extension.json to retain EV-03's permanent unregistered uid 999 and its name/version; no registration or uid migration is a task or release gate. The profile defines custom local uids, not an upstream reservation.
- [ ] Encode profile.json and profile.schema.json with closed keys and source bindings. Catalogue restrictions are executable constraints, not ignored prose. Add the compiled-format grammar checker and source resolver. Resolve upstream required fields and constraint groups before narrowing; no general upstream compiler dependency.
- [ ] Implement deterministic output and `--check`, with strict local refs and byte-identical embedding. Budget source files at 1 MiB each, 512 files, 16 MiB total; budget each compiled schema at 1 MiB, all compiled output at 8 MiB, 4096 schema nodes, depth 64 and 256 definitions. Reject excess before recursive resolution. These are build-input ceilings, separate from event budgets.
- [ ] Run `python schemas/ocsf/generate.py`, then `python schemas/ocsf/generate.py --check`, then the unittest command. Require PASS. Run `PYTHONHASHSEED=1 python schemas/ocsf/generate.py --check` and `PYTHONHASHSEED=2 python schemas/ocsf/generate.py --check`; require byte equality and no repository writes.
- [ ] The primary inspects the source/lock diff and independently checks the four allocated class/type IDs before task 2 consumes generated schemas.

### Task 2: Python validator and emitted fixtures

**Consumes:** Task 1 compiled schema bytes and immutable source bindings.

**Produces:** `validate.py` CLI, with no arguments; `validate_event(event: object, source: str) -> str | None` for decoded tests; `load_event(text: str) -> object` for strict fixture parsing. Source is exactly `agent` or `server`; result codes are the Go sentinel names without package prefix. Parser failures use `parse.invalid` separately. `test_validate.py` is runnable by unittest.

- [ ] Add failing `TestExamples`, `TestEveryActivity`, `TestPlatformCoverage`, `TestNumericTokens`, `TestByteLimits`, `TestCrossFieldRules`, `TestPrecedence` and `TestNoNetwork`. Use the four design examples as literal positive seeds; expect all to pass complete validation. Include every catalogue mutation table row as a negative or boundary fixture.
- [ ] Run `python -m unittest discover -s schemas/ocsf -p test_validate.py -v`; require failure because validation is absent.
- [ ] Define fixture.schema.json: closed root `{format: 1, events: [...], parser: [...]}`. Event cases have exactly name, source, event_json, expected_error; parser cases have name, event_json, expected_error fixed to parse.invalid. Names are unique tokens; each array has at most 2048 cases, each event_json at most 2 MiB. Event cases must parse strictly; parser cases must fail before decoded validation. Never classify duplicate-key text as a Go map-validation test.
- [ ] Implement strict loading, offline JSON Schema checks and fixed semantic rules. Pin lexical integers and rational numbers without float conversion. Test a resolver that raises on any external retrieval; known $schema/$id strings must not fetch. Verify metaschemas with only the vendored registry.
- [ ] Expand fixtures to every custom activity and source, platform-specific metric tags, every absence reason and all optional object shapes. Include MaxUint64 sequence and spool bytes, every spool table absence/presence branch, 63/64/65-byte number tokens with correct and wrong versions, gap/drop arithmetic near it, positive renew/predecessor, nonzero epoch/generation, and all rejection vectors in spec section 8. Build boundary objects in tests for limits too large for a readable fixture; cap those builders at limit+1.
- [ ] Run `python schemas/ocsf/validate.py` and `python -m unittest discover -s schemas/ocsf -p 'test_*.py' -v`; require PASS. Mutate type_uid without changing shape and require ErrConstraint, proving semantic checks run after JSON Schema. Run independent vector calculations in a separate script/process and compare expected IDs, counts and byte lengths.
- [ ] The primary checks that negative expected outcomes are not generated by calling the validator under test.

### Task 3: Standard-library Go validator

**Consumes:** Immutable compiled manifest/schemas and shared fixtures. Exact public API and all sentinels come from spec section 7; do not add raw-byte or runtime-schema APIs.

**Produces:** `ocsf.Validate(any, ocsf.Source) error`; immutable private schema interpreter; fixed rules; ordinary tests and FuzzValidate.

- [ ] Write `TestExamples`, `TestSharedFixtures`, `TestErrorPrecedence`, `TestDecodedTypes`, `TestBudgets`, `TestNoMutation`, `TestSourceContext`, `TestCoverage`, `TestSchemaLoader`, `TestCompiledDrift`, `TestConcurrentValidate` and `FuzzValidate` before implementation. Assertions use errors.Is, reject every nonselected sentinel, and compare input trees before/after with an independent test snapshot for acyclic trees.
- [ ] Run `cd server && go test -count=1 ./internal/events/ocsf`; require failure for missing API.
- [ ] Implement bounded ordered preflight first; add typed nil, unsupported numeric/alias types, invalid UTF-8, cycles, repeated aliases, huge keys and number strings. Ensure size checks happen before sorting large maps or allocating from a claimed field. Match ErrBudget for number tokens longer than 64 bytes before syntax/version checks; run the shared boundary/version vectors and native malformed overlength json.Number cases.
- [ ] Implement private load of go:embed data with manifest, keyword, schema-node and local-ref checks using task 1's build-input bounds. Use sync.Once and immutable internal values. Fail closed for damaged embedded artifacts; do not panic, fetch, expose setters or return mutable schema maps.
- [ ] Implement the supported structural keywords against json.Number values with exact arithmetic. Test all logical branches, unknown/wrong-case keys at every nesting level, local refs and null rejection. An unsupported class is ErrClass even if its schema is present in the upstream vendor tree.
- [ ] Implement fixed semantic rules in catalogue order and source constraints. Require eventid.Parse for both metadata UUIDs and any class UUID; expose only ErrConstraint on UUID failure. Preserve MaxUint64 exactly, check subtraction before count equality, and avoid overflow when rounding kilobytes.
- [ ] Run `cd server && go test -count=1 ./internal/events/ocsf` and `cd server && go vet ./internal/events/ocsf`; require PASS. Run `cd server && gofmt -l internal/events/ocsf`; require no output. Ordinary tests execute only fuzz seeds, not timed fuzzing.

### Task 4: Integration checks and handoff

**Consumes:** All task outputs and confirmed code reviews. Primary integration owns this task and any shared-file changes.

- [ ] Add the exact transitive Python pins from spec section 8 to .github/requirements-design.txt without changing other slice pins. Verify the resolved versions before running schema checks.
- [ ] Add scoped design CI commands `python schemas/ocsf/generate.py --check`, `python schemas/ocsf/validate.py`, and `python -m unittest discover -s schemas/ocsf -p 'test_*.py' -v`. Watch schemas/ocsf, embedded copies and the OCSF spec/plan paths. Keep all schema checks offline after dependency setup.
- [ ] Add server CI ordinary tests and race coverage, plus one anchored fuzz job: `cd server && go test -count=1 ./internal/events/ocsf -fuzz='^FuzzValidate$' -fuzztime=60s -parallel=2`. Add the same command to the single testing-instruction target list. Run the shared corpus on macOS ARM64, Windows x64 and Linux x64 with Go 1.27.1. No native telemetry support claim follows.
- [ ] Locally rerun generation check, Python validator/unittests, Go focused tests, vet and gofmt from the commands above. Run `git diff --check`, inspect the complete diff, and verify no changes under transport packages, no adapters, no authority gate bypass and no new runtime dependency.
- [ ] The primary compares Go and Python results against every expected shared vector. Record test counts, tool versions and the exact head reviewed. Read every triggered CI result, including race, timed fuzz and native matrix, before integration; a missing run is not a pass.
- [ ] Obtain the Astra xhigh whole-slice adversarial review, including malformed decoded graphs and schema-loader inputs, and its fix confirmation. The primary updates analysis/TODO statements to reflect actual implemented files only after verification. No worker changes status to imply production ingest, native telemetry or audit readiness.

## Acceptance and unresolved work

Completion means the pinned source inventory verifies offline, regeneration is byte-stable, all emitted fixtures pass their expected structural and semantic outcomes in Python and Go, code review confirms fixes, and the required CI runs pass. The design-only change does not satisfy those implementation checks.

The profile's unresolved questions remain review choices. Audit payloads, generated event types, producers, runtime admission, enrichment, domain mappings, native collection and authority recovery each need their own reviewed contract and evidence. Keep those dependencies visible when this slice lands.
