# ReportTemplate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the published ReportTemplate contracts' Python checks and standard-library Go decoded-template validator.

**Architecture:** JSON Schema and an immutable source catalogue define authoring shape and capabilities. Python supplies independent structural and semantic checks; Go mirrors acceptance, deterministic errors and bounds against the same fixtures without loading schemas at runtime.

**Tech Stack:** Go 1.27.1 standard library, Python with jsonschema 4.25.1 and PyYAML 6.0.3, Node 24.21.0 for schema-pattern parity.

**Spec:** [Report template](../specs/report-template.md), including its security trace, operator bindings, unresolved choices and later-consumer gates.

## Global constraints

- An independent Sol xhigh reviewer, `gpt-6.1-sol` at `xhigh`, must approve the spec, plan, schemas, catalogue and fixtures before implementation. Review-ready documents are not approval. The designer and reviewer never implement this slice.
- A separate Sol medium implementer, `gpt-6.1-sol` at `medium`, owns the code paths below. Astra xhigh, `gpt-6-astra` at `xhigh`, reviews the full slice once, after the last code task and before integration, with an adversarial pass, and confirms fixes. A model never reviews code it wrote, as required by instructions/workflow.md (Reviews).
- Include an adversarial review of decoded untrusted input, catalogue substitution, reference confusion, bounds and every authorization handoff. Pure validation cannot authorize requests or establish stored-footprint integrity.
- The primary agent owns planning, verification, worktrees and Git. Workers never commit or push. Give each worker the approved spec/plan, authorities, owned paths, forbidden actions, required checks and report contract. Workers are not alone and must preserve other workers' edits. Concurrent edits require separate worktrees; these tasks run in dependency order.
- Installed versions are Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 with pnpm 11.18.0. Rust and pnpm have no implementation role here. Retain `go 1.27.1` in server/go.mod without a toolchain directive or dependency edits.
- Preserve exact existing design pins: jsonschema==4.25.1, PyYAML==6.0.3, rfc3339-validator==0.1.4, six==1.17.0. The report checker directly uses only the first two and Python's calendar tools. No Go third-party dependency; no package installation, build-file, licensing or .github/ edits in this slice.
- Write each failing test first and observe the intended missing-interface or assertion failure before implementation. An unrelated environment failure does not count. The primary agent inspects edits and reruns light checks before accepting a worker report.
- Local checks stay light: focused ordinary tests, gofmt, vet, schema checks and deterministic vectors. No local race or timed fuzz runs. CI owns race, timed fuzz and the native platform matrix; passing a pure library test does not establish endpoint support.
- No handlers, generic raw decoder, SQL engine, parameter-submission API, scheduler, dashboard, renderer, run storage, footprint signing, approval journal, extension loader or permission schema edits. No secret values. Keep independent oracle and mutation scripts in /tmp.
- Schemas and fixtures are reviewed design inputs. A mismatch returns to the designer and reviewer for a contract correction; never weaken a schema or alter expected errors merely to fit Go output.
- Documents state current contracts without dates, history wording or em dashes; a spec or plan is at most 400 lines. Follow instructions/go.md, instructions/testing.md and instructions/workflow.md.

## Review focus

- A valid catalogue or template must never be mistaken for an effective grant or immutable run footprint. Task 2 checks detached metadata and exact PKI/RADIUS/lineage obligations; the later-consumer gates remain explicit.
- A field, alias or cross-source enum parameter must not select unprojected data. Task 3 tests reference stages, collision rules and every output consumer.
- Invalid input must not trigger unbounded map sorting, recursion, allocation or custom methods. Task 2 tests immediate-container bounds, hostile Go values and independent charge vectors.
- Closed union branches and locale rules must agree in Python and Go, including combined defects. Tasks 1 and 3 test branch mutations, en/vi, discriminators and deterministic error precedence.
- Shared fixture agreement must not hide a shared mistake. Task 4 uses independent oracles, capability coverage and deliberate drift mutations rather than treating dual acceptance as proof.

## Files and ownership

Published design inputs are under `schemas/report/v1alpha1/`:

| File | Responsibility |
|---|---|
| report-template.json | Closed authoring shape, all parameter/filter/layout branches and local limits |
| catalogue.schema.json | Closed typed source/field shape and capability/type constraints |
| catalogue.json | Complete source/field inventory and exact permission/footprint metadata |
| fixtures/templates.json | Complete positive/negative templates with structural and full outcomes |

The implementer creates only these paths:

| File | Responsibility |
|---|---|
| schemas/report/v1alpha1/validate.py | Local schema registry, strict fixture loading, catalogue integrity and template semantic checks, CLI entry |
| schemas/report/v1alpha1/test_validate.py | Checker regression, boundary, branch and capability coverage tests |
| server/internal/events/reportvalidate/catalogue.json | Byte-identical embedded copy of the reviewed snapshot |
| server/internal/events/reportvalidate/catalogue.go | Builtin, Catalogue methods and private strict catalogue loader |
| server/internal/events/reportvalidate/validate.go | Public Result/Error API, stage dispatch and envelope checks |
| server/internal/events/reportvalidate/budget.go | Bounded decoded-domain scan and encoded charge |
| server/internal/events/reportvalidate/structure.go | Schema-equivalent structural checks with deterministic paths |
| server/internal/events/reportvalidate/semantic.go | Names, references, parameter/type/operator/aggregate and output checks |
| server/internal/events/reportvalidate/catalogue_test.go | Embedded-byte drift, permission bindings and hostile catalogue mutations |
| server/internal/events/reportvalidate/validate_test.go | Contract, error, ownership and concurrency tests |
| server/internal/events/reportvalidate/budget_test.go | Bounds and independently calculated charge vectors |
| server/internal/events/reportvalidate/fixtures_test.go | Complete shared-corpus outcomes and generated capability tests |
| server/internal/events/reportvalidate/fuzz_test.go | FuzzValidate and FuzzBudget seed invariants |

No public ParseCatalogue API, runtime override or generator binary. Tests read canonical files using paths anchored by runtime.Caller, never current working directory or a network fetch. Production imports only standard-library packages; tests read permission JSON without crossing module internals. Missing testdata is failure, not skip.

### Task 1: Python checks for the published contracts

**Consumes:** Spec sections 2, 3, 6 and 7; four published design files; schemas/permissions/v1/catalogue.json as read-only metadata.

**Produces:** `validate_template(document) -> list[dict]`, `check_catalogue(document) -> list[str]`, and two executable Python check files. A template result is empty or one exact sentinel/path/rule record.

- [ ] Add `test_validate.py` tests `test_schema_inventory`, `test_fixture_contract`, `test_catalogue_integrity`, `test_permission_bindings`, `test_reference_registry`, `test_precedence`, `test_bounds`, `test_calendar` and `test_capability_matrix`. Test missing/extra files, every schema $ref, duplicate fixture ids and duplicate/nonfinite JSON. Assert fixture structure and full outcomes independently.
- [ ] Run `python schemas/report/v1alpha1/test_validate.py`. Require the intended missing validate module failure and record it before writing validate.py.
- [ ] Implement local registry for exactly the two schema ids. Call Draft202012Validator.check_schema, resolve only bundled references and check every fragment. Reject remote refs, duplicate/nested ids, unresolved fragments and cycles. Never let a schema trigger retrieval.
- [ ] Implement catalogue shape, ordering, complete-source, capability and permission checks. Pin the source binding table from spec section 3 in test expectations; check active role permissions, correct owner and scope, conditional PKI binding and exact footprint enum. Do not infer bindings from source name prefixes.
- [ ] Implement template semantic stages, domain/budget preflight and deterministic diagnostic selection from spec section 6. Use calendar checks without format-checker dependency. The schema pass remains independent; do not use the first jsonschema error as the contract's first error.
- [ ] Add generated tests for every source field, operator and aggregation, all parameter/default/reference sites, mixed selectors and malformed references with exact diagnostics, non-enum parameter fields with absent and explicit defaults, all layout variants, each cap and rejected pair. Validate every expected-positive generated case before deriving its negative; a negative must fail for its intended defect. A same-shaped wrong enum source must fail even when enum values coincide.
- [ ] Run `python schemas/report/v1alpha1/validate.py` and `python schemas/report/v1alpha1/test_validate.py`. Require exit 0, both schemas valid, complete catalogue and fixture/capability counts with no skipped cases.
- [ ] In a temporary Node script, compile every schema pattern with `new RegExp(pattern, 'u')` and compare identifier/locale/control boundary cases with Python, including final LF, four-byte scalars and quoted/backslash text. Record `node /tmp/report-patterns.mjs` and its result.

### Task 2: Immutable catalogue, public API and bounded input

**Consumes:** Reviewed Task 1 results, spec sections 3, 5 and 6, canonical catalogue and fixtures.

**Produces:** Exact Builtin, Catalogue, Result, SourceRequirement, ConditionalRead, Error, six sentinels and Validate signature from spec section 5; private input and charge checks. Validate may still fail valid fixtures until Task 3, but must not claim complete acceptance.

- [ ] Write `TestBuiltin`, `TestBuiltinDrift`, `TestPermissionBindings`, `TestCatalogueIntegrity`, `TestUnavailableCatalogue`, `TestInputDomain`, `TestBudgetBoundaries`, `TestChargeVectors`, `TestErrorRedaction` and `TestCatalogueDetachedJSON`. Use errors.Is/errors.As; require nil/zero catalogue before any input error.
- [ ] Run `cd server && go test -count=1 ./internal/events/reportvalidate -run 'Test(Builtin|Permission|Catalogue|Unavailable|Input|Budget|Charge|Error)'`. Require missing declared API/type errors as the initial failure.
- [ ] Copy with `cp schemas/report/v1alpha1/catalogue.json server/internal/events/reportvalidate/catalogue.json` from the repository root. Implement unexported embed plus private loader and sync.Once initialization. Apply the private-loader bounds in spec section 3 before materializing catalogue state. Reject duplicate keys, trailing documents, invalid UTF-8 and all catalogue shape/integrity errors; return only ErrCatalogue/catalogue. The private loader is not an untrusted runtime input path.
- [ ] Implement the exact API and bounded template scan before structural code. Reject immediate container counts and oversized total key bytes before collecting sort keys; bound string byte lengths before scanning UTF-8. Count aliases per occurrence and stop cycles by depth. Use no marshal round trip and call no input methods. Charge with saturated counters and preserve the spec's preflight order.
- [ ] Test typed nil maps/slices, native ints, json.Number, structs with panic marshalers, pointers, NaN/infinity, out-of-range float64, malformed UTF-8 and cycles. Check root nil reaches envelope after valid catalogue. Include oversized invalid UTF-8 strings, oversized common-prefix keys, equal/larger budget plus bad kind and unavailable catalogue plus huge input.
- [ ] Recompute charge independently in budget_test.go. Assert null=4, true=4, number=24, empty map=2, empty string=2, Vietnamese scalar=5, number array=26, keyed number=30 and quote/backslash/LF string=12. Generate complete otherwise-valid templates at 65536 and 65537 using schema-valid text and assert the boundary through Validate after Task 3.
- [ ] Run the Task 2 test command again and require PASS for implemented stages. Run `cd server && go vet ./internal/events/reportvalidate`.

### Task 3: Complete template structural and semantic validation

**Consumes:** Reviewed catalogue/API/budget implementation and Python reference checks.

**Produces:** Complete Validate(map[string]any, *Catalogue) (Result, error), without caller mutation, external resolution or approval effects.

- [ ] Write `TestFixtureDrift`, `TestAllCapabilities`, `TestBranches`, `TestParameterReferences`, `TestOutputReferences`, `TestErrorPrecedence`, `TestNoMutation`, `TestDetachedResult` and `TestConcurrent`. Iterate every published fixture; compare acceptance, errors.Is, *Error fields and zero Result. Success checks sorted unique sources including unused datasets, catalogue revision and conditional-read slices.
- [ ] Run `cd server && go test -count=1 ./internal/events/reportvalidate`. Record intended failures for valid corpus cases and missing semantic rejection before completing the validator.
- [ ] Implement envelope and closed structural validation in structure.go with tagged branch dispatch. Enforce both locales, exact counts and no unknown properties at every nesting level. Use direct helpers, not a general schema interpreter. Use reference-first dispatch and the operand/reserved-filter branch rules in spec section 6. Missing and forbidden keys retain diagnostic paths.
- [ ] Implement semantic.go stages in order: unique names, complete reference resolution, compatibility, then outputs. Validate enum parameter field types at the field path even when unused or without defaults; skip dependent enum-default checks for non-enum fields. Validate other parameter defaults even when unused. Resolve references independent of declaration order. Never use caller input to choose source ownership, permissions or the PKI condition.
- [ ] Add paired tests for every semantic rejection and nearest accepted case: exact cross-source enum identity, integer versus boolean, string parameters limited to string eq/prefix, nullable-field exists, literal range ordering, leap-year rules, groupability, measure alias/source collisions, order output, table output, grouped KPI, chart dimension count and line/area timestamp x.
- [ ] Exercise every combined-defect vector in spec section 7 and numeric index ordering beyond index 9. Test the same invalid tree repeatedly with randomized insertion order; sentinel/path/rule must match. Ensure Error() contains no key, value or pointer, while escaped Path is exact.
- [ ] Complete generated count and charge boundary tests. Add FuzzValidate and FuzzBudget with fixture and hostile-shape seeds. FuzzValidate caps raw fuzz bytes at 65536 and ordinary decoded trees at spec budgets; FuzzBudget limits its own generated trees and compares a separate charge implementation. Run only seed corpora locally through ordinary tests.
- [ ] Run `python schemas/report/v1alpha1/validate.py`, `python schemas/report/v1alpha1/test_validate.py`, then `cd server && go test -count=1 ./internal/events/reportvalidate`. Require agreement across all published fixtures and generated coverage tables.

### Task 4: Drift hardening and handoff

**Consumes:** All reviewed implementation and test outputs.

**Produces:** Complete light-check evidence, independent oracle results and a CI handoff without workflow edits.

- [ ] Write failing regression tests for uncovered Review focus conditions and explicit fixture inventory completeness. Require at least one accepted fixture per source, all parameter types and layout branches across published and generated cases. Tests must detect removal of coverage, not only validate whatever remains.
- [ ] Run the affected Python and focused Go test commands to observe each intended regression failure. Fill test/implementation gaps, or request reviewed contract corrections for schema gaps, then rerun to PASS.
- [ ] Use two independent /tmp scripts to recompute every published fixture and numeric vector without importing the checker under test. Record both commands and disagreements. Inspect permission binding and row-grain projections manually against the spec and catalogue.
- [ ] In temporary copies, remove vi, allow an unknown operator, change a capability/type pair, remove the PKI conditional read and change the byte cap. Require at least one test failure for each deliberate drift; never leave mutated files in the working tree.
- [ ] Run every light command below, inspect the complete diff and obtain the independent whole-slice Astra xhigh code review with fix confirmation. The reviewer attacks structural/full distinctions, catalogue permission substitutions, source substitution, private-loader misuse, unsafe type assertions, alias confusion and missing footprint metadata, and does not implement fixes. The primary agent checks ownership and remaining query/storage/authority gates before Git integration.

## Final verification

Run each command from the repository root in a fresh shell:

```sh
python schemas/report/v1alpha1/validate.py
python schemas/report/v1alpha1/test_validate.py
cd server && gofmt -l internal/events/reportvalidate
cd server && go vet ./internal/events/reportvalidate
cd server && go test -count=1 ./internal/events/reportvalidate
python server/internal/authz/catalogue/schema_test.py
python server/internal/authz/catalogue/schema_test.py --check-sources
git diff --check
wc -l docs/specs/report-template.md docs/plans/report-template.md
```

Require exit 0 and no gofmt output; apply gofmt only to owned Go files if needed. The source-digest check can fail because this design changes a covered document. Report that failure explicitly; its source inventory/permission refresh belongs to a separate authorized maintenance change, not permission-schema edits here. The ordinary permission structural check must still pass.

Parse every authored JSON file, check all schema examples and fixtures, scan touched documents for em dashes and date/history wording, verify local links and the 400-line spec/plan cap. Recompute every vector independently. No claim of complete implementation precedes fresh passing checks of the implemented paths.

CI handoff to the primary agent: the existing workflow does not discover these new report commands or fuzz targets automatically. A separately authorized workflow change must run both Python report commands, ordinary tests and race tests, and add the following targets to the central fuzz list before integration. Do not edit .github/ or instructions/testing.md within this slice. Require actual CI results for the exact reviewed head; local seed tests do not substitute for this gate.

```sh
cd server && go test -race -count=1 ./internal/events/reportvalidate
cd server && go test -count=1 ./internal/events/reportvalidate -fuzz='^FuzzValidate$' -fuzztime=60s -parallel=2
cd server && go test -count=1 ./internal/events/reportvalidate -fuzz='^FuzzBudget$' -fuzztime=60s -parallel=2
```

The final worker report lists changed paths, tests and exact outcomes, test-first failures, independent reviews, fixture/capability counts, both oracle results, permission-source drift, CI evidence supplied by the primary agent and open consumer gates. Failed, blocked and skipped checks keep those labels.
