# ExportDestination Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate ExportDestination authoring resources in design CI and a standard-library-only Go package.

**Architecture:** The reviewed schema and shared fixtures define the wire-shaped resource. A Python sibling runner checks schema outcomes; an internal Go leaf package mirrors the predicates over decoded JSON and compares errors against the same fixtures.

**Tech Stack:** Go 1.27.1 standard library; Python design tooling at existing exact pins.

**Spec:** [ExportDestination schema](../specs/export-destination-schema.md).

## Global constraints

- An independent Sol xhigh (`gpt-6.1-sol`, `xhigh`) review must approve the spec, schema, fixtures and this plan before code starts. Review the configuration and secret boundaries adversarially. Candidate questions in spec section 10 receive explicit review dispositions; unresolved runtime gates remain blocked.
- A separate Sol medium implementer (`gpt-6.1-sol`, `medium`) owns the code paths below. The designer and reviewer do not implement. Each fix requires independent Sol xhigh confirmation; the reviewer never writes the fix.
- The primary agent owns Git, final diff inspection and required checks. Workers never commit or push. Concurrent editors use separate worktrees and disjoint paths. These tasks run sequentially because CI and Go consume Task 1's runner and fixture conventions.
- Preserve module `github.com/ricevanta/ricevanta/server`, `go 1.27.1`, and no `toolchain` directive. CI pins Go 1.27.1.
- Installed toolchains: Go 1.27.1; Rust 1.99.0 with cargo 1.99.0; Node 24.21.0 with pnpm 11.18.0. Rust and Node require no changes or builds for this slice.
- Existing direct design pins remain `jsonschema==4.25.1`, `PyYAML==6.0.3`, `rfc3339-validator==0.1.4`, `six==1.17.0`. Add no dependency; preserve the requirement file. No Go JSON Schema library or licensing edit is needed.
- Write the failing test first and record its expected failure before the least implementation that passes it. Do not infer correctness from fixture regeneration.
- No secret reads, adapters, byte/YAML parser, CEL compiler, normalization API, network calls, database, approval workflow, secret resolver or delivery-plan consumer belongs here. Keep every later gate in spec section 1 blocked.
- This plan authorizes implementation paths only after review. The design author edits only task-owned documents and schema artifacts, not Python, Go or `.github/` files.

## Review focus

- Unknown nested keys and wrong adapter blocks fail even for disabled destinations; Go must not drop them through struct decoding.
- Whole-string matching rejects trailing newlines; integral floats and Unicode character lengths match Python semantics.
- Missing credentials, workload identities, OTLP header references, UDP/TLS mismatches and connector overrides follow the exact error stages.
- Projection ancestors cannot erase event identity; class selection never treats spool classes as OCSF classes.
- Invalid Unicode, cyclic decoded trees, huge containers and budget boundaries fail without logging hostile values or allocating beyond the stated bound.
- Successful shape validation never becomes authorization, secret resolution, CEL admission or a delivery claim.

---

### Task 1: Schema fixture runner and design CI

**Files:**

- Create: `schemas/export/v1alpha1/validate.py`
- Test: `schemas/export/v1alpha1/test_validate.py`
- Modify: `.github/workflows/design.yml`
- Consume: `schemas/export/v1alpha1/export-destination.json`, `fixtures.schema.json`, `fixtures.json`
- Consume examples: `docs/specs/export-destination-schema.md`, `docs/specs/event-export.md`
- Consume class source: `docs/specs/ocsf-profile.md` sections 1 and 2

**Interfaces:**

- `validate.py` exposes `validate(root: pathlib.Path) -> list[str]` and `main() -> int`. `validate` returns safe failure labels, never fixture content. `main` prints counts on success, labels to stderr on failure, and returns 0 or 1.
- `test_validate.py` uses `unittest`, temporary repository-shaped copies and the callable validator. It exits nonzero on a failed assertion.
- Later tasks use the checked-in fixture manifest unchanged. Python asserts valid/invalid; Go asserts exact sentinel names. Both reject duplicate case IDs.

- [x] **Step 1: Write failing runner tests.** Add tests for valid checked-in input; missing exact schema filename; broken local reference; duplicate ID; empty manifest; missing one of the ten adapter positives; flipped positive and negative expectations; absent negative sentinel; unknown sentinel; a complete example that fails; absence of an example; and changed class enum with an unchanged profile. Require all failures to return labels without a synthetic canary.
- [x] **Step 2: Record the expected failure.** Run `python schemas/export/v1alpha1/test_validate.py`. Expect an import failure because the runner is absent, not a missing jsonschema dependency.
- [x] **Step 3: Implement the sibling runner.** Follow the local registry pattern in `schemas/policy/v1alpha1/validate.py`; load `export-destination.json` explicitly and metaschema-check both contracts. Use a `referencing.Registry` containing only the two local schemas and a retrieval function that refuses any URI. Validate the manifest before accessing cases. Compare every outcome and required positive adapter coverage. Traverse references so a dangling reference fails even in a branch unused by fixtures.
- [x] **Step 4: Check profile and examples.** Read the Class column of the section 1 profile table and Class rows in section 2, qualify extension classes with `ricevanta/`, and compare that set with `$defs.class.enum`. Ignore attribute and object rows. Scan complete fenced JSON/YAML resource examples in both specs, reject unknown kinds, and require at least one ExportDestination example. Use the existing pinned PyYAML for YAML. Do not parse unrelated prose or incomplete field fragments as resources.
- [x] **Step 5: Run the runner tests and fixture checks.** Run `python schemas/export/v1alpha1/test_validate.py` then `python schemas/export/v1alpha1/validate.py`. Expect PASS and all cases plus the example validated. Run `python schemas/policy/v1alpha1/validate.py` and `python schemas/policy/v1alpha1/test_validate.py`; both must remain passing.
- [x] **Step 6: Extend design CI.** Add a named ExportDestination validation step running both new Python commands after existing policy validation. Existing `schemas/**` and `docs/**` path filters already cover the slice; do not broaden triggers or change unrelated jobs. Add the export spec and plan to line-limit checking if the existing job still omits plans, scoped to this plan rather than enforcing a new repository-wide policy.
- [x] **Step 7: Obtain independent Sol xhigh review.** The reviewer checks the schema and fixture handling, local-only resolution, missing-file failures, class extraction and absence of canary output. The implementer fixes findings; a separate Sol xhigh reviewer confirms each fix before Task 2.

### Task 2: Decoded Go resource validator

**Files:**

- Create: `server/internal/events/exportdest/validate.go`
- Create: `server/internal/events/exportdest/common.go`
- Create: `server/internal/events/exportdest/adapters.go`
- Test: `server/internal/events/exportdest/validate_test.go`
- Test: `server/internal/events/exportdest/fixtures_test.go`

**Interfaces:**

- Consumes: ordinary decoded JSON values and the schema predicates in spec sections 2 to 6.
- Produces: `Validate(resource any) error` and the seven sentinels named in spec section 6. No other public API is needed.
- `validate.go` owns preflight, envelope, adapter dispatch and error ordering. `common.go` owns common-field validation; `adapters.go` owns block and cross-field rules. Private helper signatures are implementer choices.

- [x] **Step 1: Write failing tests.** Add `TestFixtureDrift`, `TestPreflight`, `TestPrecedence`, `TestNoMutation`, `TestNoInputInErrors`, `TestNumericSemantics`, `TestWholeStringPatterns`, `TestUnicodeLengths`, `TestClosedObjects`, `TestDefaultsAndNull`, `TestProjectionProtection`, `TestAuthCombinations` and `TestParameterBoundaries`. Use all shared fixtures and every boundary and generated mutation class in spec section 7. Read the manifest at `../../../../schemas/export/v1alpha1/fixtures.json` from the package directory; do not copy fixtures into the module.
- [x] **Step 2: Record the expected failure.** Run `cd server && go test ./internal/events/exportdest`. Expect undefined Validate and sentinels. Keep malformed byte-parser cases out of this API's acceptance tests; test the decoded values that actually cross its boundary.
- [x] **Step 3: Implement preflight and stages.** Build bounded tree checks before any schema predicates. Check and charge aggregate key byte lengths before UTF-8 scanning or sorting at most 8192 keys per object. Include the long-common-prefix and invalid-key precedence cases in spec section 7. Preserve depth, node and UTF-8 byte accounting, typed-nil refusal and sentinel precedence from spec section 6. No mutation, retained input or formatting of unsupported values is allowed.
- [x] **Step 4: Implement common and adapter predicates.** Match schema closures, bounds, integer semantics and regex behavior with whole-string matching. Use rune counts for schema string lengths. Implement each adapter block and then its credential/endpoint/archive/byte-cap combinations in the prescribed stage. Do not rely on schema defaults or attempt network checks. Use only standard-library imports.
- [x] **Step 5: Run focused tests.** Run `cd server && go test ./internal/events/exportdest -count=1`. Expect PASS for every fixture and all mutation/boundary tests. Confirm errors.Is matches the named sentinel and all canaries remain absent from returned errors.
- [x] **Step 6: Obtain independent Sol xhigh code review.** Review against the complete schema, not just fixtures. Adversarially inspect every authentication branch, alternate spelling, whole-string match, projection ancestor, preflight budget and combined defect. The implementer resolves findings, with a separate Sol xhigh fix confirmation before Task 3.

### Task 3: Fuzzing, cross-language drift and CI integration

**Files:**

- Test: `server/internal/events/exportdest/fuzz_test.go`
- Modify: `.github/workflows/server.yml`
- Modify: `instructions/testing.md`
- Check: the ExportDestination schema-presence and implementation-status statement in `docs/specs/policy-envelope.md` section 8

**Interfaces:**

- Consumes: Task 1's runner, Task 2's `Validate` and sentinels, unchanged shared fixtures.
- Produces: `FuzzValidate`, `FuzzDecoded`, and explicit CI coverage of schema changes against the Go mirror.

- [x] **Step 1: Write failing drift coverage tests.** Add `TestSchemaMutationCoverage`: construct the required mutations using literal expected outcomes from the spec; check that all adapter auth modes and all common fields have at least one required boundary or negative test. Deliberately change a fixture expectation in a temporary manifest and prove the drift harness fails. Restore the test input before implementation; never rewrite the source fixture's expected values to make tests pass.
- [x] **Step 2: Record the expected failure.** Run `cd server && go test ./internal/events/exportdest -run TestSchemaMutationCoverage -count=1`. Expect failure naming a missing coverage category if Task 2 omitted one. If all categories already pass, introduce the test's controlled temporary wrong expectation and verify rejection; do not modify production code just to manufacture failure.
- [x] **Step 3: Add fuzz targets.** Implement both targets exactly as spec section 7 requires. Cap fuzz JSON bytes at 262144 before decoding; seed every shared case. Ensure a cyclic tree is never marshalled by a test oracle. Compare sentinel identity across repeated runs; do not compare incidental error strings as the acceptance oracle.
- [x] **Step 4: Run bounded fuzzing.** Run `cd server && go test ./internal/events/exportdest -fuzz=FuzzValidate -fuzztime=5s -parallel=2` and `cd server && go test ./internal/events/exportdest -fuzz=FuzzDecoded -fuzztime=5s -parallel=2`. Require PASS; report duration and any minimized inputs.
- [x] **Step 5: Wire Go schema drift triggers.** Inspect the existing server workflow. Add `schemas/export/**` to both push and pull-request path filters so changing the schema runs `TestFixtureDrift`; keep existing triggers and jobs. Run the Python export checks in that workflow before the existing Go checks, with the existing exact design requirement pins, so neither mirror can pass alone. Preserve native platform jobs and pinned action revisions.
- [x] **Step 6: Document checks and verify implementation status.** Add both fuzz commands to `instructions/testing.md`. The policy envelope section 8 identifies the ExportDestination schema and its Go validation and CI integration; the S3 plan, replay and receipt schemas and delivery remain later gates. The primary agent must not claim Go validation exists until the code and CI tasks pass. Preserve all other missing-resource gates.
- [x] **Step 7: Obtain final independent Sol xhigh review.** Include an adversarial pass because the package validates untrusted data. Confirm every spec rule has a test or an explicit downstream gate; resolve findings through the implementer and independent fix confirmation.

## Final verification

Run from the repository root unless the command begins with `cd server`.

- [x] `python schemas/export/v1alpha1/validate.py`
- [x] `python schemas/export/v1alpha1/test_validate.py`
- [x] `python schemas/policy/v1alpha1/validate.py`
- [x] `python schemas/policy/v1alpha1/test_validate.py`
- [x] `cd server && gofmt -w internal/events/exportdest`
- [x] `cd server && gofmt -l .`, requiring no output.
- [x] `cd server && go test ./...`
- [x] `cd server && go test -race ./...`
- [x] `cd server && go vet ./...`
- [x] Run both new fuzz commands in Task 3 and all existing bounded Go fuzz commands in `instructions/testing.md`, each for 5 seconds and `-parallel=2`.
- [x] `git diff --check`; inspect the full diff and require only approved paths and no secret material.
- [x] `wc -l docs/specs/export-destination-schema.md docs/plans/export-destination-schema.md`; require each at most 400 lines.
- [x] Check local links, schema reference resolution, absence of em dashes and date/history prose in changed text. Report pre-existing findings separately.

The primary agent reports exact commands and results, reviewer dispositions and remaining runtime gates. No Go, Python runner, CI or delivery test is considered complete solely because this plan exists.
