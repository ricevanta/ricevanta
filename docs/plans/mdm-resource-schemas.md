# MDM Resource Schemas Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Go decoded-resource validation against the published MDM schemas, fixtures and Python design checks.

**Architecture:** JSON Schema plus Python semantic checks define the design CI acceptance path. A standard-library leaf package mirrors that contract, with fixture drift tests that run without Python or schema retrieval inside Go.

**Tech Stack:** Go 1.27.1; existing Python design dependencies. No added module dependency.

**Spec:** [MDM resource schemas](../specs/mdm-resource-schemas.md), including its unresolved choices and native execution blockers.

## Global constraints

- An independent Sol xhigh review approves the spec, plan, published schemas, fixtures and design checks before consumer implementation. A reviewer never implements the slice reviewed.
- A separate Sol medium implementer, `gpt-6.1-sol` at `medium`, owns the paths below. The design author does not implement them. Every code review and fix confirmation uses `gpt-6.1-sol` at `xhigh`.
- Sol xhigh independently reviews each task before dependent work starts and the complete slice before integration. Include an adversarial pass because this code accepts untrusted trees and classifies privileged configuration. Obtain independent fix confirmation after implementation changes.
- The primary agent owns planning, verification, worktrees and Git. Workers never commit or push. Give each worker the approved spec, plan, exact owned paths, forbidden actions, required commands and report contract. Keep concurrent edits in separate worktrees; the tasks here run sequentially because they share contracts.
- Installed versions: Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 with pnpm 11.18.0. Rust is not used in this slice. Node checks schema-pattern parity in ECMAScript Unicode mode during contract verification. Keep the existing `server/go.mod` directive `go 1.27.1`; do not add a toolchain directive or alter existing dependencies.
- Keep exact design pins: `jsonschema==4.25.1`, `PyYAML==6.0.3`, `rfc3339-validator==0.1.4`, `six==1.17.0`. No dependency, licensing, build-file or `.github/` changes. `referencing` is the existing jsonschema dependency, not a new direct dependency.
- Write a failing test first, run it and record the intended assertion or missing-interface failure, then write the least implementation that passes. Unrelated environment failures do not establish the test-first step.
- Consume validate.py and test_validate.py as published design checks without changing Policy/Exception acceptance. Preserve existing schema and fixture files. MDM errors use prefixed entries in expected-errors.json and full outcomes in the MDM manifest.
- No API handler, database, native executor, SQL/CEL compiler, signing, approval journal or evidence-recovery implementation. No secret values. Keep validation helpers used only for design experiments in `/tmp`.
- Documents describe current state without dates, history wording or em dashes. A spec or plan stays at most 400 lines. Link to the spec instead of repeating field rules.

## Review focus

- A report policy or false author flag must not turn polkit, systemd, raw files, software, profiles or CSP settings into unprotected publication. Published classification tests and Task 2 result tests cover this.
- Unknown properties inside a union branch must not disappear during decoding or make oneOf accept the wrong OS, source or signature. Published schema checks and Task 2 test every branch and foreign field.
- A structural schema pass must not bypass duplicate-id, byte-budget, registry-path, unsigned-exception or field-relation checks. Published Python checks and Task 2 test full and structural expectations separately.
- A failed resource must return zero Result and deterministic errors without logging privileged bytes. Task 2 tests combined defects, mutation, aliasing and hostile decoded Go types.
- CSP namespace checks must accept Device and User with identical segment rules. Version checks must use the spec's fixed excluded scalar set, including U+0085 and U+FEFF, without language whitespace predicates. Task 1 checks Python and ECMAScript Unicode-mode patterns; Task 2 checks all shared Version fields and both CSP namespaces.
- Shared fixture success must not hide correlated validator mistakes, missing fixture coverage or untested boundaries. Published Python checks and Task 3 use independent budget oracles, manifest completeness and focused mutations.

## Published design inputs

The implementer consumes these files. Schema or fixture changes require a reviewed contract correction, not silent adjustment to match Go output.

| Paths under `schemas/policy/v1alpha1/` | Contract |
|---|---|
| `mdm-common.schema.json` | Shared definitions and metadata intersection |
| `baseline.schema.json`, `software-package.schema.json`, `device-group.schema.json` | Closed resource roots and platform variants |
| `baseline/<kind>.json` | All 17 settings schemas and effect/protection annotations |
| `fixtures/mdm/manifest.json`, `fixtures/mdm/{valid,invalid}/*.json` | Structural and full outcomes with exact sentinel, path and rule |
| `fixtures/expected-errors.json` | Existing Policy/Exception paths and prefixed MDM error paths |
| `validate.py`, `test_validate.py` | Local schema registry, full Python validation and design CI checks |

## Owned implementation files

| Paths | Responsibility |
|---|---|
| `server/internal/mdm/resourcevalidate/validate.go`, `budget.go`, `baseline.go`, `software.go`, `group.go` | Public API, bounded traversal and private resource validators |
| `server/internal/mdm/resourcevalidate/validate_test.go`, `budget_test.go`, `fixtures_test.go`, `fuzz_test.go` | Unit, drift, boundary and fuzz tests |

Do not modify another path without a reviewed scope amendment. No package initializer reads files; fixture I/O exists only in tests. Keep the shared schema fixture directory as testdata, without copying the corpus. The implementer creates no generator or command binary.

### Task 1: Verify the published contract

**Consumes:** Spec sections 2..8 and every published design input above.

**Produces:** Verification evidence and an independently reviewed contract ready for the Go consumer. This task authors no schemas or fixtures.

- [ ] Run `python schemas/policy/v1alpha1/validate.py` and `python schemas/policy/v1alpha1/test_validate.py`. Require PASS, 23 schemas, five resource kinds and both structural and full fixture agreement.
- [ ] Inspect all 17 item annotations, every SoftwarePackage matrix row and group selector operator. Check the manifest and expected-errors index against fixture inventory.
- [ ] Recompute every fixture outcome with a separate temporary script that imports no validator helpers. Check the four exact budget vectors and generated settings/root cap boundaries, including multibyte strings and control escapes. Record both command results and every discrepancy.
- [ ] Obtain independent Sol xhigh approval of the spec, plan, schemas, fixtures and Python checks. Include malformed local references, manifest omissions, privileged kinds, unsigned exceptions and combined defects. Resolve contract defects through the designer and confirm fixes independently before Task 2.

### Task 2: Go decoded-resource validator

**Consumes:** Spec sections 6..8, published reviewed schemas, full Python checks and the shared corpus.

**Produces:** Exact `Validate(map[string]any) (Result, error)`, Result, Error and five sentinels from the spec. Private helpers belong in the five implementation files in the ownership table. No Go module or public service changes.

- [ ] Write `TestValidateFixtures`, `TestValidateErrorPrecedence`, `TestValidateInputDomain`, `TestValidateBudgetBoundaries`, `TestValidateClassification`, `TestValidateNoMutation`, `TestValidateNoAliases`, `TestValidateConcurrent`, `TestErrorRedaction` and `TestFixtureDrift`. Use errors.Is and errors.As, assert zero Result for every rejection, input-order ApplyItemIDs for success and nil when absent.
- [ ] Include tests for nil map, nil typed collections, unsupported ints/json.Number/structs/custom marshalers, NaN/infinity, unsafe integers, invalid UTF-8, cycles, shared subtrees, negative zero and fractional values. Nil map is an envelope failure, nil slice is not an array in the decoded domain and must be ErrInput; no custom marshaler method may run. Test zero and maximum counts plus Unicode scalar/byte differences.
- [ ] Run `cd server && go test ./internal/mdm/resourcevalidate` and record the expected missing Validate/types failure. Do not implement before observing it.
- [ ] Implement bounded input traversal and budget accounting first, then the envelope and per-resource checks. Return redacted *Error values with sentinel causes. Use explicit switches for discriminators and small rule helpers, not reflection-based serialization, schema retrieval or a generic schema interpreter. Type assertions cannot panic. Keep returned slices detached from input.
- [ ] Mirror required/unknown-field and branch rules with deterministic location ordering. Apply semantic rule groups only after all structural checks pass. Classification comes from a closed kind table, never from input annotations. Preserve query, polkit and directive text as input without executing or normalizing it.
- [ ] Add `FuzzValidate` and `FuzzBudget` exactly as specified, with fixtures and all combined-defect cases as seeds. Use a simple independent charge oracle in budget_test.go. Test that a larger budget failure wins over an invalid kind and a structural error wins over a duplicate id.
- [ ] Run `cd server && go test ./internal/mdm/resourcevalidate` and require PASS. Run `python schemas/policy/v1alpha1/validate.py` from the root; both languages must agree on every fixture. No difference may be resolved by changing only the manifest expectation without checking the spec.
- [ ] Obtain independent Sol xhigh code review with an adversarial pass over all new Go/Python code and schemas. Resolve defects through the implementer; independent fix confirmation gates Task 3.

### Task 3: Drift hardening and whole-slice verification

**Consumes:** All preceding reviewed outputs.

**Produces:** A complete checked corpus, meaningful regression tests and verification evidence. This task changes only owned Go test paths. A shared schema or fixture coverage gap returns to the designer for a reviewed contract correction.

- [ ] Write failing regression tests for any uncovered Review focus condition. Add Go fixture completeness tests that fail after removing a branch's only positive fixture or its paired negative. Manifest records identify files, so coverage expectations live in explicit test tables keyed by kind/platform/source branch rather than an undocumented filename convention.
- [ ] Run `python schemas/policy/v1alpha1/test_validate.py` and `cd server && go test ./internal/mdm/resourcevalidate` to observe each new regression before filling the coverage gap. Require intended failures, then obtain a reviewed design correction for corpus gaps and require PASS.
- [ ] Exercise deliberate schema/Go drift in temporary copies: weaken a protected annotation, accept an unknown field, remove an OS branch and change a numeric boundary. Require at least one corresponding test failure for each mutation, restore the original files and rerun ordinary checks. Do not leave mutation scripts in the repository.
- [ ] Run every Final verification command below and inspect the complete diff. Passing pure-library tests establishes portable input validation only, not native support on macOS ARM64, Windows x64 or Linux x64.
- [ ] Obtain a whole-slice independent Sol xhigh review including schema/Python/Go agreement, ownership, native blockers and error precedence. Require independent confirmation of fixes and fresh checks for changed paths. The primary agent handles any integration and Git workflow after acceptance.

## Final verification

Run from the repository root unless a command begins with `cd server`:

```sh
python schemas/policy/v1alpha1/validate.py
python schemas/policy/v1alpha1/test_validate.py
cd server && gofmt -w internal/mdm/resourcevalidate
cd server && gofmt -l .
cd server && go test ./...
cd server && go test -race ./...
cd server && go vet ./...
cd server && go test ./internal/mdm/resourcevalidate -fuzz=FuzzValidate -fuzztime=5s -parallel=2
cd server && go test ./internal/mdm/resourcevalidate -fuzz=FuzzBudget -fuzztime=5s -parallel=2
git diff --check
```

Each command runs in a fresh shell rooted at the repository; the cd commands are not one sequential shell block. Require exit 0 for each and no gofmt -l output. Ordinary Go tests run all seed corpora; timed fuzzing is bounded and does not replace the race check. Run the existing bounded fuzz commands in `instructions/testing.md` before final code review, preserving their 5-second and parallelism-2 bounds.

Parse every new JSON file. Check every touched Markdown file's line count and scan for em dashes, date and history wording. Inspect relative links and run the existing design/spec limit and agent TOML syntax check from design CI without changing CI. The primary agent reruns required checks after integration.

The report lists touched files, exact commands and outcomes, independent review results, fixture/branch coverage, both budget oracle results and remaining native/compiler blockers. Failed and skipped checks stay labeled failed and skipped. No claim of code completion precedes those results.
