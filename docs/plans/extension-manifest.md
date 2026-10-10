# Extension manifest validator implementation plan

> For agentic workers: use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to execute the reviewed tasks in order. Unchecked steps are work to perform, not evidence of completion.

Goal: implement the decoded manifest validator in [the spec](../specs/extension-manifest.md), with schema parity, semantic fixtures, bounded fuzzing and independent adversarial review.

Architecture: one leaf package under `server/internal/extensions/manifest` accepts an immutable decoded tree and trusted caller options. Its success means structural validity only. The spec owns the API, bounds, algorithms and error order; the schema owns the field inventory.

## Global constraints

- An independent Sol xhigh reviewer (`gpt-6.1-sol`, `xhigh`) must approve the spec, plan, schemas and fixtures before code. The design author does not implement or review code for this slice.
- A separate Sol medium implementer (`gpt-6.1-sol`, `medium`) owns only the code paths listed below. The implementer is not alone in the repository and must preserve other workers' edits. Concurrent edits require separate worktrees; these tasks share one package and run sequentially.
- Sol xhigh (`gpt-6.1-sol`, `xhigh`) independently reviews the complete code with an adversarial pass for untrusted decoded input. The implementer resolves findings; a separate Sol xhigh reviewer confirms each fix before dependent work or acceptance.
- The primary agent owns planning, coordination, integration, final verification and all Git operations. Workers never commit or push. Review reports do not replace primary inspection and required checks.
- Installed pins: Go 1.27.1; Rust 1.99.0 and cargo 1.99.0; Node 24.21.0; pnpm 11.18.0. Only Go participates here. Preserve the existing `go 1.27.1` module directive and build configuration.
- Production and test code in this slice use only the Go standard library. Add no dependency or `go.mod`/`go.sum` change. The spec pins `go.yaml.in/yaml/v3` v3.0.4 for the later YAML loader, with a licensing row; do not import it here. That loader verifies authorized DSSE bytes before a token-aware explicit-tag check and one `yaml.Node` decode, then decoded validation. Its separate acceptance tests must consume `loader-vectors.json`, including bare `!` on mappings, sequences and scalars; `TaggedStyle` alone cannot detect every explicit tag.
- Write each test first, run it and record the expected failure, then add the least implementation that passes. A failing build from the missing package is sufficient only for Task 1; later tasks must fail a behavioral assertion.
- No YAML decoder, archive reader, DSSE verifier, trust database, installer, grant store, network request, OS write, code generator or CI change belongs in this slice. Do not implement consumers around unresolved security gates.
- The schema and corpus are reviewed inputs. A discovered contract defect returns to the designer and independent design review; the implementer must not silently rewrite fixtures to match code.
- Follow `instructions/go.md`, `instructions/testing.md` and `instructions/workflow.md`. Every failed check stays failed in the report until a recorded rerun passes.

## Owned files and interfaces

| File | Responsibility |
|---|---|
| `server/internal/extensions/manifest/manifest.go` | Exported options, constants, sentinels and ordered `Validate` orchestration |
| `server/internal/extensions/manifest/tree.go` | Bounded dynamic-tree checks and structural equality |
| `server/internal/extensions/manifest/fields.go` | Closed shape selection and all schema-local constraints |
| `server/internal/extensions/manifest/relations.go` | Reserved ids, duplicate identities, paths, totals, requirements, ownership and capability relations |
| `server/internal/extensions/manifest/metadata.go` | Bounded SPDX grammar and final URL checks |
| `server/internal/extensions/manifest/manifest_test.go` | Direct-value, boundary and combined-defect tests |
| `server/internal/extensions/manifest/fixtures_test.go` | Shared corpus loader and exact sentinel assertions |
| `server/internal/extensions/manifest/fuzz_test.go` | `FuzzValidate` and seed loading |

All helpers remain unexported. Expose exactly `Options`, the spec's constants and sentinels, and `Validate(any, Options) error`. Tests use package `manifest_test` and public behavior. Read fixtures from `../../../../schemas/extension/v1alpha1/fixtures.json` relative to the package test directory. Do not copy them into a second corpus. Use `encoding/json.Decoder.UseNumber`; corpus options decode separately into typed test metadata.

## Review focus

- A malformed decoded tree cannot bypass early bounds by hiding under an unknown field or a cycle.
- A map cannot exploit case-insensitive decoding, duplicate identity, escaped path spelling or ignored capability fields.
- Schema and Go accept exactly the same local shapes; Go also refuses every semantic-negative fixture.
- Every adjacent error stage has a combined-defect test, including options before tree and tree before shape.
- `AllowReservedID` is caller authority, never read from the manifest, inferred from its display name or accepted fingerprint.
- Digest grammar does not claim hash verification, key validity, ownership, tombstone enforcement or grants.
- Requested connector destinations and browser policy names cannot trigger network access or OS writes.

## Task 1. API, decoded tree and schema-local validation

Consumes: spec sections 1 through 3 and 6; the complete manifest schema. Produces: the API, bounded preflight, exact shape/field validation and no success for incomplete fields.

- [ ] Write `TestOptions`, `TestTreeTypes`, `TestTreeBudgets`, `TestTreeCycles`, `TestShape`, `TestFields`, `TestLocalBoundaries` and `TestLocalPrecedence` before implementation. Enumerate the schema's required and forbidden keys, branch discriminants, constants, enums, patterns, number bounds, length bounds, object cardinality (`minProperties`) and `uniqueItems`. Accept `listDeviceSoftware`; reject `getDeviceSoftware` both alone and alongside `listDeviceSoftware`. Require `ErrField` for empty `spec.requires` and browser `capabilities.os`, including each combined with a reserved id; require `ErrShape` when either empty object also has an unknown key elsewhere. Include both ordinary and typed nils, invalid UTF-8, raw integer/float types, canonical and noncanonical `json.Number`, alias types and huge shallow containers.
- [ ] Run `cd server && go test ./internal/extensions/manifest -run 'Test(Options|Tree|Shape|Fields|Local)' -count=1`. Record the missing implementation failure.
- [ ] Implement `manifest.go`, `tree.go` and `fields.go` for stages 1 through 4. Inspect container lengths before iteration and stop counters before overflow. Use whole-string grammar checks and explicit branch selection. Traverse all shape checks before field checks. Do not coerce values, rewrite strings or mutate arrays.
- [ ] Run the same focused command. Require PASS. Add `TestNoMutation` and a repeated/reordered-map test proving that validation does not depend on map iteration order; run `cd server && go test ./internal/extensions/manifest -run 'Test(NoMutation|LocalPrecedence)' -count=20` and require PASS.
- [ ] Have an independent Sol xhigh reviewer inspect the task before Task 2. Resolve findings through the implementer and obtain independent fix confirmation. The primary agent inspects the diff and reruns the focused command.

Boundary assertions must test all individual schema bounds, not only example values. A field is invalid at one beyond its maximum even when the whole tree is below its budget. Separate tests exercise the tree budget before shape errors. Test exact duplicate array objects against `ErrField`; unequal objects sharing an identity belong to Task 2.

## Task 2. Namespace, file and capability relations

Consumes: Task 1's ordered stages and spec sections 3 through 6. Produces: stages 5 through 11 and all cross-reference checks.

- [ ] Write `TestReservedID`, `TestDuplicateIdentities`, `TestPortablePaths`, `TestFileTotals`, `TestRequires`, `TestFileOwnership`, `TestCapabilityRelations` and `TestSemanticPrecedence`. Include every semantic-negative corpus case for these stages, all reserved DOS stems, prefix collisions, missing entry/row-schema references, component-owned attestations and mixed packages with multiple worlds/contracts.
- [ ] Run `cd server && go test ./internal/extensions/manifest -run 'Test(Reserved|Duplicate|Portable|File|Requires|Capability|Semantic)' -count=1`. Record behavioral failures showing invalid documents accepted or the wrong sentinel returned.
- [ ] Implement `relations.go`. Check the reserved id with exact equality or a dot boundary. Build bounded indexes without changing input order. Subtract before adding to the configured byte ceiling. Compare exact requirement sets and enforce one owner per listed non-attestation file. Apply collector relations only after reference validity.
- [ ] Run the same command and require PASS. Run `cd server && go test ./internal/extensions/manifest -count=1` and require PASS for Tasks 1 and 2 together.
- [ ] Obtain independent Sol xhigh review and independent fix confirmation. The primary agent inspects the changes and reruns package tests before Task 3.

Tests distinguish a valid reserved id with `AllowReservedID=true` from proof of publisher authority, which this API cannot supply. Include package-level unknown `allow_reserved_id`, grants, targets, trust and ownership fields, all of which fail. Passing fingerprints never change namespace permission.

## Task 3. License, URL and complete fixture parity

Consumes: Tasks 1 and 2, spec sections 3 and 6, and the complete shared corpus. Produces: stages 12 and 13, a corpus test and pairwise precedence tests across every stage.

- [ ] Write `TestLicenseExpression`, `TestMetadataURL`, `TestFixtures`, `TestAllStagePrecedence` and `TestErrorText`. The corpus loader maps every named error to the exported sentinel, rejects duplicate case names and unknown expectations, and calls `errors.Is` rather than comparing error strings. Positive cases must return nil. Never skip a case because its JSON Schema result is true or false.
- [ ] Run `cd server && go test ./internal/extensions/manifest -run 'Test(License|MetadataURL|Fixtures|AllStage|ErrorText)' -count=1`. Require and record the behavioral failures for malformed SPDX and URL cases.
- [ ] Implement `metadata.go` with the spec's bounded expression grammar and host/port/escape checks. Add no remote SPDX lookup, URL fetch or network validation. Complete `Validate` in the exact order, wrapping one sentinel without attacker-controlled values.
- [ ] Run the same command and require PASS. Run `cd server && go test ./internal/extensions/manifest -count=20` to exercise map-order independence.
- [ ] Independently recompute the public-key fingerprint and both file vectors in test code with `crypto/sha256`. Check that corpus positives use those values; do not derive expected values with the code under test. Exact file bytes are the corpus UTF-8 strings, with no added newline.
- [ ] Obtain independent Sol xhigh review and fix confirmation; the primary agent inspects and reruns package tests.

JSON Schema evaluation remains a design/tooling check, not a runtime dependency. The Go tests exercise every local schema keyword through table tests and every corpus semantic expectation. If schema and Go disagree, report the case and determine whether it is one of the spec's declared semantic-only constraints before changing code.

## Task 4. Fuzzing, adversarial review and final verification

Consumes: the complete validator. Produces: bounded fuzz coverage and the review evidence needed for integration.

- [ ] Add `TestFuzzInvariants` before any needed fixes. It supplies direct cycles, invalid types, aliases, long numeric lexemes and combined defects to assert no panic, deterministic sentinel and unchanged input. Run `cd server && go test ./internal/extensions/manifest -run TestFuzzInvariants -count=1`; record a failing assertion before changing production code for any discovered defect.
- [ ] Add `FuzzValidate` as specified in spec section 8. Use all small corpus manifests as seeds, arbitrary caller options, JSON decode with `UseNumber`, bounded input length and map-key reordering. Keep generated cap-sized inputs in unit tests rather than the fuzz seed corpus.
- [ ] Run `cd server && go test ./internal/extensions/manifest -fuzz=FuzzValidate -fuzztime=5s -parallel=2`. Require PASS and retain useful minimized failures under this package's `testdata/fuzz/FuzzValidate/` only after independent review.
- [ ] Run `cd server && gofmt -w internal/extensions/manifest` then `cd server && gofmt -l .`; the second command must print no files. Review formatting changes within the owned paths only.
- [ ] Run `cd server && go test ./...`, `cd server && go test -race ./...` and `cd server && go vet ./...`. Require PASS or exit 0 for each. Do not equate a successful focused suite with full module verification.
- [ ] Run all existing bounded Go fuzz commands from `instructions/testing.md` with their exact 5-second, parallel-2 budgets, plus `FuzzValidate` above. Record each command and result. Ordinary test execution covers fuzz seeds; it does not replace the bounded runs.
- [ ] Run `git diff --check` from the repository root. Inspect the complete code diff against the approved spec, schema and plan, including unauthorized paths and dependency changes.
- [ ] Obtain the independent Sol xhigh whole-slice code review and adversarial pass. Attack graph exhaustion, precedence masking, path aliasing, namespace authority confusion, integer overflow and semantic/schema drift. Resolve findings through the implementer, then obtain separate Sol xhigh fix confirmation and rerun affected checks.
- [ ] The primary agent inspects the final diff and records exact commands, outcomes and limitations before any Git operation under the workflow.

These checks establish portable decoded validation only. They do not establish YAML safety, cryptographic trust, archive safety, stateful admission, OS support or any runtime qualification. The production consumers named in spec section 1 remain separate reviewed slices.
