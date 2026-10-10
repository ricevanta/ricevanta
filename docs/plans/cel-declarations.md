# CEL Declarations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded, standard-library Go loader for the reviewed CEL declaration catalogue.

**Architecture:** One leaf package owns strict JSON parsing, declaration validation and immutable catalogue views. It embeds the reviewed catalogue and rejects semantic changes under its supported version tuple. It performs no compilation or evaluation.

**Tech Stack:** Go 1.27.1 and its standard library. Fixture checks use Python `jsonschema==4.25.1` outside the Go runtime.

**Spec:** [CEL variable declarations](../specs/cel-declarations.md). That spec and `schemas/cel/v1/` travel with every implementation and review brief.

## Global constraints

- An independent Sol xhigh reviewer must approve the spec, plan, schema and fixtures before code starts. This document is review-ready, not a record of approval.
- A separate Sol medium implementer (`gpt-6.1-sol`, `medium`) owns all code paths below. The design author and reviewers do not implement this slice.
- Sol xhigh (`gpt-6.1-sol`, `xhigh`) reviews code, including an adversarial pass over untrusted JSON parsing, resource bounds, error precedence and catalogue replacement. Each fix requires independent Sol xhigh confirmation from a reviewer who did not write it.
- Go 1.27.1 is the module minimum, locally installed version and exact CI pin. Preserve the module and dependency pins in `server/go.mod`; add no dependency and no `toolchain` directive.
- The installed companion toolchains are Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0. They are not used by this Go slice. Python validation pins `jsonschema==4.25.1`; installed `cryptography==50.0.0` is not used.
- cel-go remains a later dependency at the profile's `v0.32.0` pin, subject to the spec's `verify` gate. Add no cel-go, protobuf, JSON Schema Go dependency, compiler, evaluator, command, database, API endpoint or runtime value validator.
- Use one isolated implementation worktree. Tasks are sequential because they share parser and document types. Other workers are not alone in the repository; do not revert their edits. If ownership conflicts arise, the primary agent coordinates separate worktrees.
- Read `AGENTS.md`, `instructions/go.md`, `instructions/testing.md`, `instructions/workflow.md`, the spec and machine assets before editing. Do not edit the approved contract to make a test pass.
- Write each test first and record its expected failing result before implementation. A compilation failure is sufficient for an absent API; subsequent tasks require behavior-specific failures.
- The primary agent owns Git operations, integration and final verification. Workers never commit or push. This plan authorizes only the code paths listed below; no build or CI changes are required.
- The source-schema and CEL-integration gates in spec sections 3 and 7 block those consumers, not this loader. Passing package tests cannot close those gates or establish platform support.

## Review focus

- A schema-valid declaration that weakens certificate presence or adds a variable to another domain must fail `ErrCatalogue`.
- Duplicate escaped keys, invalid Unicode, case-insensitive matches and noncanonical number spellings must not pass through Go decoder defaults.
- A combined defect must return the first phase's sentinel regardless of map order, including a later syntax defect after an earlier duplicate.
- Size, token, nesting and graph bounds must hold before recursive expansion or unbounded reading; integer conversion must not overflow.
- Returned maps, slices and type pointers must not let a caller alter the trusted document or another concurrent reader's result.
- Successful declaration loading must not imply that schema-backed maps are ready for compilation, that runtime data is trustworthy or that bundle replay is prevented.

## Files and ownership

The implementer owns only `server/internal/policy/celdecl/`:

| File | Responsibility |
|---|---|
| `types.go` | Exact exported view types and private `Document` |
| `errors.go` | Exact sentinel names and text |
| `parse.go` | Byte/token/depth bounds, strict JSON scan and phased validation |
| `catalogue.go` | Embedded trusted catalogue, structural equality, snapshots and environments |
| `variables.json` | Byte-identical copy of `schemas/cel/v1/variables.json` |
| `parse_test.go` | Fixture, grammar, Unicode, boundary and precedence tests |
| `load_test.go` | Reader behavior and read-error precedence |
| `catalogue_test.go` | Embedded copy, domain cross-checks and detached views |
| `fuzz_test.go` | `FuzzParse` and `FuzzLoad` |

Do not copy fixture files into the package. Tests read the repository fixtures at `../../../../schemas/cel/v1/` from the package directory. Read the fixture manifest; assert that every listed fixture is executed and no declaration fixture is unlisted. Repository tests have filesystem access; production parsing does not read schemas from disk.

### Task 1: Strict, bounded declaration loading

**Interfaces:** Consume `[]byte` or `io.Reader`. Produce `Parse([]byte) (*Document, error)`, `Load(io.Reader) (*Document, error)`, `MaxBytes`, the view types and sentinels from spec sections 4 and 5. Keep partially implemented semantic validation private until Task 2 passes.

- [x] **Step 1: Write the failing parser and reader tests.**

Create `parse_test.go` and `load_test.go`. Add `TestParseJSON`, `TestParseDuplicateKeys`, `TestParseNumbers`, `TestParseShape`, `TestParseWireBounds`, `TestParseLexicalPrecedence`, `TestLoadReaderErrors`, `TestLoadReadLimit` and `TestLoadNoProgress`. Cover all generated byte vectors in spec section 6 that concern phases 1 through 4. Assert `errors.Is`, nil document on every error, 262,145 maximum bytes read, short reads, EOF-with-data and original reader-cause wrapping. Build depth/token boundary inputs independently of production helpers.

- [x] **Step 2: Run the focused tests and record the failure.**

Run from `server/`: `go test ./internal/policy/celdecl -run 'Test(Parse(JSON|DuplicateKeys|Numbers|Shape|WireBounds|LexicalPrecedence)|Load)' -count=1`

Expected: failure for absent package symbols. Do not substitute a skipped test or mark the task passing while validation phases remain absent.

- [x] **Step 3: Implement the parsing boundary.**

Create `types.go`, `errors.go` and `parse.go`. Use spec section 5's complete-phase order. Preflight bytes, containers and tokens; validate UTF-8 and escaped surrogate pairing; use lossless number tokens and reject declaration number spellings outside the decimal rule. Detect duplicate decoded keys at every depth. Validate known fields by exact spelling, not direct case-insensitive struct decoding. Defer type-subtree grammar to the later type phase. Cap no-progress reads and preserve reader causes. Expose no partly validated document on a successful return from the finished package.

- [x] **Step 4: Run the focused tests.**

Run the Step 2 command. Expected: PASS for the parser/read boundaries implemented in this task. Record which semantic tests await Task 2. Do not claim the package complete.

- [x] **Step 5: Obtain independent review before dependent work.**

Sol xhigh reviews parser resource bounds and phase separation. The implementer fixes findings; an independent Sol xhigh reviewer confirms fixes. The primary agent inspects the diff and reruns Step 2 before accepting the task.

### Task 2: Catalogue validation and detached views

**Interfaces:** Consume Task 1's bounded token tree. Complete `Parse` and `Load`, and implement `(*Document).Snapshot() Catalogue` and `(*Document).Environment(domain, context string) ([]Variable, error)`. All signatures and data fields come from spec section 4.

- [x] **Step 1: Write the failing semantic and fixture tests.**

Add `TestFixtures`, `TestVersionPrecedence`, `TestTypeGrammar`, `TestDeclarationLimits`, `TestDomainContexts`, `TestReferencesAndCycles`, `TestSemanticPrecedence`, `TestCatalogueIdentity`, `TestEmbeddedCatalogue`, `TestSnapshotIsolation`, `TestEnvironmentIsolation`, `TestEnvironmentErrors` and `TestZeroDocument`. Execute all manifest cases and all remaining spec section 6 vectors. Check every sentinel's exact text separately from `errors.Is` classifications. `TestEnvironmentErrors` requires a nil slice and only `ErrDomain` for unknown domains, unknown contexts and unavailable pairs such as `("edr", "query")`. `TestZeroDocument` requires a nil slice and only `ErrDocument` for nil and zero documents with both supported and unsupported pairs. Assert both classifications with `errors.Is` to prove precedence.

Test the full 14-variable inventory and the per-domain sets against a test-owned expectation, not a production-generated list. Check all section-5 profile fields recursively, including immutable rule identity fields, categories, inherited evidence, account/tenant and certificate time siblings. Check forbidden domain leakage and that a well-formed `duration` or `null` replacement reaches `ErrCatalogue`. Test each adjacent phase precedence and reorder object keys without changing the expected classification.

- [x] **Step 2: Run the tests and record the expected failures.**

Run from `server/`: `go test ./internal/policy/celdecl -run 'Test(Fixtures|VersionPrecedence|TypeGrammar|DeclarationLimits|DomainContexts|ReferencesAndCycles|SemanticPrecedence|CatalogueIdentity|EmbeddedCatalogue|SnapshotIsolation|EnvironmentIsolation|EnvironmentErrors|ZeroDocument)' -count=1`

Expected: absent view methods or failure on semantic inputs that the incomplete parser accepts. A failure unrelated to the intended assertion must be fixed before implementation proceeds.

- [x] **Step 3: Implement semantic validation and catalogue access.**

Complete `parse.go` and create `catalogue.go`. Copy the exact schema catalogue into the package's `variables.json` and embed it using `embed`. Decode the trusted asset without recursively calling the public parser's catalogue comparison. A private initialization path records an internal asset failure; public calls return `ErrCatalogue` rather than panic if that impossible deployment defect occurs. Test the embedded asset with the same structural/semantic validation excluding self-comparison, then require byte identity with the repository asset.

Validate supported tuple, names, recursive type variants and declaration limits before domains and references. Resolve all references, then detect cycles with graph marks, including list/map edges and unused definitions. Compare the entire decoded candidate against the trusted catalogue after these checks. Implement recursive copying for snapshots and environment entries. Never expose the private maps, slices or type pointers.

- [x] **Step 4: Run package and module tests.**

Run from `server/`: `go test ./internal/policy/celdecl -count=1`, then `go test ./...`.

Expected: PASS. Confirm the package imports only standard-library packages with `go list -f '{{join .Imports "\n"}}' ./internal/policy/celdecl` and inspect the output. Existing module dependencies remain untouched.

- [x] **Step 5: Obtain semantic and adversarial review.**

Sol xhigh attacks hostile recursive inputs, catalogue injection, certificate weakening, schema/Go disagreements and mutation through returned views. The implementer resolves findings; independent Sol xhigh confirmation follows. The primary agent inspects every edit and reruns the package tests before acceptance.

### Task 3: Fuzz properties and whole-slice verification

**Interfaces:** Use only the finished public API and fixture inputs. Produce bounded fuzz coverage and the review evidence; do not add production features.

- [x] **Step 1: Add the fuzz targets and concurrency tests first.**

Create `fuzz_test.go` with `FuzzParse` and `FuzzLoad` exactly as spec section 6 defines. Seed every persisted fixture, invalid encodings, duplicate escaped keys and bound crossings. Add `TestConcurrentViews` that mutates detached copies while other goroutines read the same document. Record a failing test before any resulting production fix; if all properties pass initially, record that result without inventing a defect.

- [x] **Step 2: Run tests and bounded fuzzing.**

Run from `server/`:

```sh
go test ./internal/policy/celdecl -count=1
go test ./internal/policy/celdecl -fuzz=FuzzParse -fuzztime=5s -parallel=2
go test ./internal/policy/celdecl -fuzz=FuzzLoad -fuzztime=5s -parallel=2
```

Expected: PASS, no panic, race or uncontrolled allocation. Keep useful minimized failures under `server/internal/policy/celdecl/testdata/fuzz/`, owned by this task. Those files are the only addition to the ownership table.

- [x] **Step 3: Run the repository checks.**

Run from `server/`:

```sh
gofmt -w internal/policy/celdecl
gofmt -l .
go test ./...
go test -race ./...
go vet ./...
go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2
go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2
go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzDecode -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzExtractLine -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzDecode -fuzztime=5s -parallel=2
```

Expected: no files from `gofmt -l`, every command exits 0. Run timed targets sequentially. Report any environment failure as failed; do not infer success from ordinary tests. From repository root, run `git diff --check` and inspect the full diff for scope and dependency changes.

- [x] **Step 4: Validate the fixture contract independently.**

From repository root, use this exact command with the installed validation dependency:

```sh
python - <<'PY'
import json
from pathlib import Path
from importlib.metadata import version
from jsonschema import Draft202012Validator
assert version('jsonschema') == '4.25.1'
p = Path('schemas/cel/v1')
schema = json.loads((p / 'declarations.schema.json').read_text())
Draft202012Validator.check_schema(schema)
v = Draft202012Validator(schema)
assert v.is_valid(json.loads((p / 'variables.json').read_text()))
m = json.loads((p / 'fixtures.json').read_text())
for case in m['cases']:
    value = json.loads((p / case['file']).read_text())
    assert v.is_valid(value) == case['schema_valid'], case['file']
print('schema and all fixture expectations pass')
PY
```

This checks the schema column, not Go error precedence. `TestFixtures` checks that second column. Do not replace lexical duplicate-key tests with JSON Schema validation.

- [x] **Step 5: Obtain the final independent code review.**

A separate Sol xhigh reviewer checks the complete diff against the approved spec/plan and all Review focus inputs. Include an adversarial pass because this package parses untrusted declarations. Give the reviewer the exact checks and outputs, not only a pass claim. Fix through the implementer and obtain independent fix confirmation. The primary agent reruns checks justified by the fixes and owns any subsequent Git work.

## Handoff report

The implementer reports owned files changed, tests first observed failing, all exact verification commands and results, fuzz durations, remaining failures and review findings. State explicitly that no compiler, CEL evaluation, bundle verification, runtime value enforcement or platform qualification was implemented. Source-schema gates remain with their owners. A successful handoff requires the full fixture manifest, immutable views and all error phases, not only successful loading of the canonical file.
