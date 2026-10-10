# Core Event Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add reusable Go validation for UUIDv7 event identifiers and decoded event batch descriptors.

**Architecture:** Two leaf packages under `server/internal/events` expose fixed-size value types and validation. Neither package imports transport, schema, storage or the other package.

**Tech Stack:** Go 1.27.1 and its standard library.

**Spec:** `docs/specs/core-primitives.md`

## Global constraints

- Product code starts only after an independent Sol xhigh design review approves the spec and plan and the reviewed Go, testing, release and CI workflow changes are integrated.
- A separate Sol medium implementer owns the code paths in this plan. The design author and reviewer do not implement them.
- Start `server/go.mod` with `module github.com/ricevanta/ricevanta/server`, then `go 1.27.1`; add no `toolchain` directive.
- Go 1.27.1 is the module minimum and the locally tested version. CI pins exact Go 1.27.1.
- Add no third-party dependency, product service, command, database, generated schema or wire decoder.
- Write each test first, run it and observe the expected failure, then add the least code that passes it.
- The primary agent owns Git operations. Workers do not commit or push.
- After every prerequisite above passes, the primary agent copies the reviewed spec and plan into both implementation worktrees. Tasks 1 and 2 may then run in parallel. Each task uses the identical two-line `server/go.mod`; the primary agent integrates one copy.

## Review focus

- Uppercase or mixed-case UUID text returns `ErrNonCanonical`, with no partially parsed ID.
- A UUID with correct text shape but wrong version or variant returns the specific sentinel.
- Combined UUID defects follow shape, uppercase, hexadecimal, version, then variant precedence.
- Sequence arithmetic near `math.MaxUint64` never wraps or panics.
- Descriptor counts at 0, 1, 10,000 and 10,001 apply the exact boundaries.
- Multi-invalid descriptors return the first error in the specified validation order.
- A semantically equal batch ID with leading zeroes or another class spelling is rejected.

---

### Task 1: UUIDv7 event identifiers

**Files:**

- Create: `server/go.mod`
- Create: `server/internal/events/eventid/id.go`
- Test: `server/internal/events/eventid/id_test.go`

**Interfaces:**

- Consumes: event identifier strings extracted by future OCSF decoding.
- Produces: `type ID [16]byte`, `Parse(string) (ID, error)`, `(ID).String() string`, and the four error sentinels in the spec.

- [x] **Step 1: Write the failing table tests**

Add `TestParse`, `TestParseRejectsMalformedText`, `TestParseRejectsNonCanonicalText`, `TestParseRejectsWrongVersion`, `TestParseRejectsWrongVariant`, `TestParseErrorPrecedence`, `TestStringArbitraryID` and `FuzzParse`. Use every vector in spec section 2 as tests and fuzz seeds. Assert `errors.Is`, a zero ID on failure, no panic, exact lowercase round trips and raw formatting for arbitrary `ID` values.

- [x] **Step 2: Run the focused tests and record the expected failure**

Run: `cd server && go test ./internal/events/eventid`

Expected: fail because the package implementation does not exist.

- [x] **Step 3: Implement the fixed-size parser and formatter**

Create the exact API from spec section 2. Apply its error precedence: shape, any uppercase, other invalid hex, version, then variant. Decode 32 hex digits into 16 bytes and format directly from those bytes. Do not accept braces, URNs, missing dashes or whitespace.

- [x] **Step 4: Run package tests**

Run: `cd server && go test ./internal/events/eventid`

Expected: PASS.

- [x] **Step 5: Review Task 1 independently**

A Sol xhigh reviewer checks the diff against spec section 2, including error precedence and all Review focus inputs. The implementer resolves findings, and a separate Sol xhigh confirmation accepts the fixes before integration.

### Task 2: Decoded batch descriptor validation

**Files:**

- Create: `server/internal/events/batch/descriptor.go`
- Test: `server/internal/events/batch/descriptor_test.go`

In its separate worktree, create the same `server/go.mod` listed in Task 1 when the design-review worktree does not already contain it. The primary agent keeps one identical copy during integration.

**Interfaces:**

- Consumes: a future transport decoder's `Descriptor` and claimed batch ID.
- Produces: `SpoolClass`, its five constants and `String`; `Descriptor`, `Validate`, `BatchID`, `ValidateBatchID`; and the six error sentinels in spec section 3.

- [x] **Step 1: Write all failing descriptor tests**

Add `TestSpoolClassString`, `TestDescriptorValidate`, `TestDescriptorBoundaryCounts`, `TestDescriptorMaxUint64Sequences`, `TestBatchID`, `TestValidateBatchID`, `TestDescriptorRejectsClass`, `TestDescriptorRejectsZeroEpoch`, `TestDescriptorRejectsCount`, `TestDescriptorRejectsReversedRange`, `TestDescriptorRejectsCountMismatch`, `TestDescriptorErrorPrecedence`, `TestDescriptorMaxUint64Boundaries`, `TestValidateBatchIDRejectsNonCanonical`, `TestValidateBatchIDPrefersDescriptorError` and `FuzzDescriptor`. Cover all classes and every valid, invalid, precedence and boundary vector from spec section 3 as tests and fuzz seeds.

- [x] **Step 2: Run the focused tests and record the expected failure**

Run: `cd server && go test ./internal/events/batch`

Expected: fail because the package implementation does not exist.

- [x] **Step 3: Implement descriptor validation and identity**

Create the exact API and validation order from spec section 3. Compare `LastSequence - FirstSequence` with `uint64(RecordCount - 1)` only after the range and nonzero-count checks. Return empty strings for an unknown class and an invalid descriptor. Build valid IDs with `strconv.FormatUint` and the canonical class name.

- [x] **Step 4: Run package and module tests**

Run: `cd server && go test ./internal/events/batch && go test ./...`

Expected: PASS with no downloaded modules.

- [x] **Step 5: Review Task 2 and the complete slice independently**

A Sol xhigh reviewer checks both packages against the spec, attacks boundary arithmetic and alternate identifier spellings, and confirms that no code claims to decode, authenticate, store or acknowledge batches. Resolve findings through the implementer, obtain independent Sol xhigh fix confirmation, then let the primary agent run the repository checks and Git workflow.

## Final verification

- [x] Run `cd server && gofmt -w internal/events/eventid/*.go internal/events/batch/*.go` and require a clean diff from a second `gofmt -d` check.
- [x] Run `cd server && go vet ./...` and require exit 0.
- [x] Run `cd server && go test -race ./...` and require PASS.
- [x] Run `cd server && go test -parallel=2 ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s` and `go test -parallel=2 ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s`; require PASS. CI runs the seed corpus through ordinary `go test`, not timed fuzzing.
- [x] Run the repository documentation and design checks required by `instructions/workflow.md` and the new language and testing instructions.
- [x] Inspect `git diff --check` and the full diff. Confirm only reviewed plan, instruction, CI and two primitive-package changes are present for this slice.
