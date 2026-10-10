# Ed25519 Key Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject invalid Ed25519 keys at a shared admission boundary and in DSSE verification.

**Architecture:** A leaf `ed25519key` package decodes public points with `math/big` and applies the canonical prime-subgroup predicate. DSSE maps its failures to `ErrPublicKey`. Future admission services consume the same validator under the spec's integration gates.

**Tech Stack:** Go 1.27.1 standard library; JSON Schema 2020-12 fixtures.

**Spec:** [Ed25519 key admission](../specs/ed25519-key-admission.md), including exact API, arithmetic, errors and caller obligations. Read [DSSE](../specs/dsse-envelope.md), `instructions/go.md` and `instructions/testing.md` too.

## Global constraints

- An independent Sol xhigh reviewer approves the spec and plan before code starts. Dispatch explicitly with `gpt-6.1-sol`, `xhigh`.
- A separate Sol medium implementer, `gpt-6.1-sol`, `medium`, owns all code paths below. The design author and reviewer do not implement them. Keep tasks sequential in one isolated implementation worktree.
- Independent Astra xhigh code review, `gpt-6-astra`, `xhigh`, includes an adversarial pass over decoding, subgroup arithmetic and the signing boundary. All code reviews, adversarial reviews and code fix confirmations use that model and effort because Sol implements the code. The reviewer never implements the slice. The single whole-slice review in Task 3 Step 3 runs after the last code task; obtain its fix confirmation before integration.
- The primary agent owns Git operations and integration. Workers do not commit or push. Respect the repository's six-job concurrency cap across slices.
- Go 1.27.1 is the installed version and CI pin. Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0 are installed but unused by this Go slice. Preserve `server/go.mod` and its `go 1.27.1` directive.
- Add no third-party Go dependency. Python schema checks use the existing exact `jsonschema==4.25.1` pin. Temporary design computations use `cryptography==50.0.0`; do not add it to product or CI requirements.
- Write failing tests first, run them, record the actual expected failure, then implement. Existing passing tests do not prove a regression test fails before the fix.
- Run only formatting, vet, focused ordinary tests and bounded fixture checks locally. No local race tests, timed fuzzing or extended property runs. CI owns those and the cross-OS qualification required by later consumers.
- Do not implement trust-list storage, certificate profiles, custody ceremonies, the parallel extension loader or a Rust verifier. Their integration obligations are in spec section 5. Do not claim this slice completes any of those consumers.
- Keep all existing DSSE fixtures passing. Treat a new dependency, changed admission predicate or changed error precedence as a design change requiring review, not an implementation choice.

## Review focus

- Identity passes `[L]A == O`; Task 1 must separately reject it, and Task 2 must reject its fixed signature on unrelated envelopes.
- A y reduction, discarded sign bit or partial decode can admit aliases; Task 1 covers the full y overflow interval and all torsion encodings.
- Reducing L before multiplication defeats subgroup checks; Task 1 covers every nonzero torsion component attached to B and 2B.
- Mutable `big.Int` receivers can poison constants or later calls; Task 1 tests repeat and concurrent validation with independent inputs and an independent oracle.
- Moving the key check ahead of envelope parsing changes observable errors; Task 2 exercises combined defects at each preceding stage and both member orders.
- An admitted key is not authority; Task 3 reviews the caller inventory and the parallel loader contract without claiming absent consumers are implemented.

---

### Task 1: Shared validator and complete corpus

**Files:**

- Create: `server/internal/signing/ed25519key/key.go` for API, sentinels and validation stages.
- Create: `server/internal/signing/ed25519key/point.go` for private public-point arithmetic.
- Test: `server/internal/signing/ed25519key/key_test.go`, `vectors_test.go`, `oracle_test.go` and `fuzz_test.go`.
- Read: `schemas/dsse/v1/key-admission-vectors.json` and `key-admission-vectors.schema.json`; do not weaken their expectations to fit the implementation.

**Interfaces:**

- Consumes arbitrary raw key bytes, including nil.
- Produces `Validate([]byte) error` and the five exact sentinels from spec section 2. No point type or arithmetic helper is exported.

- [x] **Step 1: Write failing tests and the independent oracle.**

Add `TestValidateVectors`, `TestVectorRecipes`, `TestValidatePrecedence`, `TestValidateBoundaries`, `TestValidateInputOwnership`, `TestValidateConcurrent` and `FuzzValidate`. Load the shared fixture relative to the test source, using `runtime.Caller`; fail if absent or if a row is not executed. Check its format, unique names and known outcome names. Decode hex strictly. Reconstruct all recipes, including seed keys with `crypto/ed25519.NewKeyFromSeed`.

For every row, assert nil only for `accept`; otherwise assert `errors.Is` against the expected sentinel and false against all other sentinels. Never match error strings. Cover the exact combined-defect and length cases in spec sections 3 and 8. Preserve input bytes on success and failure; validate admitted and rejected keys repeatedly and in concurrent calls with independent input copies. A zero-length non-nil slice and nil both return `ErrLength`.

Keep a test-only affine oracle in `oracle_test.go`, with independently expressed inversion, decoding and group addition. Do not import production point helpers into the oracle. Reconstruct T, prove `[8]T == O` and `[4]T != O`, and enumerate all fourteen permissive torsion encodings. Confirm each occurs in the corpus and fails admission. All 38 y-overflow encodings must be present. Use the oracle for recipe reconstruction and the success invariant of `FuzzValidate`.

- [x] **Step 2: Run and record the expected failure.**

```sh
cd server && go test -count=1 ./internal/signing/ed25519key
```

Expected: compilation fails because `Validate` and its sentinels are absent. Do not create a passing stub first.

- [x] **Step 3: Implement the exact API and arithmetic.**

Implement spec sections 2 and 3. Reject length before decoding or input-sized allocation; copy 32 bytes before extracting sign. Use canonical y bounds, checked inverse and square root, signed-zero rejection, `[8]A` and integer `[L]A` in that order. Use complete extended-coordinate addition with modular reduction and a checked projective identity predicate. Keep every mutable receiver private to the call. Do not add signature or private-key arithmetic.

- [x] **Step 4: Run focused checks.**

```sh
cd server && gofmt -w internal/signing/ed25519key/*.go
cd server && go vet ./internal/signing/ed25519key
cd server && go test -count=1 ./internal/signing/ed25519key
```

Run each command from the repository root. Require exit 0 and PASS, including ordinary fuzz seed execution. No timed fuzz run. Inspect the full diff before Task 2.

### Task 2: DSSE verification boundary

**Files:**

- Modify: `server/internal/signing/dsse/dsse.go`.
- Test: `server/internal/signing/dsse/key_admission_test.go`, `dsse_test.go` and `fuzz_test.go`.
- Read: the existing DSSE parser, test helpers and both shared corpora.

**Interfaces:**

- Consumes `ed25519key.Validate([]byte) error` from Task 1.
- Produces unchanged `dsse.Verify` API, `Verified{}` on every error and the mapped `ErrPublicKey` behavior in spec section 4.

- [x] **Step 1: Write the failing DSSE regressions.**

Update the `ErrPublicKey` message assertion in `dsse_test.go`'s `TestPayloadTypes` to expect `dsse invalid public key`.

Add `TestVerifyRejectsIdentityForgery`, `TestVerifyKeyAdmissionVectors`, `TestVerifyKeyAdmissionPrecedence` and `TestSignKeysPassAdmission`. The identity regression builds two valid envelopes with different supported types and payloads, using A=identity and R=identity/S=0. Establish the raw standard-library acceptance for the pinned toolchain, then require `errors.Is(err, dsse.ErrPublicKey)` and `Verified{}` from each DSSE verification.

For every rejected corpus key, supply a well-formed envelope with a 64-byte invalid signature; expect `ErrPublicKey`, not `ErrSignature`. For every accepted corpus key, that signature must yield `ErrSignature`. Assert DSSE failures do not also match any `ed25519key` sentinel. Test both signing fixture keys and fixed generated keys to keep positive sign/verify coverage.

Construct combined-defect tests for every DSSE stage before public-key validation, using its existing helpers for size boundaries. Repeat small-order, noncanonical, off-curve and mixed-order keys with malformed JSON, signature count, type, hint, payload and signature encoding defects. A short signature wins with `ErrSignature`; a correctly sized bad signature loses with `ErrPublicKey`. Reorder root and signature members to prove identical errors. Every failure has zero output. Extend `FuzzVerify` seeds with every rejected key and test the key-admission invariant on success.

- [x] **Step 2: Run and record the regression failure.**

```sh
cd server && go test -count=1 ./internal/signing/dsse -run '^(TestPayloadTypes|TestVerify(RejectsIdentityForgery|KeyAdmissionVectors|KeyAdmissionPrecedence))$'
```

Expected: `TestPayloadTypes` fails on the sentinel message; the identity envelope succeeds or a bad key yields `ErrSignature` instead of `ErrPublicKey`. Record the message failure and the admission regression behavior, not an unrelated test setup failure.

- [x] **Step 3: Integrate the validator.**

Replace only the length check after `parseEnvelope` with the validator call. Map every failure to `ErrPublicKey`, without wrapping the validator error. Set the sentinel message to `dsse invalid public key`. Keep parsing order, PAE, hints, signing and signature verification unchanged. Add a concise API comment pointing admission callers to the shared validator without claiming that successful verification grants trust.

- [x] **Step 4: Run focused verification.**

```sh
cd server && gofmt -w internal/signing/dsse/*.go
cd server && go vet ./internal/signing/ed25519key ./internal/signing/dsse
cd server && go test -count=1 ./internal/signing/ed25519key ./internal/signing/dsse
```

Require exit 0 and PASS for both complete corpora and the regressions.

### Task 3: CI contract checks and handoff gates

**Files:**

- Modify: `scripts/ci/validate_contracts.py` to retain the registered key-admission schema/fixture pair and add checks for missing coverage or duplicate names.
- Test: `scripts/ci/test_key_admission_contract.py` for checker failure behavior.
- Modify: `.github/workflows/design.yml` to run that checker test.
- Modify: `.github/workflows/server.yml` and `instructions/testing.md` to register the single new `FuzzValidate` target and retain the existing `FuzzVerify` target.
- Test: `server/internal/signing/ed25519key/benchmark_test.go` with `BenchmarkValidate` for accepted, off-curve, small-order and mixed-order keys.

These paths belong to the separate implementer, not the document author. Add no package installer or new dependency pin. Preserve existing workflow pins and checks. The key-admission schema/fixture pair is registered in the explicit inventory, and repository validation passes. Task 3 adds coverage checks, checker tests and CI wiring.

**Interfaces:**

- Consumes both completed Go packages and the schema/corpus.
- Produces deterministic schema-check failures and CI coverage; no new product API.

- [x] **Step 1: Add and run failing checker tests.**

Make the checker test validate temporary copies with an extra property, malformed hex, missing field, unknown result, duplicate name, missing torsion row, missing y-overflow row and changed expected class. Require failure for each mutation and success for the exact corpus. Give the shared checker a testable path input without changing its existing root command behavior.

```sh
/home/danny/.cache/ricevanta-validation/bin/python scripts/ci/test_key_admission_contract.py
```

Expected: failure because the checker does not reject all mutations. Retain schema validation and implement the corpus coverage checks. Arithmetic acceptance remains exercised by the independent Go oracle and both design scripts; JSON Schema alone cannot prove it.

- [x] **Step 2: Wire CI and run light local checks.**

Add `./internal/signing/ed25519key` / `FuzzValidate` to the workflow's existing target list, with exact target anchoring and the existing failure-corpus upload. Keep the instruction list aligned. Add benchmark cases without a pass/fail latency threshold; performance qualification belongs to the first consumer.

```sh
/home/danny/.cache/ricevanta-validation/bin/python scripts/ci/test_key_admission_contract.py
/home/danny/.cache/ricevanta-validation/bin/python scripts/ci/validate_contracts.py
cd server && gofmt -l .
cd server && go vet ./internal/signing/ed25519key ./internal/signing/dsse
cd server && go test -count=1 ./internal/signing/ed25519key ./internal/signing/dsse
```

Require exit 0, no formatting output and PASS. Benchmark execution stays in CI with `cd server && go test -run '^$' -bench '^BenchmarkValidate$' -benchmem -benchtime=100x ./internal/signing/ed25519key`; report time and allocations without inventing a consumer budget.

- [x] **Step 3: Obtain final review and read CI evidence.**

The independent Astra xhigh reviewer, `gpt-6-astra`, `xhigh`, attacks the full slice against every Review focus item and spec section 5 and confirms code fixes. Check the parallel loader's merged contract for compatible raw-key validation, DSSE precedence and bounded candidate handling. An unavailable loader branch does not authorize implementing it or claiming it is covered. Record that integration question separately.

The primary agent follows `instructions/workflow.md`. CI runs the full ordinary suite, `cd server && go test -race -count=1 ./...`, and these timed targets:

```sh
cd server && go test -count=1 ./internal/signing/ed25519key -fuzz='^FuzzValidate$' -fuzztime=60s -parallel=2
cd server && go test -count=1 ./internal/signing/dsse -fuzz='^FuzzVerify$' -fuzztime=60s -parallel=2
```

Require the design and server workflows on the exact integration head, including new checker tests, benchmark output and successful race/fuzz results. Preserve useful minimized failures. The Rust slice must run the shared key corpus on macOS ARM64, Windows x64 and Linux x64 before its verifier ships. This Go primitive's tests do not establish platform or recovery support.

## Final verification

- [x] `git diff --check` reports no whitespace errors; the primary inspects the full diff and required check results.
- [x] Spec and plan remain at most 400 lines each. Check touched documents for em dashes, dates, history wording and stale length-only claims.
- [x] Every corpus row, combined defect, ownership boundary and Review focus item maps to a passing test or an explicit future consumer gate.
- [x] Independent Astra xhigh review and fix confirmation approve the final code, including public arithmetic, error precedence and no returned authority on failure.
- [x] Report exact commands and failed or skipped checks. Leave absent consumer work and unresolved questions in their own slices; do not remove the whole admission obligation because only DSSE is implemented.
