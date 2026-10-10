# DSSE envelope implementation plan

Add the shared single-signature primitive defined by [the DSSE spec](../specs/dsse-envelope.md), using the checked corpus in `schemas/dsse/v1/`. This plan implements the primitive only; production consumers remain subject to their trust and schema gates.

## Global constraints

- An independent Sol xhigh design review must approve both spec and plan before code starts. Resolve findings and obtain independent Sol xhigh fix confirmation.
- A separate Sol medium implementer owns the code paths below. The designer and reviewers never implement those paths. Use `gpt-6.1-sol` at `medium` for implementation and at `xhigh` for review, with explicit model and effort on every dispatch.
- Use Go 1.27.1 and module `github.com/ricevanta/ricevanta/server`. Preserve `server/go.mod`; add no dependency or toolchain directive.
- Use one implementation worktree and sequential tasks because the parser, signer and verifier share a package. If work is delegated concurrently, use separate worktrees and disjoint owned files.
- Write tests first, run them and record the expected failure, then implement the least code that passes. A missing symbol or an asserted contract failure is evidence; an unrelated environment failure is not.
- Do not add a service, endpoint, certificate validator, key store, payload schema validator, quorum verifier or production consumer. Do not resolve open payload types by inventing names.
- The primary agent owns Git operations, inspects every diff and runs the required checks. Workers never commit or push and must preserve others' changes.
- Sol xhigh reviews the completed code with an adversarial pass for signing and authentication boundaries. The implementer fixes findings; an independent Sol xhigh reviewer confirms each fix before acceptance.

## Ownership and interfaces

Create `server/internal/signing/dsse/dsse.go`, `parse.go` and `pae.go`, with corresponding `dsse_test.go`, `parse_test.go`, `pae_test.go`, `vectors_test.go` and `fuzz_test.go`. The implementer may split private helpers within this package but must not expand its exported API.

Read the shared corpus from `../../../../schemas/dsse/v1/vectors.json` relative to the package test directory. Do not copy or regenerate it in Go tests. Standard-library test structs decode the fixture format; tests reject unknown fixture properties and check named key references and sentinels. The JSON Schemas are design-time checks, not a Go runtime dependency.

The implementer also owns one additive change to `instructions/testing.md`: the bounded `FuzzVerify` command in Task 4. No `.github/`, other instruction, event package or consumer change belongs to this slice. Design or vector changes found necessary during implementation return to the designer and independent review.

## Review focus

- The exact API, closed payload types, constants, nil/empty behavior and error messages match spec section 2.
- Raw framing, Unicode, duplicate detection and exact key names do not rely on permissive struct decoding.
- Fixed field sets and early size bounds avoid input-sized collections of signatures or unknown objects.
- Expected type mismatch precedes cryptography; public key and private-key guards prevent library panics.
- Canonical signing, exact received-byte hashing and unchanged verified payload bytes agree with the corpus.
- Key hints never select authority, and single-signature verification cannot stand in for recovery quorum validation.
- Combined defects, not just isolated failures, follow the full precedence table.
- No passing primitive test is reported as certificate, recovery, extension or platform qualification.

## Task 1: API, PAE and deterministic signing

**Owned files:** `dsse.go`, `pae.go`, `dsse_test.go`, `pae_test.go`, `vectors_test.go` under the package directory above.

**Consumes:** explicit type, opaque payload bytes, a certificate fingerprint and Ed25519 private-key bytes.

**Produces:** exact canonical envelope bytes or the spec's signing error sentinel.

- [x] Write `TestPayloadTypes`, `TestPAE`, `TestSignVectors`, `TestSignErrors`, `TestSignDeterministic`, `TestSignOwnership` and `TestSignBoundaries` first. Add every positive corpus row's canonical output, both RFC keys and every signing-negative row. `TestPAE` checks exact hex, empty input and UTF-8 payload byte counts. Tests must reject altered private-key suffixes rather than signing with them.
- [x] Run `cd server && go test ./internal/signing/dsse -run 'Test(PayloadTypes|PAE|Sign)' -count=1`. Record failure from absent API or behavior.
- [x] Implement the constants, types and sentinels exactly as spec section 2. Build private PAE from byte lengths, guard inputs in signing precedence order and emit the fixed JSON layout. Use plain Ed25519 only. Do not add a generic signer abstraction or public PAE API.
- [x] Repeat the focused command and require PASS. Compare every canonical envelope and signature with the shared corpus, not with output generated by the code under test.
- [x] Have the primary agent inspect the diff and check its scope before Task 2 starts.

## Task 2: Bounded raw envelope validation

**Owned files:** `parse.go`, `parse_test.go`; extend `vectors_test.go` for parsing cases.

**Consumes:** untrusted raw JSON bytes.

**Produces:** private parsed values, never an exported parse-only result.

- [x] Write `TestParseVectors`, `TestParseShape`, `TestParseUnicode`, `TestParseBase64`, `TestParseLimits` and `TestParsePrecedence` first. Cover every non-cryptographic negative, legal alternate spellings, all missing fields, nulls, exact names, escaped duplicates and unexpected nesting. Make schema/Unicode failures outrank count failures regardless of member order.
- [x] Run `cd server && go test ./internal/signing/dsse -run TestParse -count=1`. Record the expected failure.
- [x] Implement bounded syntax/Unicode and token-based shape checks, fixed per-object field tracking and signature counting without an unbounded slice. Use no regular expressions or generic object tree in product parsing. Guard encoded payload length before base64 allocation, then check decoded length. Use strict standard base64 plus exact re-encoding equality. Keep error ordering aligned with spec section 7 even when the parser detects a later defect early.
- [x] Repeat the focused command and require PASS. Run `cd server && go test ./internal/signing/dsse -count=1` to retain signing behavior.
- [x] Have the primary agent inspect the diff, allocation bounds and precedence tables before Task 3 starts.

## Task 3: Verification, hash binding and API boundaries

**Owned files:** extend `dsse.go`, `dsse_test.go`, `vectors_test.go` and private helpers only as needed.

**Consumes:** raw envelope, caller-selected expected type and an already authorized public key.

**Produces:** one `Verified` result containing the exact checked payload and received-envelope digest, or a zero result and one sentinel.

- [x] Write `TestVerifyVectors`, `TestVerifyErrors`, `TestVerifyPrecedence`, `TestVerifyOwnership`, `TestEnvelopeHashBinding`, `TestKeyIDIsHint`, `TestSignatureCount` and `TestVerifyBoundaries` first. Map all error names to sentinels and assert `errors.Is` plus zero results. Every negative corpus row must execute. Verify that the changed-hint positive succeeds while its envelope digest differs. Use the same payload and key when isolating formatting changes.
- [x] Add pairwise combined-defect tests for all precedence stages, including valid-length cryptographic failures with invalid public keys, malformed base64 at the encoded payload limit, decoded sizes above the limit, and a mismatch with a malformed signature. Tests for size boundaries construct the large inputs in memory without committing large blobs.
- [x] Run `cd server && go test ./internal/signing/dsse -run 'Test(Verify|EnvelopeHashBinding|KeyIDIsHint|SignatureCount)' -count=1`. Record the expected failure.
- [x] Implement `Verify`. Check caller intent before Ed25519, ignore the hint for cryptography, guard public-key length, return independently owned decoded bytes and hash the exact input. Never return payloads on failure or reparse the envelope after verification.
- [x] Repeat the focused command and require PASS. Run `cd server && go test ./...` and require PASS without downloaded modules.
- [x] Have the primary agent inspect all three tasks against the spec before fuzz work starts.

## Task 4: Fuzzing and testing instructions

**Owned files:** `fuzz_test.go` and the additive fuzz command in `instructions/testing.md`.

- [x] Write `FuzzVerify` with calls to a new independent invariant helper before defining that helper; run `cd server && go test ./internal/signing/dsse -run FuzzVerify -count=1` and record the missing-helper failure before completing the harness. Do not weaken a correct production contract merely to create a failure.
- [x] Complete the fuzz harness with spec section 10's invariants and all small vector seeds. Check independent PAE construction and `ed25519.Verify` on success, received-byte hashes and payload isolation. Cap fuzz input before making duplicate test copies; include over-limit cases in unit tests. Do not seed multi-megabyte recipes.
- [x] Add exactly `go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2` to the bounded fuzz commands in `instructions/testing.md`. Keep ordinary CI seed-only behavior and retain the existing targets.
- [x] Run `cd server && go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2`; require PASS. Retain any useful minimized regression corpus in `server/internal/signing/dsse/testdata/fuzz/FuzzVerify/`.

## Task 5: Independent review and final verification

The reviewer reads the spec, plan, shared corpus and entire package diff. The adversarial pass attacks parser disagreements, base64 malleability, hint substitution, cross-type signature reuse, signature-count downgrades, allocation pressure, key panics and any mismatch between verified and returned bytes. The reviewer checks every excluded trust duty and open consumer gate. Reviewers edit no implementation files.

- [x] Obtain Sol xhigh code and adversarial review. Resolve findings through the implementer and obtain independent Sol xhigh fix confirmation.
- [x] Run `cd server && gofmt -w internal/signing/dsse/*.go`, then `cd server && gofmt -l .`; require no listed files.
- [x] Run `cd server && go test ./...`; require PASS.
- [x] Run `cd server && go test -race ./...`; require PASS.
- [x] Run `cd server && go vet ./...`; require exit 0.
- [x] Run `cd server && go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2`; require PASS.
- [x] Run `cd server && go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2`; require PASS.
- [x] Require the Task 4 DSSE fuzz run to pass on the final reviewed code; rerun only if later changes affect it.
- [x] Run `git diff --check` from the repository root and inspect the full diff. Confirm no dependency, consumer or unrelated change.
- [x] Report exact commands, observed failures and passing checks. Primitive tests establish no operating-system, network, database or recovery support.
