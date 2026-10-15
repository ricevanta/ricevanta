# Extension admission implementation plan

> For agentic workers: use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to execute the reviewed tasks in order. Unchecked steps are work to perform, not evidence of completion.

Goal: implement the pure admission decision function and its parsers in [the contracts](../specs/extension-admission-contracts.md) under [the admission design](../specs/extension-admission.md), driven by the published vectors, with independent adversarial review. The production coordinator stays blocked on BE-12 and is not part of this plan's code.

Architecture: one leaf package `server/internal/extensions/admission` above `loader`, `manifest` and `ed25519key`. Typed inputs in, a typed decision out. No I/O, clock, database, network or shared state. The spec owns stages, reason codes, digests and bounds; the schemas own field inventories.

Tech stack: Go 1.27.1 standard library. Python `jsonschema` 4.25.1 in the existing design validator environment for schema checks; no new dependency and no licensing change.

## Global constraints

- An independent `design_reviewer` approves both specs, the schemas and this plan before code under the AGENTS.md routing. The design author cannot supply that approval.
- A separate `implementer` owns the code paths below. An independent `code_reviewer` reviews the code with an adversarial pass (trust, ownership, tombstone and approval binding are security-relevant) and confirms fixes.
- Failing test first: write the test, record its intended failure, implement the smallest change, rerun.
- Fixtures are evidence, not targets: never edit `admission-vectors.json` or the schema-cases files to fit the implementation. A disagreement goes back to the design author and independent reviewer with the case name.
- No permission check, journal, database, blob publication, generation allocation, HTTP handler or bundle hand-off belongs here. Production consumers of this package wait for BE-12.
- Local checks are formatting, vet and focused tests. Race and timed fuzzing run in CI. Full support on macOS ARM64, Windows x64 and Linux x64 is unchanged; this package is portable Go with no OS mechanism.
- Workers never commit or push. The primary agent inspects every diff.

## Review focus

- A stage cannot be skipped or reordered by input shape, array order or map iteration; identical inputs give identical bytes of output.
- Owner and prior-owner rules: no path lets a non-owner publish a new version or lets any key change the bytes of a tombstoned pair.
- Approval binding: digest, epoch, separation or exemption preconditions and consumption are all checked, and the closure contains every fact the decision read, including the approval-policy setting and every generation, so a reverted change never revives an approval.
- Release-fixed is unreachable for a non-project key, a non-reserved id, a source other than `server-image` or another release; it admits without an operator only at first start, for an unwidened upgrade with equal targets and for a recovery re-assertion, always at or above the journaled automatic release floor and with current-epoch registrations, and an upgrade or reinstall carries the install's enabled state. `all_devices` is unreachable from any other source; the single-administrator exemption is unreachable while policies are enabled, for another principal or for a server-image request; the system principal requests only as the server image and never approves.
- A grant update passes every stage an install passes and needs an active install of the version; it keeps but never introduces `all_devices`, and under a retired key it only narrows.
- Grant subset rules per kind, including the console slot map and collector roots and profile.
- Parsers reject duplicate keys, non-canonical `uint64` lexemes and out-of-ceiling values exactly where the schemas do.

## Owned paths

| Path | Responsibility |
|---|---|
| `server/internal/extensions/admission/types.go`, `evidence.go` | Exported types, `FromPackage`, `Values` selection |
| `server/internal/extensions/admission/parse.go`, `parse_grant.go`, `parse_resource.go` | Strict JSON parsers and sentinels |
| `server/internal/extensions/admission/decide.go`, `stages.go`, `subset.go` | `Decide`, the stage sequence, operation selection, subset rules |
| `server/internal/extensions/admission/digest.go` | JCS emitter for the closed digest types, `ClosureDigest`, `RequestDigest` |
| `server/internal/extensions/admission/*_test.go` | Vector runner, schema-cases runner, stage, digest, bounds, aliasing and fuzz tests |
| `scripts/ci/validate_contracts.py` | Task 0 registration of the four schema and fixture pairs (implementer-owned; the design task did not edit it) |
| `.github/workflows/server.yml`, `scripts/ci/targets.toml`, `scripts/ci/fixtures/fuzz-targets.json`, `scripts/ci/inventory.py`, `scripts/ci/test_route.py`, `scripts/ci/test_required.py` | Task 5 fuzz-target registration, following the loader plan's CI integration pattern |

### Task 0: Confirm schema registration and regenerate design fixtures

The four admission schema/fixture pairs are registered in `scripts/ci/validate_contracts.py`. Keep them and every unrelated pair. No validator code change is needed for S-01 to S-03.

- [ ] The designer regenerates admission vectors only through `python3 -B /tmp/scratchpad/extadmission-design-fix/generate_admission.py` from the repository root. This scratch generator reads the seed corpus at `8c0d3b7`, reconstructs the seed digests before transformation and emits the revised vectors, vector schema and schema cases. Retain the generator with the design handoff; it is temporary design tooling, not product code. Never generate expectations from the Go decision function.
- [ ] Run `python3 -B scripts/ci/validate_contracts.py`; require `24 schemas, 37 pairs, 427 instances` for this inventory. Run `python3 -B -m unittest discover -s scripts/ci -p 'test_validate_contracts.py' -v`; `test_admission_pairs_registered` currently fails because it asserts `17 schemas, 24 pairs, 311 instances`; the implementer must update that exact assertion to the current totals without dropping unrelated registrations.
- [ ] Check all embedded manifests (only `input-evidence-invalid-document` is intentionally invalid), request grants and stored grant records against their schemas, all 93 admission schema cases against their expected validity, and all 55 reason codes against corpus coverage. Independently check every digest and the new reducer-state witnesses before approving the design.

### Task 1: Types, parsers and schema parity

Files: update the existing `types.go`, `parse.go`, `parse_grant.go`, `parse_resource.go`, `parse_test.go`, `schema_cases_test.go`, `schema_defs_test.go`.

- [ ] Write `TestSchemaCases` reading the three `schema-cases.json` files relative to the package (`../../../../schemas/extension/v1alpha1/`) and asserting Go acceptance equals `valid` for every case through `ParseResource`, `ParseGrantRecord` and `ParseSnapshot` plus `ParseRequest` on the vectors envelope. Write `TestSchemaDefsIdentical` comparing the shared `$defs` and approval shapes across the three schema files. Write `TestParsePhases` for `ErrJSON`, `ErrShape`, `ErrField`, `ErrGrant` precedence with duplicate keys, lone surrogates, `"07"` generations, `18446744073709551616`, integer epochs, a `..` root segment, a `windows` root with a POSIX path, a Windows segment ending in a period, a trust display name with a C0 or C1 control character, a null release version and unknown grant kinds. Write `TestBounds` for the maximal request (1,264,586 bytes), resource (1,266,858 bytes), grant record (19,994 bytes) and snapshot (7,348,790-byte ceiling) built as contracts section 2 describes, each accepted, each padded one byte past its bound rejected with `ErrJSON`, and inputs of small values one past each value cap (65,536 snapshot, 32,768 request and resource, 1,024 grant record) rejected with `ErrJSON` before allocating the extra value. Run from `server/`: `go test -count=1 ./internal/extensions/admission -run 'Test(SchemaCases|SchemaDefsIdentical|ParsePhases|Bounds)'`; record the intended failure on the added fields and cases.
- [ ] Implement the exported types and the strict token-based parsers with the bounds in contracts section 2. Decode `uint64` from decimal strings with overflow rejection; decode digests from 64 lowercase hex characters; keep every string check in Go, not only in the schema, and add no rule the schema lacks.
- [ ] Rerun the command and require PASS. Any schema-case whose Go outcome differs from `valid` is a design finding to return to the author and reviewer, never an exception list entry.
- [ ] Obtain independent review of parser strictness before Task 2.

### Task 2: Evidence projection and digests

Files: update the existing `evidence.go`, `digest.go`, `evidence_test.go`, `digest_test.go`.

- [ ] Write `TestFromPackage` using the loader corpus (`schemas/extension/v1alpha1/package-loader-vectors.json`) decoded documents and the admission corpus documents: every valid document projects to sorted components with the right `Values` field set; the `input-evidence-invalid-document` document returns `ErrEvidence`; a zero digest or a `PublisherFingerprint` that differs from the document returns `ErrEvidence`. Write `TestEvidenceChecks` for each `input.evidence` condition on a hand-built `Evidence`. Write `TestDigests`: the JCS emitter against hand-computed RFC 8785 encodings for nested objects with unsorted keys, arrays, `"`, `\`, control characters and integers, then against every `closure_digest` and `request_digest` recorded in the corpus. Run `go test -count=1 ./internal/extensions/admission -run 'Test(FromPackage|EvidenceChecks|Digests)'`; record the failure.
- [ ] Implement `FromPackage(p, options)` over `loader.Package` (validate with `manifest.Validate` under the options with `AllowReservedID` forced true, check the fingerprint and digests, then project typed fields; never touch `Archive`, `Files` bytes or `Envelope`). Implement the typed JCS emitter: sorted member names, compact, ASCII-only output, escapes per RFC 8785 section 3.2.2.2; refuse any non-ASCII rune with a panic-free error because the schemas exclude it.
- [ ] Rerun and require PASS. Prove the emitter never calls `encoding/json.Marshal` on a map for digest input.
- [ ] Obtain independent review of the digest field lists against contracts section 3 before Task 3.

### Task 3: Decision stages

Files: update the existing `decide.go`, `stages.go`, `subset.go`, `decide_test.go`, `stage_test.go`, `vectors_test.go`.

- [ ] Write `TestVectors` running all 169 corpus cases: parse snapshot and request, project evidence, build verdicts, call `Decide`, and compare outcome, operation, stage, reasons, digests and intent (including approval kind, ownership reservation, release-floor advance, enabled state, targets and registration bindings) exactly, with zero operation, digests and intent on every reject and identical retry. Write `TestStageIsolation` with combined defects across every adjacent stage pair and with permuted arrays. Write `TestNoAliasing` per contracts section 7. Run `go test -count=1 ./internal/extensions/admission -run 'Test(Vectors|StageIsolation|NoAliasing)'`; record the failure.
- [ ] Implement the stages in the specified order with sorted, deduplicated reasons, the thirteen snapshot rules and four request rules, the in-package registration duplicate rule, canonical set-valued arrays, the binding set as the complete after-image, the parser value caps, the operation precedence, the grant-update path, the per-kind subset rules including roots and profile against a current grant, the ownership and prior-owner rule with revoked entries counted as covering and retired entries not, the registration epoch, intersection and active-holder exclusivity rules, the identical-retry return after the component stage, the identical-retry equality of grants and targets, the `all_devices` source rule, the release-fixed preconditions (including the absent release of an unsigned build) and the release-floor check before operation cases with widening and target comparison, the bounded release-order comparator, the irreversible `ReleaseFloorRaise` intent, the retired-key narrowing rule for grant updates, the enabled-state rule, the server-image-only `release` closure member, reserved-id `automatic_release_floor`, registration `recovery_epoch` and the install generation, and the operator and single-administrator kinds. Call `ed25519key.Validate` on the verifying entry's raw key on every decision. Never read a stored validity flag; the snapshot has none.
- [ ] Rerun and require PASS for all 169 cases without editing fixtures. Add negative controls: temporarily reverse the sort order, skip the consumed check, accept the single-administrator kind while policies are enabled, refuse the prior-owner exception for a rollback upgrade, admit a release-fixed install after first start, drop a generation from the closure, enable on upgrade, accept `all_devices` from an upload, let a grant update introduce `all_devices`, let a retired key widen a grant, accept a release-fixed approval with no running release, ignore a stale registration on recovery or identical retry, lower the floor on operator rollback, compare numeric version fields lexically, and admit an older replica below the floor; each must fail at least one vector; restore the source.
- [ ] Obtain independent adversarial review of the stage code and the vector results, including the review-focus items, before Task 4.

### Task 4: Fuzzing and local integration

Files: update the existing `fuzz_test.go`.

- [ ] Add `FuzzDecide` (arbitrary snapshot and request bytes plus each corpus evidence) and `FuzzParse` (each parser). Assert no panic, determinism across two calls, one sentinel per parse failure, and for every `Admit` an independent recheck of the owner rule, subset rule, digest equality, the release-fixed operation cases, the system-principal rules and approval consumption. Seed from every corpus case and schema case.
- [ ] From `server/`: `go test -count=1 ./internal/extensions/admission/...`, `go vet ./internal/extensions/admission/...`, `gofmt -l internal/extensions/admission` with no output, and `go test -count=1 ./internal/extensions/manifest ./internal/extensions/loader/... ./internal/extensions/admission/...` once for integration. From the repository root: `/home/danny/.cache/ricevanta-validation/bin/python scripts/ci/validate_contracts.py` and `git diff --check`.
- [ ] CI only: timed fuzzing of both targets for 60 seconds with two workers under the existing fuzz matrix, and the server-wide race job. No local timed fuzzing.

### Task 5: CI fuzz registration

Owner: one `implementer` after Task 4, following the [loader plan's CI integration](extension-loader.md#task-5-ci-integration) pattern and owning only the CI paths in the table above.

- [ ] Add the two admission fuzz pairs to `scripts/ci/targets.toml` and `scripts/ci/fixtures/fuzz-targets.json`, raise the required unique main fuzz pair count in `scripts/ci/inventory.py` by two, and extend `test_route.py` and `test_required.py` so a missing admission fuzz receipt fails `required.verify`. Keep every existing pair and budget.
- [ ] Local, repository root: `python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v`, `python -B scripts/ci/inventory.py --fuzz-matrix`, `python -B scripts/ci/check_policy.py --root .`, `actionlint .github/workflows/*.yml`; require PASS.
- [ ] The primary agent obtains green PR CI for the final head, including both new fuzz leaves and `server-race`, then independent `code_reviewer` confirmation. This task authorizes no production consumer.

## S-01 to S-03 implementation acceptance

- [ ] Task 1: add `Snapshot.AutomaticReleaseFloor`, `Registration.RecoveryEpoch` and `Intent.ReleaseFloorRaise` with the exact schema shapes. Keep parser byte/value/depth caps unchanged. Rebuild the snapshot capacity witness with 64 maximal epochs and a maximal floor; rerun the same bound tests.
- [ ] Task 2: hash registration epochs and the reserved-id floor; preserve canonical sorting and update no expectation by hand. Approval digests must stale on registration renewal or a concurrent floor advance.
- [ ] Task 3: add `TestReviewRegressions` for the 29 added vectors, snapshot rules 9 and 13, delayed identical retry, and rollback reason precedence. `OwnershipCreate` retains its API name but now requests an irreversible prepare reservation. Test first-start abort, fresh approved retry, stale consumed retry, same-version recovery below a higher floor, older-image restore, and an older replica concurrent with a newer prepare. Model those snapshots without claiming an executable BE-12 proof.
- [ ] Task 4: seed fuzzing with all added vectors; independently assert current registration authority and no automatic mutation below the floor on every admit. Run focused admission checks, then require independent adversarial code review and fix confirmation before Task 5.

## Blocked follow-on work

Not part of this plan; each needs its own reviewed design and plan:

- The admission coordinator: source and requester from the authenticated call path, journal-projected, decision-scoped snapshot under the writer fence with every generation and the first-start marker, approval request storage of the request content keyed by request digest, approval expiry, single-administrator exemption records in the same guard, prepare/commit/abort/epoch reducers that retain ownership reservations, tombstones, consumed authorizations and the global release floor on abort, publish only committed after-images, and never relabel registrations; replay rebuilds the floor from all reserved-id history, refuses a missing floor and fences old replicas, including binaries that do not implement the floor contract and cannot obtain writer authority. Require crash fixtures before/after each journal and database step, first-prepare abort/retry, concurrent ownership claims, stale-registration recovery and mixed-version floor races. Commit the `Intent` including targets, enabled state and registration bindings, generation allocation, blob publication and hand-off to `policy` and `api`. Blocked on BE-12 (`authority-journal-protocol.md` section 10).
- The GitOps `Extension` apply path and the console install view, which consume `ParseResource` and the coordinator.
- The release-manifest payload and browser-registration schema with canonical OS targets and protected current-epoch renewal, the disclosure-profile catalogue, the console bridge catalogue and the connector contracts (`analysis.md` section 3).

The separate permission-coverage refresh must add both admission specs to the source inventory, re-pin changed extension documents, and replace the extension portion of the `offline-recovery` exemption with: "First-party server-image admission uses the fixed system principal and verified release authority only for first-start installs, unwidened upgrades with unchanged targets, and bounded recovery re-assertion at or above the journaled automatic release floor. Every referenced browser registration must have current-epoch protected authority; release-fixed approval cannot renew it. Backward server-image proposals require operator approval under `authz.approvals.approve`; operator approval never lowers the floor. Aborted prepares retain ownership reservations, tombstones, floor advances and consumed authorizations without publishing installs or grants." Preserve the exemption's unrelated first-start, custodian and key-admission text. Do not edit coverage pins in this slice.

## Handoff questions

- Which executable journal gate will carry the `Intent` fields into the prepare record, and does the reducer need a canonical encoding other than the JCS objects defined here?
- Who owns the disclosure-profile catalogue and its reviewed publication contract?
- Should device-group existence become journaled authority? The admission spec keeps it a `devices` module fact until that owner decision changes.
