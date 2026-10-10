# Agent sealed batch writer implementation plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task by task. Checkboxes record completed work, not intended work.

**Goal:** Produce the canonical upload header and sealed body from one complete spool segment, with live Go decoder conformance tests.

**Architecture:** A file-free Rust leaf crate calls the existing spool recovery codec, checks NDJSON framing, derives both descriptors and performs bounded one-shot compression. A test-only example feeds Rust output into the fixed Go wire/body decoders.

**Tech stack:** Rust 1.99.0 with Cargo 1.99.0 and Go 1.27.1. Node 24.21.0 with pnpm 11.18.0 are installed but unused by this slice. Exact dependencies and features are in [the spec](../specs/agent-batch-writer.md#1-boundary-dependencies-and-alternatives).

**Spec:** [Agent sealed batch writer](../specs/agent-batch-writer.md), AG-11. EV-08 and EV-09 remain authoritative for server acceptance.

## Global constraints

- An independent Sol xhigh review approves both spec and plan before code starts. Approval must cover the binding, closure, error order and memory boundary; a design marked review-ready is not approval.
- A separate Sol medium implementer, `gpt-6.1-sol` at `medium`, owns the paths below. The designer and reviewers never implement this slice. Dispatch explicit model and effort with a self-contained brief.
- Use `gpt-6.1-sol` at `xhigh` for every design/code review and independent fix confirmation. Code review includes an adversarial pass over untrusted segments, integer bounds, FFI dependency behavior, incomplete output and child-process test framing.
- The primary agent owns planning, verification and Git. Workers never commit, push, stage, rewrite history or change another worker's files. Use one isolated implementation worktree for this sequential slice; other workers use separate worktrees. Do not revert their edits.
- Follow `instructions/rust.md`, `instructions/go.md`, `instructions/testing.md` and `instructions/workflow.md`. Preserve existing toolchain, module directives, lints and exact lockfile pins. Product Rust contains no unsafe code.
- Write tests first, run them and record the intended failure, then implement the least code that passes. Compilation failure for an absent API is valid initial evidence; a dependency download failure is not a failing behavior test.
- Keep native file ownership, durability, timers, upload, retries, epoch/counter creation, JSON/OCSF validation, admission and acknowledgement outside this slice. Do not change server production decoders to accept writer output.
- Verify release license texts and the exact resolved dependency/feature closure before adding product use. The one licensing row lists the whole added closure; it does not approve unspecified dependencies. If a pin cannot resolve, stop dependent implementation and correct the design for independent review.
- The slice implementer owns `.github/workflows/agent.yml` for Task 4. Leave all other `.github/` files, including `server.yml`, unchanged. Native Rust/C checks on macOS ARM64, Windows x64 and Linux x64 are acceptance requirements; lack of a native result stays an open gate. Run CI interoperability once in a separate Linux job, outside the native matrix.
- Report exact commands, failures, mutation seed/count, native compiler identity and any unrun check. Never claim a durable file or successful upload from a codec test.

## Owned paths and order

| Path | Responsibility |
|---|---|
| `agent/Cargo.toml`, `agent/Cargo.lock` | Add only the batch member and reviewed dependency closure |
| `agent/crates/batch/Cargo.toml` | Inherited package metadata/lints, exact spool and zstd dependencies |
| `agent/crates/batch/src/lib.rs` | Public API, validation, errors and descriptor assembly |
| `agent/crates/batch/src/compress.rs` | Private configured one-shot compression |
| `agent/crates/batch/tests/seal.rs` | Boundaries, byte ownership and precedence |
| `agent/crates/batch/tests/support/mod.rs` | Independent test record/CRC builder and frame inspector |
| `agent/crates/batch/tests/fuzz_seal.rs` | Deterministic bounded mutation checks |
| `agent/crates/batch/examples/seal-vector.rs` | Test-only stdin/stdout bridge to `seal` |
| `server/internal/events/body/rust_writer_test.go` | Tagged live interop test and fixture adapters |
| `.github/workflows/agent.yml` | Exact dependency check, native bundled C qualification, scoped job filters and Linux-only interop job |

Existing spool/server production code, schemas and fixtures are read-only. Reuse existing Go test helpers inside package `body` without exporting production APIs or refactoring unrelated tests. No new fixture file is needed: recipes in `schemas/events/v1/fixtures/body.json`, `header.json` and `descriptor.json` own shared inputs and expectations. Rust-only cases use explicit test construction under the owned test paths.

Tasks 1 through 5 are sequential. After each task, the primary agent inspects the diff and runs its focused checks before dependent work starts. A reviewer reports severity, path, concrete defect and expected behavior, or explicit approval. The implementer reports changed paths, tests before/after, results and remaining gates. Independent Sol xhigh confirmation accepts fixes before integration.

## Review focus

- A checksum-invalid tail never becomes a valid-prefix upload or an instruction to delete/truncate the original segment.
- Total plaintext includes every LF; a legal maximum-sized payload cannot cause a one-record overshoot beyond 4 MiB.
- A late spool error wins over earlier bad line framing; framing wins over the same record's total-byte overflow.
- Full-width counters reach both descriptors unchanged; stored sequence validation does not rewrite JSON sequence claims.
- Compression honors checksum/content-size/window controls and emits one frame after exactly 48 descriptor bytes.
- JSON/UTF-8 defects preserve raw bytes and produce Go quarantine, rather than writer reserialization or whole-batch failure.
- Live interop runs the actual newly built example, fails on a missing executable and preserves the descriptor's consumed reader budget.
- Workflow filters run interop for either crate, either decoder or the v1 event fixtures, never for unrelated paths. Decoder/fixture-only edits do not launch the native matrix. Exact dependency checks admit only the reviewed closure, and every native host compiles bundled zstd with system-library selection disabled.
- All added transitive crates/features and native code licenses match the reviewed closure. Codec portability is not a process-memory or durability claim.

### Task 1: Segment validation and canonical descriptors

**Files:** workspace/member manifests and lockfile; `src/lib.rs` with private unit tests.

**Interface:** the public value/error types in spec section 2 and a private preparation function. Private unit tests exercise validated metadata and byte totals without publishing a second API. The public `seal` function and compression arrive together in Task 2; do not add a placeholder success path.

- [x] Read the authorities and inspect the installed exact dependency manifests/license files. Resolve the added closure in an isolated temporary Cargo workspace first, with `ZSTD_SYS_USE_PKG_CONFIG` unset. Compare every package and feature against spec section 1. Preserve the spool closure. Verify full release notices; record the C compiler identity. An unavailable pin or unexpected dependency blocks the next step.
- [x] Add the batch workspace member and the exact dependencies after the closure check. Set `zstd` default features false. Use `cargo update -p <crate> --precise <version>` for each transitive pin in the spec table as needed; review the final lockfile rather than accepting an unconstrained resolution. Run `cd agent && cargo tree --locked --target all --edges normal,build,dev` and `cd agent && cargo tree --locked --target all -e features -p zstd`.
- [x] Write `rejects_segment_size`, `rejects_spool_errors`, `rejects_tail`, `rejects_empty_and_count`, `line_framing_precedence`, `decoded_limit_precedence`, `descriptors_all_classes` and `sequence_boundaries`. Use the existing spool encoder only in ordinary setup; use a bitwise Castagnoli oracle in a private test builder for corruption/precedence cases. Include every spec section 3 combined defect and unchanged input on failure. These are private unit tests of preparation; no public sealing stub is required.
- [x] Run `cd agent && cargo test --locked -p ricevanta-batch --lib`. Require the intended failure for the missing API/behavior; record it.
- [x] Implement bounded entry precheck, recovery, tail refusal, count/framing checks, checked totals, typed errors and canonical header/descriptor helpers. Preserve spool causes through `source()`. Add a redacted `Debug` for successful batches; error formatting must never include event text.
- [x] Run `cd agent && cargo test --locked -p ricevanta-batch --lib`. Require all Task 1 rejection tests to pass; do not claim successful sealing before Task 2. Independently review these changes before building on the validation order.

### Task 2: Single-frame compression and owned output

**Files:** `src/compress.rs`; `src/lib.rs`; `tests/seal.rs`; `tests/support/mod.rs`.

**Interface:** successful `seal` returns the complete private `SealedBatch`; accessors and `into_parts` implement spec section 2. The private compressor accepts only validated plaintext and the descriptor prefix.

- [x] Write `seals_one_frame`, `content_size_boundaries`, `max_ndjson`, `max_records`, `incompressible_bound`, `preserves_payload_bytes`, `quarantine_payloads_seal`, `owned_output`, `redacts_debug` and `compression_error_source`. Inspect frame structure independently of the Rust decompressor: flags, content size including the two-byte bias, window, block boundaries, checksum and EOF. Include one-byte payloads, both legal line-size boundaries and all plaintext sizes in spec section 6.
- [x] Run `cd agent && cargo test --locked -p ricevanta-batch --test seal`. Require failure on the absent successful sealing behavior, not an ignored test.
- [x] Implement the exact level, setter order, output allocation and single `compress_to_buffer` call from spec section 5. Write descriptor fields explicitly, truncate once, enforce complete-body length, drop plaintext and return only completed output. Do not use a decoder in the production path. Map every constructor/setter/codec error without string inspection.
- [x] Unit-test error mapping by injecting an `io::Error` into the private mapping helper and checking `source()`; do not add public codec controls or an arbitrary writer solely for tests. Test the private final length guard with synthetic lengths at 5,000,000 and 5,000,001 so its defensive branch is covered without pretending valid compression reaches it.
- [x] Recompute `compress_bound(MAX_NDJSON_BYTES)` with the pinned library and an independent formula. Require the spec's complete-body bound. Decompress success outputs and compare each byte with payload-plus-LF construction. Drop the source allocation before reading the returned result in the ownership test.
- [x] Run `cd agent && cargo test --locked -p ricevanta-batch` and `cd agent && cargo clippy --locked --workspace --all-targets -- -D warnings`. Require PASS. Obtain independent review before the cross-language bridge consumes the output.

### Task 3: Live Go decoder conformance

**Files:** `examples/seal-vector.rs`; `server/internal/events/body/rust_writer_test.go`.

**Interface:** the test-only byte protocol in spec section 6. Keep the Go test in package `body` with `//go:build rustinterop`. Import only existing event packages and Go standard packages. `TestRustWriterFixtures`, `TestRustWriterBoundaries` and `TestRustWriterMutations` are the required test names.

- [x] Write the Go tests first. Reuse `loadFixtures`, `bodyFixture.plain`, `bodyFixture.descriptor`, `digestOK` and `assertReferenceLine` where their contracts fit. Decode header/descriptor fixture JSON through small local test structs. Do not use the permissive test schema helper as the sole schema validator. Select all eligible successful cases as specified; fail if none or if any selected case is silently skipped.
- [x] For body cases, construct spool CRCs with `hash/crc32` and compare Go line errors using an explicit `errors.Is` mapping for expected sentinels and nested causes. For descriptor cases, compare exact prefix bytes and header text against existing fixture values, not a copy of the Rust algorithm alone. Synthetic payloads use the existing fixture record template and positional decimal sequences.
- [x] Run `cd server && go test -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1`. Require failure because `RICEVANTA_BATCH_VECTOR` is absent. Record this as the explicit harness precondition check; the following failing behavior test must also run after the bridge builds.
- [x] Create the std-only example, bounded stdin/stdout protocol and variant-only failure output. It must invoke the public library, not reconstruct compression or descriptors. Handle broken pipes as errors. Build with `cd agent && cargo build --locked -p ricevanta-batch --example seal-vector`.
- [x] Run the tagged tests against that absolute executable path. Require live output to satisfy each independent fixture expectation. Test harness failure paths with a test-local malformed child response and a nonexistent executable; neither may skip the test or count as a successful decode.
- [x] Add all positive size/count/full-width vectors and the 128 fixed-seed generated segments from spec section 6. Test CRC-preserving JSON defects and mixed quarantine. Corrupt live Rust frames structurally to check checksum, absent flags, excess window, trailing frame and descriptor mismatch errors. Supply the same limited reader to both Go decoders, with no budget reset.
- [x] Run the exact commands below on Linux from the repository root. Require all tagged tests to execute, including the precondition check in an isolated child test, without requiring Cargo for ordinary untagged Go tests. Task 4 owns their CI execution. The commands also support local macOS diagnosis; Windows commands below are optional local diagnosis.

```sh
RICEVANTA_BATCH_VECTOR="$PWD/agent/target/debug/examples/seal-vector" sh -c 'cd server && go test -tags rustinterop ./internal/events/body -run "^TestRustWriter" -count=1'
RICEVANTA_BATCH_VECTOR="$PWD/agent/target/debug/examples/seal-vector" sh -c 'cd server && go test -race -tags rustinterop ./internal/events/body -run "^TestRustWriter" -count=1'
```

On native Windows PowerShell, from the repository root:

```powershell
$env:RICEVANTA_BATCH_VECTOR = (Resolve-Path agent/target/debug/examples/seal-vector.exe).Path
Push-Location server
go test -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1
go test -race -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1
Pop-Location
```

- [x] Obtain independent Sol xhigh review and fix confirmation. The reviewer checks that the bridge is test-only and verifies both header equality and actual Go acceptance rather than only decompression.

### Task 4: Native build and Linux interop workflow

**Owner and files:** the same Sol medium slice implementer owns `.github/workflows/agent.yml`, including the inline changed-path detector. No separate workflow owner or unowned follow-up is required. Do not edit `server.yml` or add a filter action or helper file.

**Interface:** implement [spec section 6.1](../specs/agent-batch-writer.md#61-ci-ownership-and-scope). Use `agent.yml` to share its Rust toolchain and dependency policy. Keep Go setup and tagged tests in the standalone Linux job so native Rust/C qualification does not pay for three Go runs.

- [x] Extend the exact `cargo metadata --locked --format-version 1` expected set with `ricevanta-batch` 0.1.0 and all twelve spec section 1 name/version pairs. Retain `ricevanta-spool` 0.1.0, `crc32c` 0.6.8, `rustc_version` 0.4.1 and `semver` 1.0.27. Preserve both set equality and package-count equality, now 17. Check the complete lockfile closure, including target-specific packages; do not use subset checks or platform filtering. Verify rejection of an extra package and a changed version using synthetic metadata.
- [x] Keep all three native runner/host pairs and the existing fixture, format, Clippy and workspace-test checks. In every Cargo shell step, run `unset ZSTD_SYS_USE_PKG_CONFIG` and `test -z "${ZSTD_SYS_USE_PKG_CONFIG+x}"` before Cargo. Use verbose build output for the first compiling step and record the actual selected compiler/version, including MSVC on Windows. Require logs showing bundled zstd C sources compile on all three hosts. Retain download caches without caching `target`; an empty environment value or a restored compiled library does not qualify this check.
- [x] Add the three server/schema workflow paths and a Linux `changes` job with `native` and `interop` outputs as specified. Use the pinned checkout action with `persist-credentials: false` and sufficient Git history for the comparisons. Read event SHAs from `GITHUB_EVENT_PATH`; compare PR merge-base to PR head and push `before` to push `after`. For an all-zero push base, compare the empty tree to `after`. Fetch a missing comparison commit by validated SHA or fail the detector; never return false on a diff error. Use NUL-separated `git diff --name-only --no-renames -z` output so additions, deletions and both sides of a rename participate without filename shell interpolation. Use an inline standard-library script; do not execute repository code in the detector. Manual dispatch sets native true and interop false.
- [x] Gate `validate` with `needs: changes` and `if: needs.changes.outputs.native == 'true'`. Add `rustinterop` with `needs: changes` and `if: needs.changes.outputs.interop == 'true'`, `runs-on: ubuntu-24.04`, no matrix and a 15-minute timeout. Do not make interop depend on `validate`, which is skipped for decoder/fixture-only edits. Preserve read-only permissions, branch restrictions and concurrency cancellation. Reuse pinned checkout, Go setup and Cargo download-cache actions; Go setup reads `server/go.mod` and caches against `server/go.sum`.
- [x] Install Rust 1.99.0 and verify the Linux native host. Set `CARGO_TARGET_DIR` to the absolute `${{ runner.temp }}/ricevanta-batch-target` path for the job. With system-library selection unset and absence checked, run `cargo build --locked -p ricevanta-batch --example seal-vector` in `agent`. Export `RICEVANTA_BATCH_VECTOR` as `${CARGO_TARGET_DIR}/debug/examples/seal-vector`, verify that it is absolute and executable, then run both Task 3 tagged Go commands in `server`, using that path instead of the local default. Require all three `TestRustWriter` suites to execute with `-count=1`; no skip, prebuilt artifact or ordinary untagged test substitutes for them.
- [x] Validate workflow syntax and exercise the actual inline detector and job conditions for push and PR inputs. Each of the five interop path patterns must select exactly one Linux interop job. Each crate change also selects the native matrix; wire, body and v1 fixture-only changes do not. Check negative cases: unrelated agent/server code, `agent/Cargo.lock`, `server/go.mod`, `schemas/agent/**`, `schemas/events/v2/**`, docs and workflow-only changes must not select interop. Check mixed paths, deletions, renames, all-zero push base, missing comparison history and manual dispatch. Confirm native selection retains its specified scope. Obtain independent Sol xhigh review and fix confirmation of the workflow, including event handling and job dependencies.

### Task 5: Mutation tests and complete verification

**Files:** `tests/fuzz_seal.rs`; test support only for shared generators.

- [x] Write `fuzz_seal` and ignored `fuzz_seal_extended` using the spec's seed, recurrence, budgets and invariants. Include every fixed boundary as an ordinary seed test. Have the tests call an absent test-support mutation generator and observe the compilation failure with `cd agent && cargo test --locked -p ricevanta-batch --test fuzz_seal`; then implement that generator without changing the asserted product invariants.
- [x] Run `cd agent && cargo test --locked -p ricevanta-batch --test fuzz_seal`. Require the mutation target to pass with its seed and 2,000 cases reported. Do not suppress panics or discard successful cases.
- [x] Run the extended target below with 20,000 cases. Report elapsed time and results; this deterministic stable target adds no fuzz runtime dependency.
- [x] Run the full final checklist. Review the entire slice independently on Sol xhigh, including its adversarial pass. A different Sol xhigh reviewer confirms fixes. The primary agent inspects every edit and repeats checks affected by fixes before accepting the work.

## Final verification

Run these from the repository root unless the command changes directory. Use a writable build/cache directory without changing dependency versions. Unset `ZSTD_SYS_USE_PKG_CONFIG` and verify its absence in each shell that runs Cargo, including the Task 3 bridge build.

```sh
python agent/tools/generate-spool-fixtures.py --check
cd agent && cargo fmt --all -- --check
cd agent && cargo clippy --locked --workspace --all-targets -- -D warnings
cd agent && cargo test --locked --workspace
cd agent && cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact
cd agent && cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact
cd agent && cargo tree --locked --target all --edges normal,build,dev
cd agent && cargo tree --locked --target all -e features -p zstd
cd server && gofmt -l .
cd server && go test ./...
cd server && go test -race ./...
cd server && go vet ./...
cd server && go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2
cd server && go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2
cd server && go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2
cd server && go test ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=5s -parallel=2
cd server && go test ./internal/events/wire -fuzz=FuzzDecode -fuzztime=5s -parallel=2
cd server && go test ./internal/events/body -fuzz=FuzzExtractLine -fuzztime=5s -parallel=2
cd server && go test ./internal/events/body -fuzz=FuzzDecode -fuzztime=5s -parallel=2
git diff --check
```

Each `cd ... && ...` line is a separate command launched from the repository root. Require exit zero; `gofmt -l` must print nothing. Task 3's Linux bridge build and both tagged Go commands, plus Task 4's workflow/filter checks, are mandatory in addition to this list. Require native workspace builds/tests and bundled C compilation evidence on the exact three target pairs; interop CI runs only in the separate Linux job. Record absent target results as unrun, not successful cross-compilation.

Validate the unchanged shared fixture containers with Python jsonschema 4.25 from the repository root:

```sh
python - <<'PYVALIDATE'
import json
from pathlib import Path
from jsonschema import Draft202012Validator
root = Path('schemas/events/v1')
for schema, names in [('fixture.schema.json', ['header', 'descriptor', 'response']),
                      ('body-fixture.schema.json', ['body'])]:
    value = json.loads((root / schema).read_text())
    Draft202012Validator.check_schema(value)
    validator = Draft202012Validator(value)
    for name in names:
        validator.validate(json.loads((root / 'fixtures' / (name + '.json')).read_text()))
        print(name, 'PASS')
PYVALIDATE
```

The report must distinguish pure codec correctness, native C dependency build evidence and unresolved operational memory/durability gates. End with verified commands and open gates. The primary agent alone performs any later Git operations under repository workflow.
