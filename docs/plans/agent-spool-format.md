# Agent spool format implementation plan

**Goal:** Build the file-free Rust segment encoder and recovery library specified in [agent-spool-format.md](../specs/agent-spool-format.md), with shared fixtures and native-host CI.

**Architecture:** One leaf package in the `agent/` virtual workspace. Encoders write explicit fields; recovery returns a borrowed, validated prefix and typed diagnostics. No process, filesystem, runtime or networking integration enters the library.

**Toolchain:** Rust 1.99.0 with Cargo 1.99.0. The installed companion tools are Go 1.27.1, Node 24.21.0 and pnpm 11.18.0; this slice does not require Node or pnpm. Python fixture generation uses only the standard library; CI pins Python 3.13.7.

## Global constraints

- An independent `gpt-6.1-sol` reviewer at `xhigh` must approve the spec, plan, fixtures and Rust/testing instructions before code starts. Review-ready does not mean approved.
- A separate `gpt-6.1-sol` implementer at `medium` owns the code paths below. The design author and reviewer do not implement this slice. Dispatch with a self-contained brief naming the approved documents, owned files, forbidden actions, commands and expected report.
- Use one implementation worktree. Tasks depend on their predecessors and run in order. Other workers are not alone in the repository: preserve their changes and use separate worktrees for concurrent edits. Do not edit unrelated files.
- A `gpt-6.1-sol` reviewer at `xhigh` independently reviews each completed task before dependent work starts. The final code review includes an adversarial pass because recovery parses untrusted bytes. A separate xhigh reviewer confirms fixes. Reviewers never implement fixes.
- Write the test first, run it and observe its intended failure, then implement the least code that passes it. A build failure from a missing public item is an acceptable first failure when establishing the crate; test-command typos are not.
- The primary agent inspects changes, runs required checks, integrates work and owns all Git operations. Workers never commit or push. Design approval does not grant native durability or authorize production consumers of unresolved gates.
- Follow [Rust instructions](../../instructions/rust.md), [testing instructions](../../instructions/testing.md#rust-agent), and [licensing rules](../licensing.md). Do not add unreviewed dependencies, features or APIs.

## Owned implementation paths

Create `agent/Cargo.toml`, `agent/Cargo.lock`, `agent/rust-toolchain.toml`, `agent/.gitignore`, `agent/crates/spool/Cargo.toml`, `agent/crates/spool/src/lib.rs`, `agent/crates/spool/tests/{header,record,recovery,fixtures,fuzz_recover}.rs`, `agent/crates/spool/tests/support/{mod,fixture_data}.rs`, and `agent/tools/generate-spool-fixtures.py`. Create `.github/workflows/agent.yml` only in this implementation stage. Make only the dependency/build-tool additions required below to `docs/licensing.md`.

Shared schemas and design documents are read-only implementation inputs. Report a contract defect to the primary agent for design revision and independent approval. Do not silently change fixture expectations to make tests pass. No root ignore settings, other workflow, server source, agent binary or OS integration is owned by this plan.

## Review focus

- Verify every class value/name against Go and distinguish spool bytes from the upload frame.
- Enforce the exact public API, header padding, CRC input and unsigned little-endian fields.
- Test combined defects in the declared order, including unsupported headers versus repairable tails.
- Check `usize` and u64 arithmetic, arbitrary lengths, empty input, maximum payload and exhausted sequence.
- Prove unchanged output on encoder failure and no accepted bytes beyond a corrupt record.
- Keep recovery allocation-free and immutable, with no file mutation, implicit durability or authenticity claim.
- Execute shared fixtures, independently check CRCs, and prevent generated Rust fixture drift.
- Verify native target triples in CI; a macOS Intel pass cannot stand in for ARM64.

## Task 1: Workspace, license closure and header

**Interfaces:** `SpoolClass`, `Header`, constants, `Error`, and `encode_header` from spec section 3. Recovery-dependent tests wait for Task 3.

- [ ] Add license records before relying on tools: Rust 1.99.0 toolchain/standard library (MIT OR Apache-2.0), `rustc_version` 0.4.1 and `semver` 1.0.27 (MIT OR Apache-2.0), and `actions/cache` v6.1.0 at the commit in Task 5 (MIT). Inspect that release's `LICENSE` and bundled dependency license notices at the exact pinned commit. These license expressions remain verify checks against exact release texts. Add Python 3.13.7 as a build tool under the [PSF license and incorporated-software terms](https://docs.python.org/3.13/license.html). Verify upstream license texts and retain applicable notices. The existing `crc32c`, checkout, setup-python and Python validation-tool rows cover those named tools; refine the crc32c row with its exact version. If the resolved closure differs, stop dependent work for a reviewed pin/license correction, not a floating update.
- [ ] Create the workspace metadata and toolchain file exactly as [Rust instructions](../../instructions/rust.md) require. Use `members = ["crates/spool"]`. Member metadata inherits version, edition, rust-version, license and publish. Inherit workspace lints. Put `/target/` in `agent/.gitignore`; do not alter global Git configuration. Add `crc32c = "=0.6.8"` in workspace dependencies and inherit it in the member. No other direct dependency or feature override.
- [ ] Generate the lockfile once: `cd agent && cargo generate-lockfile`, then `cargo update -p rustc_version --precise 0.4.1` and `cargo update -p semver --precise 1.0.27`. Require exactly the three external packages in spec section 1. Run `cargo tree --locked --edges normal,build,dev` and inspect all licenses, sources, features and build scripts. Lockfile pins are exact even though upstream manifests use compatible ranges.
- [ ] Write `header.rs` tests first: all five enum values/names, unknown bytes across 0..=255, exact header bytes, zero epoch, zero counters, all-u64-max fields, error trait use and variant matching. Do not use Rust memory layout to construct expected bytes.
- [ ] Run `cd agent && cargo test --locked -p ricevanta-spool --test header`; record failure for missing API. Implement only the declared types/constants and header encoder, then rerun for PASS.
- [ ] The primary agent checks the diff and obtains independent xhigh approval before Task 2.

## Task 2: Record encoder

**Interfaces:** `Record` and `encode_record`; output is caller-owned scratch space, not a file append.

- [ ] Write `record.rs` tests first. Cover empty/binary payloads, sequence 0 and u64::MAX, asymmetric byte order, independent checksum bytes, payload lengths just below/at/above the cap, all output sizes from zero through the encoded size for a small record, and a larger buffer with untouched trailing sentinels. Oversized payload plus short output must return `PayloadTooLarge`; every error preserves the entire buffer.
- [ ] Run `cd agent && cargo test --locked -p ricevanta-spool --test record`; require the expected missing-function failure. Add the encoder with preflight checks before mutation and incremental CRC without concatenation. Run the same command for PASS.
- [ ] Verify checksum arithmetic against the independent fixture oracle and ASCII check value, not just another call to the same production helper. Obtain independent review before Task 3.

## Task 3: Recovery and shared fixtures

**Interfaces:** `recover`, `Recovery` accessors, borrowed iterator and tail/error types from spec section 3. The JSON fixture schema is the data contract; no new Rust JSON dependency is needed.

- [ ] Write the std-only Python generator. It reads `schemas/agent/spool/v1/fixtures.json` relative to its own repository path, preserves fixture IDs, converts decimal strings with u64 range checks, decodes bounded lowercase even hex, and emits typed static Rust expectations under `tests/support/fixture_data.rs`. Cap each fixture at 2 MiB decoded bytes. Reject unsupported outcome variants and fields. It never computes expected recovery results; it translates the independently supplied expectations. `--check` compares regenerated bytes without writing and fails on any drift. Generated Rust uses `#[rustfmt::skip]` only on generated data items, not the surrounding test harness.
- [ ] Put shared fixture types/helpers in `tests/support/mod.rs`; integration tests import `mod support`. Keep support out of separate Cargo integration targets. The generated file contains data only, with an attribution comment naming its JSON source and generator command.
- [ ] Run `python agent/tools/generate-spool-fixtures.py` from the repository root. Write `fixtures.rs` and `recovery.rs` tests before implementing recovery. Every fixture compares the exact error variant and fields or every header/record/summary/tail field. Assert borrowed payload pointers lie within the original accepted input. Snapshot input before calling recovery to prove immutability.
- [ ] Run `cd agent && cargo test --locked -p ricevanta-spool --test recovery --test fixtures`; observe the missing recovery implementation failure. Implement the ordered checks and private prefix state, then require PASS from the same command.
- [ ] Additional recovery tests: final-record truncation at every byte; header truncation at all 32 short lengths; multi-invalid precedence; bad first record; bad interior record with good suffix; full-width lengths; u64 exhaustion followed by clean EOF, partial, bad-CRC and valid-CRC records; first-sequence mismatch; repeated iteration; exact and above-cap payloads. Construct a segment above 4 MiB and a segment with 5,001 empty records and accept both to prove sealing thresholds are not decoder limits.
- [ ] Check encoders against every clean successful fixture: re-encode header and records and compare exact bytes. For recoverable suffix cases, re-encode only the prefix and compare with `input[..valid_len]`. Fatal errors return no prefix. Never require opaque payloads to pass JSON/OCSF rules.
- [ ] Run `python agent/tools/generate-spool-fixtures.py --check`, the focused tests, and `cd agent && cargo test --locked --workspace`. Obtain independent adversarial review before Task 4.

## Task 4: Bounded fuzz-like tests

**Files:** `tests/fuzz_recover.rs` and shared test helpers. No cargo-fuzz, nightly, random crate or test-time network.

- [ ] Write two targets: ordinary test `fuzz_recover` and `#[ignore]` test `fuzz_recover_extended`. Use fixed seed `0x525653505f763031` and a documented std-only xorshift64 sequence (left 13, right 7, left 17, u64 shifts/XOR). Normal budget is 10,000 cases; extended budget is 100,000. Print seed and case index on failure, not arbitrary event payloads.
- [ ] Seed from every shared fixture and encoder-generated records. Cycle through prefix cuts, single-bit flips, insertions, deletions, length/sequence substitutions, and generated byte strings of lengths 0 through 4,096; cap mutated buffers at 8,192 bytes. Include targeted lengths 0, 1, 3, 4, 15, 16, 31, 32, 33 and the maximum u32 field. Deterministic boundary tests cover the 1 MiB payload sizes outside this budget.
- [ ] Assert no panic; unchanged input; on success `32 <= valid_len <= input.len()`; tail offset equals valid length; no-tail length equals input length; iterator count and next sequence agree with summary; every returned CRC/sequence agrees with an independent std-only bitwise test oracle; rescanning the accepted prefix returns the same records with no tail. Encode generated headers/records and require exact round trips. Do not reproduce the production parser as the only oracle.
- [ ] Run `cd agent && cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover -- --exact`; observe the missing test-helper/API invariant failure before completing the harness, then PASS. Demonstrate that a deliberate CRC or sequence-check mutation in the implementation is caught, restore the correct code, and record the failing assertion and final pass. Do not retain the deliberate defect.
- [ ] Run `cd agent && cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact`. Record elapsed time and case count. Commit useful minimized regression inputs through the primary agent's normal reviewed fixture process.
- [ ] Justification: fixed mutation budgets run on stable Rust on all three hosts and need no extra dependency. They are fuzz-like property tests, not coverage-guided fuzzing or proof of memory/OS support. Expanding to cargo-fuzz requires a reviewed setup and does not waive these checks. Obtain independent review before Task 5.

## Task 5: CI and whole-slice review

**File:** `.github/workflows/agent.yml`. Match `.github/workflows/server.yml` for trigger shape, read-only permission, checkout credentials, timeouts, cache and concurrency conventions.

- [ ] Name the workflow `Agent checks`. Trigger pushes on `master`, pull requests, and manual dispatch. Both path filters include `agent/**`, `schemas/agent/**`, `schemas/events/v1/**`, `server/internal/events/batch/**`, `docs/specs/agent-spool-format.md`, `docs/plans/agent-spool-format.md`, `instructions/rust.md`, `instructions/testing.md`, `docs/licensing.md` and `.github/workflows/agent.yml`.
- [ ] Set `permissions: { contents: read }`, concurrency group `agent-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}` and `cancel-in-progress: true`. Use a matrix with `fail-fast: false`, a 15-minute timeout per job, and `defaults.run.working-directory: agent`, `defaults.run.shell: bash`.
- [ ] Use the native matrix below. Check `${{ runner.arch }}` against ARM64 or X64 and `rustc -vV` against the exact host triple before building. A mismatch fails, not skips. [GitHub's runner table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) documents these architectures; hosted image labels do not certify every eligible product OS.

| Runner label | Host target | runner.arch |
|---|---|---|
| `macos-15` | `aarch64-apple-darwin` | `ARM64` |
| `windows-2025` | `x86_64-pc-windows-msvc` | `X64` |
| `ubuntu-24.04` | `x86_64-unknown-linux-gnu` | `X64` |

- [ ] Use these full action pins, with readable version comments. Checkout sets `persist-credentials: false`. Python setup sets `python-version: '3.13.7'`. Rust setup runs `rustup toolchain install 1.99.0 --profile minimal --component rustfmt --component clippy`; subsequent Cargo commands select the checked-in toolchain file. No unpinned Rust action or downloaded install script.

| Action | Exact commit | Basis |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | [v7.0.1 release](https://github.com/actions/checkout/releases/tag/v7.0.1), server and design workflow pin |
| `actions/setup-python` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | [v7.0.0 release](https://github.com/actions/setup-python/releases/tag/v7.0.0), design workflow pin |
| `actions/cache` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | [v6.1.0 release](https://github.com/actions/cache/releases/tag/v6.1.0) |

- [ ] Cache only `~/.cargo/registry/index`, `~/.cargo/registry/cache` and `~/.cargo/registry/src`, not the whole Cargo home, credentials or build output. Key: `agent-cargo-${{ runner.os }}-${{ runner.arch }}-1.99.0-${{ hashFiles('agent/Cargo.lock') }}`; no cross-OS cache or broad restore prefix. Downloads remain checked against Cargo.lock. Check `cargo metadata --locked --format-version 1` resolves the expected pins without changing the lockfile.
- [ ] Run `python tools/generate-spool-fixtures.py --check`, `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, and `cargo test --locked --workspace` on every native matrix host. Normal tests include shared fixtures and 10,000 mutation cases; the larger ignored test is required locally before review. Add a workflow assertion that the checked Rust toolchain version equals 1.99.0.
- [ ] Before the final workflow exists, record that its absence fails the task's workflow inspection. After creation, parse YAML and inspect action SHAs, matrix, path filters, commands, permissions and cache paths. The primary agent runs the workflow through the normal Git process only after review; failed/missing native runs remain failed/pending evidence, never claimed passes.
- [ ] Obtain final independent Sol xhigh code review with an adversarial parser pass, then separate fix confirmation where needed. The primary agent runs final checks and inspects the full diff.

## Final verification

Run from the repository root unless `cd agent` is shown. Record output, not just commands.

- [ ] `python agent/tools/generate-spool-fixtures.py --check`
- [ ] `cd agent && cargo fmt --all -- --check`
- [ ] `cd agent && cargo clippy --locked --workspace --all-targets -- -D warnings`
- [ ] `cd agent && cargo test --locked --workspace`
- [ ] `cd agent && cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact`
- [ ] `cd agent && cargo tree --locked --edges normal,build,dev`
- [ ] `git diff --check`; inspect the complete diff and confirm only owned paths changed.
- [ ] Report each of the three native CI results separately. Linux local tests cannot substitute for Windows or macOS runs. Report design approval, code review and fix confirmation status without implying any native durability gate passed.

## Open gates

The spec's [unresolved questions](../specs/agent-spool-format.md#8-unresolved-questions-and-review-focus) are review decisions, not permission to redesign during implementation. Verify exact upstream license texts and CI tool availability before using the chosen pins. Missing tools or incompatible pins block dependent work until a reviewed correction. Physical spool management, native durable sync, sealing/compression, upload, caps and stream-counter persistence require separate designs and qualification; do not create them under this plan.
