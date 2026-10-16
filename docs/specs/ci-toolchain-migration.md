# Toolchain migration files

This file names the atomic implementation scope for [CI toolchain refresh](ci-toolchain-refresh.md). It is not a second Playwright task. [CI Task 11](../plans/ci-hardening.md#task-11-refresh-toolchains-and-retire-the-ubuntu-2404-console-identity) owns the promotion; its base must have green Task 10 evidence. Paths below are implementation ownership, not permission for the designer to edit code.

## 1. Executable consumers

| Paths | Required change |
|---|---|
| `server/go.mod`, `scripts/ci/gotestdecls/go.mod` | Set the identical target `go` directive; retain no toolchain auto-download directive |
| `agent/rust-toolchain.toml` | Set the target patch; keep profile/components; `agent/Cargo.toml` minimum Rust language version and `agent/Cargo.lock` dependencies stay unless an independently explained lock-format change is necessary |
| `console/.node-version`, `console/package.json`, `console/pnpm-lock.yaml` | Align Node target and three Playwright package pins/integrities; retain pnpm exact engines/packageManager and ordinary dependency versions |
| `console/scripts/check-toolchain.ts`, `console/tests/unit/toolchain.test.ts` | Assert selected Node and retained pnpm, reject mismatches |
| `console/playwright.config.ts`, `console/vitest.config.ts`, `console/scripts/csp-reporter.ts`, `console/tests/unit/probes.test.ts` | Preserve exact per-leaf projects, headless/CSP settings and same-dist evidence; explicitly suppress new device `screen` forwarding; adapt reporter only to verified API/report changes |
| `console/tests/unit/browser-world-contract.test.ts`, `console/tests/unit/csp-evidence-contract.test.ts` | Recheck source-specific Playwright instrumentation seams and negative controls against the selected package; no weakened CSP assumptions |
| `scripts/ci/toolchains.lock.json` | Promote selected archive rows with their consumers; preserve retained Python/pnpm rows on remaining hosts; remove all Ubuntu 24.04 lock rows; add no unimplemented Arm64 support |
| `scripts/ci/bootstrap.py`, `scripts/ci/bootstrap/controls.py`, `scripts/ci/test_bootstrap.py` | Update accepted compiler/browser versions, revised browser layouts/native loads and hash tests; refuse the removed platform; preserve independent URL/size/hash checks, host validation, macOS no-xz and pnpm version-switch refusal |
| `scripts/ci/check_policy.py`, `scripts/ci/inventory.py`, `scripts/ci/test_policy.py`, `scripts/ci/test_triggers.py`, `scripts/ci/test_route.py`, `scripts/ci/test_required.py` | Move console/bootstrap host maps, remove one ordinary bootstrap receipt, preserve stable Linux test target suffixes and exact expected receipt equality |
| `scripts/ci/run_selected.py`, `scripts/ci/test_run_selected.py`, `scripts/ci/targets.toml`, `scripts/ci/fixtures/selected/playwright-report.json`, `scripts/ci/fixtures/selected/go-suite.jsonl`, `scripts/ci/fixtures/selected/go-interop.jsonl` | Refresh captured version/revision evidence using real output; preserve exact test selection, counts, timing and Go framing contracts |
| `.github/workflows/console.yml`, `.github/workflows/bootstrap.yml`, `.github/workflows/agent.yml` | Console Linux leaf and bootstrap run on Ubuntu 26.04; delete Ubuntu 24.04 bootstrap leaf; update explicit Cargo cache compiler key. Other workflow labels/action pins stay at Task 10 values |
| `.github/workflows/ci.yml`, `.github/workflows/design.yml`, `.github/workflows/server.yml`, `.github/workflows/copilot-code-review.yml` | Search and reconcile any explicit pin or removed platform reference introduced by prerequisite implementation; continue to use the common lock rather than add setup actions or another pin |
| `schemas/ci/v1/contracts.schema.json`, `schemas/ci/v1/examples.json` | Remove only the temporary Ubuntu 24.04 lock-platform enum/examples when no consumer selects it; retain release-only Arm64 shape and stable `linux-x64` native target IDs |
| `schemas/agent/footprint/v1/example.json`, `schemas/agent/footprint/v1/schema-cases.json` | Reconcile synthetic compiler-version evidence with the target without changing the footprint schema or budgets |

Task 11 must search the final base, because Tasks 7 through 10 can add consumers. The list does not authorize unrelated dependency upgrades, native platform redesign, weaker tests, manual edits to generated package integrity values or blindly rewriting every `linux-x64` string. `route.py`/`required.py` change only if an implemented map is owned there; their semantic contract stays the same.

### 1.1. Loader renewal ownership and handoff

Task 11's implementer owns the following migration work under [refresh section 2.1](ci-toolchain-refresh.md#21-loader-source-and-native-proof-renewal). These paths require evidence-based reconciliation even where executable behavior does not change.

| Paths | Required work before atomic Go promotion |
|---|---|
| `server/internal/extensions/loader/ALLOCATION_AUDIT.md`, `server/internal/extensions/loader/GATE_A_REVIEW.md`, `server/internal/extensions/loader/GATE_B_REVIEW.md` | Renew affected source bounds, exact compiler/helper provenance, all-three-native derivations and both independent source/native and qualification approval bindings; retain the identity and scope of existing Go 1.27.1 evidence until new evidence supersedes its applicability |
| `server/internal/extensions/loader/tree.go`, `server/internal/extensions/loader/internal/yamltokens/ALLOCATION_AUDIT.md`, `server/internal/extensions/loader/internal/yamltokens/resolve.go` | Recheck allocator/map/slice/interface boxing, parser fixed reserves and escapes, scalar integer recognition and their pinned source comments; update citations only after proving the target invariant |
| `server/internal/extensions/loader/yaml_qualification_test.go`, `server/internal/extensions/loader/loader_qualification_test.go`, `server/internal/extensions/loader/internal/yamltokens/qualification_test.go`, `server/internal/extensions/loader/internal/yamltokens/qualification_agreement_test.go`, `server/internal/extensions/loader/internal/qualificationfixture/maximum.go`, `server/internal/extensions/loader/internal/qualificationfixture/branches.go` | Preserve complete Gate A/B case and repetition inventories, same-call observations, raw counters and all bounds; reconcile only justified harness compatibility changes, with affected evidence renewed |
| `server/internal/extensions/manifest/`, `server/internal/signing/dsse/`, loader compression helpers and every selected standard-library/compiler helper identified by the audits and native compiler inputs | Inventory and review reached source, descriptor/cache/escape/linkage/stack dependencies; record hashes and source decisions in the owning audits, including unchanged sources. This is proof ownership, not permission for incidental dependency or behavior changes |

The implementer hands exact source and all three native artifacts to an independent `code_reviewer` for source/native confirmation, and both gates' raw qualification records for independent qualification confirmation. The coordinator binds both confirmations to the tested candidate and final integration CI before landing. A troubleshooter owns failures; changed proof invariants or mechanisms require designer and independent design-reviewer approval. No automatic version-string rewrite, frozen native-table copy or receipt-only approval satisfies this handoff. Keep this work in Task 11, with the target compiler staged in the candidate until every promotion gate passes.

## 2. Release and Python boundaries

`docs/plans/release-builds.md` Task 2 consumes the refreshed family. If `.github/workflows/release.yml`, release bootstrap maps or release recipes already contain version assertions, Task 11 reconciles them with the common lock and runs the release-only Arm64 leaf. If Arm64 admission is not implemented, its six Go/Rust candidates remain in licensing staging. Never add its rows alone. `scripts/release/build_root.py` and `scripts/release/elf_abi.py` remain owned by release Task 4A, which verifies the exact compiler in the pinned roots without changing the ABI floor.

`.github/python-version` and `.github/requirements-design.txt` stay unchanged in Task 11. Release Task 2 owns adding the two staged cp314 aarch64 hashes, plus corresponding `scripts/ci/python_env.py`, `scripts/ci/test_python_env.py` and bootstrap/policy fixtures, only with native closure admission. Ordinary CI hosts still resolve exactly nine locked distributions.

A future Python migration must change `.github/python-version`, `.github/requirements-design.txt`, `scripts/ci/{bootstrap,python_env,check_policy}.py`, `scripts/ci/bootstrap/controls.py`, `scripts/ci/test_{bootstrap,python_env,policy}.py`, all affected workflow bootstrap selections, lock payloads, license rows and docs together. It must prove versioned Windows registration handling, the macOS framework replacement/re-exec path, Linux relocation, bundled pip and optional zstd support. This is a blocked follow-on, not additional work hidden inside Task 11.

## 3. Documentation promotion inventory

The design preserves current implementation facts. When Task 11 promotes targets, update every affected statement in the following files in the same change. Prefer a link to the target/pin owner where repeating a version is unnecessary. Tagged Go source citations are evidence, not merely pins: preserve the documented invariant or revise it from the new source and tests. The compiler-bound loader audit/source inventory and mandatory independent renewal are in section 1.1, including files outside `docs/` and `instructions/`. Do not rewrite historical source-version examples that intentionally test a rejection.

| File | Pin/source occurrences to reconcile |
|---|---|
| `docs/architecture.md` | 1.27.1 |
| `docs/design/events.md` | 1.27.1 |
| `docs/licensing.md` | 1.27.1, 1.59.1, 1.99.0, 11.18.0, 24.21.0, 3.14.8 |
| `docs/plans/agent-batch-writer.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/agent-spool-format.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0, 3.14.8 |
| `docs/plans/cel-declarations.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/ci-hardening.md` | 1.27.1, 1.59.1, 11.18.0, 24.21.0, 3.14.8 |
| `docs/plans/console-foundation.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/core-primitives.md` | 1.27.1 |
| `docs/plans/dsse-envelope.md` | 1.27.1 |
| `docs/plans/ed25519-key-admission.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/event-batch-body.md` | 1.27.1 |
| `docs/plans/event-upload-wire.md` | 1.27.1 |
| `docs/plans/export-destination-schema.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/extension-admission.md` | 1.27.1 |
| `docs/plans/extension-loader.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/extension-manifest.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/footprint-harness.md` | 3.14.8 |
| `docs/plans/ingest-admission.md` | 1.27.1 |
| `docs/plans/mdm-resource-schemas.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/ocsf-contracts.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0, 3.14.8 |
| `docs/plans/permission-catalogue.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/release-builds.md` | 3.14.8 |
| `docs/plans/report-template.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/plans/server-runtime.md` | 1.27.1 |
| `docs/specs/cel-declarations.md` | 1.27.1 |
| `docs/specs/ci-hardening.md` | 1.27.1, 1.59.1, 1.99.0, 11.18.0, 24.21.0, 3.14.8 |
| `docs/specs/console-foundation.md` | 1.27.1, 1.59.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/core-primitives.md` | 1.27.1 |
| `docs/specs/dsse-envelope.md` | 1.27.1 |
| `docs/specs/ed25519-key-admission.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/event-batch-body.md` | 1.27.1 |
| `docs/specs/event-upload-wire.md` | 1.27.1 |
| `docs/specs/export-destination-schema.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/extension-admission-contracts.md` | 1.27.1 |
| `docs/specs/extension-loader.md` | 1.27.1 |
| `docs/specs/extension-manifest.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/ingest-admission.md` | 1.27.1 |
| `docs/specs/linux-build-root.md` | 3.14.8 |
| `docs/specs/mdm-resource-schemas.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/ocsf-profile.md` | 1.27.1, 3.14.8 |
| `docs/specs/permission-catalogue.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/report-template.md` | 1.27.1, 1.99.0, 11.18.0, 24.21.0 |
| `docs/specs/server-runtime.md` | 1.27.1 |
| `instructions/go.md` | 1.27.1 |
| `instructions/rust.md` | 1.99.0 |
| `instructions/vue.md` | 11.18.0, 24.21.0 |

Python/pnpm occurrences in this inventory remain current and must not be mechanically raised. The target specification continues to state their blockers. `docs/decisions.md` contains no exact pin among these versions, so this refresh changes no decision ID; BE-13's exact-pinning/CSP requirement continues to apply. If implementation changes a decision rather than a pin, return it to a designer and independent design reviewer before proceeding.

## 4. Promotion and rollback unit

The implementer first adds negative controls for mismatched manifest/lock/compiler versions, old browser revisions, wrong or removed host mappings, missing native libraries, corrupt/unlicensed payloads, omitted projects and stale receipts. After those controls fail for their intended reason, one change promotes every executable consumer, schema, fixture and affected document above. Re-run all light checks and the full native route under the selected versions. The coordinator retains the actual tested integration SHA, run URL, cold-install/version evidence and red controls, obtains independent code review with an adversarial admission pass, and lands only green `ci-required` after the separate loader source/native and Gate A/B qualification confirmations in section 1.1. Existing Go 1.27.1 approval does not authorize the target compiler.

If native evidence fails, keep the entire active version set at the green base while the responsible troubleshooter resolves the failure. An archive-only, manifest-only or browser-only partial landing is not a rollback strategy. A changed target or library/codec provisioning mechanism requires design review; do not silently substitute an older browser or platform. This file adds no security mechanism beyond the protocol and attacker outcomes in [refresh section 7](ci-toolchain-refresh.md#7-security-benefits-and-limits).
