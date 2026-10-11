# CI hardening implementation plan

Implement [the CI hardening spec](../specs/ci-hardening.md) in nine separate PRs, in dependency order. Both documents require independent `design_reviewer` approval before code starts. The designer authors contracts and does not implement or independently approve them.

Roles: the coordinator owns dispatch, Git, live CI evidence and landing; the implementer owns one task's paths; the troubleshooter owns unknown failures; the independent code reviewer reviews each completed task and confirms fixes. CI, bootstrap and catalogue changes require the adversarial pass. Workers never commit or push. Follow [workflow](../../instructions/workflow.md); use separate worktrees for concurrent writers and keep each review separate from authorship.

Use the project's task-by-task execution workflow, with `superpowers:subagent-driven-development` or `superpowers:executing-plans` as applicable. Each checkbox has a verifiable result. Do not turn unavailable tools, missing targets or absent evidence into skips.

## Contracts and checks

All paths are repository-relative. Commands run at the root unless a working directory is stated. `python` means the admitted Python 3.14.8 validator venv after Task 6; before then use the existing design environment for lightweight tests and preserve its pins. Implementation commands below are requirements, not checks run by this design task.

- Native qualification remains Linux x64 (`ubuntu-24.04`), Windows x64 (`windows-2025`) and macOS ARM64 (`macos-15`). Assert actual OS/architecture before tests. These runners do not prove complete endpoint support.
- Existing component tool pins, all 20 Go fuzz targets, loader qualification, Rust property budgets, console production CSP and both clean console builds remain required.
- Read component guides before changing tests. No production runtime behavior, permission name or OS mechanism changes in this plan.
- Light checks run locally. Race, timed fuzzing, extended properties, browsers and native matrices run in CI. Every negative control must fail for its intended defect, not a missing tool or broken fixture setup.
- Each task starts with the named failing regression, records that failure, implements the contract, runs the same command successfully, and obtains independent code review. The coordinator reads actual run URLs and SHAs before landing.
- Update consumer documentation in the same task that changes behavior. Do not leave `wip/**` pushes, dispatch substitutes or duplicate validator instructions described as the normal gate.

Review focus: stale integration SHAs after base movement (Task 2); deleted matrix rows despite green matrix summaries (Task 2); nested helpers returning zero without measurement (Task 4); semantically changed catalogue with a bumped revision (Task 5); tool download chains and warm-cache bypasses (Task 7). Each receives an explicit negative control below.

## Task 1. PR/master triggers and separate server race job

Owner: implementer. Own `.github/workflows/{design,server,agent,console}.yml`, `scripts/ci/test_triggers.py`, and trigger/race wording in `instructions/workflow.md` and `instructions/testing.md`. This first PR retains separate workflows; Task 2 moves their triggers into one caller. Keep the existing diagnosis exception.

Consumes: existing component jobs and spec sections 2 and 5. Produces: only PR/master-push normal triggers, PR-only cancellation, and server job IDs `validate` and `race`. Race uses its own 20-minute timeout; ordinary validation uses 20 minutes.

- [ ] Add `test_triggers.py` cases parsing workflow YAML: forbid normal `push` on `wip/**`; require PR plus master; forbid cancellation of master running or pending work; require race as a separate job with `go test -race -count=1 ./...`, never nested in `validate`. Include a positive temporary exact-branch diagnosis fixture and a negative landing fixture.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_triggers.py -v`; require failures against the current trigger/race configuration.
- [ ] Change triggers and use event-qualified PR groups with unique run-ID groups for non-PR events. Remove duplicate dispatch landing guidance. Document that pushes to `wip/<slice>` need an open PR for normal CI. A temporary push diagnosis workflow remains allowed and is removed before landing.
- [ ] Repeat the test command and run `actionlint .github/workflows/*.yml`; require pass. CI proof: `Server checks` validate and race, existing Design/Agent/Console workflows on affected inputs. The coordinator confirms two pushes to one PR supersede only that PR and master runs are not cancelled by concurrency.
- [ ] Independent code review checks preserved test commands and permission boundaries. Coordinator owns the signed-off commit and PR; workers perform neither Git operation.

## Task 2. Routing, receipts and one required result

Owner: implementer. Own `.github/workflows/ci.yml`, reusable conversion of `design.yml`, `server.yml`, `agent.yml`, `console.yml`, new `bootstrap.yml`, `scripts/ci/{route,inventory,required,check_policy}.py`, `scripts/ci/targets.toml`, `scripts/ci/test_{route,required,policy}.py`, test fixture directory `scripts/ci/fixtures/`, and workflow integration wording. Consume the design-owned schema under `schemas/ci/v1/`; propose schema changes to the designer instead of silently changing the contract.

Consumes: Task 1 job split, spec sections 2 to 4 and 12. Produces the fixed routing and aggregate CLIs, `check_policy.check(root: pathlib.Path) -> list[str]`, `route` workflow input and exact `ci-required` check name. At this stage `bootstrap` runs contract/schema fixture tests on its three hosts; Task 7 adds real cold installs. Until Task 4, receipts prove existing step success but do not claim selected-test audit closure. Add each later required check ID atomically with its implementation; the complete audit contract remains unfulfilled until all tasks pass.

- [ ] Add routing fixtures for every table row and individual consumed input, including each of the four CI-06 inputs, each lock/workflow, rename/delete, unknown path, empty diff, Unicode/newline path, more than 300 files, fork PR, missing Git objects, all-zero push base, non-ancestor push and PR base advancement. Use disposable Git repositories. Assert exact selected groups, units and checkout/event binding.
- [ ] Add aggregate fixtures for every required result value, missing `needs` key, malformed route, omitted/duplicate/extra/stale receipt, wrong SHA/run/attempt, empty check list, removed matrix row, selected-but-skipped caller and unselected caller unexpectedly run. Positive fixtures include intentionally unaffected callers and a docs-only route with real design/contract receipts.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_route.py -v` and `python -B -m unittest discover -s scripts/ci -p test_required.py -v`; require red before helpers exist. Fixture setup must itself succeed.
- [ ] Move all 20 server fuzz package/name pairs into `targets.toml` and generate the unchanged matrix from that single list. Implement the spec's full Git diff and inventories, same-commit workflow calls, exact `needs` set and unconditional aggregate. Implement receipt upload/download with full-SHA actions, current-run selection, separate download directories, no execution of downloaded files and schema plus semantic validation. Add actual action pins and inspect the admitted download action's bundled licenses before use.
- [ ] Move all Python validators into `design`, including blocking default catalogue validation. Remove server's duplicate export validation and permission venv. Keep `--check-sources` advisory. Run policy tests that mutate a fixture workflow to remove each consumer and prove rejection. Keep the optional Copilot environment outside `ci-required`.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v`, `python -B scripts/ci/check_policy.py --root .` and `actionlint .github/workflows/*.yml`; require pass. Validate CI schema examples using the command in the schema note below, and install that validation in `design.yml` so later schema edits cannot bypass it. Confirm both documents stay below 400 lines.
- [ ] CI proof: `design`, `ci-contracts`, routed reusable jobs and `ci-required`. Use a disposable draft PR for a failed leaf, cancelled leaf and missing matrix receipt; retain red run URLs, then remove mutations and capture green proof. Whole-run cancellation must never produce a green required check. No owner ruleset changes are bundled into this PR.

## Task 3. Fresh Go build caches in every authoritative job

Owner: implementer. Own `scripts/ci/fresh_go.py`, `scripts/ci/test_fresh_go.py`, cache rules in `check_policy.py`, cache steps in server/agent/bootstrap/Copilot workflows, and cache wording in testing instructions. No compiler or runtime changes.

Consumes: Task 2 policy checker and receipts. Produces `fresh_go.py --root PATH --env-out PATH`; emitted environment fixes `GOCACHE`, fresh `GOMODCACHE`, `GOTOOLCHAIN=local` and `GOFLAGS=-mod=readonly` for all later Go consumers.

- [ ] Add tests for inherited poisoned home cache, restored object directories, symlink/nonempty/reused cache roots, omitted nested-child environment, setup-go cache enabled and a cached Rust target. Plant a harmless execution sentinel in the prior-cache fixture and prove the test detects unsafe reuse.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_fresh_go.py -v`; require failure against current restores, including agent interop.
- [ ] Implement unique empty cache creation and recorded initial counts. Disable combined setup-go caches. Run `go mod download` then `go mod verify` in each Go job. Pass the environment through loader and interop children. Preserve `-count=1` independently.
- [ ] Keep Cargo registry-download caches only, discard restored extracted sources, recheck archive hashes against Cargo.lock, and use a fresh target directory. Corrupted `.crate` and compiled-output restore fixtures must fail policy/integrity checks.
- [ ] Repeat `test_fresh_go.py`, run `python -B scripts/ci/check_policy.py --root .` and `actionlint .github/workflows/*.yml`. CI proof: `server-validate`, `server-race`, all server fuzz leaves, loader/OCSF native leaves and `interop`. Logs show empty initial cache and inherited child paths. A second run with the poisoned prior-cache fixture must not execute its marker.

## Task 4. Prove selected tests, fuzzing and nested harness execution

Owner: implementer. Own `scripts/ci/{run_selected.py,targets.toml,test_run_selected.py}`, captured-output fixtures, selected-test steps in component workflows, `server/internal/extensions/loader/yaml_budget_test.go`, its focused tests, nested `internal/yamltokens/qualification_test.go` and focused measurement tests, Rust property tests only for evidence format, and interop child proof in `server/internal/events/body/rust_writer_test.go`. Read `server/AGENTS.md`, Go testing rules and Rust instructions.

Consumes: Task 3 fresh environments and Task 2 receipt inventory. Produces `run_selected.py --id ID --evidence DIR` and `--list`, shared target inventory, and verified check IDs in receipts. No direct command-string execution interface.

- [ ] Add pinned Go JSON/progress/benchmark, stable Rust harness and Vitest/Playwright report fixtures. Assert rejection for zero/renamed selector, missing binary, unexpected skip, duplicate/unfinished event, package failure after test pass, seed-only fuzz output, truncated output, missing property record and a reduced count. Positive fixtures contain exact names, counts and terminal successes.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_run_selected.py -v`; require red. Test one real tiny Go and Rust target to ensure parsers reflect the pinned tools, not just invented output.
- [ ] Consume Task 2's 20 Go fuzz pairs from `targets.toml`. Add loader qualification, native OCSF, Rust extended targets and the four non-helper interop tests, with mode-specific helper skips. Cross-check discovery and inventory. Use 60 seconds and two workers for each timed Go target. Preserve Go tags and flags between discovery and execution.
- [ ] Make nested loader children emit sample identity and complete measurements. Add `TestParserBudgetEvidence` with child rename, empty output, skipped child, missing/extra/duplicate measurement, repeated sample ID and non-finite counter controls. Parent expected keys come from the corpus before child execution. Do not include oracle work in measured allocations.
- [ ] From `server/`, run `go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetEvidence$'` first red, then green. Run `gofmt -l internal/extensions/loader internal/events/body` and `go vet ./internal/extensions/loader ./internal/events/body`. Use small child fixtures locally; do not run Gate A's heavy budgets locally.
- [ ] Wire Rust `--nocapture`, exact discovery and seed/count/duration checks: recovery 100,000 and seal 20,000. Expose ordinary-suite execution inventories and exact helper/extended skip reasons. Use `cargo fmt --all -- --check` from `agent/` for any Rust edits.
- [ ] Repeat parser tests; run `python -B scripts/ci/run_selected.py --list` and `python -B scripts/ci/check_policy.py --root .`. CI proof: every fuzz leaf, all loader and agent native leaves, OCSF, ordinary/race server suites and interop. Negative target/harness mutations must turn `ci-required` red; restore them and obtain all green native evidence before review.

## Task 5. Catalogue compatibility against the reviewed base

Owner: implementer. Own `scripts/ci/{catalogue_compat,test_catalogue_compat}.py`, default-validator reuse in `server/internal/authz/catalogue/schema_test.py` only where needed, compatibility steps in `design.yml`, catalogue test comments and the compatibility handoff in `docs/plans/permission-catalogue.md`. Do not change catalogue data or the advisory coverage policy.

Consumes: validated route `baseSha` and `testedSha`. Produces `catalogue_compat.py --root PATH --base-sha SHA --candidate-sha SHA` with strict Git-object admission and the spec's lifecycle rules.

- [ ] Add disposable Git histories for valid no-change, formatting, note bump, new name, retirement and revision-only increase. Add scope mutation at unchanged and bumped revision, deleted name, changed approval/owner/grant/uses, altered introduced revision, tombstone mutation/resurrection, revision decrease/overflow, missing base, malformed base and PR-controlled baseline substitution.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_catalogue_compat.py -v`; require red. Reproduce the audit probe changing `mdm.commands.restart.scope` with revision 3 and require explicit compatibility rejection even if both candidate copies match.
- [ ] Implement direct Git-object reads without executing base code. Reuse strict shape/lifecycle validation, but do not trust the candidate's choice of base. Wire every PR/master route's compatibility check into `design`; log both object IDs and catalogue revisions. A schema-valid semantic change still fails.
- [ ] Repeat the test command and run `python -B server/internal/authz/catalogue/schema_test.py`. From `server/`, run `go test -count=1 ./internal/authz/catalogue` and `go vet ./internal/authz/catalogue`. Require pass. Source freshness remains a separately reported advisory result.
- [ ] CI proof: `design`, `server-validate`, `server-race` and catalogue fuzz leaves. Preserve a red compatibility run for the audit probe and a green unmodified candidate. Independent adversarial review confirms base admission and immutable semantic fields, not just revision arithmetic.

## Task 6. One hash-locked Python validator closure

Owner: implementer. Own `.github/requirements-design.txt`, `.github/python-version`, validator setup in all workflows including Copilot, `scripts/ci/{python_env,test_python_env}.py`, lock/license policy checks and `docs/licensing.md` only for verified exact-distribution details. `.github/python-version` contains `3.14.8` plus LF; all consumers read it. No dependency upgrade is part of the default task.

Consumes: Task 2's consolidated design validation, existing nine pins and approved licensing rows. Produces one wheel-hash closure and `python_env.py --check` for resolved version, wheel metadata and license completeness. Before Task 7, exact setup-python remains temporary payload admission; do not claim CI-04 closed.

- [ ] Add controls for floating Python, unhashed/transitive requirement, wrong wheel bytes, source distribution, extra validator package, incompatible wheel, duplicate divergent environment and an absent licensing row. Routing fixtures change each of the four CI-06 paths alone and must select the validator.
- [ ] Add separate controls for wheel metadata and shipped license files disagreeing with the inventory, plus a missing required notice. Include a `jsonschema-specifications` 2025.9.1 fixture declaring MIT with MIT-only COPYING against an inventory claiming `MIT AND BSD-3-Clause`; require admission failure naming the package, version and mismatch. The matching MIT inventory must pass.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_python_env.py -v`; require red against the unhashed requirements. Build an isolated wheelhouse fixture so a corrupted wheel fails its hash specifically.
- [ ] Download each selected platform's exact wheels for lock review, record filenames and SHA-256, inspect bundled license files and add `--hash=sha256:...` entries. Do not substitute remembered hashes or silently upgrade a pin if a wheel is absent. Resolve that absence through the designer and independent reviewer.
- [ ] Install with `python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: -r .github/requirements-design.txt`; run `python -m pip check` and `python -B scripts/ci/python_env.py --check`. Reject all package differences except the separately recorded Python-bundled pip bootstrap.
- [ ] Run `python -B schemas/ocsf/generate.py --check`, `python -B schemas/ocsf/validate.py`, `python -B schemas/policy/v1alpha1/validate.py`, `python -B schemas/export/v1alpha1/validate.py`, `python -B schemas/report/v1alpha1/validate.py`, `python -B server/internal/authz/catalogue/schema_test.py`, `python -B scripts/ci/validate_contracts.py` and `python -B agent/tools/generate-spool-fixtures.py --check`. Keep each validator's existing unit/mutation tests in `design` too.
- [ ] Repeat `test_python_env.py` and policy checks. CI proof: `design`, `ci-contracts`, clean closure installation on the three `bootstrap` hosts and agent fixture checks. Copilot setup consumes the same files, but Copilot availability is not a landing condition. Record exact selected wheels; Linux ARM64 joins when release Task 2 needs it.

## Task 7. Digest-checked toolchain downloads

Owner: implementer. Own `scripts/ci/{bootstrap,test_bootstrap}.py`, `scripts/ci/toolchains.lock.json`, platform extraction/install helpers beneath `scripts/ci/bootstrap/`, toolchain steps in all workflows, and exact payload license evidence in `docs/licensing.md`. No new SDK/vendor registration or dependency without its reviewed licensing row.

Consumes: CI schema and Task 6 pins. Produces the spec's bootstrap CLI, admitted paths/environment, complete consumed-payload lock and cold-install evidence. Initial runner Python executes only standard-library bootstrap logic; validators use admitted Python afterward.

- [ ] Add positive tiny archive fixtures and negative size/hash, extra/duplicate lock selection, wrong host/version, redirected URL, traversal, case collision, escaping link, nonempty destination and warm tool-cache substitution cases. An installer fixture creates a sentinel only if executed; corrupt its download and assert sentinel absence before extraction and execution.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_bootstrap.py -v`; require red. Cover separate Go/Python/Rust/Node/pnpm/browser paths so protecting only one setup action cannot pass.
- [ ] Record real first-party URLs, sizes, digests and license evidence for all consumed payloads. Validate the lock with the CI schema. Verify byte hashes before any archive or installer runs. Validate installed tool versions/hosts; refuse missing platform rows. Use verified offline Rust components and admitted pnpm/browser payloads, with no implicit download chain.
- [ ] Remove unchecked setup downloads and `playwright install --with-deps`. Inventory runner-provided compiler/SDK/system libraries and fail explicitly if required browser libraries are absent. Any extra downloaded package requires a digest and license entry before use. Record bootstrap interpreter, runner image, C compiler, SDK and final tool versions.
- [ ] Run the test command, `python -B scripts/ci/check_policy.py --root .` and `actionlint .github/workflows/*.yml`. In CI execute `python -B scripts/ci/bootstrap.py --lock scripts/ci/toolchains.lock.json --platform "$CI_PLATFORM" --tools "$CI_TOOLS" --dest "$RUNNER_TEMP/admitted" --cache-mode none --env-out "$RUNNER_TEMP/tools.env"`; `CI_PLATFORM` and `CI_TOOLS` come from fixed workflow matrices, never PR text.
- [ ] CI proof: cold installs and corrupted-payload sentinels in all three `bootstrap` leaves; every consuming job passes using admitted paths. Retain per-payload evidence and verify no tool-cache or network fallback. Release Task 2 adds Linux ARM64, Syft and release-only payloads through the same contract before their consumers run.

## Task 8. Publish console budgets and extended property evidence

Owner: implementer. Own `console/scripts/audit-dist.ts`, `console/tests/unit/output.test.ts`, new `console/tests/unit/budget-evidence.test.ts`, `console/tests/unit/fuzz.test.ts`, `console/vitest.config.ts`, `console/playwright.config.ts`, `.github/workflows/console.yml`, console IDs in `targets.toml` and console gate wording in `docs/plans/console-foundation.md`. Task 4 already owns Rust output exposure; do not duplicate that change.

Consumes: verified toolchain, selected-run verifier and console foundation limits. Produces printed byte totals and a required 10,000-iteration console property run, with diagnostic artifacts.

- [ ] Add `budget-evidence.test.ts` under `console/tests/unit/`: assert entry and every lazy route print measured bytes and exact limits on both success and over-budget failure; exclude shared entry members once; fail a missing route measurement. Add property reporter controls for zero/100 iterations, missing initial seed and renamed test. Keep pure measurement helpers testable without a browser.
- [ ] Run `pnpm --dir console test:unit -- tests/unit/budget-evidence.test.ts`; require red. Use fixtures with entry 250,000/250,001 and route 150,000/150,001 bytes after the same Brotli calculation, not approximate source sizes.
- [ ] Print closure names/members, measured bytes, limit and result. Print initial property seed, completed iterations and duration. Wire `pnpm test:fuzz` through selected-run verification; keep the two clean build comparison and CSP negative controls unchanged.
- [ ] Run `pnpm --dir console typecheck`, `pnpm --dir console lint`, `pnpm --dir console format:check` and `pnpm --dir console test:unit`; require pass. Do not run browser or 10,000-case tests locally.
- [ ] CI proof in `console`: `pnpm build`, `pnpm check:reproducible`, `pnpm test:fuzz`, `pnpm test:component` and `pnpm test:csp` from `console/`, through the wrapper's named IDs. Capture all three browser reports, versions/revisions and failure traces/screenshots for 30 days. `ci-required` fails absent reports or budget evidence. Confirm Rust logs still expose both seeds, exact counts and durations on all native hosts.

## Task 9. Label local/CI commands and verify owner handoff

Owner: implementer for instructions/tests; coordinator for live proof; repository owner for settings. Own `instructions/testing.md`, final CI/review wording in `instructions/workflow.md`, `scripts/ci/test_testing_docs.py`, and only the shared-interface references in `docs/specs/release-builds.md` and `docs/plans/release-builds.md`. No settings writes by workers.

Consumes: Tasks 1 through 8. Produces complete command labels and the tested contract for release Task 2. The design documents already name those interfaces; change them only through designer and reviewer agreement if implementation exposes a real conflict.

- [ ] Add document checks for every runnable block, inline execution command and command-table row: explicit `Local`, `CI` or `Local and CI` plus working directory. Negative fixtures omit a label, label race/browser/extended tests local, retain a duplicate fuzz inventory, or present a dispatch as required-check proof.
- [ ] Run `python -B -m unittest discover -s scripts/ci -p test_testing_docs.py -v`; require red against unlabeled/mixed command blocks.
- [ ] Label all commands, split mixed blocks and use `run_selected.py --list` as the exact selector source. Include both Rust crates, interop, catalogue compatibility, Python lock checks, nested loader proof, console property counts and printed budgets. Replace stale wip-push wording everywhere these changed instructions repeat it.
- [ ] Keep Copilot optional when unavailable and its frequency owner-selected. State exact-head independent review and `ci-required` remain mandatory. Preserve temporary exact-wip diagnosis and separate review bypass from CI enforcement.
- [ ] Repeat the document test; run `python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v`, `python -B scripts/ci/check_policy.py --root .`, `actionlint .github/workflows/*.yml` and `git diff --check`. CI proof: `design`, `ci-contracts`, full route and `ci-required`. Cross-check release Task 2 imports/CLIs against the implemented names.
- [ ] Coordinator collects the spec section 10 positive/negative run URLs, current integration SHAs and cancellation proof. Owner separately configures `ci-required` from GitHub Actions, current-base enforcement, a CI ruleset without routine bypass, and a distinct review-bypass ruleset; retains force-push/deletion protection and 30-day evidence retention. Record live settings inspection and enforcement proof, not the audit's unverified snapshot.
- [ ] Independent code reviewer performs the final adversarial pass over the complete diff and evidence. Release consumers wait until all required tasks and owner enforcement checks pass. Coordinator handles commits and landing; no worker or designer claims a missing live check passed.

## Schema validation and design checks

The design-owned schema uses [Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core). From the repository root, validate each synthetic example without network references:

```sh
python3 -B - <<'PY'
import json
from pathlib import Path
from jsonschema import Draft202012Validator
root = Path('schemas/ci/v1')
schema = json.loads((root / 'contracts.schema.json').read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
examples = json.loads((root / 'examples.json').read_text())
for example in examples:
    validator.validate(example)
print(f'PASS CI schema and {len(examples)} examples')
PY
```

This light `Local and CI` command validates shape only. Aggregate set equality, event provenance, catalogue semantics, actual downloaded bytes and real test execution require the plan's implementation checks.

## Open verification questions

- Which exact wheels and tool payload digests pass cold admission on each consumed native host, and which bundled notices accompany them? Task 6 and Task 7 must record real evidence before their consumers land.
- Do live owner rulesets reject failed or absent `ci-required` under the review bypass and admit the intended current-base fast-forward? Task 9 must prove both before routine landing uses the split rulesets.

These are evidence questions with explicit owning tasks, not permission to choose weaker gates. No runtime authority or native-support question is resolved by this CI slice.
