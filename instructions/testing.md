# Testing

Before review, run light checks for the touched component. Local, Go server, `server/`:

```sh
gofmt -l .
go vet ./internal/path/to/touched/package
go test -count=1 ./internal/path/to/touched/package
```

`-count=1` prevents cached Go test results from hiding changes to fixtures outside `server/`. It does not disable compiled-object reuse.

Every CI Go consumer uses `scripts/ci/fresh_go.py --root PATH --env-out PATH` to create unused absolute build and module cache directories below `RUNNER_TEMP`. The helper records zero initial entries and exports the environment fixed by [CI hardening section 5](../docs/specs/ci-hardening.md#5-fresh-go-compilation-and-dependency-caches-ci-03), including `GOENV=off` and an empty `GOCACHEPROG`, through its pinned `GITHUB_ENV` step. Children inherit these values. Each job runs `go mod download` followed by `go mod verify` before Go checks. Setup-go caching and compiled-output restores are forbidden.

Cargo caches only the registry index and `.crate` archives. The same helper's Cargo mode discards restored extracted sources, checks archive SHA-256 values against `agent/Cargo.lock`, fetches locked dependencies, rechecks downloads and discards extracted sources before compilation. Each job uses a fresh `CARGO_TARGET_DIR`. Console caches no `node_modules` or build output. Tag builds restore and save no caches.

`gofmt -l .` must print no files. Replace the example package path with the touched packages. Fix formatting with `gofmt -w` on the touched files.

The `CI` entry routes the full ordinary suite, race tests and timed fuzzing on pull requests targeting `master` and pushes to `master` from the full Git diff. Design and CI contract checks always run. `ci-required` requires successful selected callers and one same-run receipt per expected leaf; missing matrix rows fail even when other rows pass. A push to `wip/<slice>` needs an open PR for normal CI. Draft PRs run checks. Superseding pushes cancel only the same PR's runs; master pushes use unique run-ID groups and never cancel running or pending master work.

CI, `server/`: server jobs `validate` and `race` run separately, each with a 20-minute timeout. `validate` keeps ordinary tests, formatting, vet and the key-admission benchmark. `race` runs `go test -race -count=1 -timeout=15m ./...` with default `GORACE`; [CI hardening section 5](../docs/specs/ci-hardening.md#5-fresh-go-compilation-and-dependency-caches-ci-03) owns the package deadline, evidence and limits. Preserve the complete corpus and serial cold measurement children; deadline expiry fails the check.

CI, `server/`: ordinary `go test -count=1 ./...` keeps running every fuzz target's seed corpus. The primary agent reads the CI results before merging and does not merge failed checks.

The complete CI fuzz inventory is [scripts/ci/targets.toml](../scripts/ci/targets.toml). Each of its 23 main package/target pairs gets one matrix entry with an anchored selector, 60-second duration and two workers from `server/`. The separate Gate A selector stays outside that main matrix. CI uploads each target's corpus on failure, including new failing entries. Commit useful minimized inputs to the target's seed corpus. Report the command, duration and result from CI.

Local and CI, repository root, for loader CI integration:

```sh
python -B -m unittest discover -s scripts/ci -p test_route.py -v
python -B -m unittest discover -s scripts/ci -p test_required.py -v
python -B -m unittest discover -s scripts/ci -p test_policy.py -v
python -B -m unittest discover -s scripts/ci -p test_fresh_go.py -v
python -B scripts/ci/inventory.py --fuzz-matrix
python -B scripts/ci/check_policy.py --root .
actionlint .github/workflows/*.yml
git diff --check
```

Local and CI, repository root, for the validator and bootstrap helpers:

```sh
python -B -m unittest discover -s scripts/ci -p test_python_env.py -v
python -B -m unittest discover -s scripts/ci -p test_bootstrap.py -v
python -B -m unittest discover -s scripts/ci -p test_run_selected.py -v
python -B -m unittest discover -s scripts/ci -p test_policy.py -v
python -B -m unittest discover -s scripts/ci -p test_fresh_go.py -v
```

These helper tests inject platform identities and use tiny payload fixtures. Native cold installs, Windows per-user Python registration cleanup and Git Bash resolution, macOS system-Python re-execution and the exact MSVC PowerShell invocation run only in CI. The admitted Python closure and pinned Go must also pass there. Every Bash step uses the admission shell from [CI hardening section 8](../docs/specs/ci-hardening.md#environment-admission-in-every-authoritative-job); only the exact native MSVC step uses the no-profile PowerShell shell.

Local, `server/`, focused complete-loader checks:

```sh
go test -count=1 ./internal/extensions/loader -run '^TestLoaderBudgetSmoke$'
```

CI, `server/`, complete-loader native qualification on Linux x64, Windows x64 and macOS ARM64 (`loader-gate-b`):

```sh
go test -count=1 ./internal/extensions/loader -run '^TestLoaderBudgetExtended$' -v -args -loader-budget-extended
```

The [native receipt and measurement contract](../docs/specs/ci-hardening.md#loader-qualification-inventory) requires all six loader leaves, exact same-run checks, separate retained measurement logs and all 23 main fuzz leaves. Gate A and Gate B commands capture combined output with Bash `set -euo pipefail` and `tee`. Diagnostics upload even after failure; complete nonempty logs are required before success receipts. Both gates keep fresh compiler caches and cold measurement children. These receipts prove step success; qualification review also checks the retained measurements. The existing server-wide race job covers the loader.

CI, `server/`: the extension loader's Gate A job runs natively on Linux x64, Windows x64 and macOS ARM64 in `.github/workflows/server.yml` (`loader-gate-a`), from `server/`:

```sh
go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -v -args -loader-budget-extended
go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetSmoke$' -v -args -loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50
go test -count=1 ./internal/extensions/loader -fuzz='^FuzzParserQualification$' -fuzztime=60s -parallel=2
```

Keep these commands aligned with that job; it uploads the fuzz corpus on failure.

CI, `server/`: key admission reports time and allocations without a pass/fail latency threshold:

```sh
go test -run '^$' -bench '^BenchmarkValidate$' -benchmem -benchtime=100x ./internal/signing/ed25519key
```

The first consumer owns performance qualification and its request and candidate bounds.

CI: `server-validate` requires the 50-case composite ingest proof from [ingest admission section 9.1](../docs/specs/ingest-admission.md#91-selected-test-proof-composition). From the repository root, the dedicated wrapper verifies the test phase before running and verifying the three-iteration benchmark phase:

```sh
python -B scripts/ci/run_selected.py --id ingest-cost-model --evidence "$RUNNER_TEMP/evidence"
```

The wrapper sets `GOENV=off`, `RICEVANTA_COST_MODEL=full` and `GOGC=100`. It retains both payloads and their diagnostics outside receipt directories in `ingest-measurements/cost-model.log`, uploaded for 30 days. A receipt requires both successful phases, all 50 exact case keys and the same tested commit, run and attempt. Ordinary suites allow only the exact observed `TestDecodeCostModel` skip; they never replace the dedicated proof. Without `RICEVANTA_COST_MODEL=full`, the cost-model parent starts no child.

CI qualification commands, from `server/`:

```sh
RICEVANTA_COST_MODEL=full GOGC=100 go test -count=1 -timeout=15m ./internal/events/body -run '^TestDecodeCostModel$' -v
go test -run '^$' -bench '^BenchmarkDecodeCost$' -benchmem -benchtime=3x -timeout=15m ./internal/events/body
```

Run full cost, memory, race and fuzz qualification in CI. Local body/admission checks use the focused ordinary suites; the small `TestAdversarialCostCorpus` representatives exercise structural and rejection stages without running memory-limit children. Handler integration still requires the separate CPU contention, ARM64, transport and storage qualification gates.

Race tests, timed fuzzing, extended property tests, browser tests and the cross-OS matrix belong in PR/master CI. Console browser checks run in `.github/workflows/console.yml`.

A temporary push diagnosis workflow may target one exact `wip/<slice>` branch with distinct job names, read-only permissions and no secrets or required-check claim. Remove the diagnosis workflow before opening a landing PR to `master`; see [workflow](workflow.md#parallel-slices-and-ci).

The initial server packages have pure unit and fuzz tests. They do not establish PostgreSQL, network, process, operating-system or platform support. Add integration and platform checks with the first code that crosses those boundaries, following its reviewed design and the qualification gates in `docs/specs/platform-qualification.md`.

## Rust agent

The first Rust slice follows [instructions/rust.md](rust.md) and [the spool implementation plan](../docs/plans/agent-spool-format.md). Run fixture drift checks from the repository root:

```sh
python agent/tools/generate-spool-fixtures.py --check
```

Before review, run Cargo formatting, Clippy and ordinary tests for touched crates from `agent/`:

```sh
cargo fmt --all -- --check
cargo clippy --locked -p ricevanta-spool --all-targets -- -D warnings
cargo test --locked -p ricevanta-spool
cargo tree --locked --edges normal,build,dev
```

Select the touched crates with `-p`; `ricevanta-spool` is the current crate.

CI also runs the extended property test on every native matrix entry:

```sh
cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact
```

The ordinary suite runs every shared fixture and the deterministic `fuzz_recover` target. The ignored extended target runs in CI; report its seed, case count, elapsed time and result. The plan fixes both budgets and mutation invariants. Tests match error variants and fields, check combined defects and use an independent CRC oracle. A failed check stays failed in the report.

CI runs fixture regeneration, fmt, Clippy, ordinary tests and the extended property test natively on macOS ARM64, Windows x64 and Linux x64 with the exact Rust pin. These checks establish portable codec behavior, not file permissions, power-loss durability, sensors, resource budgets or full platform support. Add native integration checks only with their reviewed slice and [platform qualification](../docs/specs/platform-qualification.md).

No releasable binary exists, so the repository has no binary, installer, container or upgrade test yet.

## Console

The console foundation uses [Vue instructions](vue.md) and [the foundation spec](../docs/specs/console-foundation.md). Run from `console/` with the pinned Node and pnpm:

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm format:check
pnpm audit:deps
pnpm test:unit
pnpm exec playwright install --with-deps chromium firefox webkit
pnpm test:component
pnpm build
pnpm check:reproducible
pnpm test:csp
pnpm test:fuzz
```

Type checking includes application, tooling and test projects. Lint includes catalogue key, syntax, plural and source-usage validation. Unit tests cover pure contracts and validator failures. Component tests use Vitest's Playwright provider; their development server does not establish production CSP compatibility.

`test:csp` serves built `dist/` through the static header harness and runs Chromium, Firefox and WebKit with Trusted Types enforced. It checks the exact response header, fails normal cases on every CSP violation, and separately proves blocked operations with negative controls and policy-free controls. Missing browser enforcement or missing violation events fail the check; never skip them or weaken CSP. Record the actual browser versions and revisions.

`test:fuzz` runs 10,000 seeded cases per foundation property target. Save minimized failures in the console fixture corpus. CI must run the seed fixtures in ordinary unit tests; the bounded run is required before review. Frozen install, type check, lint, formatting, dependency audit, unit tests, component tests, build, reproducibility and the CSP gate must run in `.github/workflows/console.yml`.

Two clean builds must have identical sorted path/SHA-256 manifests. Report measured Brotli budgets, asset checks and font notices. Dependency changes also require a resolved-license review and OSV scan under the implementation plan. These checks qualify only the static foundation in the tested engines; login, sessions, CSRF, change streams, Go serving, extension isolation and the full supported browser/OS matrix require their own tests.

## CI security scans

CI requires Gitleaks, Semgrep Code and Semgrep Supply Chain on every PR/master event under [the scan contract](../docs/specs/ci-security-scanning.md). Semgrep Secrets is excluded. The existing console OSV audit remains required. Missing credentials, unsupported input parsing or incomplete scan execution fail the required check; documented limits of the scanner's analysis remain visible in its coverage report.

Local and CI, repository root: run focused scanner and workflow contract tests through `python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v`, then `python -B scripts/ci/check_policy.py --root .`. Live authenticated scan qualification belongs in normal PR CI. Never print the token or raw scan reports. A fork PR cannot receive the token; use the spec's reviewed maintainer-owned replacement PR procedure and keep the fork result failed.
