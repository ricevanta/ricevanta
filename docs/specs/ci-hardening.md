# CI hardening

GitHub CI must prove that required work ran against the tested source, using admitted tools and fresh compiler output. A green process exit without execution evidence is insufficient. This specification owns CI routing, evidence and tool admission; [the plan](../plans/ci-hardening.md) implements them in separate PRs. The independent CI audit's CI-01 through CI-08 findings define the defect coverage.

Authorities: SH-04, PF-01, PF-04, AG-09, BE-13 and BE-14 in [decisions](../decisions.md), [workflow](../../instructions/workflow.md), [testing](../../instructions/testing.md), [permission catalogue](permission-catalogue.md), [console foundation](console-foundation.md) and [release builds](release-builds.md). Both this specification and its plan require an eligible independent `design_reviewer` approval before implementation. This design is not that approval.

## 1. Scope and limits

The slice owns `.github/workflows/ci.yml`, shared component workflows, `scripts/ci/` helpers, test-harness proof, validator dependencies and CI instructions. It introduces no runtime API, permission or signing key. Owner settings are separate in section 10. The core hardening mechanisms require no additional account or vendor program. [CI security scanning](ci-security-scanning.md) separately defines the owner-authorized Semgrep analysis service and its sole step-scoped credential exception; no package registry publishing credential is required.

Keep the native macOS ARM64, Windows x64 and Linux x64 checks. Hosted Windows Server runners do not qualify Windows 11, and hosted codec tests do not qualify sensors. [Platform support](../platform-support.md) and its release gates remain authoritative. Every blueprint feature remains required at v1.0.0 except its two listed v2.0.0 capabilities.

This is a reviewed implementation contract. Helpers and workflow paths specified below are deliverables, not claims that they exist. [CI contract schema](../../schemas/ci/v1/contracts.schema.json) and its [examples](../../schemas/ci/v1/examples.json) exist for design validation. Examples use synthetic identities and tool bytes; they authorize no download or CI success.

## 2. Entry workflow and cancellation

`.github/workflows/ci.yml`, named `CI`, owns `pull_request` targeting `master` and `push` with `branches: [master]`. It has no workflow-level path filter. Include PR activities `opened`, `synchronize`, `reopened`, `ready_for_review` and `edited`; a base-branch change needs fresh routing. Draft PRs still run. No normal workflow pushes on `wip/**`.

Convert `design.yml`, `server.yml`, `agent.yml` and `console.yml` to `workflow_call` consumers of this entry. Remove their push, PR and dispatch triggers and their concurrency blocks. Each takes required string input `route` containing the route object in section 3. Use same-commit local calls, not a branch reference or `workflow_run` fan-in. Do not grant inherited secrets. `ci.yml` has no manual dispatch path claiming the required result.

The entry's concurrency group is `ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}` and `cancel-in-progress` is `${{ github.event_name == 'pull_request' }}`. PR runs supersede runs for that PR only. Unique master-push groups avoid cancellation of queued pushes as well as running pushes. Reusable workflows never cancel their caller. [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) defines these controls.

A temporary `.github/workflows/diagnose-<slice>.yml` may run on push to one exact `wip/<slice>` branch. It uses distinct job names, read-only permissions, no secrets and no required-check claim. Delete it before landing; the policy checker rejects a diagnosis workflow in a PR to `master`. A draft diagnosis branch can exist without a landing PR. [Workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch) explains why dispatch cannot bootstrap a workflow absent from the default branch.

Use `contents: read`, full-SHA third-party actions and `persist-credentials: false` on every checkout. Do not introduce `pull_request_target`, privileged follow-up workflows, write tokens, OIDC grants or self-hosted production runners. `copilot-code-review.yml` remains an optional review environment with its product-required job name; its runs and reviews are outside the required CI result.

## 3. Changed paths, identities and expected work

`scripts/ci/route.py --event-name EVENT --event PATH --root PATH --out PATH` accepts PR and master-push events only. It reads event data as data, validates full lowercase commit IDs, fetches missing objects from the configured origin without credentials persisted in Git, and verifies checkout identity. No event value is interpolated into shell code.

For PRs, record `baseSha` from `pull_request.base.sha`, `headSha` from `pull_request.head.sha`, and `testedSha` from the checked-out integration commit equal to `GITHUB_SHA`. Verify its parents bind that base and head. The changed-path set is the union of merge-base-to-head and base-to-tested diffs. For master pushes use `before`, `after` and checkout `after`; a missing/zero base or non-ancestor base is an error for this established repository. Fetch failure is failure, never an empty diff. Rebase and rerun when master moves before landing.

Diff with `git diff --name-only --no-renames -z BASE HEAD --`; deletion and rename source paths therefore remain inputs. Read the full local Git diff, not a truncated API or workflow path filter. Treat undecodable or unknown paths conservatively by selecting every group. Empty valid diffs still select `design` and `ci-contracts`.

The route object has `kind: route`, `version: 1`, `event`, `baseSha`, `headSha`, `testedSha`, decimal-string `runId` and `runAttempt`, sorted unique `groups` and sorted unique `units`. `groups` names selected consumers. `units` enumerates every expected leaf, including matrix rows, before jobs run. Never derive expected work from uploaded results. `scripts/ci/inventory.py` owns group expansion and consumer inputs; `scripts/ci/targets.toml` owns exact test/fuzz selectors. The policy checker requires workflow matrices and their `needs` edges to match those inventories. The route job exposes the compact JSON as output `route`; callers receive that string and the aggregate writes it from `needs.route.outputs.route` to its input file.

| Group | Leaf unit IDs and owner workflow |
|---|---|
| `design` | `design`; `design.yml`: all Python validators and document checks |
| `ci-contracts` | `ci-contracts`; `ci.yml`: routing, policy, evidence, cache, compatibility and bootstrap unit tests |
| `server` | `server-validate`, `server-race`, `server-fuzz:<package>:<target>` for all 20 targets; `server.yml` |
| `loader` | `loader:linux-x64`, `loader:windows-x64`, `loader:macos-arm64`; `server.yml` |
| `ocsf` | `ocsf:linux-x64`, `ocsf:windows-x64`, `ocsf:macos-arm64`; `server.yml` |
| `agent` | `agent:linux-x64`, `agent:windows-x64`, `agent:macos-arm64`; `agent.yml` |
| `interop` | `interop`; `agent.yml`: live writer plus ordinary and race decoder tests |
| `console` | `console`; `console.yml`: existing gates plus extended properties and evidence |
| `bootstrap` | `bootstrap:linux-x64`, `bootstrap:windows-x64`, `bootstrap:macos-arm64`; new `bootstrap.yml` |

`design` and `ci-contracts` are always selected. The [security scanning contract](ci-security-scanning.md#5-required-result-and-policy-checker) adds two always-selected direct leaves and their check inventories. The following union is the routing floor; overlapping matches add groups. Full-group selection intentionally favors coverage over narrowly routing each Go package.

| Changed inputs | Additional groups |
|---|---|
| `server/**`; `schemas/{dsse,events,ocsf,cel,export,policy,report,extension,permissions}/**` | `server`, `loader`, `ocsf`, `interop` |
| `agent/**`, `schemas/agent/**` | `agent`, `interop` |
| `server/go.mod`, `server/go.sum`, `schemas/events/**` | `agent` |
| `console/**`, `branding/**`, `docs/design/console.md`, `docs/specs/console-foundation.md`, `docs/plans/console-foundation.md`, `instructions/vue.md` | `console` |
| `.github/**`, `scripts/ci/**`, `schemas/ci/**`, `instructions/testing.md`, `instructions/workflow.md`, `docs/licensing.md` | Every group |
| Other `docs/**`, `instructions/**`, root Markdown, `NOTICE`, `LICENSE`, `DCO`, `.gitattributes`, `.gitignore`, `.claude/agents/**`, `.codex/agents/**` | No extra group unless a validator's consumer inventory names the path |
| Any path not matched above | Every group |

Consolidate export, policy, report, OCSF and default permission Python validation in `design`; remove duplicate server environments and export validation. Thus `.github/requirements-design.txt`, `docs/specs/ocsf-profile.md`, `docs/specs/export-destination-schema.md` and `docs/specs/event-export.md` always reach their sole validator consumer (CI-06). Catalogue compatibility also runs in `design` on every event. Permission source freshness remains advisory as its spec requires; it is not compatibility evidence.

A `route.py --full --event-name push ...` mode admits validated tag events only for the release caller: select all groups, compare the tag commit's catalogue to its first parent on protected master, and bind `testedSha` to the resolved tag commit. Require full history and master ancestry. Missing parents fail. Release jobs extend the inventory through reviewed changes; this slice enables no tag publication. Diagnostics cannot set `--full` to impersonate a PR event.

## 4. One required result

The entry has caller jobs `design`, `server`, `agent`, `console`, `bootstrap`, its own `route` and `ci-contracts`, the direct `gitleaks` and `semgrep` jobs defined by the security scanning contract, and one terminal job with both ID and display name `ci-required`. Its `needs` lists these seven predecessors and both direct security scanner jobs literally; it uses `if: ${{ always() }}`. Caller jobs use route group membership. Component leaf jobs use the same route; matrix `fail-fast` is false and required jobs never use `continue-on-error`.

Each successful leaf emits exactly one receipt after all checks pass and uploads it as `ci-proof-<runId>-<runAttempt>-<safe-unit-id>`, with 30-day retention and missing-file upload treated as failure. The receipt has `kind: receipt`, `version: 1`, the route's run binding and tested SHA, its exact `unit`, `result: success`, and a nonempty list of executed check IDs in `checks`. Encode artifact unit names with a collision-free hex encoding of UTF-8 bytes. Upload raw logs and measurements beside the receipt, never executable artifacts that the aggregate will run.

The aggregate downloads only this run/attempt's proof artifacts into separate directories, without merging filenames. It validates the schema, exact receipt set, unique unit IDs, identity binding and required check IDs from the inventory. `scripts/ci/required.py --route PATH --needs PATH --receipts DIR` exits zero only when:

1. `route` and `ci-contracts` succeeded and route decoding/identity checks succeeded.
2. Every selected caller has `needs.result == success`; every unselected caller is `skipped` and routing explicitly proves it unaffected.
3. Every expected leaf supplied one valid success receipt. Missing, extra, duplicated, stale or malformed receipts fail. A removed matrix entry therefore fails even when the remaining matrix succeeds.
4. No required result is failure, cancellation, skipped, neutral, absent or unknown. No `continue-on-error` success wrapper may hide one.

`NEEDS_JSON: ${{ toJSON(needs) }}` goes through an environment variable to a file, not through a shell expression. The aggregate recomputes routing from checkout/event and compares it with the supplied route before accepting results. No API search for the latest green run and no cross-run artifact reuse is permitted. Component failures do not prevent this job from reporting failure. Whole-run cancellation or platform outage can prevent any final job from running; a cancelled or absent `ci-required` blocks landing rather than becoming success.

[GitHub required-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks) accepts some skipped/neutral checks and ignores dispatch-run checks for PR requirements. Consequently `ci-required` runs only under the PR/master entry, has no conditional success path, and cannot be replaced by a manual dispatch. [Reusable calls](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows) retain their caller's event. Merge queues are not enabled by this slice; adding one requires its own `merge_group` integration.

Receipts catch missing execution and accidental routing defects. Candidate source controls tests and workflow code, so receipts cannot defeat a malicious author who rewrites both the gate and its evidence. Independent review of CI changes, read-only jobs and owner rules are part of the boundary, not something a self-test proves.

## 5. Fresh Go compilation and dependency caches (CI-03)

Move `go test -race -count=1 ./...` from server `validate` into sibling `race`, both selected by `server`. Preserve ordinary tests, formatting, vet and the key-admission benchmark in `validate`; preserve dedicated fuzz, loader, OCSF and interop jobs. Give race its own 20-minute timeout and ordinary validation 20 minutes. Do not run race before ordinary tests within the same job.

Every Go consumer, including nested children, interop, native qualification and future release builds, sets `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, and a newly created empty absolute `GOCACHE` under `RUNNER_TEMP`. `fresh_go.py --root PATH --env-out PATH` creates a unique directory, rejects symlinks/reuse/nonempty roots, records its path and initial entry count zero, and emits environment assignments. All subprocesses inherit that cache. Compilation may reuse objects within the job only. Disable setup-go caching entirely; no Go cache artifact restore and no fallback to a home cache. Run `go mod download` and `go mod verify` in a fresh per-job module directory in this slice.

`-count=1` disables test-result reuse, not compiled-object reuse; [Go's command reference](https://pkg.go.dev/cmd/go#hdr-Build_and_test_caching) distinguishes them. A two-run control populates a real prior Go build cache with a marker-producing fixture, then places that cache at the restore location and proves the next job starts empty and never reads that location or executes its marker. First prove the unsafe restore fixture exposes the cache, so an inert marker cannot make the negative control pass. Check actual environment and workflow restore paths as well as unit behavior.

Cargo keeps dependency-download caching only, never `target/`. Cache registry index and `.crate` archives, discard restored extracted `registry/src`, verify archive SHA-256 against Cargo.lock, and extract into a fresh source root. Set a fresh `CARGO_TARGET_DIR`. A modified archive must fail before compilation. [Cargo fetch](https://doc.rust-lang.org/cargo/commands/cargo-fetch.html) defines locked fetch behavior. Console keeps frozen dependency resolution but restores no `node_modules` or build output. Tag builds restore and save no cache of any kind.

## 6. Execution proof (CI-01 and CI-08)

`scripts/ci/run_selected.py --id ID --evidence DIR` owns command execution, discovery and result verification. IDs resolve through `targets.toml`; no arbitrary shell command is accepted. It streams stdout/stderr into CI logs, retains raw output, uses argument arrays and returns nonzero for child failure or incomplete evidence. Only verified runs may add the ID to a leaf receipt. Fixed IDs are `server-unit`, `server-race`, `key-admission-bench`, `go-fuzz:<package>:<target>`, `loader-extended`, `loader-repeat`, `loader-fuzz`, `ocsf-native`, `agent-unit`, `spool-extended`, `batch-extended`, `interop-unit`, `interop-race`, `console-unit`, `console-component`, `console-csp` and `console-fuzz`. Other leaf checks (format, schema, license, build and bootstrap) have explicit IDs in `inventory.py`; each leaf has a closed required check set. The inventory changes with any added check.

Discovery must match the committed required names, not merely find at least one match. Ordinary Go/Rust suites enumerate their test binaries/packages and tests, require nonempty inventories where tests are expected, and compare executed names with discovery. Selected qualification names have no skip allowance. Ordinary-suite skips for helper entry points and explicitly separate extended tests use an exact-name, mode-specific allowlist with a reason and the separate proving unit. No wildcard skip allowance. Detect a renamed selector, removed binary, duplicate result, incomplete output and output from a different invocation.

| Mode | Required evidence |
|---|---|
| Go selected tests / ordinary and race suites | `go test -list` discovery with identical package, build tags and flags; run with `-json -count=1`; named `run` then terminal `pass`, no selected `skip` or `fail`; successful package termination. Parse the [test2json event format](https://pkg.go.dev/cmd/test2json), including subtests, without treating plain text PASS as proof. |
| Go selected benchmark | Discover exactly `BenchmarkValidate`; retain `-benchmem -benchtime=100x` and require positive operation count plus time/allocation results. The intentional `-run '^$'` runs no tests and cannot satisfy a test receipt. |
| Go fuzz | Exactly one discovered fuzz name; anchored selector, `-fuzztime=60s -parallel=2`, seed completion plus positive fuzz execution count beyond seed collection and successful termination. Preserve the pinned Go runner's progress output and elapsed time; missing progress fails. Go JSON events alone do not prove mutation execution. |
| Rust selected properties | Stable harness `--list` with the same binary/filter, then `--ignored --exact --nocapture --test-threads=1`; require the exact named `ok`, one passed/zero failed/zero ignored, and the seed/count/duration record. Parse pinned stable text; do not rely on unstable JSON output. [Rust test options](https://doc.rust-lang.org/rustc/tests/index.html) define listing, exact matching and output capture. |
| Interop | Build the live `seal-vector` first; require `TestRustWriterFixtures`, `TestRustWriterBoundaries`, `TestRustWriterMutations` and `TestRustWriterCaptureOverflow` in ordinary and race mode, plus their expected subtests. `TestRustWriterPrecondition` and `TestRustWriterCaptureChild` are subprocess-only helpers; parents must prove their intended rejection/overflow behavior under the supplied mode, not count their no-op top-level returns. Missing writer paths fail. |
| Loader Gate A | Require extended corpus, 50 fresh repeated samples for `comment-collections/262144/combined`, and 60-second fuzz qualification on each native host. Verify the nested harness as described below. |
| Console | Vitest/Playwright result reports must enumerate the selected tests with no unexpected pending/skipped cases, including the bounded property target and all three browser projects. Empty reports and renamed selectors fail. |

`targets.toml` moves all 20 existing server fuzz package/name pairs out of workflow YAML without dropping one; include `FuzzParserQualification` separately under loader. Keep exact command flags and budgets in that inventory and generate matrices from it. Cross-check discovered fuzz targets so adding a target requires an inventory entry. Expose `--list` on the wrapper to print IDs and commands for local documentation.

Nested loader changes belong in `server/internal/extensions/loader/yaml_budget_test.go` and `internal/yamltokens/qualification_test.go` beneath that directory. The parent enumerates the expected recipe/size/mode/sample keys from the input corpus before spawning children. The child writes one `PARSER_MEASUREMENT` per key. The parent checks exact key equality, uniqueness, numeric finite counters, existing bounds and successful named subtest events. Repetition has sample IDs 1 through 50; 50 copies of one sample cannot pass. A zero exit with no `TestParserBudgetHarness` execution, one omitted measurement, an extra measurement or a skipped child fails. Preserve cold-child isolation and the existing measurement accounting; this slice changes proof, not resource limits.

Rust recovery reports seed `0x525653505f763031`, 100,000 cases and elapsed duration; sealing reports seed `0x5249564241544348`, 20,000 cases and duration. Require exact counts and seeds on all three hosts. Missing output or a reduced case budget fails. Console's bounded property run reports initial seed `0x52495641`, 10,000 iterations covering catalogue, preferences and locale, elapsed duration and pass result. These are deterministic mutation runs, not coverage-guided fuzzing.

Every parser has positive captured outputs from the pinned runner and negative controls for zero matches, rename, skip, truncation, duplicate result, failing child and missing measurements. Test parsers with small synthetic runs locally; race, timed fuzzing, native extended properties and browsers remain CI-only. Raw failed output and minimized corpora retain 30-day evidence; upload failure cannot erase the original check failure.

## 7. Reviewed-base catalogue compatibility (CI-02)

`scripts/ci/catalogue_compat.py --root PATH --base-sha SHA --candidate-sha SHA` reads canonical `schemas/permissions/v1/catalogue.json` directly from both Git objects, never a working-tree baseline or PR-supplied base file. The workflow supplies the validated route's base and tested SHA. PR base is the event's reviewed master SHA, not its merge base; master push base is `before`. Read `GITHUB_EVENT_NAME`, `GITHUB_EVENT_PATH` and `GITHUB_SHA` through the same event-admission code as routing; local tests supply fixture environments. Require the base/candidate arguments to equal the validated event-derived pair in section 3; reject substitutions even when the replacement objects are valid ancestors. Reject absent objects/catalogues, equal candidate/base commits in a changed PR, invalid wire/schema data and unsupported format versions. Emit both SHAs and revisions. Keep canonical/embedded byte-equality tests separately.

Apply the lifecycle in [permission catalogue section 2](permission-catalogue.md#2-names-fields-and-lifecycle): existing names and `introduced` values remain; `owner`, `scope`, `grant`, `rule`, `protection`, `approval` and `uses` cannot change in place. Changes to uses are treated as semantic, including additions; introduce a new name instead. Active-to-retired is allowed with `retired_in` greater than the base revision and no greater than candidate revision. Retired rows retain all metadata and their retirement revision permanently. New names have `introduced` greater than the base revision and no greater than candidate revision. Active `note` and `source` corrections are allowed with a revision increase and semantic review.

Any decoded content change requires a strictly greater root revision; decreasing revision always fails. Formatting/member-order changes alone may retain revision; a revision-only increase is allowed. Revision overflow fails. A semantic change fails even with a revision increase. Strict duplicate-key and integer checks run before comparison; an unknown field is not silently discarded. Default schema validation and the advisory source inventory cannot substitute for this check.

Negative controls include changing `mdm.commands.restart.scope` to `organization` at revision 3, the same change with a bumped revision, deletion, tombstone resurrection, modified retirement/introduced values, changed approval/grant/uses, note change without bump, missing base and candidate-as-base substitution. Positive controls cover unchanged bytes, formatting, new names and retirement. Tag builds use section 3's independently bound parent and still require the separate permission coverage refresh before publication.

## 8. One validator environment and admitted tools (CI-04 to CI-07)

The exact validator Python is `3.14.8`, recorded once in `.github/python-version` with LF, everywhere: design, agent fixture generation, CI helpers, Copilot setup and release validation. `.github/requirements-design.txt` remains the sole validator closure, keeping its nine exact package versions and adding approved wheel SHA-256 values for every selected platform. No ad hoc jsonschema venv and no floating Python minor pin.

Install into a fresh venv with `python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: -r .github/requirements-design.txt`, then `python -m pip check`. Verify the complete installed validator set against the lock, not only direct dependencies; record bootstrap pip separately as part of the admitted Python tool. Reject editable, VCS and URL requirements, unhashed transitives, source distributions, extra validator packages and unlicensed closure entries. [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/) supplies hash-checking requirements. An unavailable compatible wheel blocks that platform until a reviewed pin change; no source-build fallback.

[Licensing](../licensing.md) records attrs, jsonschema-specifications, rpds-py and typing-extensions before use. `python_env.py --check` compares installed names/versions, wheel METADATA and shipped license files with the closure and license inventory. If a locked wheel's metadata or shipped license files disagree with the inventory, the admission check fails and names the package, version and mismatch. Missing required notices also fail admission. Lock updates retain wheel names, hashes and release-tag license evidence in review. No new Python runtime dependency is introduced in Ricevanta binaries.

`scripts/ci/toolchains.lock.json` is the reviewed download authority, validated by the CI schema's `toolchains` branch. Each entry has unique `id`, `tool`, exact `version`, `platform`, HTTPS `url`, positive `size` and lowercase SHA-256. `scripts/ci/bootstrap.py --lock PATH --platform PLATFORM --tools TOOL[,TOOL...] --dest DIR --cache-mode sources|none --env-out PATH` rejects missing/duplicate selections, downloads to a new directory with HTTPS-only redirects and a byte limit equal to the recorded size, verifies size and digest before extraction/install/execution, then checks executable version and host. Unknown platforms fail. The lock contains no secrets and cannot be updated automatically during CI.

The initial [GitHub-hosted runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) OS, shell, Git, TLS roots, hashing tools and preinstalled Python used only to run the standard-library bootstrap are trusted inputs. Log their paths/versions plus runner image version. The admitted Python replaces the bootstrap interpreter for validators. Do not install third-party Python modules to verify Python itself. Disable implicit setup-action downloads and automatic Go/Rust/Corepack/browser updates. Do not accept an existing runner tool-cache directory merely because its version string matches.

The first lock covers Go 1.27.1, Python 3.14.8, Rust 1.99.0 distribution components (rustc, cargo, std, rustfmt, clippy), Node 24.21.0 and pnpm 11.18.0 on hosts where consumed. Include Playwright 1.59.1's Chromium, Firefox, WebKit and required helper archives on Linux x64, plus any downloaded actionlint binary. Setup actions may remain only when they cannot fetch or execute an unchecked payload. Rust installation must use verified offline components, not an unverified rustup download chain. pnpm's tarball and installer path must be admitted before use.

Use public first-party distribution inputs: [Go download metadata](https://go.dev/dl/?mode=json&include=all), [Python runner builds](https://github.com/actions/python-versions), [Rust distribution code](https://github.com/rust-lang/rustup), [Node release verification](https://github.com/nodejs/node#verifying-binaries), and [Playwright browser distributions](https://playwright.dev/docs/browsers). An upstream checksum fetched during the same install is evidence for lock review, not the runtime authority. The reviewed repository digest is authoritative. No sample hash from the schema examples is an approved payload.

Check archives for traversal, absolute paths, case collisions and escaping links before extraction. Preserve legitimate internal toolchain symlinks only after verifying their resolved targets remain inside staging. Use an empty destination; no partial-install fallback. Any downloaded native SDK or OS dependency package also needs a lock entry and license review. Prefer required system libraries already present on the recorded runner image; remove unchecked `playwright install --with-deps` installs. Missing system libraries fail with their names. Cold-install CI must demonstrate this on each consumed host before landing.

`bootstrap.yml` proves cold installs and one-byte-corruption rejection before any extraction or execution, including installer side-effect sentinels. Tests distinguish bad size, bad digest and unsupported host. Release Task 2 adds Linux ARM64 entries and a native Ubuntu ARM64 proof using this same interface, then passes `--cache-mode none` for tag jobs. SBOM/native SDK additions extend this lock only after their licensing rows exist.

## 9. Published budgets and local command labels

`console/scripts/audit-dist.ts` prints entry and every lazy route's measured Brotli byte total beside the limit, even on failure: entry at most 250,000 bytes; each route closure excluding entry at most 150,000. Name closure members so missing/double-counted assets are reviewable. Keep compression quality, graph checks, font notices and both clean reproducibility builds from the console spec. CI runs `pnpm test:fuzz`, retains Vitest/Playwright reports and failure traces/screenshots, and logs browser versions/revisions. Measurements are evidence, never a substitute for failed assertions.

Every runnable command in `instructions/testing.md` receives one explicit label: `Local` (light touched-scope checks), `CI` (heavy or native qualification), or `Local and CI` (cheap deterministic checks in both places). Label command blocks, inline execution instructions and generated command tables, including working directory. Fuzz, race, extended properties, all browsers, full ordinary suites and reproduction are CI; focused unit tests, formatting, vet/clippy and fixture/schema checks may be local. Link to the inventory for exact selectors instead of maintaining another fuzz list. Explain PR-triggered CI for `wip/` branches and the isolated diagnosis exception.

## 10. Owner settings and acceptance

These are repository settings, not workflow implementation and not verified live by this design:

- Require exact check `ci-required` from the GitHub Actions app for `master`, with the branch current against its base. Observe the emitted name in a real PR before configuring it. No dispatch substitute or similarly named optional check.
- Put CI enforcement, force-push and deletion protection in an active ruleset with no routine administrator bypass. Keep the owner's authorized review bypass in a separate review ruleset. [Ruleset layering](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) applies both; a review bypass must not exempt CI.
- Keep read-only default workflow permissions and full-SHA action policy. Give artifacts at least 30 days of allowed retention. Release-tag protection belongs to the release-build plan.
- Copilot review frequency is the owner's choice. Copilot is optional when unavailable; exact-head independent review and green required CI remain mandatory.

The coordinator records run URLs and tested SHAs for a docs-only PR, each routing family, a failing required job, a cancelled required job, an omitted matrix receipt and a superseded PR. Verify a current-base green PR can be fast-forwarded under the review bypass while failed/missing `ci-required` cannot. Do not test rejection by landing deliberately failing code on master; use ruleset evaluation evidence and a disposable branch with equivalent rules. If GitHub rejects the intended fast-forward despite the valid PR check, resolve the integration method before enabling routine landing, without adding a CI bypass.

## 11. Security trace, benefits and alternatives

The trust path is GitHub event and reviewed base, full Git diff, expected unit inventory, read-only job checkout, admitted tools, fresh compilation, verified test output, same-run receipts, aggregate check, then independent review and owner-enforced landing. No CI job receives enrollment material, organization data, production signing keys or database credentials. CI logs use synthetic fixtures only; endpoint raw sensitive content remains on device except policy-permitted redacted snippets.

| Attacker | Result across routing, compatibility, tool admission, evidence and landing |
|---|---|
| Stolen enrollment token | Gains no repository or CI credential and cannot change a base, digest or receipt. Enrollment authorization remains PKI-02's runtime boundary. |
| Compromised agent host | Can forge local telemetry, not GitHub job outcomes. The host receives no CI key. Runtime attestation/enforcement remains outside these library tests. |
| Compromised console session | Gains only runtime session rights, no CI or repository rights. Exported console data cannot enter workflow commands or expected work. |
| Rogue extension publisher | Cannot change the tool lock or CI inventory through a published extension. If contributing a PR, gets untrusted read-only execution; workflow/test edits still need independent review. No publisher package is executed by the aggregate. |
| Network position between agent and server | Has no authority over CI. On CI download paths, substituted bytes fail pinned digests; blocking downloads causes failure. TLS or matching hashes alone cannot make an unreviewed digest trustworthy. |
| Database writer without signing keys | Cannot rewrite Git objects, Actions receipts or owner rules through runtime rows. Forged runtime authorization remains subject to its separate authority protocol. |
| Server restored from backup | Restores no CI credentials, result authority or signing keys from this slice. Old artifacts/receipts cannot satisfy a different SHA/run/attempt. This does not implement runtime rollback or recovery fences. |

A compromised GitHub administrator, runner image, reviewed action or approved tool payload can defeat this CI boundary. Hash admission prevents replacement after review, not malicious bytes approved in the lock. A malicious PR can falsify its own tests; independent adversarial code review covers CI and harness mutations. Restricting the token limits damage but does not prove source honesty.

Benefits: one required result covers every PR, evidence exposes omitted work, fresh compilers remove cross-run object reuse, compatibility uses reviewed history, and one Python closure removes divergent validators. Costs: more cold compilation/download time, maintained result parsers, matrix receipts and digest updates. Bound resource use with existing fuzz/property budgets and per-job timeouts; never lower required budgets to hide a timeout.

Alternatives rejected: workflow-level path filters can leave required checks absent; API polling across independent runs admits stale results; always-success wrappers hide skipped jobs; dispatch cannot satisfy the PR gate; revision-only catalogue checks miss changed semantics; setup-action pins alone leave payload bytes unpinned; compiled caches retain the audit's reuse threat. A dedicated external attestation service adds accounts and is unnecessary for this slice.

## 12. Release-build handoff

Full tag routing includes the security scanner groups; release consumers remain blocked on the separate [tag scanner contract prerequisite](ci-security-scanning.md#1-boundary-and-admission). PR/master scanner credentials and receipts cannot satisfy that contract.

[Release plan Task 2](../plans/release-builds.md#task-2-consume-the-audited-ci-trust-boundary) consumes `route.py`, `inventory.py`, `required.py`, `run_selected.py`, `targets.toml`, `catalogue_compat.py`, `fresh_go.py`, `python_env.py`, `bootstrap.py`, `toolchains.lock.json`, `.github/requirements-design.txt` and the CI schema. Their CLIs are fixed above. `scripts/ci/check_policy.py --root PATH` checks workflow safety, input coverage, matrices, allowed caches and bootstrap coverage, and exits nonzero with each offending path. It exposes `check(root: pathlib.Path) -> list[str]` for fixture-based release tests.

Release jobs call these helpers and reusable workflows with the same route contract, add their explicit units to inventory, and select full mode for tag builds. `release-ready` is a separate tag aggregate using the same verifier, not an alternate branch status named `ci-required`. Ordinary CI proof is a prerequisite, never permission to publish or sign. Any interface change requires this spec and the release consumer plan to change together.
