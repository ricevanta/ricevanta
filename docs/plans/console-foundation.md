# Console foundation implementation plan

Build the static console foundation specified in [console-foundation.md](../specs/console-foundation.md), with working rules in [Vue instructions](../../instructions/vue.md). The spec and this plan require independent review; unchecked tasks are required work, not completed checks.

## Global constraints

- An independent Sol xhigh reviewer must approve the spec, plan and instruction changes before code starts. Dispatch `gpt-6.1-sol` at `xhigh` explicitly; the design author cannot approve the design.
- A separate implementer, `gpt-6.1-sol` at `medium`, owns `console/**` and `.github/workflows/console.yml`. The designer and reviewers do not implement the slice. No worker commits or pushes; the primary agent owns Git.
- Review with `gpt-6.1-sol` at `xhigh` after the final code task. Include an independent adversarial pass over source validators, preference parsing, static serving, CSP enforcement and CI. A separate Sol xhigh reviewer confirms fixes; the implementer resolves findings.
- Use the spec's exact pins. Installed tools are Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0. Only Node and pnpm build this slice; do not add Go or Rust work.
- Run tasks sequentially in one implementation worktree because configuration and shared source contracts overlap. Other design workers keep separate worktrees. Any delegated brief must include the spec, owned paths, forbidden actions, commands and required report.
- Write each behavior test first, run it to observe the intended missing-behavior failure, implement the least code that passes, and rerun. Tool installation or syntax errors unrelated to the behavior do not count as the red test.
- Add no backend calls, authentication substitute, permission claim, deployment, extension loader or unused stack dependency. Preserve the v0.1.x follow-on slices named in spec section 1.
- Do not edit branding, server code, shared schemas or other workflows. Generated files stay inside ignored console paths. A needed change outside ownership returns to the primary agent with an exact reason.
- Report changed files, focused red and green results, full checks, unresolved verify claims and measured browser revisions. Do not report this work as full browser/OS qualification.

## Review focus

- The build excludes runtime compilers and inline code, and all route chunks run under the exact enforcing header.
- Vue's `vue` policy is not a sanitizer; source checks close HTML and binding paths without adding a bypass policy.
- Browser probes prove actual string-sink refusal and event observation in every engine; no skips, policy relaxation or Playwright evaluation shortcut.
- Catalogue validators detect duplicate keys before conversion, follow error precedence, check both locales and reject malformed plural forms.
- Tokens come from the named brand and semantic tables; generated colours pass contrast and explicit themes beat system preference.
- Corrupt or inaccessible storage grants no authority and cannot stop startup; unknown routes reveal no input text.
- Static serving cannot escape its root, serve a test asset as production output, or return HTML for a reserved route.
- Dependency installation uses exact pins, a frozen lockfile, strict peers and no lifecycle hooks. OSV exceptions require exact advisory, package/version and full-path matches; stale entries and every unlisted finding fail with named diagnostics. CI uses immutable actions, minimal permissions and bounded runs.
- All three compiler projects use `skipLibCheck: true` for the dependency declaration errors described in spec section 2. Every other strictness flag remains enabled. Project declarations are forbidden except the exact Vite env reference; compiler coverage includes source, tools, JavaScript configuration and tests. Reject unused bundler type devDependencies, ambient stubs and dependency patches for the reasons in spec section 8.

## Script interface

All commands below run from `console/` unless prefixed with `cd`. Create these package scripts; scripts may call shared typed helpers, but must preserve these meanings:

| Command | Required behavior |
|---|---|
| `pnpm generate` | Validate token inputs, generate token CSS, copy brand/font notices |
| `pnpm check:source` | Validate catalogues, source usage and static source restrictions |
| `pnpm typecheck` | Run the toolchain declaration and compiler coverage checks, generate, repeat the declaration check to catch generated files; `vue-tsc --noEmit -p tsconfig.app.json`, then `tsc --noEmit -p tsconfig.tools.json`, then `vue-tsc --noEmit -p tsconfig.test.json`; run the compile-negative harness with the same flags and require intended diagnostics |
| `pnpm lint` | `eslint . --max-warnings 0`, then source checks |
| `pnpm audit:deps` | Check every locked resolved license and query OSV for all resolved npm package/version pairs; apply only reviewed exact exceptions from `security/osv-exceptions.json`; fail on unlisted findings, stale or invalid entries, or incomplete results, naming each finding |
| `pnpm format:check` | `prettier . --check` |
| `pnpm test:unit` | `vitest run --project unit` with Node environment and at most two workers |
| `pnpm test:component` | Generate first; `vitest run --project component` using headless Chromium and at most two workers |
| `pnpm build` | Source checks, generation, Vite production build, output audit and compression |
| `pnpm check:reproducible` | Two isolated clean builds in temporary directories; compare path/SHA-256 manifests, fail on differences |
| `pnpm test:csp` | `playwright test --config playwright.config.ts`, all three projects, one worker, zero retries, no skipped test accepted |
| `pnpm test:fuzz` | Unit property targets only, fixed seed and 10,000 cases per target |

Keep test helpers out of production imports. Use `vitest.config.ts` projects with explicit includes so unit tests never execute Playwright test files. Component transforms share the Vue and i18n build settings, but the component dev harness is not CSP evidence.

### Task 1: Project and validation harness

**Create:** `console/package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.node-version`, `.gitignore`, `tsconfig.app.json`, `tsconfig.tools.json`, `tsconfig.test.json`, `src/env.d.ts`, `vite.config.ts`, `vitest.config.ts`, `eslint.config.mjs`, `prettier.config.mjs`, `.prettierignore`, `scripts/check-toolchain.ts`, `scripts/audit-deps.ts`, `security/osv-exceptions.json`, `tests/unit/audit-deps.test.ts`, `scripts/eslint-rules/`, and `tests/unit/toolchain.test.ts` plus rule fixtures.

**Consumes:** spec section 2 pins and Vue instructions. **Produces:** reproducible install and runnable unit/component harnesses; no application authority.

- [x] Create the package/configuration scaffolding needed to run tests, with exactly the pinned direct dependencies. Ignore `node_modules`, `dist`, generated assets, `.vite`, coverage and browser reports locally; never alter global ignores.
- [x] Pin `eslint-plugin-vue` 10.11.1 and `vue-eslint-parser` 10.3.0; retain `eslint` and `@eslint/js` 9.39.1. Check the published required and optional peers from spec section 2 without adding the optional stylistic plugin. Verify all selected direct and transitive releases are at least 1,440 minutes old. Resolve and lock `postcss-selector-parser` 7.1.6 through the plugin's compatible range; require no affected selector-parser version anywhere in the lockfile and no exception for `GHSA-rj75-hqrm-r3gf`.
- [x] Set `skipLibCheck: true` in application, tooling and test projects for the missing unused bundler imports in spec section 2. Retain every other Vue instruction strictness flag, including `exactOptionalPropertyTypes` and strict templates. Include every Ricevanta source, tool, configuration and test file; enable `allowJs` and `checkJs` for JavaScript configuration and helpers. Keep project types in `.ts` modules. Permit only the exact one-line Vite reference in `src/env.d.ts`; forbid all other authored or generated project `.d.ts`, `.d.mts` and `.d.cts` files. Add no unused bundler type devDependencies, ambient stubs or dependency patches.
- [x] Set `console/pnpm-workspace.yaml` to `supportedArchitectures: { os: [linux, darwin, win32], cpu: [x64, arm64], libc: [glibc] }` with exactly those lists for the v1.0.0 console build targets, selecting glibc where pnpm requires a Linux C library. Follow the [pnpm supportedArchitectures documentation](https://pnpm.io/settings/dependency-resolution#supportedarchitectures). On every runner, verify the frozen install includes every eligible locked package (its `os`, `cpu` and `libc` fields allow a supported combination), list ineligible packages as excluded, run OSV for every locked package, and reconcile installed license evidence against every package in `console/pnpm-lock.yaml` before OSV runs, including `lightningcss-darwin-arm64` and win32 builds on Linux. Missing evidence must fail. Reject skipping evidence for uninstalled packages because that leaves locked dependencies unaudited; reject registry license fetches at audit time because they substitute network metadata for installed locked-package evidence.
- [x] Run `node --version` and `pnpm --version`; require the spec's values. Run `pnpm install` once to create the lockfile, then `pnpm install --frozen-lockfile`; require zero peer conflicts and no lifecycle script execution. Do not use `--force` or suppress a peer warning.
- [x] Record `pnpm list --depth 0` and `pnpm licenses list --json`. Review all resolved licenses against console design section 6.3 and verify each exception against the pinned package LICENSE file recorded in `docs/licensing.md`. Permit BlueOak-1.0.0 and Python-2.0.1 only for development and build tooling. Normalize declared `Python-2.0` to `Python-2.0.1` only for pinned `argparse` 2.0.1 with matching recorded LICENSE evidence; retain both identifiers in the resolved inventory used by dependency and build-output checks. Add fixtures accepting that normalized package as tooling and rejecting runtime use, other packages or versions claiming the mapping, and missing or mismatched LICENSE evidence. Permit MPL-2.0 only for test tools and unmodified build-time tools whose code is never shipped in the console bundle; Task 4 must verify the output boundary. Test unknown-license, permitted tooling, forbidden runtime use of tooling-only licenses and modified MPL build tools before implementing license checks.
- [x] Write failing `tests/unit/audit-deps.test.ts` fixtures for clean results, the exact braces exception, unlisted advisories including a second advisory on braces, another path to the same affected version, promotion of the unchanged braces path root into `dependencies` or `optionalDependencies`, manifest/lockfile dependency-class disagreement, changed or removed path edges and versions, a removed package, an absent advisory, malformed/missing/duplicate/wildcard entries, multiple findings, pagination and unavailable or incomplete service responses. Require every finding's advisory ID, package, exact version, path and disposition in diagnostics; require every stale entry and its reason in the audit error. Run `pnpm test:unit -- tests/unit/audit-deps.test.ts` and observe the intended missing-behavior failures.
- [x] Implement `audit:deps` with Node built-ins: invoke pnpm for structured resolved-package and license inventories, reject unknown licenses, retain all dependency paths from the frozen lockfile, deduplicate exact npm package/version pairs only for requests, query the [OSV query batch API](https://google.github.io/osv.dev/api/#operation/querybatch) in batches of at most 100 with a 30-second request timeout, and follow every returned pagination token. Apply the strict six-field exception contract and matching rules in spec section 2. Require the braces root only in the console importer's `devDependencies` in both manifest and lockfile; identical package/version paths under runtime or optional-runtime roots still fail. Fail on every unlisted finding, stale or invalid entry, or incomplete response. Aggregate and sort named diagnostics before failure; network failure is a failed check, not an empty finding list.
- [x] Create the committed `security/osv-exceptions.json` with the spec's exact `GHSA-vfj7-8cjw-p6xm` entry for `braces` 3.0.3 and the versioned Intlify -> fast-glob -> micromatch -> braces path. Obtain independent Sol xhigh review of the entry, repository-controlled pattern inputs and removal condition. Confirm no external pattern source and no shipped code on that path using Task 4's graph and asset provenance checks. Keep the exception separate from license permissions; reject no audit, a nonexistent braces override and a private fork for the reasons in spec section 8. Rerun the audit fixtures and `pnpm audit:deps`; retain findings, exception dispositions and review evidence before acceptance.
- [x] Write tests for wrong tool versions, version ranges, missing lockfile, raw text, unsafe sinks and hidden bindings. Run `pnpm test:unit -- tests/unit/toolchain.test.ts`; observe the expected missing validator failure, then implement the toolchain checker and local lint rules.
- [x] Test and implement the toolchain declaration and compiler coverage checks from spec section 2. Reject extra declaration files under source, scripts, tests and generated source, additions to `src/env.d.ts`, and project files omitted from compiler coverage. Run the declaration check before and after generation in `pnpm typecheck`. Store forbidden declaration fixtures as text or create them in temporary test directories so the project inventory itself remains valid.
- [x] Run the focused unit tests and `pnpm format:check`. With `skipLibCheck: true` and every other strictness flag enabled, verify project type errors in application, tooling, JavaScript configuration and tests still fail. Include unchecked indexed values and invalid template props. Compile these negative fixtures separately from normal production compilation with the same flags, and require the intended project diagnostics rather than any nonzero exit.

### Task 2: Tokens, fonts and brand assets

**Create:** `scripts/generate-tokens.ts`, `scripts/prepare-assets.ts`, `src/ui/styles/{base,fonts}.css`, `src/ui/RicevantaLogo.vue`, `tests/unit/tokens.test.ts`, `tests/unit/assets.test.ts`, and token/input fixtures.

**Consumes:** spec section 5 and read-only brand files. **Produces:** generated CSS, copied brand files and local font assets/notices.

- [x] Write all table-parser, malformed-input, deterministic-output, role-mapping and contrast tests. Run `pnpm test:unit -- tests/unit/tokens.test.ts tests/unit/assets.test.ts`; require the intended missing-generator failure.
- [x] Implement the strict table parser and deterministic CSS writer. Make missing/extra/duplicate roles fail before writing any output. Add font imports only after confirming the pinned package subset paths and OFL notice; report mismatches without substituting a different version.
- [x] Add asset-copy and font-notice tests. Verify generated image bytes equal their branding sources, no remote URL is emitted, and both logo variants are selected by CSS without duplicate accessible names.
- [x] Run `pnpm generate`, repeat it and compare hashes of generated files. Run the focused tests; require every spec colour pair to meet its unrounded contrast threshold.

### Task 3: Internationalization and preferences

**Create:** `src/locales/en.json`, `src/locales/vi.json`, `src/app/i18n.ts`, `src/app/locale.ts`, `src/stores/preferences.ts`, `scripts/check-catalogues.ts`, `scripts/check-source.ts`, and unit/fixture files for catalogue, plural, locale, preference and source validation.

**Consumes:** spec sections 6 and 7. **Produces:** typed keys, precompiled catalogues, validated preference state and stable validator diagnostics.

- [x] Write failing tests for both locale key sets, syntax and placeholder matching, duplicates, bounds, banned keys, missing/unused strings, plural rendering and every error-precedence vector. Run `pnpm test:unit -- tests/unit/catalogues.test.ts tests/unit/preferences.test.ts tests/unit/locale.test.ts` and record the intended failures.
- [x] Implement duplicate-aware parsing and phase ordering. Use the pinned compiler only in tooling. Add the named TypeScript helper contracts; invalid counts throw only the specified `RangeError` and preference failures produce complete defaults.
- [x] Build finite typed lists for control labels and route title keys. Source checking treats those lists as use sites and rejects arbitrary key expressions. Add actual shell strings to both catalogues; keep synthetic count fixtures out of product catalogues.
- [x] Verify locale selection, blocked storage, write failures and reactive locale changes. Run the focused unit tests, `pnpm check:source`, `pnpm typecheck` and `pnpm test:fuzz`.

### Task 4: Routing shell and build output

**Create:** `index.html`, `src/app/{main.ts,App.vue,router.ts,fatal.ts}`, views under `src/features/{home,not-found}/`, `src/ui/{ShellHeader,PreferenceControls}.vue`, `scripts/{audit-dist,compress,check-reproducible}.ts`, and component/unit tests for routes, fatal state and build output.

**Consumes:** generated tokens, i18n and preference contracts. **Produces:** static shell and audited `dist/` output.

- [x] Write component tests for navigation, title/lang updates, heading focus, keyboard selectors, skip link, unknown route, fatal errors and failed dynamic imports. Run `pnpm test:component`; record the missing-shell failures before adding components.
- [x] Implement exactly the two routes in the spec. Use root history and literal dynamic imports. No fake counts, disabled login mockups, session fetch or placeholder API module.
- [x] Implement generic error presentation and explicit reload. Test repeated chunk failure without reload loops and verify no exception/query/path text enters the DOM.
- [x] Write failing build-audit tests against fixture output containing inline styles/scripts, source maps, remote assets, compiler modules, eager routes, leaked test probes, files or bundled code under MPL-2.0, BlueOak-1.0.0 or Python-2.0.1 and over-budget chunks. Add build graph inspection through Vite's output hooks and copied-asset provenance checks against the resolved license inventory; reject any MPL-2.0, BlueOak-1.0.0 or Python-2.0.1 licensed file or code in shipped assets. Cover bundled modules and copied files under each tooling-only license with negative fixtures. Include `argparse` 2.0.1 fixtures with declared `Python-2.0` metadata normalized to `Python-2.0.1`; reject both bundled modules and copied files from that package. Also reject bundled modules or copied code from the braces exception path in spec section 2, with negative fixtures. Do not infer compiler or tooling-only code absence from a text search alone.
- [x] Implement build, compression and isolated repeat-build comparison. Run `pnpm typecheck`, `pnpm lint`, `pnpm test:unit`, `pnpm test:component`, `pnpm build` and `pnpm check:reproducible`; require all to pass.

### Task 5: Enforcing CSP browser harness

**Create:** `security/csp.txt`, `scripts/serve-dist.ts`, `playwright.config.ts`, `tests/browser/{shell,csp-controls,serving}.spec.ts`, `tests/browser/fixtures.ts`, `tests/fixtures/csp/`, and `tests/unit/serving.test.ts`.

**Consumes:** immutable `dist/` bytes and the spec's complete header. **Produces:** passing behavior evidence for the pinned engines and precise failures for missing enforcement.

- [x] Write serving tests for traversal, encoded separators, external symlinks, bad Host, MIME, methods, compression, reserved-prefix refusal and HTML fallback. Run `pnpm test:unit -- tests/unit/serving.test.ts`; observe the intended missing-server failure, then implement only a loopback test server.
- [x] Install engine binaries explicitly with `pnpm exec playwright install --with-deps chromium firefox webkit`. No browser installation runs as a dependency hook.
- [x] Implement normal-run observers and isolated negative-control pairs using the per-engine expectation table and engine-selection rule in [spec section 7](../specs/console-foundation.md#7-required-tests-and-error-precedence). Implement its protected-header checks in the shared verifier.
- [x] Separate header-integrity and behavior checks in the shared verifier and browser mutation tests according to section 7's mutation requirements. Add unit coverage for completion and each named rejection independently of header failure. Keep source-directive and missing-header checks distinct from executable mutation evidence.
- [x] Wire external probe scripts and passive pre-navigation event capture as required by section 7. Keep the probe mount and mutation routes confined to the test harness.
- [x] Run `pnpm build` and `pnpm test:csp` in CI; require the full shell matrix, source-free error states, all protected/control probe pairs and mutation checks to pass on all engines. Record browser versions, revisions, each probe's expected and observed directive and outcome, and any verify claim resolved by the run. Require independent review of the spec's expectation table when browser pins change.
- [x] Scan accessibility and test keyboard paths as specified. Keep axe outside the production CSP gate if its injection needs a bypass. Run font loading checks after `document.fonts.ready` and verify Vietnamese glyph text and all four requested weights.

### Task 6: Console CI

**Create:** `.github/workflows/console.yml`. **Consumes:** all checks above. **Produces:** CI scoped like [server.yml](../../.github/workflows/server.yml).

- [x] Name the workflow `Console checks`. Use `push` to `master`, `pull_request` and `workflow_dispatch`. Both path filters contain `console/**`, `branding/BRAND_SPEC.md`, `branding/dist/**`, `docs/design/console.md`, `docs/specs/console-foundation.md`, `docs/plans/console-foundation.md`, `instructions/vue.md`, `instructions/testing.md`, `docs/licensing.md` and `.github/workflows/console.yml`.
- [x] Set `permissions: { contents: read }`, concurrency group `console-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}` and `cancel-in-progress: true`. Use one `validate` job on `ubuntu-24.04`, timeout 20 minutes, `defaults.run.working-directory: console`, and `CI: true`.
- [x] Use only these action pins, in order. The checkout SHA matches the server workflow; the other SHAs resolve to commits, not annotated tag objects.

| Action | Full commit pin | Inputs |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `persist-credentials: false` |
| `pnpm/action-setup` | `ea17c68df8912ef543352723c149a84f56e3d413` | `version: 11.18.0`, `run_install: false`, `package_json_file: console/package.json` |
| `actions/setup-node` | `949feb2413d6458794dcd2491c4babbbce0c15c1` | `node-version-file: console/.node-version`, `cache: pnpm`, `cache-dependency-path: console/pnpm-lock.yaml` |

Sources: latest releases [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [pnpm/action-setup v6.1.0](https://github.com/pnpm/action-setup/releases/tag/v6.1.0) and [setup-node v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0), each linking to the full commit above. [Licensing](../licensing.md#brand-assets-and-build-tools) records both setup actions as MIT CI tools. Verify action operation with pnpm 11.18.0 during the first CI run; package installation must remain an explicit later step.

- [x] Run separate named steps for `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm lint`, `pnpm format:check`, `pnpm audit:deps`, `pnpm test:unit`, engine installation, `pnpm test:component`, `pnpm build`, `pnpm check:reproducible` and `pnpm test:csp`, in that order. An unavailable engine is a failed job. Do not use `continue-on-error`.
- [x] Cache the pnpm store through setup-node, not `node_modules`, `dist/` or browser binaries. Reinstall browsers from the pinned Playwright package. Log the bundle manifest and measured engine revisions; do not upload storage dumps or page contents.
- [x] Have the primary agent inspect the workflow structure, action pins, paths, cache inputs and command order against this task. Do not add a parser solely to compare a workflow to itself.

## Final verification and handoff

- [x] Run the full command block in [testing instructions](../../instructions/testing.md) from a frozen install; retain results and byte budgets. Ordinary CI runs property seeds through unit tests; the bounded 10,000-case run is required locally before review.
- [x] Run `git diff --check`, inspect the full diff and verify the worker changed only the owned code paths. The primary agent performs Git operations and verifies final CI after the workflow is available.
- [x] Obtain independent Sol xhigh code review and the adversarial pass. Resolve findings with the implementer and obtain separate Sol xhigh fix confirmation. Run only the checks justified by the fixes, then complete primary verification.
- [x] Report the actual install, license/OSV review, type, lint, format, unit, component, build, reproducibility and three-engine CSP results. Failed or unavailable checks remain failed. Identify follow-on backend and browser/OS qualification gates explicitly.
