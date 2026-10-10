# Console foundation implementation plan

Build the static console foundation specified in [console-foundation.md](../specs/console-foundation.md), with working rules in [Vue instructions](../../instructions/vue.md). No console code exists. This plan is ready for independent review; unchecked tasks are required work, not completed checks.

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
- Dependency installation uses exact pins, a frozen lockfile, strict peers and no lifecycle hooks. CI uses immutable actions, minimal permissions and bounded runs.

## Script interface

All commands below run from `console/` unless prefixed with `cd`. Create these package scripts; scripts may call shared typed helpers, but must preserve these meanings:

| Command | Required behavior |
|---|---|
| `pnpm generate` | Validate token inputs, generate token CSS, copy brand/font notices |
| `pnpm check:source` | Validate catalogues, source usage and static source restrictions |
| `pnpm typecheck` | Generate first; `vue-tsc --noEmit -p tsconfig.app.json`, then `tsc --noEmit -p tsconfig.tools.json`, then `vue-tsc --noEmit -p tsconfig.test.json` |
| `pnpm lint` | `eslint . --max-warnings 0`, then source checks |
| `pnpm audit:deps` | Check every locked resolved license and query OSV for all resolved npm package/version pairs; fail on findings or incomplete results |
| `pnpm format:check` | `prettier . --check` |
| `pnpm test:unit` | `vitest run --project unit` with Node environment and at most two workers |
| `pnpm test:component` | Generate first; `vitest run --project component` using headless Chromium and at most two workers |
| `pnpm build` | Source checks, generation, Vite production build, output audit and compression |
| `pnpm check:reproducible` | Two isolated clean builds in temporary directories; compare path/SHA-256 manifests, fail on differences |
| `pnpm test:csp` | `playwright test --config playwright.config.ts`, all three projects, one worker, zero retries, no skipped test accepted |
| `pnpm test:fuzz` | Unit property targets only, fixed seed and 10,000 cases per target |

Keep test helpers out of production imports. Use `vitest.config.ts` projects with explicit includes so unit tests never execute Playwright test files. Component transforms share the Vue and i18n build settings, but the component dev harness is not CSP evidence.

### Task 1: Project and validation harness

**Create:** `console/package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.node-version`, `.gitignore`, `tsconfig.app.json`, `tsconfig.tools.json`, `tsconfig.test.json`, `src/env.d.ts`, `vite.config.ts`, `vitest.config.ts`, `eslint.config.mjs`, `prettier.config.mjs`, `.prettierignore`, `scripts/check-toolchain.ts`, `scripts/audit-deps.ts`, `scripts/eslint-rules/`, and `tests/unit/toolchain.test.ts` plus rule fixtures.

**Consumes:** spec section 2 pins and Vue instructions. **Produces:** reproducible install and runnable unit/component harnesses; no application authority.

- [ ] Create the package/configuration scaffolding needed to run tests, with exactly the pinned direct dependencies. Ignore `node_modules`, `dist`, generated assets, `.vite`, coverage and browser reports locally; never alter global ignores.
- [ ] Run `node --version` and `pnpm --version`; require the spec's values. Run `pnpm install` once to create the lockfile, then `pnpm install --frozen-lockfile`; require zero peer conflicts and no lifecycle script execution. Do not use `--force` or suppress a peer warning.
- [ ] Record `pnpm list --depth 0` and `pnpm licenses list --json`. Review all resolved licenses against console design section 6.3; MPL packages must be test-only. Check the resolved package/version list with the [OSV query batch API](https://google.github.io/osv.dev/api/#operation/querybatch); review or resolve every finding before acceptance, and retain the result in the task evidence. Implement `audit:deps` with Node built-ins: invoke pnpm for structured resolved-package and license inventories, reject unknown licenses, deduplicate exact npm package/version pairs, query OSV in batches of at most 100 with a 30-second request timeout, and follow every returned pagination token. Any finding or incomplete response fails. Test clean, vulnerable, unknown-license, paginated and unavailable-service fixtures before implementing the scanner. Network failure is a failed check, not an empty finding list.
- [ ] Write tests for wrong tool versions, version ranges, missing lockfile, raw text, unsafe sinks and hidden bindings. Run `pnpm test:unit -- tests/unit/toolchain.test.ts`; observe the expected missing validator failure, then implement the toolchain checker and local lint rules.
- [ ] Run the focused unit tests and `pnpm format:check`. Verify strict TypeScript rejects unchecked indexed values and invalid template props with compile-negative test fixtures excluded from normal production compilation.

### Task 2: Tokens, fonts and brand assets

**Create:** `scripts/generate-tokens.ts`, `scripts/prepare-assets.ts`, `src/ui/styles/{base,fonts}.css`, `src/ui/RicevantaLogo.vue`, `tests/unit/tokens.test.ts`, `tests/unit/assets.test.ts`, and token/input fixtures.

**Consumes:** spec section 5 and read-only brand files. **Produces:** generated CSS, copied brand files and local font assets/notices.

- [ ] Write all table-parser, malformed-input, deterministic-output, role-mapping and contrast tests. Run `pnpm test:unit -- tests/unit/tokens.test.ts tests/unit/assets.test.ts`; require the intended missing-generator failure.
- [ ] Implement the strict table parser and deterministic CSS writer. Make missing/extra/duplicate roles fail before writing any output. Add font imports only after confirming the pinned package subset paths and OFL notice; report mismatches without substituting a different version.
- [ ] Add asset-copy and font-notice tests. Verify generated image bytes equal their branding sources, no remote URL is emitted, and both logo variants are selected by CSS without duplicate accessible names.
- [ ] Run `pnpm generate`, repeat it and compare hashes of generated files. Run the focused tests; require every spec colour pair to meet its unrounded contrast threshold.

### Task 3: Internationalization and preferences

**Create:** `src/locales/en.json`, `src/locales/vi.json`, `src/app/i18n.ts`, `src/app/locale.ts`, `src/stores/preferences.ts`, `scripts/check-catalogues.ts`, `scripts/check-source.ts`, and unit/fixture files for catalogue, plural, locale, preference and source validation.

**Consumes:** spec sections 6 and 7. **Produces:** typed keys, precompiled catalogues, validated preference state and stable validator diagnostics.

- [ ] Write failing tests for both locale key sets, syntax and placeholder matching, duplicates, bounds, banned keys, missing/unused strings, plural rendering and every error-precedence vector. Run `pnpm test:unit -- tests/unit/catalogues.test.ts tests/unit/preferences.test.ts tests/unit/locale.test.ts` and record the intended failures.
- [ ] Implement duplicate-aware parsing and phase ordering. Use the pinned compiler only in tooling. Add the named TypeScript helper contracts; invalid counts throw only the specified `RangeError` and preference failures produce complete defaults.
- [ ] Build finite typed lists for control labels and route title keys. Source checking treats those lists as use sites and rejects arbitrary key expressions. Add actual shell strings to both catalogues; keep synthetic count fixtures out of product catalogues.
- [ ] Verify locale selection, blocked storage, write failures and reactive locale changes. Run the focused unit tests, `pnpm check:source`, `pnpm typecheck` and `pnpm test:fuzz`.

### Task 4: Routing shell and build output

**Create:** `index.html`, `src/app/{main.ts,App.vue,router.ts,fatal.ts}`, views under `src/features/{home,not-found}/`, `src/ui/{ShellHeader,PreferenceControls}.vue`, `scripts/{audit-dist,compress,check-reproducible}.ts`, and component/unit tests for routes, fatal state and build output.

**Consumes:** generated tokens, i18n and preference contracts. **Produces:** static shell and audited `dist/` output.

- [ ] Write component tests for navigation, title/lang updates, heading focus, keyboard selectors, skip link, unknown route, fatal errors and failed dynamic imports. Run `pnpm test:component`; record the missing-shell failures before adding components.
- [ ] Implement exactly the two routes in the spec. Use root history and literal dynamic imports. No fake counts, disabled login mockups, session fetch or placeholder API module.
- [ ] Implement generic error presentation and explicit reload. Test repeated chunk failure without reload loops and verify no exception/query/path text enters the DOM.
- [ ] Write failing build-audit tests against fixture output containing inline styles/scripts, source maps, remote assets, compiler modules, eager routes, leaked test probes and over-budget chunks. Add build graph inspection through Vite's output hooks; do not infer compiler absence from a text search alone.
- [ ] Implement build, compression and isolated repeat-build comparison. Run `pnpm typecheck`, `pnpm lint`, `pnpm test:unit`, `pnpm test:component`, `pnpm build` and `pnpm check:reproducible`; require all to pass.

### Task 5: Enforcing CSP browser harness

**Create:** `security/csp.txt`, `scripts/serve-dist.ts`, `playwright.config.ts`, `tests/browser/{shell,csp-controls,serving}.spec.ts`, `tests/browser/fixtures.ts`, `tests/fixtures/csp/`, and `tests/unit/serving.test.ts`.

**Consumes:** immutable `dist/` bytes and the spec's complete header. **Produces:** passing behavior evidence for the pinned engines and precise failures for missing enforcement.

- [ ] Write serving tests for traversal, encoded separators, external symlinks, bad Host, MIME, methods, compression, reserved-prefix refusal and HTML fallback. Run `pnpm test:unit -- tests/unit/serving.test.ts`; observe the intended missing-server failure, then implement only a loopback test server.
- [ ] Install engine binaries explicitly with `pnpm exec playwright install --with-deps chromium firefox webkit`. No browser installation runs as a dependency hook.
- [ ] Write normal-run observers and isolated negative-control pairs from spec section 7. Require `require-trusted-types-for` for raw-string `Function` and `script-src` for `Function(trustedTypes.emptyScript)` under the unchanged header; assert each pair's control result and protected exception. A missing header and an observer that discards events must each make the tests fail. Keep these mutations in test fixtures, never in committed production output.
- [ ] Use external probe JS for protected operations and passive pre-navigation event capture. Compare the header to both the file and an independent expected literal. No test uses `bypassCSP`, a permissive browser flag, a default policy or a skipped Trusted Types probe.
- [ ] Run `pnpm build` and `pnpm test:csp`; require the full shell matrix, source-free error states and all protected/control probe pairs to pass on all engines. Record browser revisions and any verify claim resolved by the run.
- [ ] Scan accessibility and test keyboard paths as specified. Keep axe outside the production CSP gate if its injection needs a bypass. Run font loading checks after `document.fonts.ready` and verify Vietnamese glyph text and all four requested weights.

### Task 6: Console CI

**Create:** `.github/workflows/console.yml`. **Consumes:** all checks above. **Produces:** CI scoped like [server.yml](../../.github/workflows/server.yml).

- [ ] Name the workflow `Console checks`. Use `push` to `master`, `pull_request` and `workflow_dispatch`. Both path filters contain `console/**`, `branding/BRAND_SPEC.md`, `branding/dist/**`, `docs/design/console.md`, `docs/specs/console-foundation.md`, `docs/plans/console-foundation.md`, `instructions/vue.md`, `instructions/testing.md`, `docs/licensing.md` and `.github/workflows/console.yml`.
- [ ] Set `permissions: { contents: read }`, concurrency group `console-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}` and `cancel-in-progress: true`. Use one `validate` job on `ubuntu-24.04`, timeout 20 minutes, `defaults.run.working-directory: console`, and `CI: true`.
- [ ] Use only these action pins, in order. The checkout SHA matches the server workflow; the other SHAs resolve to commits, not annotated tag objects.

| Action | Full commit pin | Inputs |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `persist-credentials: false` |
| `pnpm/action-setup` | `ea17c68df8912ef543352723c149a84f56e3d413` | `version: 11.18.0`, `run_install: false`, `package_json_file: console/package.json` |
| `actions/setup-node` | `949feb2413d6458794dcd2491c4babbbce0c15c1` | `node-version-file: console/.node-version`, `cache: pnpm`, `cache-dependency-path: console/pnpm-lock.yaml` |

Sources: latest releases [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [pnpm/action-setup v6.1.0](https://github.com/pnpm/action-setup/releases/tag/v6.1.0) and [setup-node v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0), each linking to the full commit above. [Licensing](../licensing.md#brand-assets-and-build-tools) records both setup actions as MIT CI tools. Verify action operation with pnpm 11.18.0 during the first CI run; package installation must remain an explicit later step.

- [ ] Run separate named steps for `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm lint`, `pnpm format:check`, `pnpm audit:deps`, `pnpm test:unit`, engine installation, `pnpm test:component`, `pnpm build`, `pnpm check:reproducible` and `pnpm test:csp`, in that order. An unavailable engine is a failed job. Do not use `continue-on-error`.
- [ ] Cache the pnpm store through setup-node, not `node_modules`, `dist/` or browser binaries. Reinstall browsers from the pinned Playwright package. Log the bundle manifest and measured engine revisions; do not upload storage dumps or page contents.
- [ ] Have the primary agent inspect the workflow structure, action pins, paths, cache inputs and command order against this task. Do not add a parser solely to compare a workflow to itself.

## Final verification and handoff

- [ ] Run the full command block in [testing instructions](../../instructions/testing.md) from a frozen install; retain results and byte budgets. Ordinary CI runs property seeds through unit tests; the bounded 10,000-case run is required locally before review.
- [ ] Run `git diff --check`, inspect the full diff and verify the worker changed only the owned code paths. The primary agent performs Git operations and verifies final CI after the workflow is available.
- [ ] Obtain independent Sol xhigh code review and the adversarial pass. Resolve findings with the implementer and obtain separate Sol xhigh fix confirmation. Run only the checks justified by the fixes, then complete primary verification.
- [ ] Report the actual install, license/OSV review, type, lint, format, unit, component, build, reproducibility and three-engine CSP results. Failed or unavailable checks remain failed. Identify follow-on backend and browser/OS qualification gates explicitly.
