# Vue development

The console is a private Vue single-page application in `console/`. Use Node 24.21.0 and pnpm 11.18.0. [Console foundation](../docs/specs/console-foundation.md) owns exact dependency pins, build output, tokens, catalogues and the CSP contract. Keep the package manifest, lockfile, `.node-version` and CI aligned.

## Project and types

- Use only dependencies required by the reviewed slice and listed in `docs/licensing.md`. Pin direct versions exactly and commit the pnpm lockfile. Use frozen installs in CI; never repair the lockfile during checks.
- Keep package-manager settings in `console/pnpm-workspace.yaml`. Disable install scripts. An unreviewed build hook or peer mismatch fails the task; do not add a broad exception.
- Follow the spec's directory ownership. `src/app` composes features; features may import `src/ui` and shared app contracts, but UI components never import features or stores. A feature owns its views and composables. Create an API directory only with a reviewed API contract.
- Use `<script setup lang="ts">`, Composition API and precompiled single-file components. Name components in PascalCase and composables `useThing`. Use explicit imports; no auto-import or global component plugin.
- Enable `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noFallthroughCasesInSwitch`, `noUnusedLocals`, `noUnusedParameters`, `useUnknownInCatchVariables`, `isolatedModules`, `verbatimModuleSyntax` and `noEmit`. Set `skipLibCheck: true` in application, tooling and test projects because the pinned third-party declarations import unused bundler types and contain incompatible parser types. Keep every other strictness flag. Use `module: ESNext`, `moduleResolution: Bundler`, target `ES2022`, and `vueCompilerOptions.strictTemplates: true`.
- `skipLibCheck` skips all declaration files, including project declarations. Forbid authored or generated project `.d.ts`, `.d.mts` and `.d.cts` files except `src/env.d.ts`, whose exact content is `/// <reference types="vite/client" />` followed by LF. Put project types in checked `.ts` modules. The toolchain checker enforces this boundary and compiler coverage before type checking, as specified in foundation section 2. Do not install unused bundler type packages as devDependencies, add ambient stub modules or patch dependencies to silence declaration errors; foundation section 8 gives the reasons.
- Separate application, tooling and test TypeScript projects. Application types include DOM and Vite client types only; tooling gets Node types; tests import runner APIs explicitly. Include every Ricevanta source, tool, configuration and test file, with `allowJs` and `checkJs` for JavaScript configuration and helpers. Check compile-negative fixtures separately with the same strictness flags. Run `vue-tsc` for Vue files and `tsc` for tooling. Vite transpilation is not type checking.
- Treat storage and future network data as `unknown` until validated. Avoid `any`, non-null assertions and unchecked casts. Narrow discriminated unions and preserve unexpected errors as causes for local debugging; show only reviewed localized messages to operators.

## Components and state

- Type props and emitted events. Props are read-only; children emit changes. Keep transient form and control state local with `ref` or `reactive`; derive values with `computed` before adding a watcher.
- Use Pinia setup stores for shared state with explicit actions. The foundation has only the preference store. Never add a fake session, permissions, resource cache or API response to make a shell look connected.
- Composables release listeners, timers and subscriptions on disposal. Inject storage and browser-language inputs into pure helpers so unit tests can cover denied storage and bad data without changing globals.
- Use native semantic elements for simple controls. Wrap a Reka primitive only when a reviewed component requires it. Accessible names, focus, keyboard behavior, reduced motion and 24-pixel minimum targets are component contracts.
- Use generated CSS custom properties and plain external CSS. Components select classes and `data-*` values, not raw colours. Keep theme and density effects in CSS. Do not edit generated token or copied brand files.

## Strings and browser security

- Every operator-facing string uses a typed translation key, including titles, accessible labels, errors and empty states. Add English and Vietnamese in the same change. Resource data is text, not a translation key.
- Follow the spec's nested JSON, named parameters and explicit zero/one/many rules. Do not concatenate sentences or dynamic keys. Use `n` and `d` for locale formatting and the validated wrapper for counts. Missing, extra or unused keys fail checks.
- Compile messages at build time and use runtime-only Vue and vue-i18n. No runtime templates, server-delivered catalogues or executable strings.
- The foundation bans HTML sinks, `v-html`, executable URL construction, policy creation, dynamic script loading and CSS injection as listed in the spec. No style binding or whole-object `v-bind` in this slice. An eventual exception needs its own reviewed contract and production browser tests.
- Trusted Types is not sanitization. Never import Vue's unsafe conversion helper or create a default policy. No dependency may require weaker CSP, `unsafe-inline`, `unsafe-eval`, wildcard policy names or disabled browser enforcement.
- Preferences are the only persistent browser data here. Do not store credentials, tokens, CSRF values or server authority in storage. Route visibility never authorizes an operation.

## Lint, format and tests

- Use an ESM flat `eslint.config.mjs`: `@eslint/js` recommended, `typescript-eslint` strict type-checked rules and `eslint-plugin-vue` flat recommended. Feed Vue scripts through the TypeScript parser under `vue-eslint-parser`. Run with zero warnings.
- Add tested local rules for the spec's sink, binding and translation restrictions. Parse Vue and TypeScript syntax; regex alone cannot distinguish strings, comments and executable expressions. Keep negative fixtures outside production source and scope exceptions to those fixtures.
- Require handled promises, exhaustive union switches, no explicit `any`, no non-null assertion and no suppression without a specific reason. Apply checked JavaScript or TypeScript to build helpers too.
- Format console TypeScript, Vue, CSS, JSON, YAML and JavaScript with Prettier: two spaces, single quotes, no semicolons, trailing commas, width 100 and LF. Use `.prettierignore` for generated output, dependencies, test reports and binary assets. Disable conflicting stylistic ESLint rules individually; no unpinned formatter plugins.
- Write the failing behavior test first. Pure helpers use Node Vitest; components use Vitest's Playwright provider with Vue Test Utils. CSP acceptance uses Playwright against the production `dist/` server, never Vite development output.
- Keep the spec's raw-string and native `TrustedScript` compilation probes in separate fixture pages and contexts. Match the first rejecting directive specified for each probe; no alternative directive counts as a pass. The `emptyScript` probe needs no policy or header exception. Keep every unsafe probe operation outside application code and production output.
- Follow [testing instructions](testing.md) for exact commands. Run the focused tests after a change, then the required full checks once. Dependency or header changes require all three browser engines and the negative controls.
