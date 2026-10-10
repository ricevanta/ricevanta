# Console foundation

The first Vue slice builds a static routing shell with brand tokens, English and Vietnamese strings, and a browser test of the production Content Security Policy (CSP). It exposes no administrative data or operations. This is a design for independent review, not evidence of a running console.

Authorities: [console design](../design/console.md) section 1, BE-08 to BE-10 and BE-13 in [decisions](../decisions.md), [brand specification](../../branding/BRAND_SPEC.md), and the v0.1.x row of [roadmap](../roadmap.md). [The plan](../plans/console-foundation.md) owns implementation order and CI configuration; [Vue instructions](../../instructions/vue.md) own working conventions.

## 1. Boundary and dependencies

Included: the `console/` project, reproducible production assets, source checks, token generation, preference state, precompiled messages, route chunks, unit and component harnesses, and built-output browser tests. Native HTML buttons, links and selects suffice; this slice needs no component library.

Excluded: API types and clients, login forms, fake authenticated users, session or permission stores, CSRF tokens, resource caches, SSE, extension frames, charts, tables, editors, Go embedding and a deployable server. There is no API proxy until an API exists. A shell route never implies authentication or authorization.

The next v0.1.x slices are:

1. Console identity: reviewed OpenAPI operations and backend OIDC, SP-initiated SAML and break-glass endpoints, sessions, CSRF defence, safe return paths and permission-aware routes. Implement the typed API client only with those contracts.
2. Console live data: reviewed `/api/v1/changes` contract and backend watermarks, then SSE, invalidation, polling and session revocation handling.
3. Console serving: Go embedding, exact response headers, compression negotiation, cache validators and deployment tests against the real server. Reuse this slice's header and fixtures.

These remain v0.1.x requirements. The foundation does not complete the roadmap shell row. Extension egress and document binding remain separate release gates; foundation tests do not qualify EXT-04.

## 2. Toolchain, dependencies and layout

Use installed Node 24.21.0 and pnpm 11.18.0. Pin `console/.node-version` to `24.21.0`, `engines.node` to `24.21.0`, `engines.pnpm` to `11.18.0`, and `packageManager` to `pnpm@11.18.0`. The package is private, ESM, named `@ricevanta/console`, with initial unreleased version `0.1.0` under SH-04. Go 1.27.1 and Rust 1.99.0 with cargo 1.99.0 are installed but unused by this slice.

Every direct dependency uses an exact version without a range. The committed pnpm lockfile pins all transitive packages and integrity values. These pins select a compatible baseline, not a claim that each package is the newest release. Registry install, peer resolution and the browser checks must verify the combined set before acceptance; source manifests alone cannot prove it.

| Runtime package | Pin | Source |
|---|---|---|
| `vue` | 3.5.43 | [published manifest](https://registry.npmjs.org/vue/3.5.43) |
| `vue-router` | 5.0.3 | [manifest](https://github.com/vuejs/router/blob/v5.0.3/packages/router/package.json) |
| `pinia` | 3.0.4 | [manifest](https://github.com/vuejs/pinia/blob/v3.0.4/packages/pinia/package.json) |
| `vue-i18n` | 11.4.12 | [manifest](https://github.com/intlify/vue-i18n/blob/v11.4.12/packages/vue-i18n/package.json) |
| `@fontsource/be-vietnam-pro` | 5.3.0 | [published versions](https://www.npmjs.com/package/%40fontsource/be-vietnam-pro?activeTab=versions) |

| Development package | Pin | Source |
|---|---|---|
| `vite` | 8.3.2 | [published manifest](https://cdn.jsdelivr.net/npm/vite/package.json) |
| `@vitejs/plugin-vue` | 6.0.9 | [manifest](https://github.com/vitejs/vite-plugin-vue/blob/plugin-vue%406.0.9/packages/plugin-vue/package.json) |
| `typescript` | 5.9.3 | [manifest](https://github.com/microsoft/TypeScript/blob/v5.9.3/package.json) |
| `vue-tsc` | 3.1.0 | [manifest](https://github.com/vuejs/language-tools/blob/v3.1.0/packages/tsc/package.json) |
| `@types/node` | 24.10.1 | [published manifest](https://app.unpkg.com/@types/node@24.10.1/files/package.json) |
| `@vue/compiler-sfc` | 3.5.43 | Same Vue release; build-time source checks |
| `@intlify/unplugin-vue-i18n` | 11.2.5 | [manifest](https://github.com/intlify/bundle-tools/blob/v11.2.5/packages/unplugin-vue-i18n/package.json) |
| `@intlify/message-compiler` | 11.4.12 | [manifest](https://github.com/intlify/vue-i18n/blob/v11.4.12/packages/message-compiler/package.json) |
| `eslint`, `@eslint/js` | 9.39.1 each | [manifest](https://github.com/eslint/eslint/blob/v9.39.1/package.json), [JS config](https://github.com/eslint/eslint/blob/v9.39.1/packages/js/package.json) |
| `eslint-plugin-vue` | 10.11.1 | [published metadata](https://registry.npmjs.org/eslint-plugin-vue), version `10.11.1` |
| `vue-eslint-parser` | 10.3.0 | [manifest](https://github.com/vuejs/vue-eslint-parser/blob/v10.3.0/package.json), [release](https://github.com/vuejs/vue-eslint-parser/releases/tag/v10.3.0) |
| `typescript-eslint` | 8.66.0 | [manifest](https://github.com/typescript-eslint/typescript-eslint/blob/v8.66.0/packages/typescript-eslint/package.json) |
| `prettier` | 3.6.2 | [manifest](https://github.com/prettier/prettier/blob/3.6.2/package.json) |
| `vitest`, `@vitest/browser-playwright` | 4.1.11 each | [runner](https://github.com/vitest-dev/vitest/blob/v4.1.11/packages/vitest/package.json), [provider](https://github.com/vitest-dev/vitest/blob/v4.1.11/packages/browser-playwright/package.json) |
| `@vue/test-utils` | 2.4.6 | [published versions](https://www.npmjs.com/package/%40vue/test-utils?activeTab=versions) |
| `@playwright/test`, `playwright`, `playwright-core` | 1.59.1 each | [manifest](https://github.com/microsoft/playwright/blob/v1.59.1/packages/playwright-test/package.json) |
| `@axe-core/playwright` | 4.11.0 | [manifest](https://github.com/dequelabs/axe-core-npm/blob/v4.11.0/packages/playwright/package.json) |

The published `eslint-plugin-vue` 10.11.1 metadata declares required peers `eslint: ^8.57.0 || ^9.0.0 || ^10.0.0` and `vue-eslint-parser: ^10.3.0`. Its optional peers are `@typescript-eslint/parser: ^7.0.0 || ^8.0.0` and `@stylistic/eslint-plugin: ^2.0.0 || ^3.0.0 || ^4.0.0 || ^5.0.0`. Pin the minimum compatible Vue parser, 10.3.0; its ESLint peer also accepts 9.39.1. Keep `eslint` and `@eslint/js` at 9.39.1 and do not add the optional stylistic plugin. Verify these published peer claims with strict installation. Every selected direct and transitive release must be at least 1,440 minutes old; verify registry publication metadata before locking, without age exemptions.

The plugin's `postcss-selector-parser: ^7.1.4` dependency permits the fixed 7.1.6 release. Resolve and lock 7.1.6, then verify that no affected selector-parser version remains anywhere in the lockfile. [GHSA-rj75-hqrm-r3gf](https://osv.dev/vulnerability/GHSA-rj75-hqrm-r3gf) describes quadratic selector parsing and names 7.1.6 as fixed. Do not grant that advisory an exception.

`console/pnpm-workspace.yaml` is a single-package configuration: `saveExact: true`, `engineStrict: true`, `strictPeerDependencies: true`, `autoInstallPeers: false`, `ignoreScripts: true`, `verifyDepsBeforeRun: error`, and `supportedArchitectures: { os: [linux, darwin, win32], cpu: [x64, arm64], libc: [glibc] }`. Keep those architecture lists exact for the v1.0.0 console build targets; `libc: [glibc]` selects the Linux C library where pnpm requires it. [pnpm documents supportedArchitectures](https://pnpm.io/settings/dependency-resolution#supportedarchitectures) for installing optional dependencies for other platforms. A locked package is eligible when its `os`, `cpu` and `libc` fields allow at least one supported combination. Every runner must install and license-audit every eligible package, including `lightningcss-darwin-arm64` and the win32 builds, before OSV runs, and OSV scans every locked package. Reject skipping evidence for eligible packages that a runner did not install, because that leaves shipped-path dependencies unaudited. Reject fetching licenses from the registry at audit time because that substitutes network metadata for evidence from the installed locked packages. Invoke the reviewed project scripts explicitly. No dependency lifecycle scripts are approved. A required native install hook blocks acceptance until separately reviewed; do not relax the setting to get a green build. Release-age filtering keeps the pnpm 11 default of 1,440 minutes; exact pins and the frozen lockfile already prevent silent upgrades. [pnpm documents script suppression](https://pnpm.io/settings/build) and [release-age filtering](https://pnpm.io/settings/dependency-resolution). Verify those settings against the installed pnpm, since the online reference includes newer versions. License evidence covers every locked package that pnpm installs for those architectures; a locked package whose `os`, `cpu` or `libc` fields exclude every supported combination (for example esbuild's aix, android and freebsd builds) is never installed for any target, so the audit lists it as excluded instead of requiring evidence, and fails if such a package is installed.

Check every resolved dependency against [console design](../design/console.md) section 6.3. BlueOak-1.0.0 and Python-2.0.1 are permitted only for development and build tooling. MPL-2.0 is permitted only for test tools and unmodified build-time tools whose code is never shipped in the console bundle. Record the pinned package LICENSE evidence in [licensing](../licensing.md). For pinned `argparse` 2.0.1 only, normalize declared `Python-2.0` metadata to `Python-2.0.1` using the recorded LICENSE evidence before dependency and build-output checks. Retain both identifiers in the resolved license inventory. Reject this normalization for other packages or versions and for missing or mismatched LICENSE evidence. The build-output check below enforces the shipping boundary using the normalized inventory.

### Dependency audit exceptions

`pnpm audit:deps` checks licenses and queries OSV for every resolved npm package/version in the frozen lockfile, including development dependencies. Commit `console/security/osv-exceptions.json` as the only OSV exception source. Require independent Sol xhigh review of each entry and any change to its input boundary or removal condition before acceptance. An exception does not waive license checks, release age, strict peers, network errors or incomplete OSV results.

The file is a JSON array. Each entry has exactly six required fields: `advisoryId`, `package`, `version`, `dependencyPath`, `untrustedInputRationale` and `removeWhen`. All fields except `dependencyPath` are nonempty strings. `version` is an exact npm version. `dependencyPath` is a nonempty ordered array of objects with exactly `package` and `version` strings, each version exact, from a direct dependency of the console importer through the affected package. Its last node must equal the entry's package/version. Reject malformed files, unknown or missing fields, duplicate advisory/package/version/path identities, ranges and wildcards. Use `[]` when no exceptions apply; a missing file fails.

Match each finding by exact OSV advisory ID, package, version and dependency path. Deduplicate package/version pairs only for OSV requests; preserve every path through the lockfile graph for exception matching. All paths to an affected package must have matching reviewed entries; one listed development path cannot exempt another path or runtime use. Validate every node and edge against the frozen lockfile. The braces path root must appear only in the console importer's `devDependencies`; reject roots in `dependencies` or `optionalDependencies`, even when every package/version node matches. Check dependency classes in both the manifest and lockfile and fail if they disagree. Fail on an unlisted advisory or path, a listed entry whose package/version or path no longer matches the lockfile, or an entry whose advisory is absent from the complete OSV result for that package/version. Never silently carry an exception across dependency changes.

Collect all findings before reporting failure. For each finding, print the advisory ID, package, exact version, dependency path and disposition (`excepted` or `unlisted`). For every stale or invalid entry, print its entry index, available identity fields and rejection reason. Sort diagnostics by advisory ID, package, version and path. The audit error must name each unlisted finding and stale entry, not just a count; report incomplete requests separately and fail even when all received findings are excepted.

The file contains this entry for the build dependency with no fixed release. Verify the complete path and the repository-only pattern boundary during implementation review:

```json
[
  {
    "advisoryId": "GHSA-vfj7-8cjw-p6xm",
    "package": "braces",
    "version": "3.0.3",
    "dependencyPath": [
      { "package": "@intlify/unplugin-vue-i18n", "version": "11.2.5" },
      { "package": "fast-glob", "version": "3.3.3" },
      { "package": "micromatch", "version": "4.0.8" },
      { "package": "braces", "version": "3.0.3" }
    ],
    "untrustedInputRationale": "Only repository-controlled build patterns for src/locales/en.json and src/locales/vi.json reach braces through the Intlify plugin. No request, endpoint data, uploaded catalogue, environment value or external configuration supplies patterns. This path runs only during the build and is absent from shipped assets. Changes to build patterns require review; untrusted pull-request code has no trusted build privileges.",
    "removeWhen": "Remove when a published fixed braces release at least 1,440 minutes old can be locked through a compatible upstream dependency, when this dependency path disappears or changes, or when OSV no longer reports the advisory. Remove and block acceptance before any untrusted pattern input or runtime use is introduced; a changed path needs fresh review."
  }
]
```

[GHSA-vfj7-8cjw-p6xm](https://osv.dev/vulnerability/GHSA-vfj7-8cjw-p6xm) describes stack exhaustion in deeply nested brace patterns and lists `last_affected: 3.0.3` with no fixed version. Development-only classification alone is insufficient: review the actual pattern inputs and verify that the path's code is absent from shipped assets. The exception accepts the bounded build exposure; it does not claim that `braces` is fixed.

Create directories only with real files:

| Path under `console/` | Ownership |
|---|---|
| `src/app/` | `main.ts`, `App.vue`, router, i18n setup, fatal error state |
| `src/stores/preferences.ts` | Locale, theme and density only |
| `src/features/home/`, `src/features/not-found/` | Lazy route views |
| `src/ui/` | Shell controls, `RicevantaLogo.vue`, plain CSS |
| `src/locales/` | `en.json`, `vi.json` |
| `src/generated/` | Ignored token CSS; recreated before checks |
| `scripts/` | Typed Node build helpers, source validators and static test server |
| `tests/unit/`, `tests/component/`, `tests/browser/`, `tests/fixtures/` | Pure tests, browser components, production tests, hostile inputs |
| `public/brand/` | Ignored copies of approved brand output, generated before build |

Do not create `src/api/` or empty feature folders. Use `@/` only for `src/`; tooling imports explicit relative paths. Keep Node types in a tooling TypeScript project, DOM types in the application project, and test globals out of application types.

Set `skipLibCheck: true` in all three TypeScript projects. Keep every other compiler and template strictness flag in [Vue instructions](../../instructions/vue.md). The pinned `unplugin` 2.3.11 declarations import `@farmfe/core`, `@rspack/core`, `rollup`, `unloader` and `webpack`, which this Vite console does not install; `webpack-virtual-modules` 0.6.2 also imports `webpack`. Those imports cause six TS2307 errors. Skipping declaration checking avoids these dependency-internal errors while Ricevanta source, tools and tests remain strictly checked. Imported types still participate in checking project uses; this setting does not validate the declarations themselves.

Because `skipLibCheck` applies to every declaration file, forbid authored or generated project `.d.ts`, `.d.mts` and `.d.cts` files anywhere under `console/`, except `src/env.d.ts`. That file contains exactly `/// <reference types="vite/client" />` followed by LF, with no project declarations or augmentations. Define project types in checked `.ts` modules. Before generation and compiler runs, `scripts/check-toolchain.ts` inventories project files, rejects other declaration files or changed env content, and verifies every Ricevanta source, tool, configuration and test file belongs to a compiler project or the separately compiled negative-fixture harness. JavaScript configuration and helpers use `allowJs: true` and `checkJs: true`. Dependency, build-output and report directories are not project inputs; no authored source may live there to bypass checks. Repeat the declaration check after generation to catch generated declarations. Compile-negative fixtures use the same strictness flags and must fail on the intended project diagnostic.

## 3. Build and output contract

`pnpm build` validates source inputs, generates assets, runs `vite build`, audits output and precompresses it. Pin Vite `base: '/'`, target `es2022`, `assetsInlineLimit: 0`, `cssCodeSplit: true`, `manifest: true`, `sourcemap: false`, and `modulePreload.polyfill: false`. Root hosting is the only deployment shape in this slice. Use runtime-only Vue and one deduplicated Vue runtime; disable Options API and production devtools flags. Precompile all single-file component templates.

Configure the Intlify plugin for exactly the two catalogue files, `runtimeOnly: true`, `compositionOnly: true`, `dropMessageCompiler: true` and `strictMessage: true`. Runtime messages are bundled precompiled AST resources, never JSON fetched from a server. Verify the emitted module graph excludes the Vue template compiler and Intlify message compiler. Intlify documents precompiled AST resources and the runtime-only build in its [optimization guide](https://vue-i18n.intlify.dev/guide/advanced/optimization); this is a vendor claim, verify the selected build with section 7.

`dist/index.html` references external, content-hashed module scripts and styles under `/assets/`. It contains no inline script, event handler, style element, style attribute or `javascript:` URL. No CDN, remote import, `data:` asset, source map, service worker, worker, iframe or dynamic executable URL is emitted. The generated manifest records lazy routes; the output audit follows imports recursively rather than looking at the entry size alone. Cross-check the emitted module graph and copied-asset provenance against the resolved license inventory; fail if any MPL-2.0, BlueOak-1.0.0 or Python-2.0.1 licensed file or code appears in shipped assets. A text search alone cannot prove exclusion.

Use Node's built-in Brotli quality 11 and gzip level 9 for `.html`, `.js`, `.css`, `.svg`, `.json` and `.webmanifest`. Write `.br` and `.gz` siblings deterministically, with no wall-clock metadata. Keep originals. Do not recompress WOFF2 or PNG. Two clean builds with identical inputs must produce the same sorted relative-path/SHA-256 manifest. Budget: at most 250,000 Brotli bytes for the entry and its static JavaScript dependency closure and at most 150,000 per lazy route closure excluding that entry closure. The release-to-release regression comparison awaits a release baseline.

The server-harness MIME map is closed: HTML `text/html`, JS `text/javascript`, CSS `text/css`, JSON and Vite manifest `application/json`, webmanifest `application/manifest+json`, SVG `image/svg+xml`, PNG `image/png`, ICO `image/x-icon`, WOFF2 `font/woff2`, plain text `text/plain`; text types add UTF-8. `index.html` uses `no-cache`; an `/assets/` file uses `public, max-age=31536000, immutable` only when valid Vite manifest metadata (`.vite/manifest.json`) declares it as a build output; every other `/assets/` file, including the fixed-name font notice and any file served while that metadata is missing or malformed, uses `no-cache`; `/brand/` uses `public, max-age=86400`. The harness tests originals and negotiated compressed variants. This is a future Go-serving contract, not a shipping Node server.

## 4. Production header and trust boundary

The foundation profile specializes console design section 6.1 by denying frames and workers and removing unused `data:` images. Only a reviewed consumer can widen those directives. Keep the complete value as one LF-terminated line in `console/security/csp.txt`; strip the final LF for the response header:

```text
default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'none'; manifest-src 'self'; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types vue
```

Send `Content-Security-Policy`, never only Report-Only or a meta tag. The harness also sends `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()`. Real HTTPS serving adds `Strict-Transport-Security: max-age=31536000`; loopback HTTP tests do not claim transport security.

[CSP Level 3](https://w3c.github.io/webappsec-csp/) defines source restrictions and violation events; [Trusted Types](https://w3c.github.io/trusted-types/dist/spec/) defines string rejection at guarded sinks. MDN claims enforcement of [`require-trusted-types-for`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for) and policy-name restrictions through [`trusted-types`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/trusted-types). These are browser claims: verify enforcement in each pinned engine, not merely the existence of `window.trustedTypes`.

Vue 3.5.43 [creates a `vue` policy whose `createHTML` returns its input](https://github.com/vuejs/core/blob/v3.5.43/packages/runtime-dom/src/nodeOps.ts). This is a source claim, verify compiled static content under the header. The policy is a type conversion, not a sanitizer. Trusted Types therefore cannot make `v-html` safe. No application code creates a policy or imports Vue internals. Never allow a default policy, wildcard names or `allow-duplicates`.

The full path is reviewed source templates and catalogues, build-time validation, compiled assets, same-origin response headers, runtime text rendering, then browser refusal and test observation at forbidden sinks. Lint and source checks reject `v-html`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `DOMParser` HTML parsing, `Range.createContextualFragment`, `eval`, `Function`, string timers, dynamic script creation, CSSOM rule injection and style bindings in this slice. Fixed classes and `data-theme`/`data-density` select external CSS. Ban whole-object `v-bind`, dynamic directive arguments and runtime template compilation so a spread cannot hide a sink. These source checks reduce mistakes; they do not equal browser enforcement.

| Attacker | What the attacker gets in this slice |
|---|---|
| Stolen enrollment token | No consumer or enrollment endpoint; the token confers no shell capability. Enrollment authentication remains a backend duty. |
| Compromised agent host | No agent data enters this shell; later clients must treat all returned fields as untrusted text. |
| Compromised console session | No session exists here. In a later session, arbitrary same-origin script can act as that operator; CSP is not authorization or a cure for stolen credentials. |
| Rogue extension publisher | No extension loader, bridge or frame; `frame-src 'none'` supplies no grant and does not qualify extension isolation. |
| Network position between agent and server | No such connection is made. These tests prove neither mTLS nor resistance to changing an HTTP response. |
| Database writer without signing keys | The shell reads no database data. CSP does not authenticate records or replace signed authority. |
| Server restored from backup | The static shell grants no authority and holds no security state; backend sealed recovery and epoch checks remain required. |
| Attacker controlling a same-origin asset or build dependency | Can supply executable code allowed by `script-src 'self'`; CSP cannot distinguish that code. Locked inputs, review and deployment integrity remain necessary. |

No report endpoint is invented. Tests observe `securitypolicyviolation` events, which [MDN documents](https://developer.mozilla.org/en-US/docs/Web/API/SecurityPolicyViolationEvent); verify delivery with the negative controls. A future report collector needs its own privacy and bounds contract.

## 5. Brand tokens and assets

`generate-tokens.ts` reads only the mandatory palette table in brand specification section 3 and the semantic colour table in console design section 8. Parse named sections and column headers, not every hexadecimal string in either file. Require exactly the three brand names, unique rows, the named semantic roles, and six-digit hex values, with the sole literal exception `white text` in the light action cell, mapped to `#FFFFFF`. Fail on absent, duplicate, malformed or extra rows; documentation changes must trigger CI.

Generate `src/generated/tokens.css` with the three original `--rv-*` names and `--rv-color-page`, `surface`, `text`, `text-secondary`, `action`, `on-action`, `border`, `focus`, and `severity-{critical,high,medium,low,informational}`. Map roles in table order, with the two action values and five severity values parsed separately; ignore the contrast column. Reference brand properties when a semantic value equals a palette colour. Emit `:root`, explicit light and dark selectors, and a dark media query scoped to `data-theme="system"`. Explicit themes must override system preference.

Non-colour tokens are a closed mapping in the generator: spacing 4, 8, 12, 16, 24, 32 CSS pixels; control heights 36 comfortable and 28 compact; row heights 40 and 32; focus outline 2 pixels with 2-pixel offset; radius 4 and 8 pixels. Name spacing `--rv-space-1` through `--rv-space-6`, and name the others `--rv-control-height`, `--rv-row-height`, `--rv-focus-width`, `--rv-focus-offset`, `--rv-radius-small`, `--rv-radius-medium`. Root density defaults to comfortable. No table exists here to apply the wide-screen compact default.

`prepare-assets.ts` copies only `horizontal-color.svg`, `horizontal-dark.svg` and the files under `branding/dist/web/` into generated `/brand/`. `RicevantaLogo` uses external `<img>` sources and localized accessible text; no raw SVG import. Verify copied bytes match inputs. Do not regenerate branding or edit its masters.

Import Be Vietnam Pro's normal 400, 500, 600 and 700 Latin, Latin Extended and Vietnamese CSS subsets from the pinned font package. Vite emits fonts locally under `/assets/`; emit the package OFL copyright and license beside those fonts and check its presence. The font package is a build input, not a browser CDN dependency. Use `font-display: swap` and system sans fallback, with system monospace for technical text. Verify the pinned package's file names and license before importing; [Fontsource documents the font and license](https://fontsource.org/fonts/be-vietnam-pro/about).

Token vectors: brand names resolve respectively to `#173B54`, `#DDB85C`, `#F6F2E7`; duplicate `--rv-indigo` rejects; `#173B5` rejects; swapped semantic rows do not change output because role names drive mapping. Generated output sorts properties by name, uses uppercase hex, two-space indentation and LF, with one final LF and no timestamp. Compute WCAG contrast from generated values; require text and secondary text on page/surface and action text at least 4.5:1, borders and focus on adjacent page/surface at least 3:1. Use [WCAG 2.2](https://www.w3.org/TR/WCAG22/) as the standard, not rounded ratios copied from prose.

## 6. Catalogues, preferences and routes

Catalogues are UTF-8 JSON objects with nested object namespaces and string leaves. English is the key authority. Keys have two to four dot-separated segments, each `[a-z][a-zA-Z0-9]*`; namespaces start with `app`, `nav`, `preferences`, `home`, `notFound` or `errors` for this slice. Reject arrays, null, empty objects, empty messages, dotted property names, duplicate JSON properties and `__proto__`, `constructor`, `prototype` at any depth. Cap each catalogue at 64 KiB UTF-8, nesting at four and each leaf at 2,048 Unicode code points.

Use named interpolation only. Forbid markup, linked messages, list interpolation, locale-local keys and custom message functions. Literal text that needs Intlify escaping uses its documented literal syntax. Validate syntax with the pinned compiler in Node, never in the browser. Compare placeholder sets between locales and between plural branches. Parse JSON with TypeScript's JSON AST to detect duplicate keys before conversion; `JSON.parse` alone silently loses duplicates.

Every count key ends with `Count` and has exactly three nonempty pipe-separated forms, zero, one and many, in both locales. Every branch includes `{count}`. Other messages have exactly one form. `pluralRules.en` and `.vi` use the same project rule: zero selects 0, one selects 1, every other nonnegative safe integer selects 2. This deliberately follows the console's explicit-count contract instead of browser CLDR data; it is not a claim about Vietnamese grammar. [Intlify documents pipe forms and custom plural rules](https://vue-i18n.intlify.dev/guide/essentials/pluralization).

Define these TypeScript contracts, not Go APIs or artificial `errors.Is` wrappers:

```ts
type Locale = 'en' | 'vi'
type Theme = 'light' | 'dark' | 'system'
type Density = 'comfortable' | 'compact'
function selectLocale(saved: unknown, languages: readonly string[]): Locale
function pluralIndex(count: number): 0 | 1 | 2
function readPreferences(raw: string | null): Readonly<Preferences>
interface Preferences { locale?: Locale; theme: Theme; density: Density }
```

`pluralIndex` throws `RangeError` for negative, fractional, nonfinite or unsafe counts; return positive zero for `-0` (assert `Object.is(result, 0)`). Application count translation uses `translateCount(key: CountKey, count: number): string`, which validates first and passes the explicit count into `t`. Count messages in this slice accept no named parameter except `count`. Generate or infer `MessageKey` and `CountKey` unions from English keys; forbid unrestricted dynamic key concatenation. Route title keys and preference option keys live in finite typed lists.

`selectLocale` takes a saved exact `en` or `vi`, else scans at most 16 language tags of at most 64 characters each, accepting case-insensitive `en`, `vi` or those prefixes followed by a hyphen, else returns `en`. Do not read query strings or paths for locale. `readPreferences` reads only `rv.preferences.v1`, capped at 1,024 characters: malformed JSON, arrays, null, unknown fields or invalid fields cause a complete default `{theme:'system', density:'comfortable'}`. A valid omitted locale permits browser selection. Storage reads and writes can throw; keep the application usable with in-memory preferences. Never persist arbitrary route, markup, token or session data.

`createI18n` uses Composition API mode, English fallback and both precompiled catalogues. Missing keys fail tests; fallback is not permission to omit translations. Locale changes update `<html lang>`, document title and all labels without reload. Numbers and dates use `n` and `d`; do not assert punctuation that can vary with the engine's locale data. The shell needs no date fixture.

| Path and name | View and behavior |
|---|---|
| `/`, `home` | Lazy `HomeView.vue`, title `home.title`; show the product name and a localized statement that backend services are not connected, with no fleet counters or sign-in claims |
| `/:pathMatch(.*)*`, `not-found` | Lazy `NotFoundView.vue`, title `notFound.title`; generic message and a named-route Home link; never echo the path or query |

Create history mode with root base and literal route imports. Vue Router's [history guide](https://router.vuejs.org/guide/essentials/history-mode.html) requires server fallback, and its [lazy loading guide](https://router.vuejs.org/guide/advanced/lazy-loading.html) describes dynamic imports; these are vendor claims, verify direct navigation and chunk requests. The shell has a skip link, header, named primary navigation, main landmark, one `h1`, language/theme/density selectors, and a visible focus ring. Move focus to the view heading after successful navigation and preserve the browser back/forward behavior. Refreshing an unknown path loads the localized not-found view.

Unhandled component errors, rejected startup and chunk failures render localized generic errors with an explicit Reload button. Never render exception text, requested URLs or resource data. Do not invent request IDs. Automatic chunk-reload recovery needs version/session integration and belongs to console serving; the foundation never loops reloads.

## 7. Required tests and error precedence

The pure tooling API is `validateCatalogues(en: Uint8Array, vi: Uint8Array, usedKeys: readonly string[]): readonly Diagnostic[]`. `Diagnostic` has `code: 'input' | 'shape' | 'keys' | 'syntax' | 'plural' | 'parameters' | 'usage'`, `file: string` and optional `key: string`. Fixed catalogue file labels are `src/locales/en.json` and `src/locales/vi.json`. Build validators return those issues sorted by file then key. Do not include message text in diagnostics. Apply those phases in that order and report only the first failing phase; within that phase report sorted issues. A duplicate property plus malformed plural is `shape`; missing Vietnamese key plus bad English syntax is `keys`; invalid syntax plus wrong branch count is `syntax`; a branch-count defect plus placeholder mismatch is `plural`. Input size/read/UTF-8 failure precedes JSON shape. CLI checks exit 1 on validation failure, 0 on success, with no generated output written after failure.

| Test group | Required cases |
|---|---|
| Type boundary | All strictness flags retained with `skipLibCheck: true`; application, tool, JavaScript configuration and test errors still reject; unchecked indexed access and invalid template props reject; missing compiler coverage rejects; extra project declaration files and additions to the exact env reference reject, including generated declarations |
| Tokens | All mappings, theme precedence, repeat generation, malformed and duplicate rows, renamed heading, missing source, contrast, exact brand copies |
| Catalogues | Equal leaf sets and placeholder sets; syntax compile of every leaf; missing/extra/unused key; duplicate property; prototype keys; malformed UTF-8; size/depth boundaries; prohibited markup; all phase-precedence pairs above |
| Plurals | `0 -> 0`, `-0 -> 0`, `1 -> 1`, `2 -> 2`, `9007199254740991 -> 2`; `-1`, `0.5`, `NaN`, infinities, `9007199254740992` throw `RangeError`; render counts 0, 1, 2, 10 in both locales |
| Locale | Saved `vi` overrides `en-US`; invalid saved `fr` with `['fr','VI-vn']` yields `vi`; `['en-GB','vi']` yields `en`; empty/unsupported list yields `en`; invalid saved object never reaches a translation key |
| Preferences | Valid partial record, oversized text, invalid fields, unknown fields, blocked storage and storage write failure; all errors use complete defaults |
| Routes and components | Both routes, refresh, back/forward, heading focus, skip link, all selectors, locale/title changes, fatal and failed-chunk state, 320px and 1440px widths with no horizontal shell overflow |
| Source rules | Fixtures for every banned sink, style binding, raw template text/label, key concatenation and whole-object binding; positive fixtures for interpolation, class binding and typed finite key lists |
| OSV exceptions | Exact braces entry accepts only its complete development path; promoting its root to `dependencies` or `optionalDependencies` rejects even with identical nodes; manifest/lockfile class mismatch rejects; unlisted advisory or path rejects; changed or removed package/version/edge rejects; absent advisory rejects stale entry; malformed, missing, duplicate or wildcard entries reject; multiple findings each appear in diagnostics; pagination and service failure cannot hide findings; selector-parser resolves to 7.1.6 without an exception |
| License normalization | Accept pinned `argparse` 2.0.1 as tooling with declared `Python-2.0`, matching LICENSE evidence and normalized `Python-2.0.1`; reject runtime use, other packages or versions claiming this mapping, and missing or mismatched evidence; reject bundled modules and copied files from the normalized package |
| Output | All assets same-origin, no inline content/maps/compiler modules/test assets or files/code under MPL-2.0, BlueOak-1.0.0 or Python-2.0.1, route chunks lazy, byte budgets, deterministic compression, font licenses |

Use a synthetic `home.itemCount` in test fixture catalogues, not an unused product string: English `{count} items | {count} item | {count} items`; Vietnamese `{count} mục | {count} mục | {count} mục`. For counts 0, 1, 2, 10 the exact outputs are `0 items`, `1 item`, `2 items`, `10 items`, and `0 mục`, `1 mục`, `2 mục`, `10 mục`.

Source usage checking covers template text, text-bearing attributes (`title`, `alt`, `placeholder`, `aria-label`), and translated text in script code. Permit only the literal brand name, locale self-names and technical test identifiers in a short exact allow list. Collect keys from literal `t`/`translateCount` calls and the finite typed lists; tests do not count as product usage. Reject unused keys and suppressions without reviewed reasons.

Use seeded property tests with the existing Node/Vitest tools, not another fuzz dependency: 10,000 mutated catalogue trees, preference strings and locale tags, fixed seed `0x52495641`. Require termination, bounded diagnostics, no unexpected throw and identical results for identical inputs; save minimized failures as fixtures. Keep invalid count tests separate because their exception is intentional.

### Production browser gate

Playwright uses fresh contexts, no CSP bypass and no reused server. The static Node server binds `127.0.0.1:4173`, serves only `dist/`, enforces section 4 on every HTML response and validates Host. Its test-only probe mount is enabled explicitly and never copied into `dist/`. Refuse traversal, encoded separators, NUL and symlinks outside the served tree. Only GET/HEAD are allowed; unsupported methods return 405. An unknown HTML navigation receives `index.html`; reserved prefixes from console design section 10 and `/__test__/` never fall back. Test those refusals directly.

Run Chromium, Firefox and WebKit from the pinned Playwright installation. Record `browser.version()` and the package's browser revisions. Vendor documentation says Playwright pins its [browser binaries](https://playwright.dev/docs/browsers); verify actual revisions in CI. Playwright WebKit is not a claim of Safari or all supported OS qualification.

Before navigation, attach a passive `securitypolicyviolation` listener with `addInitScript` and forward events into the Node test process, preserving events across reloads. Do not use instrumentation to create policies, change sinks or bypass CSP. Compare the response header byte-for-byte with `security/csp.txt` and a separately written expected literal in the test. Assert no Report-Only substitution. All normal scenarios fail on any violation event, page error, console error, failed asset or unexpected external request. Failure-state scenarios use separate contexts and allow only the specifically injected chunk failure or component exception; CSP violations are never allowed there.

Exercise both routes, both locales, both densities, explicit themes and system theme changes, direct reloads, fonts, static template insertion and locale switching after lazy navigation. Assert there are no style elements/attributes or inline scripts after each interaction. Include an axe scan and keyboard checks; if axe injection conflicts with CSP, run axe in the separate component harness and retain the unmodified production gate. Never weaken CSP for axe.

Use separate negative-control pages under `/__test__/`, with the same exact header. Serve test probe code as an external same-origin script, rather than treating Playwright evaluation's privileged execution as a CSP test. Each probe has its own fresh context for a policy-free control page proving the operation can succeed and another for a protected page proving refusal. Controls must emit no violations. Except for the duplicate-policy probe, these pages load no Vue or application code and create no policy outside the operation being tested.

Expected directives follow algorithm order. [CSP Level 3 §4.4.1, EnsureCSPDoesNotBlockStringCompilation](https://w3c.github.io/webappsec-csp/#can-compile-strings), step 2.4 calls [Trusted Types §3.5, Get Trusted Type compliant string](https://w3c.github.io/trusted-types/dist/spec/#get-trusted-type-compliant-string-algorithm). With no default policy, its steps 4 to 6 and [§3.7, Process value with a default policy](https://w3c.github.io/trusted-types/dist/spec/#process-value-with-a-default-policy-algorithm) reach [§4.2.4, Should sink type mismatch violation be blocked by Content Security Policy?](https://w3c.github.io/trusted-types/dist/spec/#should-block-sink-type-mismatch).

Raw strings report `require-trusted-types-for` before CSP can reach `script-src`; CSP step 2.4.2 converts that rejection to `EvalError`.

The CSP algorithm preserves trust when the body and every parameter argument are `TrustedScript` objects. A native `trustedTypes.emptyScript` body with no parameters therefore skips the string conversion check in step 2.4, reaches the eval permission check in step 5.3 and reports `script-src`, then throws `EvalError` at step 6. The header permits neither `unsafe-eval` nor `trusted-types-eval`.

Chromium's Function constructor has an implementation limitation: the [W3C Trusted Types project's constructor explanation](https://github.com/w3c/trusted-types/wiki/Trusted-Types-for-function-constructor) documents rejection even when every argument is a `TrustedScript`. Chromium's [code-generation callback](https://chromium.googlesource.com/chromium/src.git/+/18f2e4c962e3e6fd894abdb712957ef9749ae23e/third_party/blink/renderer/bindings/core/v8/v8_initializer.cc#573) checks Trusted Types first and returns on rejection before its CSP eval check. The native body therefore does not establish that this engine reaches `script-src`.

Use this exact expectation table for the Playwright 1.59.1 engines; the Chromium row matches 147.0.7727.15, revision 1217. Firefox and WebKit reach the CSP algorithm's eval check. These are enforcement expectations for the pinned engines, not a claim of identical constructor handling.

| Function argument | Chromium | Firefox | WebKit |
|---|---|---|---|
| Raw string `'return 1'` | `require-trusted-types-for` | `require-trusted-types-for` | `require-trusted-types-for` |
| Native `trustedTypes.emptyScript` | `require-trusted-types-for` | `script-src` | `script-src` |

Select the expected directive from the configured engine before running the probe. Never infer it from captured events or accept either directive interchangeably. A browser pin change requires reviewed expectations and passing evidence; it cannot silently widen the table.

Define each pair as follows:

- Parser-inserted inline script sets a sentinel only in the control; protected execution is blocked and reports `script-src-elem`.
- A parser-inserted inline style element changes a sentinel's computed colour only in the control; protected application is blocked and reports `style-src-elem`. Both inline probes arrive in response HTML, without a script-text or HTML sink assignment. Their effective directives follow [CSP §6.8.2, Get the effective directive for inline checks](https://w3c.github.io/webappsec-csp/#effective-directive-for-inline-check).
- External probe code calls `Function('return 1')` with no parameter arguments: the control constructs and invokes the function, returning `1`; protected construction throws `EvalError` and reports `require-trusted-types-for`, with no function returned. A `script-src` event cannot satisfy this probe.
- In a separate page pair, external probe code passes the native [`trustedTypes.emptyScript` object (Trusted Types §2.3.2)](https://w3c.github.io/trusted-types/dist/spec/#dom-trustedtypepolicyfactory-emptyscript) directly to `Function` as its sole argument. Assert `trustedTypes.isScript(trustedTypes.emptyScript)`; never stringify the object or supply raw parameter strings. The control returns a callable function whose invocation returns `undefined`; protected construction throws `EvalError` and reports exactly the engine's directive from the table, with no function returned. This probe creates no policy and uses the unchanged header. Chromium's result proves Trusted Types refusal at this constructor, not independent coverage of the CSP eval check; Firefox and WebKit must report `script-src`.
- External probe code assigns a raw string to a detached element's `innerHTML`: control succeeds, protected assignment throws `TypeError`, leaves content unchanged and reports `require-trusted-types-for`.
- Creation of policy `rv-forbidden` succeeds only in the control; protected creation throws `TypeError` and reports `trusted-types`. In a separate pair, load Vue first so its `vue` policy exists, then attempt a duplicate `vue` policy: control creation succeeds, protected creation throws `TypeError` and reports `trusted-types`. Both reach [Trusted Types §4.2.5, Should Trusted Type policy creation be blocked by Content Security Policy?](https://w3c.github.io/trusted-types/dist/spec/#should-block-create-policy), before any sink operation.

Use a bounded 5-second event wait. Require the matching directive and blocked outcome for each negative control; tolerate multiple matching events but reject unrelated violations. Expected negative events never enter the normal-run allowance. An absent Trusted Types API, a missing event or a successful protected operation fails the required gate on any engine; no skip or polyfill can turn that into acceptance. Probe results resolve the browser claims marked verify in section 4. Browser matrix gaps remain release blockers for the affected guarantee.

Every protected probe asserts the exact response header against both `security/csp.txt` and the independent literal. Separate header-integrity assertions from behavior assertions so a changed header cannot prevent behavior checks from running. Keep the normal-header expectations selected by the table and rule above fixed during mutations; never replace them with observed directives or a mutated header literal.

Executable mutations must reach probe completion within the bounded wait. Assert completion outside any expected-failure wrapper, then check the observed operation and require the named behavior assertion to reject independently of header rejection:

- Remove `require-trusted-types-for` for raw-string Function on every engine and for the native-body Function on Chromium. Construction remains blocked by `script-src` with `EvalError` and no function returned; the fixed `require-trusted-types-for` event assertion must reject. Firefox and WebKit's native-body table entries expect `script-src`, so removing `require-trusted-types-for` cannot provide that negative event evidence there.
- Remove `require-trusted-types-for` for `innerHTML`. Assignment succeeds and changes the element's content; the refusal assertions for the blocked outcome, `TypeError` and unchanged content must reject.
- Remove `trusted-types` for both policy-creation probes. Creation succeeds; the refusal assertions for the blocked outcome and `TypeError` must reject.
- Discard captured events for every probe under the normal header. Header integrity, completion and refusal assertions must pass; the required-event assertion must reject. Neither an incomplete probe nor another failure can satisfy this mutation.

Directive-removal fixtures also assert that exactly the named directive is absent and that the fixed header-integrity check rejects. Missing-header mutations are header-integrity checks for every probe. Neither kind of header rejection counts as behavior evidence.

Source-directive deletions are header-integrity checks only: remove `script-src` for the inline script and Firefox/WebKit native-body probes, and `style-src` for inline style. The inline events use effective names `script-src-elem` and `style-src-elem`; `default-src 'none'` preserves the inline blocks and events when their source directive is absent. Removing `script-src` also blocks external `probe.js`, so probe completion is not required for this header-integrity check and the native-body operation is untested. Removing `style-src` leaves the inline-style block and event unchanged; only header integrity distinguishes that mutation.

Mutation fixtures never change the production header or count as successful protected evidence. A generic expected-failure wrapper around combined header and behavior acceptance is insufficient for executable mutations.

## 8. Benefits, trade-offs, alternatives and unresolved questions

Benefits: backend-independent work establishes reproducible assets, translated navigation and a testable security boundary before authentication code relies on it. Generated tokens connect the brand to both themes without a second colour authority.

Trade-offs: parsing narrow Markdown tables couples the build to documented headings; a format change fails visibly. Exact pins and three engines require maintenance. The source checks are conservative and restrict otherwise valid Vue patterns. Allowing same-origin scripts avoids nonce generation in a static shell but trusts every executable asset on that origin.

Alternatives rejected: Nuxt/SSR adds a runtime the Go deployment does not need; hash routing conflicts with the settled history-mode design; JSON runtime catalogues retain parsing/compiler paths; browser plural categories make count selection engine-dependent; hand-copied palette constants drift; a permissive dev-server test proves no production CSP guarantee; a default Trusted Types policy masks unsafe sinks. Full UI libraries wait for their first real component rather than entering this slice unused.

For declaration checking, installing unused bundler type packages as devDependencies adds dependency and license obligations without a console consumer and does not establish dependency declaration compatibility. Ambient stub modules replace missing contracts with invented or unchecked types. Patching dependencies creates a private declaration maintenance burden. Reject all three; use `skipLibCheck: true` with the project declaration ban and compiler coverage checks in section 2. The trade-off is that dependency declaration defects are not checked; strict project checks and runtime tests remain required.

For dependency findings, reject disabling the audit because it hides unrelated vulnerabilities. Reject overriding `braces` to a nonexistent fixed version because no such release can be installed or verified. Reject forking `braces` because a private parser fork adds security and release maintenance for a build path with repository-controlled inputs. Keep the narrow reviewed exception and its removal condition instead.

Unresolved questions, with the working choice fixed above:

- Does the exact pinned dependency set install with scripts disabled and strict peers? Use these pins; reject unreviewed install-hook exceptions or silent upgrades. Verify with plan Task 1.
- Do all three pinned engines enforce the header and emit the required negative-control events? Require passing probes; reject feature-detection-only acceptance. Verify with plan Task 5.
- Do the font package's exact subset files and notices match the asset contract? Use the pinned self-hosted package; reject runtime CDN fetches. Verify with plan Task 2.
- Which supported browser/OS release combinations pass beyond the pinned CI engines? Keep the console design's full release matrix; reject treating these three binaries as release qualification.
