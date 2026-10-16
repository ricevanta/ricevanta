import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { validateToolchain } from '../../scripts/check-toolchain.ts'
import { Linter } from 'eslint'
import vueParser from 'vue-eslint-parser'
import tsParser from 'typescript-eslint'
import rules from '../../scripts/eslint-rules/index.mjs'
import { compileTemplate } from '@vue/compiler-sfc'

const manifest: unknown = JSON.parse(readFileSync('package.json', 'utf8'))
describe('toolchain validation', () => {
  it('accepts the reviewed manifest and installed tool versions', () => {
    expect(validateToolchain(manifest, '24.21.0', '11.18.0', true)).toEqual([])
  })
  it.each([
    ['23.0.0', '11.18.0', true, 'node'],
    ['24.21.0', '11.17.0', true, 'pnpm'],
    ['24.21.0', '11.18.0', false, 'lockfile'],
  ])('rejects invalid inputs %s %s %s', (node, pnpm, lock, issue) => {
    expect(validateToolchain(manifest, node, pnpm, lock)).toContain(issue)
  })
  it('rejects dependency ranges', () => {
    expect(
      validateToolchain({ dependencies: { vue: '^3.5.43' } }, '24.21.0', '11.18.0', true),
    ).toContain('pins')
  })
})
const linter = new Linter()
function check(source: string, filename = 'Fixture.vue') {
  return linter.verify(
    source,
    [
      {
        files: ['**/*.vue', '**/*.ts'],
        languageOptions: {
          parser: vueParser,
          parserOptions: { parser: tsParser.parser, ecmaVersion: 'latest', sourceType: 'module' },
        },
        plugins: { rv: rules },
        rules: { 'rv/foundation': 'error' },
      },
    ],
    { filename },
  )
}
describe('foundation source restrictions', () => {
  const templates = [
    '<div v-html="value" />',
    '<div :style="value" />',
    '<div :innerHTML="value" />',
    '<div :outerHTML="value" />',
    '<div v-bind:innerHTML="value" />',
    '<div v-bind:outerHTML="value" />',
    '<div :innerHTML.prop="value" />',
    '<div :outerHTML.prop="value" />',
    '<div :innerHTML.attr="value" />',
    '<div :outerHTML.attr="value" />',
    '<div .innerHTML="value" />',
    '<div .outerHTML="value" />',
    '<div :inner-html="value" />',
    '<div :outer-html="value" />',

    '<div v-bind="value" />',
    '<div :[name]="value" />',
    '<div>Hello</div>',
    '<input aria-label="Hello" />',
    '<div>{{ t("home." + value) }}</div>',
  ]
  it.each(templates)('rejects hidden bindings and untranslated text: %s', (template) => {
    expect(check(`<template>${template}</template>`).length).toBeGreaterThan(0)
  })
  const scripts = [
    'node.innerHTML = value',
    'node["outerHTML"] = value',
    'node.insertAdjacentHTML("beforeend", value)',
    'document.write(value)',
    'new DOMParser().parseFromString(value, "text/html")',
    'range.createContextualFragment(value)',
    'eval(value)',
    'new Function(value)',
    'Function(value)',
    'setTimeout("code", 1)',
    'setInterval("code", 1)',
    'document.createElement("script")',
    'sheet.insertRule(value)',
    'sheet.replaceSync(value)',
    'sheet.replace(value)',
    'compile(value)',
    'trustedTypes.createPolicy("vue", {})',
    't("home." + value)',
  ]
  it.each(scripts)('rejects unsafe executable syntax: %s', (script) => {
    expect(check(`<script setup lang="ts">${script}</script>`).length).toBeGreaterThan(0)
  })
  it.each([
    '<template><div :class="classes">{{ t("home.title") }}</div></template>',
    '<script setup lang="ts">const example = "node.innerHTML" // eval(value)\n</script><template><div>{{ t("home.title") }}</div></template>',
  ])('accepts text interpolation and inert strings', (source) => {
    expect(check(source)).toEqual([])
  })
})

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import * as toolchain from '../../scripts/check-toolchain.ts'
it('checks declaration boundaries and compiler coverage', () => {
  expect(toolchain).toHaveProperty('checkProject')
  if (!('checkProject' in toolchain)) return
  const root = mkdtempSync(join(tmpdir(), 'rv-toolchain-'))
  try {
    mkdirSync(join(root, 'src'), { recursive: true })
    writeFileSync(join(root, 'src/env.d.ts'), '/// <reference types="vite/client" />\n')
    for (const project of ['app', 'tools', 'test']) {
      writeFileSync(
        join(root, `tsconfig.${project}.json`),
        JSON.stringify({
          compilerOptions: { allowJs: true, checkJs: true },
          include: ['src/**/*'],
        }),
      )
    }
    expect(toolchain.checkProject(root)).toEqual([])
    writeFileSync(join(root, 'src/extra.d.mts'), 'export {}')
    expect(toolchain.checkProject(root)).toContain('declaration:src/extra.d.mts')
    rmSync(join(root, 'src/extra.d.mts'))
    writeFileSync(
      join(root, 'src/env.d.ts'),
      '/// <reference types="vite/client" />\ninterface Hidden {}\n',
    )
    expect(toolchain.checkProject(root)).toContain('declaration:src/env.d.ts')
    writeFileSync(join(root, 'omitted.ts'), 'export {}')
    expect(toolchain.checkProject(root)).toContain('coverage:omitted.ts')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
it.each(['app', 'tools', 'test'])('retains strictness with skipLibCheck in %s', (project) => {
  const config = JSON.parse(readFileSync(`tsconfig.${project}.json`, 'utf8')) as {
    compilerOptions: Record<string, unknown>
    vueCompilerOptions: Record<string, unknown>
  }
  for (const flag of [
    'strict',
    'noUncheckedIndexedAccess',
    'exactOptionalPropertyTypes',
    'noImplicitOverride',
    'noFallthroughCasesInSwitch',
    'noUnusedLocals',
    'noUnusedParameters',
    'useUnknownInCatchVariables',
    'isolatedModules',
    'verbatimModuleSyntax',
    'noEmit',
    'skipLibCheck',
  ])
    expect(config.compilerOptions[flag]).toBe(true)
  expect(config.vueCompilerOptions['strictTemplates']).toBe(true)
})
it('executes strict compile-negative fixtures with intended diagnostics', async () => {
  const { existsSync } = await import('node:fs')
  expect(existsSync('scripts/check-negative.ts')).toBe(true)
  const { checkNegative } = await import('../../scripts/check-negative.ts')
  expect(await checkNegative()).toEqual([
    'application',
    'tooling',
    'javascript',
    'tests',
    'indexed',
    'template',
  ])
}, 30000)
it.each([
  '<template><span>{{ t(arbitrary) }}</span></template>',
  '<template><span>{{ t(option.other) }}</span></template>',
  '<script setup lang="ts">document.title = "Raw title"</script>',
  '<script setup lang="ts">import { unsafeToTrustedHTML as convert } from "vue"</script>',
])('rejects arbitrary translation keys, raw script labels and unsafe imports: %s', (source) => {
  expect(check(source).length).toBeGreaterThan(0)
})
it('accepts the finite preference option key use', () => {
  expect(
    check(
      '<template><option v-for="option in themeOptions">{{ t(option.key) }}</option></template>',
    ),
  ).toEqual([])
})
it.each([
  '<template><span :aria-label="\'Raw\'" /></template>',
  '<template><span>{{ "Raw" }}</span></template>',
  '<template><span>{{ t(option.key) }}</span></template>',
])('rejects hidden raw labels and keys outside finite loops: %s', (source) => {
  expect(check(source).length).toBeGreaterThan(0)
})

it('rejects a different exact pin and missing runtime packages', () => {
  const input = JSON.parse(readFileSync('package.json', 'utf8')) as {
    dependencies: Record<string, string>
  }
  input.dependencies['vue'] = '3.5.42'
  expect(validateToolchain(input, '24.21.0', '11.18.0', true)).toContain('pins')
  delete input.dependencies['vue']
  expect(validateToolchain(input, '24.21.0', '11.18.0', true)).toContain('pins')
})

it.each([
  ['inner-h-t-m-l.camel', 'innerHTML'],
  ['outer-h-t-m-l.camel', 'outerHTML'],
  ['inner-h-t-m-l.camel.prop', '.innerHTML'],
  ['outer-h-t-m-l.prop.camel', '.outerHTML'],
  ['innerHTML.prop', '.innerHTML'],
  ['inner-h-t-m-l.camel.attr', '^innerHTML'],
  ['inner-h-t-m-l.prop.camel.attr', '^.innerHTML'],
])('rejects compiler-normalized HTML binding %s', (binding, key) => {
  const source = `<div :${binding}="value" />`
  const compiled = compileTemplate({ source, filename: 'Fixture.vue', id: 'fixture' })
  expect(compiled.errors).toEqual([])
  expect(compiled.code).toContain(key)
  expect(check(`<template>${source}</template>`)).toEqual([
    expect.objectContaining({ ruleId: 'rv/foundation', messageId: 'forbidden' }),
  ])
})
it('rejects the prop shorthand combined with camel', () => {
  expect(check('<template><div .inner-h-t-m-l.camel="value" /></template>')).toEqual([
    expect.objectContaining({ ruleId: 'rv/foundation', messageId: 'forbidden' }),
  ])
})
it.each(['data-test.camel', 'data-test.prop', 'data-test.prop.camel', 'inner-h-t-m-l.prop'])(
  'accepts a binding without an HTML sink: %s',
  (binding) => {
    expect(check(`<template><div :${binding}="value" /></template>`)).toEqual([])
  },
)

import { cacheSourceImports, checkSource } from '../../scripts/check-source.ts'
it.each([
  'import value from "../.vite/cache/deps/tool.js"',
  'export * from "../.vite/cache/deps/tool.js"',
  'const value = import("../.vite/cache/deps/tool.js")',
  'const value = require("../.vite/cache/deps/tool.js")',
  'const value = new URL("../.vite/cache/deps/tool.js", import.meta.url)',
])('rejects cache imports from authored tooling %s', (source) => {
  expect(cacheSourceImports(source, 'scripts/tool.ts', '/project/console')).toEqual([
    'cache-source:scripts/tool.ts',
  ])
})
it('accepts build graph output and inert cache-like strings as data', () => {
  expect(
    cacheSourceImports(
      'const text = "../.vite/cache/tool.js"; import graph from "../.vite/build-graph.json"',
      'scripts/tool.ts',
      '/project/console',
    ),
  ).toEqual([])
})
it('resolves Vite and all actual Vitest project caches beneath the reviewed output root', async () => {
  const { resolveConfig } = await import('vite')
  const { createVitest } = await import('vitest/node')
  const expected = resolve('.vite/cache').replaceAll('\\', '/')
  expect((await resolveConfig({ configFile: 'vite.config.ts' }, 'build')).cacheDir).toBe(expected)
  const context = await createVitest('test', { config: 'vitest.config.ts', watch: false })
  try {
    expect(context.vite.config.cacheDir).toBe(
      `${expected}/vitest/da39a3ee5e6b4b0d3255bfef95601890afd80709`,
    )
    expect(context.projects.map((project) => project.name).sort()).toEqual([
      'component (chromium)',
      'unit',
    ])
    for (const project of context.projects) {
      expect(
        project.vite.config.cacheDir === expected ||
          project.vite.config.cacheDir.startsWith(`${expected}/`),
      ).toBe(true)
      expect(project.vite.config.cacheDir).not.toContain('node_modules/.vite')
    }
  } finally {
    await context.close()
  }
})

it.each([
  ['@import "../.vite/cache/deps/style.css";', 'src/app.css'],
  ['body { background: url("../.vite/cache/deps/font.css") }', 'src/app.css'],
  ['<script src="../.vite/cache/deps/module.js"></script>', 'src/App.vue'],
  ['<style src="../.vite/cache/deps/style.css"></style>', 'src/App.vue'],
  ['import value from "../.vite%2Fcache/deps/module.js"', 'scripts/tool.ts'],
])('rejects cache source input %s', (source, filename) => {
  expect(cacheSourceImports(source, filename, '/project/console')).toEqual([
    `cache-source:${filename}`,
  ])
})

it.each([
  'type Value = import("../.vite/cache/deps/value.js").Value',
  'import value = require("../.vite/cache/deps/value.js")',
  'const value = import(`../.vite/cache/deps/value.js`)',
  'const value = import("../.vite/cache/" + name)',
])('rejects cache type and computed imports %s', (source) => {
  expect(cacheSourceImports(source, 'scripts/tool.ts', '/project/console')).toEqual([
    'cache-source:scripts/tool.ts',
  ])
})

it('accepts the exact checked cacheDir output setting without allowing it as source', () => {
  const source =
    "export default { cacheDir: fileURLToPath(new URL('./.vite/cache', import.meta.url)) }"
  expect(cacheSourceImports(source, 'vite.config.ts', '/project/console')).toEqual([])
  expect(cacheSourceImports(source, 'scripts/input.ts', '/project/console')).toEqual([
    'cache-source:scripts/input.ts',
  ])
})

it.each([
  'const value = import("../.vite/" + "cache/deps/value.js")',
  'const value = import(`../.vite/${"cache"}/deps/value.js`)',
])('rejects statically assembled cache paths %s', (source) => {
  expect(cacheSourceImports(source, 'scripts/tool.ts', '/project/console')).toEqual([
    'cache-source:scripts/tool.ts',
  ])
})

it('rejects CSS-escaped imports from generated cache output', () => {
  expect(
    cacheSourceImports(
      String.raw`@import "../.v\69te/cache/deps/value.css";`,
      'src/style.css',
      '/project/console',
    ),
  ).toEqual(['cache-source:src/style.css'])
})

function completeSourceCheck(
  filename: string,
  source: string,
  cache = true,
  prepare?: (root: string) => void,
): string[] {
  const root = mkdtempSync(join(tmpdir(), 'rv-cache-source-'))
  const put = (path: string, text: string) => {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), text)
  }
  try {
    const namespaces = ['app', 'nav', 'preferences', 'home', 'notFound', 'errors']
    const catalogue = Object.fromEntries(namespaces.map((name) => [name, { title: 'Value' }]))
    for (const language of ['en', 'vi'])
      put(`src/locales/${language}.json`, JSON.stringify(catalogue))
    put('src/keys.ts', namespaces.map((name) => `t("${name}.title")`).join('\n'))
    if (cache) {
      put('.vite/cache/deps/package.json', '{\n  "type": "module"\n}\n')
      put('.vite/cache/deps/tool.js', 'export const value = 1\n')
      put('.vite/cache/deps/style.css', 'body { color: red }\n')
    }
    put('src/ordinary.js', 'export const value = 1\n')
    put('src/ordinary.css', 'body { color: blue }\n')
    put(filename, source)
    prepare?.(root)
    return checkSource(root)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
it.each([
  [
    'src/App.vue',
    '<template><div /></template><style>@import "../.vite/cache/deps/style.css";</style>',
  ],
  [
    'src/App.vue',
    '<template><div /></template><style>@import url("../.vite/cache/deps/style.css");</style>',
  ],
  [
    'src/App.vue',
    '<template><div /></template><style>body { background: url("../.vite/cache/deps/style.css") }</style>',
  ],
  [
    'src/App.vue',
    String.raw`<template><div /></template><style>@import "../.v\69te/cache/deps/style.css";</style>`,
  ],
  [
    'src/App.vue',
    '<template><div /></template><style>@import "./ordinary.css";</style><style scoped>@import "../.vite/cache/deps/style.css";</style>',
  ],
  ['src/inputs.ts', 'const inputs = import.meta.glob("../.vite/cache/deps/*.js", { eager: true })'],
  ['scripts/inputs.ts', 'const inputs = import.meta.glob("../.vite/cache/deps/*.js")'],
  [
    'src/inputs.ts',
    'const inputs = import.meta.glob(["./ordinary.js", "../.vite/cache/deps/*.js"])',
  ],
  ['src/inputs.ts', 'const inputs = import.meta.glob(`../.vite/cache/deps/*.js`)'],
  ['src/inputs.ts', 'const inputs = import.meta.glob("./*.js", { base: "../.vite/cache/deps" })'],
  ['src/inputs.ts', 'const inputs = import.meta.glob("./cache/deps/*.js", { base: "../.vite" })'],
  ['scripts/tool.cjs', 'const value = require(require.resolve("../.vite/cache/deps/tool.js"))'],
  ['scripts/tool.cjs', 'const value = require(require["resolve"]("../.vite/cache/deps/tool.js"))'],
  ['scripts/tool.cjs', 'const value = require(require.resolve(`../.vite/cache/deps/tool.js`))'],
  [
    'scripts/tool.mjs',
    'const value = await import(import.meta.resolve("../.vite/cache/deps/tool.js"))',
  ],
  [
    'scripts/tool.mjs',
    'const value = await import(import.meta["resolve"]("../.vite/cache/deps/tool.js"))',
  ],
  ['scripts/tool.cjs', 'const value = module.require("../.vite/cache/deps/tool.js")'],
  ['src/inputs.ts', 'import value from "../.vite/cache/deps/tool.js"'],
])('rejects cache source through the complete checker: %s %s', (filename, source) => {
  expect(completeSourceCheck(filename, source)).toEqual([`cache-source:${filename}`])
})
it.each([
  [
    'src/App.vue',
    '<template><div /></template><style>@import "./ordinary.css"; body { background: url("./ordinary.css") }</style>',
  ],
  [
    'src/App.vue',
    '<template><div /></template><style>/* @import "../.vite/cache/deps/style.css"; */ body { color: red }</style>',
  ],
  ['src/inputs.ts', 'const inputs = import.meta.glob(["./ordinary.js", "!../.vite/cache/**"])'],
  ['src/inputs.ts', 'const inputs = import.meta.glob("./*.js", { base: "./" })'],
  ['scripts/tool.cjs', 'const value = require(require.resolve("../src/ordinary.js"))'],
  ['scripts/tool.mjs', 'const value = await import(import.meta.resolve("../src/ordinary.js"))'],
  ['scripts/tool.cjs', 'const value = module.require("../src/ordinary.js")'],
  ['scripts/tool.ts', `const text = 'import.meta.glob("../.vite/cache/deps/*.js")'`],
])(
  'preserves ordinary inputs and inert text through the complete checker: %s %s',
  (filename, source) => {
    expect(completeSourceCheck(filename, source)).toEqual([])
  },
)
it.each([
  'import.meta.glob("../**/*.js", { exhaustive: true })',
  'import.meta.glob("../**/*.js")',
  'import.meta.glob("../.vite/{cache,other}/**/*.js")',
  'import.meta.glob("../.v*/cache/deps/*.js")',
  'import.meta.glob("../.vite/ca?he/deps/*.js")',
  'import.meta.glob("../{src,.vite}/**/*.js")',
  'import.meta.glob(["../**/*.js", "!../.vite/cache/**"])',
  'import.meta.glob("**/*.js")',
  'import.meta.glob("./cache/**/*.js", { base: "/.vite" })',
  'import.meta.glob("/.vite/{cache,other}/**/*.js")',
])('requires a disjoint fixed glob prefix before cache output exists: %s', (source) => {
  expect(completeSourceCheck('src/inputs.ts', source, false)).toEqual([
    'cache-source:src/inputs.ts',
  ])
})
it.each([
  'import.meta.glob("./features/**/*.ts")',
  'import.meta.glob("../src/**/*.js")',
  'import.meta.glob("../public/*")',
  'import.meta.glob("/src/**/*.js")',
  'import.meta.glob("@/features/**/*.ts")',
  'import.meta.glob("./features/**/*.ts", { base: "/src" })',
  'import.meta.glob("../ordinary.js")',
  'import.meta.glob("./features/*.ts", { query: { text: "../.vite/cache/deps/tool.js" } })',
])('preserves disjoint globs and exact literal inputs: %s', (source) => {
  expect(completeSourceCheck('src/inputs.ts', source)).toEqual([])
})
it('rejects a fixed glob prefix whose existing ancestor links into the cache', () => {
  const root = mkdtempSync(join(tmpdir(), 'rv-cache-glob-link-'))
  try {
    mkdirSync(join(root, 'src'))
    mkdirSync(join(root, '.vite/cache'), { recursive: true })
    symlinkSync(join(root, '.vite/cache'), join(root, 'src/linked'), 'dir')
    expect(
      cacheSourceImports('import.meta.glob("./linked/nested/*.js")', 'src/inputs.ts', root),
    ).toEqual(['cache-source:src/inputs.ts'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
it('resolves the effective literal glob base from the original importer directory', () => {
  expect(
    completeSourceCheck(
      'src/inputs.ts',
      'import.meta.glob("./{cache,other}/*.js", { base: "./nested/deeper", base: "../.vite" })',
      false,
    ),
  ).toEqual(['cache-source:src/inputs.ts'])
})

it.each(['directory', 'junction', 'file', 'nested', 'cycle-before-cache', 'absent-cache'])(
  'rejects descendant cache reachability through the complete checker: %s',
  (kind) => {
    expect(
      completeSourceCheck(
        'src/inputs.ts',
        'export const inputs = import.meta.glob("./features/**/*.js")',
        kind !== 'absent-cache',
        (root) => {
          const features = join(root, 'src/features')
          mkdirSync(features)
          const cache = join(root, '.vite/cache')
          if (kind === 'file')
            symlinkSync(join(cache, 'deps/tool.js'), join(features, 'cache.js'), 'file')
          else if (kind === 'nested') {
            const shared = join(root, 'src/shared')
            mkdirSync(shared)
            symlinkSync(cache, join(shared, 'cachelink'), 'dir')
            symlinkSync(shared, join(features, 'shared'), 'dir')
          } else {
            if (kind === 'cycle-before-cache')
              symlinkSync(features, join(features, 'a-cycle'), 'dir')
            symlinkSync(
              cache,
              join(features, 'cachelink'),
              kind === 'junction' ? 'junction' : 'dir',
            )
          }
        },
      ),
    ).toEqual(['cache-source:src/inputs.ts'])
  },
)
it.each([true, false])(
  'rejects an exact literal glob through a cache link before its leaf exists: cache=%s',
  (cache) => {
    expect(
      completeSourceCheck(
        'src/inputs.ts',
        'import.meta.glob("./linked/deps/future.js")',
        cache,
        (root) => {
          symlinkSync(join(root, '.vite/cache'), join(root, 'src/linked'), 'dir')
        },
      ),
    ).toEqual(['cache-source:src/inputs.ts'])
  },
)
it('rejects a dangling descendant link whose source graph cannot be proven', () => {
  expect(
    completeSourceCheck('src/inputs.ts', 'import.meta.glob("./features/**/*.js")', true, (root) => {
      mkdirSync(join(root, 'src/features'))
      symlinkSync(join(root, 'src/absent'), join(root, 'src/features/link'), 'dir')
    }),
  ).toEqual(['cache-source:src/inputs.ts'])
})
it('rejects external descendant targets without traversing the external tree', () => {
  const external = mkdtempSync(join(tmpdir(), 'rv-external-glob-'))
  try {
    writeFileSync(join(external, 'ordinary.js'), 'export const value = 1\n')
    expect(
      completeSourceCheck(
        'src/inputs.ts',
        'import.meta.glob("./features/**/*.js")',
        true,
        (root) => {
          mkdirSync(join(root, 'src/features'))
          symlinkSync(external, join(root, 'src/features/link'), 'dir')
        },
      ),
    ).toEqual(['cache-source:src/inputs.ts'])
  } finally {
    rmSync(external, { recursive: true, force: true })
  }
})
it.each(['real', 'directory-link', 'file-link', 'safe-cycle'])(
  'preserves a proven ordinary glob source graph: %s',
  (kind) => {
    expect(
      completeSourceCheck(
        'src/inputs.ts',
        'import.meta.glob("./features/**/*.js")',
        true,
        (root) => {
          const features = join(root, 'src/features')
          mkdirSync(features)
          writeFileSync(join(features, 'ordinary.js'), 'export const value = 1\n')
          if (kind === 'file-link')
            symlinkSync(join(root, 'src/ordinary.js'), join(features, 'linked.js'), 'file')
          else if (kind === 'directory-link') {
            const shared = join(root, 'src/shared')
            mkdirSync(shared)
            writeFileSync(join(shared, 'ordinary.js'), 'export const value = 1\n')
            symlinkSync(shared, join(features, 'shared'), 'dir')
          } else if (kind === 'safe-cycle') symlinkSync(features, join(features, 'cycle'), 'dir')
        },
      ),
    ).toEqual([])
  },
)
