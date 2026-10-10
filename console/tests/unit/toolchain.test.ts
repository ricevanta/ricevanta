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

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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
