import { checkedTool } from './run-tool.ts'
import ts from 'typescript'
import { join, relative } from 'node:path'
import { existsSync, readFileSync, readdirSync } from 'node:fs'

const approvedPins: Record<string, Record<string, string>> = {
  dependencies: {
    vue: '3.5.43',
    'vue-router': '5.0.3',
    pinia: '3.0.4',
    'vue-i18n': '11.4.12',
    '@fontsource/be-vietnam-pro': '5.3.0',
  },
  devDependencies: {
    vite: '8.3.2',
    '@vitejs/plugin-vue': '6.0.9',
    typescript: '5.9.3',
    'vue-tsc': '3.1.0',
    '@types/node': '24.10.1',
    '@vue/compiler-sfc': '3.5.43',
    '@intlify/unplugin-vue-i18n': '11.2.5',
    '@intlify/message-compiler': '11.4.12',
    eslint: '9.39.1',
    '@eslint/js': '9.39.1',
    'eslint-plugin-vue': '10.11.1',
    'vue-eslint-parser': '10.3.0',
    'typescript-eslint': '8.66.0',
    prettier: '3.6.2',
    vitest: '4.1.11',
    '@vitest/browser-playwright': '4.1.11',
    '@vue/test-utils': '2.4.6',
    '@playwright/test': '1.59.1',
    playwright: '1.59.1',
    'playwright-core': '1.59.1',
    '@axe-core/playwright': '4.11.0',
  },
}

export function validateToolchain(
  manifest: unknown,
  node: string,
  pnpm: string,
  lockfile: boolean,
): string[] {
  const issues: string[] = []
  if (node !== '24.21.0') issues.push('node')
  if (pnpm !== '11.18.0') issues.push('pnpm')
  if (!lockfile) issues.push('lockfile')
  if (typeof manifest !== 'object' || manifest === null) return [...issues, 'manifest']
  const data = manifest as Record<string, unknown>
  for (const field of ['dependencies', 'devDependencies']) {
    const deps = data[field]
    if (
      typeof deps !== 'object' ||
      deps === null ||
      Object.values(deps).some(
        (version: unknown) => typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version),
      )
    )
      issues.push('pins')
  }
  for (const [field, expected] of Object.entries(approvedPins)) {
    const actual = data[field]
    if (
      typeof actual !== 'object' ||
      actual === null ||
      Object.keys(actual).length !== Object.keys(expected).length ||
      Object.entries(expected).some(
        ([name, version]) =>
          !(name in actual) || (actual as Record<string, unknown>)[name] !== version,
      )
    )
      issues.push('pins')
  }
  const engines = data['engines']
  if (
    typeof engines !== 'object' ||
    engines === null ||
    !('node' in engines) ||
    engines.node !== '24.21.0' ||
    !('pnpm' in engines) ||
    engines.pnpm !== '11.18.0'
  )
    issues.push('engines')
  if (
    data['packageManager'] !== 'pnpm@11.18.0' ||
    data['private'] !== true ||
    data['type'] !== 'module' ||
    data['name'] !== '@ricevanta/console' ||
    data['version'] !== '0.1.0'
  )
    issues.push('manifest')
  return issues
}
if (import.meta.main) {
  const issues = validateToolchain(
    JSON.parse(readFileSync('package.json', 'utf8')) as unknown,
    process.versions.node,
    (await checkedTool('pnpm', ['--version'])).trim(),
    existsSync('pnpm-lock.yaml'),
  )
  issues.push(...checkProject(process.cwd()))
  if (issues.length) {
    console.error(issues.join('\n'))
    process.exitCode = 1
  }
}

export function projectFiles(root: string): string[] {
  const files: string[] = []
  function walk(dir: string): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (
        [
          'node_modules',
          'dist',
          '.git',
          '.vite',
          'coverage',
          'playwright-report',
          'test-results',
        ].includes(entry.name)
      )
        continue
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else files.push(relative(root, path).split('\\').join('/'))
    }
  }
  walk(root)
  return files.sort()
}
export function checkProject(root: string): string[] {
  const issues: string[] = []
  const covered = new Set<string>()
  for (const name of ['app', 'tools', 'test']) {
    const config = ts.readConfigFile(join(root, `tsconfig.${name}.json`), (path) =>
      ts.sys.readFile(path),
    )
    const parsed = ts.parseJsonConfigFileContent(
      config.config,
      ts.sys,
      root,
      undefined,
      undefined,
      undefined,
      [{ extension: '.vue', isMixedContent: true, scriptKind: ts.ScriptKind.Deferred }],
    )
    for (const path of parsed.fileNames) covered.add(relative(root, path).split('\\').join('/'))
  }
  for (const path of projectFiles(root)) {
    if (/\.d\.(?:ts|mts|cts)$/.test(path)) {
      if (
        path !== 'src/env.d.ts' ||
        readFileSync(join(root, path), 'utf8') !== '/// <reference types="vite/client" />\n'
      )
        issues.push(`declaration:${path}`)
    } else if (/\.(?:ts|mts|cts|js|mjs|cjs|vue)$/.test(path) && !covered.has(path))
      issues.push(`coverage:${path}`)
  }
  return issues.sort()
}
