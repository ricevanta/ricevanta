import { readFileSync, renameSync, mkdirSync } from 'node:fs'
import { expect, it, vi } from 'vitest'
import {
  lockedPackages,
  reconcileLicenses,
  scanOSV,
  resolvedLicenses,
} from '../../scripts/audit-deps.ts'

import { join } from 'node:path'
import { tree } from '../fixtures/dependencies/install-tree.ts'
const catalogueTool = vi.hoisted((): { catalogue: unknown; onList: () => void } => ({
  catalogue: {},
  onList: () => {},
}))
vi.mock('../../scripts/run-tool.ts', () => ({
  checkedTool: (_command: string, args: string[]) => {
    if (args.includes('--version')) return Promise.resolve('11.18.0\n')
    if (args.includes('licenses')) return Promise.resolve(JSON.stringify(catalogueTool.catalogue))
    if (args.includes('list')) {
      catalogueTool.onList()
      return Promise.resolve('[]')
    }
    return Promise.reject(new Error('Unexpected metadata command'))
  },
}))
const fragment = readFileSync('tests/fixtures/dependencies/platform-lock.yaml', 'utf8')
const supported = [
  '@blazediff/core@1.9.1',
  '@esbuild/darwin-arm64@0.25.12',
  '@esbuild/linux-x64@0.25.12',
  'lightningcss-linux-x64-gnu@1.33.0',
  'lightningcss-win32-x64-msvc@1.33.0',
]
const excluded = [
  '@esbuild/aix-ppc64@0.25.12',
  '@esbuild/android-arm64@0.25.12',
  '@esbuild/freebsd-arm64@0.25.12',
  '@esbuild/linux-arm@0.25.12',
  'lightningcss-linux-x64-musl@1.33.0',
]
function evidence(pair: string) {
  const index = pair.lastIndexOf('@')
  return {
    name: pair.slice(0, index),
    version: pair.slice(index + 1),
    declared: 'MIT',
    normalized: 'MIT',
    paths: [`/node_modules/${pair.slice(0, index)}`],
  }
}

it('reconciles supported recorded packages and reports each excluded package', () => {
  const diagnostics: string[] = []
  const licenses = reconcileLicenses(lockedPackages(fragment), supported.map(evidence), (line) => {
    diagnostics.push(line)
  })
  expect(licenses.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual(supported)
  expect(diagnostics).toEqual(excluded.map((pair) => `Excluded locked license package: ${pair}`))
})

it.each(supported)('requires evidence for supported package %s', (missing) => {
  expect(() =>
    reconcileLicenses(
      lockedPackages(fragment),
      supported.filter((pair) => pair !== missing).map(evidence),
    ),
  ).toThrow(`Missing locked license evidence: ${missing}`)
})

it.each(excluded)('rejects installed excluded package %s', (pair) => {
  expect(() =>
    reconcileLicenses(lockedPackages(fragment), [...supported.map(evidence), evidence(pair)]),
  ).toThrow(`Excluded locked package is installed: ${pair}`)
})

it('keeps excluded locked packages in OSV queries', async () => {
  const queried: string[] = []
  await scanOSV(lockedPackages(fragment), (body) => {
    const request = body as { queries: { package: { name: string }; version: string }[] }
    queried.push(...request.queries.map((query) => `${query.package.name}@${query.version}`))
    return Promise.resolve({ results: request.queries.map(() => ({})) })
  })
  expect(queried).toEqual([
    supported[0],
    ...excluded.slice(0, 4),
    supported[1],
    supported[2],
    supported[3],
    excluded[4],
    supported[4],
  ])
})

it.each([
  ['os: [linux, darwin, win32]\n    cpu: [arm64]', true],
  ["os: ['!linux', '!darwin', '!win32']", false],
  ["os: [linux, '!linux']", false],
  ['cpu: [ppc64, x64]', true],
  ['cpu: [any, ppc64]', false],
  ["cpu: ['!x64']", true],
  ["cpu: ['!x64', '!arm64']", false],
  ['libc: [musl]', false],
  ["libc: ['!musl']", true],
  ['os: [any]\n    cpu: [any]\n    libc: [any]', true],
])('matches platform restrictions %s', (fields, allowed) => {
  const locked = lockedPackages(`lockfileVersion: '9.0'\npackages:\n  tool@1.0.0:\n    ${fields}\n`)
  if (allowed) expect(() => reconcileLicenses(locked, [])).toThrow('tool@1.0.0')
  else expect(reconcileLicenses(locked, [])).toEqual([])
})

it.each(['os: linux', 'cpu: [123]', 'libc: [glibc,]', 'os: [linux]\n    os: [aix]'])(
  'rejects ambiguous platform metadata %s',
  (fields) => {
    expect(() =>
      lockedPackages(`lockfileVersion: '9.0'\npackages:\n  tool@1.0.0:\n    ${fields}\n`),
    ).toThrow('Invalid locked platform')
  },
)

it('queries all 376 frozen pairs including the four removable leaves', async () => {
  const locked = lockedPackages(readFileSync('pnpm-lock.yaml', 'utf8'))
  const queries: string[] = []
  await scanOSV(locked, (body) => {
    const values = (body as { queries: { package: { name: string }; version: string }[] }).queries
    expect(values.length).toBeLessThanOrEqual(100)
    queries.push(...values.map((value) => `${value.package.name}@${value.version}`))
    return Promise.resolve({ results: values.map(() => ({})) })
  })
  expect(queries).toHaveLength(376)
  expect(new Set(queries)).toEqual(new Set(locked.map((pkg) => `${pkg.name}@${pkg.version}`)))
  expect(queries).toContain('@rolldown/binding-linux-arm64-musl@1.2.13')
  expect(queries).toContain('@rolldown/binding-linux-x64-musl@1.2.13')
  expect(queries).toContain('lightningcss-linux-arm64-musl@1.33.0')
  expect(queries).toContain('lightningcss-linux-x64-musl@1.33.0')
})

it.each(['none', 'cache-bytes', 'cache-identity', 'installed-output'])(
  'performs a stable independent audit of generated output, mutation=%s',
  async (mutate) => {
    const value = tree()
    value.put('.vite/cache/deps/result.js', 'export {}')
    catalogueTool.catalogue = value.catalogue
    catalogueTool.onList = () => {
      if (mutate === 'cache-bytes')
        value.put('.vite/cache/deps/result.js', 'export const changed = 1')
      if (mutate === 'cache-identity') {
        renameSync(
          join(value.root, '.vite/cache/deps/result.js'),
          join(value.root, 'previous-result'),
        )
        value.put('.vite/cache/deps/result.js', 'export {}')
      }
      if (mutate === 'installed-output')
        mkdirSync(join(value.root, 'node_modules/.cache/prettier'), { recursive: true })
    }
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(value.root)
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    try {
      if (mutate !== 'none')
        await expect(resolvedLicenses().then((licenses) => licenses.length)).rejects.toThrow(
          'Installation changed during license audit',
        )
      else expect(await resolvedLicenses()).toHaveLength(342)
    } finally {
      cwd.mockRestore()
      log.mockRestore()
      value.cleanup()
    }
  },
)
