import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import { lockedPackages, reconcileLicenses, scanOSV } from '../../scripts/audit-deps.ts'

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
