import { expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { normalizeLicense, scanOSV } from '../../scripts/audit-deps.ts'
const evidence = readFileSync(
  'node_modules/.pnpm/argparse@2.0.1/node_modules/argparse/LICENSE',
  'utf8',
)
it('normalizes only the pinned argparse with matching license evidence', () => {
  expect(
    normalizeLicense({
      name: 'argparse',
      version: '2.0.1',
      declared: 'Python-2.0',
      runtime: false,
      modified: false,
      evidence,
    }),
  ).toBe('Python-2.0.1')
})
it.each([
  { name: 'argparse', version: '2.0.2', evidence },
  { name: 'other', version: '2.0.1', evidence },
  { name: 'argparse', version: '2.0.1', evidence: '' },
  { name: 'argparse', version: '2.0.1', evidence: 'CNRI mismatched' },
  { name: 'argparse', version: '2.0.1', evidence, runtime: true },
])('rejects invalid Python license normalization %j', (input) => {
  expect(() =>
    normalizeLicense({ declared: 'Python-2.0', runtime: false, modified: false, ...input }),
  ).toThrow()
})
it.each(['BlueOak-1.0.0', 'MPL-2.0', 'Python-2.0.1'])('rejects runtime %s', (declared) => {
  expect(() =>
    normalizeLicense({
      name: 'tool',
      version: '1.0.0',
      declared,
      runtime: true,
      modified: false,
      evidence: '',
    }),
  ).toThrow()
})
it.each(['BlueOak-1.0.0', 'MPL-2.0'])('accepts unmodified tooling %s', (declared) => {
  expect(
    normalizeLicense({
      name: 'tool',
      version: '1.0.0',
      declared,
      runtime: false,
      modified: false,
      evidence: '',
    }),
  ).toBe(declared)
})
it.each(['GPL-3.0', 'UNKNOWN'])('rejects unknown license %s', (declared) => {
  expect(() =>
    normalizeLicense({
      name: 'tool',
      version: '1.0.0',
      declared,
      runtime: false,
      modified: false,
      evidence: '',
    }),
  ).toThrow()
})
it('rejects modified MPL tooling', () => {
  expect(() =>
    normalizeLicense({
      name: 'tool',
      version: '1.0.0',
      declared: 'MPL-2.0',
      runtime: false,
      modified: true,
      evidence: '',
    }),
  ).toThrow()
})
const packages = [{ name: 'vue', version: '3.5.43' }]
it('deduplicates exact pairs and accepts complete clean OSV results', async () => {
  const requests: unknown[] = []
  await scanOSV([...packages, ...packages], (body) => {
    requests.push(body)
    return Promise.resolve({ results: [{}] })
  })
  expect(requests).toEqual([
    { queries: [{ package: { name: 'vue', ecosystem: 'npm' }, version: '3.5.43' }] },
  ])
})
it('follows pagination rather than accepting an incomplete first page', async () => {
  const requests: unknown[] = []
  await scanOSV(packages, (body) => {
    requests.push(body)
    return Promise.resolve(
      requests.length === 1 ? { results: [{ next_page_token: 'next' }] } : { results: [{}] },
    )
  })
  expect(requests).toHaveLength(2)
  expect(requests[1]).toEqual({
    queries: [
      { package: { name: 'vue', ecosystem: 'npm' }, version: '3.5.43', page_token: 'next' },
    ],
  })
})
it.each([
  { results: [{ vulns: [{ id: 'OSV-1' }] }] },
  { results: [] },
  {},
  { results: [{ next_page_token: 5 }] },
])('fails vulnerable or incomplete OSV response %j', async (response) => {
  await expect(scanOSV(packages, () => Promise.resolve(response))).rejects.toThrow()
})
it('fails unavailable OSV service', async () => {
  await expect(scanOSV(packages, () => Promise.reject(new Error('offline')))).rejects.toThrow(
    'offline',
  )
})
it('collects runtime package names from pnpm dependency-map keys', async () => {
  const audit = await import('../../scripts/audit-deps.ts')
  expect(audit).toHaveProperty('runtimePairs')
  if (!('runtimePairs' in audit)) return
  expect(
    [
      ...audit.runtimePairs([
        {
          name: 'root',
          version: '0.1.0',
          dependencies: {
            argparse: { version: '2.0.1', dependencies: { nested: { version: '1.0.0' } } },
          },
          optionalDependencies: { optional: { version: '2.0.0' } },
        },
      ]),
    ].sort(),
  ).toEqual(['argparse@2.0.1', 'nested@1.0.0', 'optional@2.0.0', 'root@0.1.0'])
})
it('classifies the pinned Vite peer subtree as build tooling, without exempting direct runtime use', async () => {
  const { runtimePairs } = await import('../../scripts/audit-deps.ts')
  const tree = [
    {
      name: 'root',
      version: '0.1.0',
      dependencies: {
        'vue-router': {
          version: '5.0.3',
          dependencies: {
            vite: { version: '8.3.2', dependencies: { lightningcss: { version: '1.33.0' } } },
          },
        },
        lightningcss: { version: '1.33.0' },
      },
    },
  ]
  expect([...runtimePairs(tree)]).toContain('lightningcss@1.33.0')
  const root = tree[0]
  if (!root) throw new Error('Missing fixture root')
  const child = root.dependencies as Record<string, unknown>
  delete child['lightningcss']
  expect([...runtimePairs(tree)]).not.toContain('lightningcss@1.33.0')
})

import { lockedPackages, reconcileLicenses } from '../../scripts/audit-deps.ts'
it('reconciles every locked pair for OSV coverage, including platform packages', async () => {
  const locked = lockedPackages(
    "lockfileVersion: '9.0'\npackages:\n  '@scope/tool@1.0.0':\n    optional: true\n  platform@2.0.0:\n    resolution: {}\nsnapshots:\n  ignored@1.0.0:\n",
  )
  expect(locked).toEqual([
    { name: '@scope/tool', version: '1.0.0' },
    { name: 'platform', version: '2.0.0' },
  ])
  const inventory = locked.map((pkg) => ({
    ...pkg,
    declared: 'MIT',
    normalized: 'MIT',
    paths: [`/node_modules/${pkg.name}`],
  }))
  expect(() => reconcileLicenses(locked, inventory.slice(0, 1))).toThrow('platform@2.0.0')
  expect(() =>
    reconcileLicenses(
      locked,
      inventory.map((pkg) => ({ ...pkg, paths: [] })),
    ),
  ).toThrow('evidence')
  const requests: unknown[] = []
  await scanOSV(reconcileLicenses(locked, inventory), (body) => {
    requests.push(body)
    return Promise.resolve({ results: [{}, {}] })
  })
  expect(requests).toEqual([
    {
      queries: [
        { package: { name: '@scope/tool', ecosystem: 'npm' }, version: '1.0.0' },
        { package: { name: 'platform', ecosystem: 'npm' }, version: '2.0.0' },
      ],
    },
  ])
  expect(lockedPackages(readFileSync('pnpm-lock.yaml', 'utf8'))).toHaveLength(376)
})
it.each([
  "lockfileVersion: '8.0'\npackages:\n",
  "lockfileVersion: '9.0'\npackages:\n  unparsed key:\n",
  "lockfileVersion: '9.0'\npackages:\n",
])('rejects unreadable locked coverage', (text) => {
  expect(() => lockedPackages(text)).toThrow()
})
