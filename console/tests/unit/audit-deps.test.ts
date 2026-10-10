import { expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { scanOSV } from '../../scripts/audit-deps.ts'

const path = [
  { package: '@intlify/unplugin-vue-i18n', version: '11.2.5' },
  { package: 'fast-glob', version: '3.3.3' },
  { package: 'micromatch', version: '4.0.8' },
  { package: 'braces', version: '3.0.3' },
]
const entry = {
  advisoryId: 'GHSA-vfj7-8cjw-p6xm',
  package: 'braces',
  version: '3.0.3',
  dependencyPath: path,
  untrustedInputRationale: 'Repository patterns only',
  removeWhen: 'Fixed or absent',
}
const packages = path.map((node) => ({ name: node.package, version: node.version }))
const manifest = { devDependencies: { '@intlify/unplugin-vue-i18n': '11.2.5' } }
const lockfile = `lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      '@intlify/unplugin-vue-i18n':
        specifier: 11.2.5
        version: 11.2.5
packages:
  '@intlify/unplugin-vue-i18n@11.2.5': {}
  fast-glob@3.3.3: {}
  micromatch@4.0.8: {}
  braces@3.0.3: {}
snapshots:
  '@intlify/unplugin-vue-i18n@11.2.5':
    dependencies:
      fast-glob: 3.3.3
  fast-glob@3.3.3:
    dependencies:
      micromatch: 4.0.8
  micromatch@4.0.8:
    dependencies:
      braces: 3.0.3
  braces@3.0.3: {}
`
const response = { results: [{}, {}, {}, { vulns: [{ id: entry.advisoryId }] }] }
const options = (entries: unknown = [entry], text = lockfile, input: unknown = manifest) => ({
  exceptionsText: JSON.stringify(entries),
  lockfile: text,
  manifest: input,
})
const run = (
  settings: { exceptionsText: string | undefined; lockfile: string; manifest: unknown } = options(),
  result: unknown = response,
) => scanOSV(packages, () => Promise.resolve(result), settings)

it('accepts the exact exception and reports its full identity and disposition', async () => {
  expect(await run()).toEqual([
    `${entry.advisoryId} braces@3.0.3 ${path.map((node) => `${node.package}@${node.version}`).join(' -> ')} excepted`,
  ])
})
it('accepts clean results with an empty exception file', async () => {
  expect(await run(options([]), { results: [{}, {}, {}, {}] })).toEqual([])
})
it('names every unlisted advisory, including a second advisory on braces', async () => {
  await expect(
    run(options(), {
      results: [
        { vulns: [{ id: 'OSV-Z' }] },
        {},
        {},
        { vulns: [{ id: entry.advisoryId }, { id: 'OSV-A' }] },
      ],
    }),
  ).rejects.toThrow(
    /OSV-A braces@3.0.3 .*unlisted[\s\S]*OSV-Z @intlify\/unplugin-vue-i18n@11.2.5 .*unlisted/,
  )
})
it('does not exempt another path to the same version', async () => {
  await expect(
    run(
      options(
        [entry],
        lockfile.replace('      fast-glob: 3.3.3', '      fast-glob: 3.3.3\n      braces: 3.0.3'),
      ),
    ),
  ).rejects.toThrow('braces@3.0.3 unlisted')
})
it.each(['dependencies', 'optionalDependencies'])('rejects promotion to %s', async (kind) => {
  await expect(
    run(
      options([entry], lockfile.replace('devDependencies:', `${kind}:`), {
        [kind]: manifest.devDependencies,
      }),
    ),
  ).rejects.toThrow(/entry 0 .*devDependencies/)
})
it('rejects manifest and lockfile dependency-class disagreement', async () => {
  await expect(
    run(options([entry], lockfile, { dependencies: manifest.devDependencies })),
  ).rejects.toThrow(/entry 0 .*disagree/)
})
it.each([
  lockfile.replace('      braces: 3.0.3', ''),
  lockfile
    .replace('      braces: 3.0.3', '      braces: 3.0.4')
    .replaceAll('braces@3.0.3:', 'braces@3.0.4:'),
  lockfile.replace('  braces@3.0.3: {}\n', ''),
])('rejects stale edges, versions and removed packages', async (text) => {
  await expect(run(options([entry], text))).rejects.toThrow(
    /entry 0 .*GHSA-vfj7-8cjw-p6xm.*lockfile/,
  )
})
it('rejects an advisory absent from the complete response', async () => {
  await expect(run(options(), { results: [{}, {}, {}, {}] })).rejects.toThrow(
    /entry 0 .*advisory absent/,
  )
})
it.each([
  null,
  {},
  [{ ...entry, extra: true }],
  [{ ...entry, removeWhen: '' }],
  [{ ...entry, version: '^3.0.3' }],
  [{ ...entry, dependencyPath: [] }],
  [{ ...entry, dependencyPath: [{ package: 'braces', version: '*' }] }],
  [{ ...entry, dependencyPath: [{ package: 'braces', version: '3.0.2' }] }],
  [entry, entry],
  [{ ...entry, advisoryId: undefined }],
])('rejects malformed, duplicate and wildcard entries %j', async (entries) => {
  await expect(run(options(entries))).rejects.toThrow('exception')
})
it('rejects missing and unreadable exception files', async () => {
  await expect(run({ ...options(), exceptionsText: undefined })).rejects.toThrow('exception')
  await expect(run({ ...options(), exceptionsText: '{' })).rejects.toThrow('exception')
})
it('collects paginated findings and distinguishes incomplete requests', async () => {
  let calls = 0
  await expect(
    scanOSV(
      packages,
      () => {
        calls++
        return Promise.resolve(
          calls === 1
            ? {
                results: [
                  {},
                  {},
                  {},
                  {
                    vulns: [{ id: entry.advisoryId }, { id: 'OSV-second' }],
                    next_page_token: 'next',
                  },
                ],
              }
            : { results: [] },
        )
      },
      options(),
    ),
  ).rejects.toThrow(/OSV-second.*unlisted[\s\S]*Incomplete OSV/)
  expect(calls).toBe(2)
})
it('fails unavailable service even with an exception', async () => {
  await expect(
    scanOSV(packages, () => Promise.reject(new Error('offline')), options()),
  ).rejects.toThrow('offline')
})
it('matches the reviewed entry against the real frozen lockfile', async () => {
  const text = readFileSync('security/osv-exceptions.json', 'utf8')
  const spec = readFileSync('../docs/specs/console-foundation.md', 'utf8')
  const reviewed = spec.split('```json\n')[1]?.split('\n```')[0]
  if (!reviewed) throw new Error('Missing reviewed entry')
  expect(JSON.parse(text) as unknown).toEqual(JSON.parse(reviewed) as unknown)
  const locked = readFileSync('pnpm-lock.yaml', 'utf8')
  expect(
    await run({
      exceptionsText: text,
      lockfile: locked,
      manifest: JSON.parse(readFileSync('package.json', 'utf8')) as unknown,
    }),
  ).toHaveLength(1)
})
it('keeps original entry indices when invalid and stale entries coexist', async () => {
  await expect(
    run(options([{ ...entry, version: '*' }, entry]), { results: [{}, {}, {}, {}] }),
  ).rejects.toThrow(/entry 1 stale exception .*advisory absent/)
})
it.each(['3.0.3-01', '3.0.3-..', '3.0.3+', '03.0.3'])(
  'rejects invalid exact npm versions %s',
  async (version) => {
    await expect(
      run(
        options([
          {
            ...entry,
            version,
            dependencyPath: [...path.slice(0, -1), { package: 'braces', version }],
          },
        ]),
      ),
    ).rejects.toThrow('version must be exact')
  },
)
it('names every stale entry after paginated clean results', async () => {
  const other = { ...entry, advisoryId: 'OSV-other' }
  let calls = 0
  await expect(
    scanOSV(
      packages,
      () =>
        Promise.resolve(
          ++calls === 1
            ? { results: [{}, {}, {}, { next_page_token: 'next' }] }
            : { results: [{}] },
        ),
      options([entry, other]),
    ),
  ).rejects.toThrow(
    /entry 0 stale exception .*GHSA-vfj7-8cjw-p6xm[\s\S]*entry 1 stale exception .*OSV-other/,
  )
})
it('sorts stale diagnostics by advisory identity rather than entry index', async () => {
  let message = ''
  try {
    await run(
      options([
        { ...entry, advisoryId: 'OSV-Z' },
        { ...entry, advisoryId: 'OSV-A' },
      ]),
      { results: [{}, {}, {}, {}] },
    )
  } catch (error) {
    message = String(error)
  }
  expect(message.indexOf('OSV-A')).toBeLessThan(message.indexOf('OSV-Z'))
})
it('continues pagination after an excepted advisory and reports later unlisted findings', async () => {
  let calls = 0
  await expect(
    scanOSV(
      packages,
      () =>
        Promise.resolve(
          ++calls === 1
            ? {
                results: [
                  {},
                  {},
                  {},
                  { vulns: [{ id: entry.advisoryId }], next_page_token: 'next' },
                ],
              }
            : { results: [{ vulns: [{ id: 'OSV-later' }] }] },
        ),
      options(),
    ),
  ).rejects.toThrow(/excepted[\s\S]*OSV-later braces@3.0.3 .*unlisted/)
  expect(calls).toBe(2)
})
it.each([{ vulns: 'bad' }, { vulns: [{}] }, { next_page_token: 42 }])(
  'rejects malformed service result %j',
  async (result) => {
    await expect(run(options(), { results: [{}, {}, {}, result] })).rejects.toThrow(
      'Incomplete OSV',
    )
  },
)
it.each(
  [{}, null, [], 'bad', { id: 42 }, { id: '' }, { id: ' ' }].map((malformed) => ({ malformed })),
)(
  'collects findings and follows pagination around malformed advisory %j',
  async ({ malformed }) => {
    const requests: unknown[] = []
    const error = await scanOSV(
      packages,
      (body) => {
        requests.push(body)
        return Promise.resolve(
          requests.length === 1
            ? {
                results: [
                  {},
                  {},
                  {},
                  {
                    vulns: [{ id: entry.advisoryId }, malformed, { id: 'OSV-HIDDEN' }],
                    next_page_token: 'page-2',
                  },
                ],
              }
            : {
                results: [{ vulns: [malformed, { id: 'OSV-LATER' }, {}] }],
              },
        )
      },
      options([entry, { ...entry, advisoryId: 'OSV-ABSENT' }]),
    ).catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(Error)
    const message = String(error)
    expect(message).toContain(`${entry.advisoryId} braces@3.0.3`)
    expect(message).toMatch(/OSV-HIDDEN braces@3.0.3 .*unlisted/)
    expect(message).toMatch(/OSV-LATER braces@3.0.3 .*unlisted/)
    expect(message.match(/Incomplete OSV braces@3.0.3/g)).toHaveLength(3)
    expect(message).not.toContain('advisory absent from complete OSV result')
    expect(requests).toHaveLength(2)
    expect(requests[1]).toEqual({
      queries: [
        {
          package: { name: 'braces', ecosystem: 'npm' },
          version: '3.0.3',
          page_token: 'page-2',
        },
      ],
    })
  },
)
it('follows valid pagination after a malformed vulnerability list', async () => {
  let calls = 0
  await expect(
    scanOSV(
      packages,
      () =>
        Promise.resolve(
          ++calls === 1
            ? { results: [{}, {}, {}, { vulns: 'bad', next_page_token: 'page-2' }] }
            : { results: [{ vulns: [{ id: 'OSV-LATER' }] }] },
        ),
      options(),
    ),
  ).rejects.toThrow(/OSV-LATER braces@3.0.3 .*unlisted[\s\S]*Malformed vulnerabilities/)
  expect(calls).toBe(2)
})
it('rejects repeated pagination tokens', async () => {
  await expect(
    scanOSV(
      packages,
      () => Promise.resolve({ results: [{}, {}, {}, { next_page_token: 'loop' }] }),
      options(),
    ),
  ).rejects.toThrow('Incomplete OSV')
})
it('batches at most 100 distinct package/version pairs', async () => {
  const inputs = Array.from({ length: 101 }, (_, index) => ({
    name: `package-${String(index)}`,
    version: '1.0.0',
  }))
  const sizes: number[] = []
  await scanOSV([...inputs, ...inputs], (body) => {
    const queries = (body as { queries: unknown[] }).queries
    sizes.push(queries.length)
    return Promise.resolve({ results: queries.map(() => ({})) })
  })
  expect(sizes).toEqual([100, 1])
})
