import { afterEach, expect, it, vi } from 'vitest'
import { mkdirSync, readFileSync, readlinkSync, realpathSync, symlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { finalizeInstall } from '../../scripts/finalize-install.ts'
import { removable, tree } from '../fixtures/dependencies/install-tree.ts'
const interruption = vi.hoisted(() => ({ remaining: Number.POSITIVE_INFINITY, specialPath: '' }))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    lstatSync: (...args: Parameters<typeof actual.lstatSync>) => {
      const stat = actual.lstatSync(...args)
      if (!stat || String(args[0]) !== interruption.specialPath) return stat
      return new Proxy(stat, {
        get(target, key, receiver): unknown {
          if (key === 'isFile' || key === 'isDirectory' || key === 'isSymbolicLink')
            return () => false
          return Reflect.get(target, key, receiver) as unknown
        },
      })
    },
    unlinkSync: (path: import('node:fs').PathLike) => {
      if (--interruption.remaining === 0) throw new Error('simulated interrupted removal')
      actual.unlinkSync(path)
    },
  }
})
const cleanups: (() => void)[] = []
afterEach(() => {
  interruption.remaining = Number.POSITIVE_INFINITY
  interruption.specialPath = ''
  cleanups.splice(0).forEach((cleanup) => {
    cleanup()
  })
})
function fixture(extras = false) {
  const result = tree(extras)
  cleanups.push(result.cleanup)
  return result
}
it.each([false, true])(
  'finalizes an isolated staged tree with extras=%s and repeats without deletion',
  async (extras) => {
    const value = fixture(extras)
    const result = await finalizeInstall(value.root, () => Promise.resolve(value.catalogue))
    expect(result.before.pairs.length).toBe(extras ? 346 : 342)
    expect(result.after.pairs.length).toBe(342)
    expect(result.removed.length).toBe(extras ? 4 : 0)
    expect(
      (await finalizeInstall(value.root, () => Promise.resolve(value.catalogue))).removed,
    ).toEqual([])
  },
)
it.each(['forged-root-alias', '@forged/root-alias'])(
  'rejects undeclared root link %s before deleting any staged candidate',
  async (name) => {
    const value = fixture(true)
    const path = join(value.root, 'node_modules', name)
    const target = realpathSync(join(value.root, 'node_modules/vue'))
    mkdirSync(dirname(path), { recursive: true })
    symlinkSync(target, path, 'dir')
    const candidates = removable.map((pair) => {
      const candidate = value.paths.get(pair)
      if (!candidate) throw new Error(`Missing candidate fixture: ${pair}`)
      const payload = join(value.root, candidate, 'payload')
      const incoming = join(
        value.root,
        'node_modules/.pnpm',
        pair.startsWith('lightningcss-') ? 'lightningcss@1.33.0' : 'rolldown@1.2.13',
        'node_modules',
        pair.slice(0, pair.lastIndexOf('@')),
      )
      return { payload, bytes: readFileSync(payload), incoming, link: readlinkSync(incoming) }
    })
    const error = await finalizeInstall(value.root, () => Promise.resolve(value.catalogue)).then(
      () => undefined,
      (error: unknown) => error,
    )
    expect(error).toBeInstanceOf(Error)
    expect(error instanceof Error ? String(error.cause) : '').toContain(
      `Unknown root link: node_modules/${name}`,
    )
    for (const candidate of candidates) {
      expect(readFileSync(candidate.payload)).toEqual(candidate.bytes)
      expect(readlinkSync(candidate.incoming)).toBe(candidate.link)
    }
    expect(realpathSync(path)).toBe(target)
  },
)
it.each([
  'profile',
  'version',
  'layout',
  'current-lock',
  'scripts',
  'dependencies',
  'platform',
  'license',
  'notice',
  'nonoptional',
  'fifth',
])('fails preflight without deletion for %s', async (kind) => {
  const value = fixture(true)
  const key =
    kind === 'notice'
      ? 'lightningcss-linux-x64-musl@1.33.0'
      : '@rolldown/binding-linux-x64-musl@1.2.13'
  const path = value.paths.get(key) ?? ''
  const manifest = JSON.parse(
    readFileSync(join(value.root, path, 'package.json'), 'utf8'),
  ) as Record<string, unknown>
  if (kind === 'layout') value.put('node_modules/.modules.yaml', '{}')
  else if (kind === 'current-lock') value.put('node_modules/.pnpm/lock.yaml', 'changed')
  else if (kind === 'version') {
    manifest['version'] = '1.2.14'
    value.put(`${path}/package.json`, JSON.stringify(manifest))
  } else if (kind === 'profile') value.put('pnpm-workspace.yaml', 'changed')
  else if (kind === 'notice') value.put(`${path}/LICENSE`, 'bad')
  else if (kind === 'nonoptional')
    value.put(
      'pnpm-lock.yaml',
      readFileSync('pnpm-lock.yaml', 'utf8').replace('optionalDependencies:', 'dependencies:'),
    )
  else if (kind === 'fifth')
    value.put(
      'node_modules/.pnpm/fifth@1.0.0/node_modules/fifth/package.json',
      '{"name":"fifth","version":"1.0.0"}',
    )
  else {
    manifest[kind === 'platform' ? 'cpu' : kind] =
      kind === 'platform' ? ['x64', 'arm64'] : kind === 'license' ? 'ISC' : { bad: '1' }
    value.put(`${path}/package.json`, JSON.stringify(manifest))
  }
  await expect(
    finalizeInstall(value.root, () => Promise.resolve(value.catalogue)),
  ).rejects.toThrow()
  expect(readFileSync(join(value.root, path, 'payload'), 'utf8')).toContain('payload')
})

it.each(['eligible-bytes', 'parent-link', 'metadata', 'retained-link'])(
  'rejects concurrent changes during catalogue preflight: %s',
  async (kind) => {
    const value = fixture(true)
    const candidate = value.paths.get('@rolldown/binding-linux-x64-musl@1.2.13') ?? ''
    const eligible = value.paths.get('@babel/parser@7.29.9') ?? ''
    await expect(
      finalizeInstall(value.root, async () => {
        if (kind === 'eligible-bytes') value.put(`${eligible}/payload`, 'changed')
        else if (kind === 'metadata')
          value.put('node_modules/.pnpm-workspace-state-v1.json', '{"changed":true}')
        else if (kind === 'parent-link') {
          const { renameSync, symlinkSync } = await import('node:fs')
          renameSync(join(value.root, candidate), join(value.root, candidate + '-moved'))
          symlinkSync(candidate + '-moved', join(value.root, candidate), 'dir')
        } else {
          const { symlinkSync } = await import('node:fs')
          symlinkSync('payload', join(value.root, eligible, 'new-link'), 'file')
        }
        return value.catalogue
      }),
    ).rejects.toThrow('Installation is unaccepted')
    if (kind !== 'parent-link')
      expect(readFileSync(join(value.root, candidate, 'payload'), 'utf8')).toContain('payload')
  },
)
it('propagates catalogue failure without deleting any staged package', async () => {
  const value = fixture(true)
  await expect(
    finalizeInstall(value.root, () => Promise.reject(new Error('catalogue unavailable'))),
  ).rejects.toThrow('Installation is unaccepted')
  for (const [key, path] of value.paths)
    if (key.includes('musl'))
      expect(readFileSync(join(value.root, path, 'payload'), 'utf8')).toContain('payload')
})

it('rejects a parent directory replaced with byte-identical contents before removal', async () => {
  const value = fixture(true)
  const path = value.paths.get('@rolldown/binding-linux-x64-musl@1.2.13') ?? ''
  await expect(
    finalizeInstall(value.root, async () => {
      const { renameSync, cpSync } = await import('node:fs')
      const directory = join(value.root, path).slice(
        0,
        -'/node_modules/@rolldown/binding-linux-x64-musl'.length,
      )
      renameSync(directory, directory + '-old')
      cpSync(directory + '-old', directory, { recursive: true, dereference: false })
      // Keep the old inode outside the scanned tree to isolate the identity check.
      renameSync(directory + '-old', join(value.root, 'old-instance'))
      return value.catalogue
    }),
  ).rejects.toThrow('Installation is unaccepted')
})

it('leaves an interrupted mutation unaccepted and rejects reuse of that installation', async () => {
  const value = fixture(true)
  interruption.remaining = 2
  const error = await finalizeInstall(value.root, () => Promise.resolve(value.catalogue)).then(
    () => '',
    (error: unknown) => String(error),
  )
  expect(error).toContain('Installation is unaccepted')
  interruption.remaining = Number.POSITIVE_INFINITY
  const retry = await finalizeInstall(value.root, () => Promise.resolve(value.catalogue)).then(
    () => '',
    (error: unknown) => String(error),
  )
  expect(retry).toContain('Installation is unaccepted')
})

it('rejects special filesystem entries during complete preflight on every host', async () => {
  const value = fixture(true)
  const candidate = value.paths.get('@rolldown/binding-linux-x64-musl@1.2.13') ?? ''
  const eligible = value.paths.get('@babel/parser@7.29.9') ?? ''
  interruption.specialPath = join(value.root, eligible, 'payload')
  const error = await finalizeInstall(value.root, () => Promise.resolve(value.catalogue)).then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(error).toBeInstanceOf(Error)
  expect(error instanceof Error ? String(error.cause) : '').toContain('Special file')
  expect(readFileSync(join(value.root, candidate, 'payload'), 'utf8')).toContain('payload')
})

it('unlinks staged hardlinks without changing content-store or retained eligible bytes', async () => {
  const value = fixture(true)
  const { rmSync, linkSync } = await import('node:fs')
  const candidate = value.paths.get('@rolldown/binding-linux-x64-musl@1.2.13') ?? ''
  const eligible = value.paths.get('@babel/parser@7.29.9') ?? ''
  const bytes = readFileSync(join(value.root, eligible, 'payload'), 'utf8')
  value.put('cache/v11/package-payload', bytes)
  rmSync(join(value.root, candidate, 'payload'))
  linkSync(join(value.root, 'cache/v11/package-payload'), join(value.root, candidate, 'payload'))
  await finalizeInstall(value.root, () => Promise.resolve(value.catalogue))
  expect(readFileSync(join(value.root, 'cache/v11/package-payload'), 'utf8')).toBe(bytes)
  expect(readFileSync(join(value.root, eligible, 'payload'), 'utf8')).toBe(bytes)
})

it.each([
  'node_modules/.cache',
  'node_modules/.cache/prettier',
  'node_modules/.vite-temp',
  'node_modules/.vue-global-types',
  '.vite/cache',
])('rejects consumed installation before removal %s', async (path) => {
  const value = fixture(true)
  const { mkdirSync } = await import('node:fs')
  mkdirSync(join(value.root, path), { recursive: true })
  const result = await finalizeInstall(value.root, () => Promise.resolve(value.catalogue)).then(
    () => '',
    (error: unknown) => String(error),
  )
  expect(result).toContain('Installation is unaccepted')
  for (const [key, payload] of value.paths)
    if (key.includes('musl'))
      expect(readFileSync(join(value.root, payload, 'payload'), 'utf8')).toContain('payload')
})

it.each([
  '.vite/cache/deps/entry.js',
  'node_modules/.vue-global-types/vue_3.5_1.d.ts',
  'node_modules/.cache/prettier',
])('rejects a special generated entry in the read-only audit %s', async (path) => {
  const value = fixture()
  value.put(path, 'export {}')
  interruption.specialPath = join(value.root, path)
  const { installedPackages } = await import('../../scripts/installed-packages.ts')
  expect(() => installedPackages(value.root)).toThrow('Special generated output')
})
