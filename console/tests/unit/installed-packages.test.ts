import { afterEach, expect, it } from 'vitest'
import { mkdirSync, rmSync, symlinkSync, readFileSync, realpathSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { installedPackages, validateCatalogue } from '../../scripts/installed-packages.ts'
import { tree } from '../fixtures/dependencies/install-tree.ts'
const cleanups: (() => void)[] = []
afterEach(() => {
  cleanups.splice(0).forEach((cleanup) => {
    cleanup()
  })
})
function fixture(extras = false) {
  const result = tree(extras)
  cleanups.push(result.cleanup)
  return result
}
it('inventories all 342 eligible pairs and peer-qualified physical instances', () => {
  const value = fixture()
  const inventory = installedPackages(value.root)
  expect(new Set(inventory.instances.map((item) => item.pair)).size).toBe(342)
  expect(inventory.instances.some((item) => item.key.includes('('))).toBe(true)
  expect(validateCatalogue(inventory, value.catalogue).length).toBe(342)
})
it.each(['forged-root-alias', '@forged/root-alias'])(
  'rejects undeclared root link %s to a declared direct dependency',
  (name) => {
    const value = fixture()
    const path = join(value.root, 'node_modules', name)
    mkdirSync(dirname(path), { recursive: true })
    symlinkSync(realpathSync(join(value.root, 'node_modules/vue')), path, 'dir')
    expect(() => installedPackages(value.root)).toThrow(`Unknown root link: node_modules/${name}`)
  },
)
it.each([
  ['string-width-cjs', 'string-width@4.2.3'],
  ['strip-ansi-cjs', 'strip-ansi@6.0.1'],
  ['wrap-ansi-cjs', 'wrap-ansi@7.0.0'],
])('preserves the pinned dependency alias %s to %s', (name, target) => {
  const value = fixture()
  const inventory = installedPackages(value.root)
  const path = `node_modules/.pnpm/@isaacs+cliui@8.0.2/node_modules/${name}`
  expect(inventory.links[path]).toBeDefined()
  expect(realpathSync(join(value.root, path))).toBe(join(value.root, value.paths.get(target) ?? ''))
})
it('rejects installed excluded packages independently of the catalogue', () => {
  const value = fixture(true)
  expect(() => installedPackages(value.root)).toThrow('Excluded installed package')
})
it('requires every eligible physical instance despite nonempty catalogue paths', () => {
  const value = fixture()
  rmSync(join(value.root, value.paths.get('@babel/parser@7.29.9') ?? ''), { recursive: true })
  expect(() => installedPackages(value.root)).toThrow()
})
it.each(['hidden', 'escape', 'payload-link'])('rejects unknown or linked layout %s', (kind) => {
  const value = fixture()
  if (kind === 'hidden') value.put('node_modules/.hidden/package.json', '{}')
  else if (kind === 'escape') symlinkSync('/tmp', join(value.root, 'node_modules/escape'), 'dir')
  else {
    const payload = join(value.root, value.paths.get('@babel/parser@7.29.9') ?? '')
    rmSync(payload, { recursive: true })
    symlinkSync('/tmp', payload, 'dir')
  }
  expect(() => installedPackages(value.root)).toThrow()
})
it.each(['unknown', 'license', 'version', 'absent-path'])(
  'rejects catalogue evidence mismatch %s',
  (kind) => {
    const value = fixture()
    const inventory = installedPackages(value.root)
    const catalogue = structuredClone(value.catalogue)
    if (kind === 'unknown')
      catalogue['MIT']?.push({ name: 'unknown', versions: ['1.0.0'], paths: ['/tmp'] })
    else {
      const first = catalogue['MIT']?.[0] as Record<string, unknown>
      if (kind === 'license') {
        catalogue['ISC'] = [first]
        catalogue['MIT']?.shift()
      } else if (kind === 'version') first['versions'] = ['0.0.0']
      else first['paths'] = ['/tmp/nonexistent']
    }
    expect(() => validateCatalogue(inventory, catalogue)).toThrow()
  },
)

it('accepts cached candidate catalogue rows only after proving physical absence', () => {
  const value = fixture()
  value.catalogue['MIT']?.push({
    name: '@rolldown/binding-linux-x64-musl',
    versions: ['1.2.13'],
    paths: ['/absent/cache/package'],
  })
  expect(validateCatalogue(installedPackages(value.root), value.catalogue)).toHaveLength(342)
})
it('rejects cached metadata for any other excluded locked package', () => {
  const value = fixture()
  value.catalogue['MIT']?.push({
    name: '@esbuild/aix-ppc64',
    versions: ['0.25.12'],
    paths: ['/absent/cache/package'],
  })
  expect(() => validateCatalogue(installedPackages(value.root), value.catalogue)).toThrow(
    'Absent catalogue package',
  )
})
it.each(['alias', 'executable', 'internal-escape', 'junction', 'duplicate', 'peer-hidden'])(
  'rejects unsafe materialization %s',
  (kind) => {
    const value = fixture()
    const payload = value.paths.get('@babel/parser@7.29.9') ?? ''
    if (kind === 'alias')
      symlinkSync(join(value.root, payload), join(value.root, 'node_modules/forged-alias'), 'dir')
    else if (kind === 'executable') {
      value.put('node_modules/.bin/placeholder', '')
      symlinkSync(
        join(value.root, payload, 'payload'),
        join(value.root, 'node_modules/.bin/execute'),
        'file',
      )
    } else if (kind === 'internal-escape')
      symlinkSync(join(value.root, 'package.json'), join(value.root, payload, 'escape'), 'file')
    else if (kind === 'junction') {
      rmSync(join(value.root, payload), { recursive: true })
      symlinkSync(value.root, join(value.root, payload), 'junction')
    } else
      value.put(
        `node_modules/.pnpm/${kind === 'duplicate' ? 'duplicate' : '@babel+parser@7.29.9_unknown@1.0.0'}/node_modules/hidden/package.json`,
        '{}',
      )
    expect(() => installedPackages(value.root)).toThrow()
  },
)
it('allows contained package links while inventorying their exact targets', () => {
  const value = fixture()
  const payload = value.paths.get('@babel/parser@7.29.9') ?? ''
  symlinkSync('payload', join(value.root, payload, 'internal'), 'file')
  expect(installedPackages(value.root).links[`${payload}/internal`]).toBe('payload')
})
it('rejects a missing dependency link even when both payloads exist', () => {
  const value = fixture()
  const path = 'node_modules/.pnpm/@babel+generator@7.29.8/node_modules/@babel/parser'
  rmSync(join(value.root, path))
  expect(() => installedPackages(value.root)).toThrow('Missing dependency link')
})
it('rejects extra catalogue paths that do not prove installed evidence', () => {
  const value = fixture()
  const first = value.catalogue['MIT']?.[0] as { paths: string[] }
  first.paths.push('/absent/path')
  expect(() => validateCatalogue(installedPackages(value.root), value.catalogue)).toThrow(
    'Unverified catalogue path',
  )
})
it('rejects a manifest dependency class that differs from the frozen importer', () => {
  const value = fixture()
  const manifest = JSON.parse(readFileSync('package.json', 'utf8')) as {
    dependencies: Record<string, string>
    devDependencies: Record<string, string>
  }
  manifest.dependencies['vite'] = manifest.devDependencies['vite'] ?? ''
  delete manifest.devDependencies['vite']
  value.put('package.json', JSON.stringify(manifest))
  expect(() => installedPackages(value.root)).toThrow('Importer manifest mismatch')
})
it.each(['.hidden', 'node_modules/hidden'])(
  'rejects another materialized package hidden inside an eligible payload: %s',
  (subpath) => {
    const value = fixture()
    const payload = value.paths.get('@babel/parser@7.29.9') ?? ''
    value.put(
      `${payload}/${subpath}/package.json`,
      '{"name":"lightningcss-linux-x64-musl","version":"1.33.0","license":"MPL-2.0"}',
    )
    expect(() => installedPackages(value.root)).toThrow('Nested package')
  },
)
