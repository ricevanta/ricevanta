import { afterEach, expect, it, vi } from 'vitest'
import {
  mkdirSync,
  rmSync,
  symlinkSync,
  readFileSync,
  linkSync,
  chmodSync,
  writeFileSync,
  realpathSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { installedPackages, validateCatalogue } from '../../scripts/installed-packages.ts'
import { tree } from '../fixtures/dependencies/install-tree.ts'
const generatedStat = vi.hoisted(() => ({ executablePath: '', badNameDirectory: '' }))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    lstatSync: (...args: Parameters<typeof actual.lstatSync>) => {
      const stat = actual.lstatSync(...args)
      if (!stat || String(args[0]) !== generatedStat.executablePath) return stat
      return new Proxy(stat, {
        get(target, key, receiver): unknown {
          if (key === 'mode')
            return typeof target.mode === 'bigint' ? target.mode | 0o111n : target.mode | 0o111
          return Reflect.get(target, key, receiver) as unknown
        },
      })
    },
    readdirSync: (...args: Parameters<typeof actual.readdirSync>) => {
      if (String(args[0]) === generatedStat.badNameDirectory) return ['back\\slash.js']
      return actual.readdirSync(...args)
    },
  }
})
const cleanups: (() => void)[] = []
afterEach(() => {
  generatedStat.executablePath = ''
  generatedStat.badNameDirectory = ''
  cleanups.splice(0).forEach((cleanup) => {
    cleanup()
  })
})
function fixture(extras = false) {
  const result = tree(extras)
  cleanups.push(result.cleanup)
  return result
}
function groupedShared(value: ReturnType<typeof fixture>) {
  const row = {
    name: '@intlify/shared',
    versions: ['10.0.8', '11.4.12', '11.4.13'],
    paths: ['10.0.8', '11.4.12', '11.4.13'].map((version) =>
      join(value.root, value.paths.get(`@intlify/shared@${version}`) ?? ''),
    ),
    license: 'MIT',
  }
  value.catalogue['MIT'] = (value.catalogue['MIT'] ?? []).filter(
    (item) => !(item && typeof item === 'object' && 'name' in item && item.name === row.name),
  )
  value.catalogue['MIT'].push(row)
  return row
}
it('inventories all 342 eligible pairs and peer-qualified physical instances', () => {
  const value = fixture()
  const inventory = installedPackages(value.root)
  expect(new Set(inventory.instances.map((item) => item.pair)).size).toBe(342)
  expect(inventory.instances.some((item) => item.key.includes('('))).toBe(true)
  expect(validateCatalogue(inventory, value.catalogue).length).toBe(342)
})
it.each([false, true])(
  'validates grouped catalogue versions with reordered paths=%s',
  (reverse) => {
    const value = fixture()
    const row = groupedShared(value)
    if (reverse) row.paths.reverse()
    const result = validateCatalogue(installedPackages(value.root), value.catalogue)
    expect(result).toHaveLength(342)
    expect(result.filter((item) => item.name === '@intlify/shared')).toEqual(
      ['10.0.8', '11.4.12', '11.4.13'].map((version) => ({
        name: '@intlify/shared',
        version,
        declared: 'MIT',
        paths: [join(value.root, value.paths.get(`@intlify/shared@${version}`) ?? '')],
      })),
    )
  },
)
it.each([false, true])(
  'validates grouped dependency-alias evidence with missing alias=%s',
  (missing) => {
    const value = fixture()
    value.catalogue['MIT'] = (value.catalogue['MIT'] ?? []).filter(
      (item) =>
        !(item && typeof item === 'object' && 'name' in item && item.name === 'string-width'),
    )
    const row = {
      name: 'string-width',
      versions: ['4.2.3', '5.1.2'],
      paths: ['string-width', 'string-width-cjs'].map((name) =>
        join(value.root, 'node_modules/.pnpm/@isaacs+cliui@8.0.2/node_modules', name),
      ),
      license: 'MIT',
    }
    value.catalogue['MIT'].push(row)
    if (missing) {
      row.paths.pop()
      expect(() => validateCatalogue(installedPackages(value.root), value.catalogue)).toThrow(
        'Missing physical catalogue path: string-width@4.2.3',
      )
      return
    }
    expect(
      validateCatalogue(installedPackages(value.root), value.catalogue).filter(
        (item) => item.name === 'string-width',
      ),
    ).toEqual(
      ['4.2.3', '5.1.2'].map((version) => ({
        name: 'string-width',
        version,
        declared: 'MIT',
        paths: [join(value.root, value.paths.get(`string-width@${version}`) ?? '')],
      })),
    )
  },
)
it.each([
  ['missing-oldest-path', 'Missing physical catalogue path: @intlify/shared@10.0.8'],
  ['missing-middle-path', 'Missing physical catalogue path: @intlify/shared@11.4.12'],
  ['duplicate-other-version-path', 'Missing physical catalogue path: @intlify/shared@11.4.12'],
  ['unlisted-version-path', 'Unverified catalogue path: @intlify/shared@10.0.8'],
  ['omitted-version-evidence', 'Missing eligible license evidence: @intlify/shared@11.4.13'],
  ['unknown-version', 'Unknown catalogue row: @intlify/shared@99.0.0'],
  ['other-package-path', 'Unverified catalogue path: @intlify/shared@10.0.8'],
  ['absent-path', 'Unverified catalogue path: @intlify/shared@10.0.8'],
  ['relative-path', 'Unverified catalogue path: @intlify/shared@10.0.8'],
  ['wrong-license', 'Catalogue license mismatch: @intlify/shared@10.0.8'],
])('rejects incomplete or mismatched grouped catalogue evidence: %s', (kind, cause) => {
  const value = fixture()
  const row = groupedShared(value)
  if (kind === 'missing-oldest-path') row.paths.shift()
  else if (kind === 'missing-middle-path') row.paths.splice(1, 1)
  else if (kind === 'duplicate-other-version-path') row.paths[1] = row.paths[0] ?? ''
  else if (kind === 'unlisted-version-path') row.versions.pop()
  else if (kind === 'omitted-version-evidence') {
    row.versions.pop()
    row.paths.pop()
  } else if (kind === 'unknown-version') row.versions.push('99.0.0')
  else if (kind === 'other-package-path')
    row.paths.push(join(value.root, value.paths.get('@babel/parser@7.29.9') ?? ''))
  else if (kind === 'absent-path') row.paths.push(join(value.root, 'absent'))
  else if (kind === 'relative-path') row.paths.push('node_modules/@intlify/shared')
  else {
    value.catalogue['MIT'] = (value.catalogue['MIT'] ?? []).filter((item) => item !== row)
    row.license = 'ISC'
    value.catalogue['ISC'] = [row]
  }
  expect(() => validateCatalogue(installedPackages(value.root), value.catalogue)).toThrow(cause)
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

it.each([
  'node_modules/.cache',
  'node_modules/.cache/prettier',
  'node_modules/.vite-temp',
  'node_modules/.vue-global-types',
  '.vite/cache',
  '.vite/cache/deps',
])('audits exact generated scaffold %s without package evidence', (path) => {
  const value = fixture()
  mkdirSync(join(value.root, path), { recursive: true })
  const inventory = installedPackages(value.root)
  expect(inventory.pairs).toHaveLength(342)
  expect(inventory.generated).toHaveProperty(path)
})
it('inventories the exact reviewed generated Vue declaration', () => {
  const value = fixture()
  value.put(
    'node_modules/.vue-global-types/vue_3.5_1.d.ts',
    readFileSync('tests/fixtures/dependencies/vue-global-types.txt', 'utf8'),
  )
  expect(
    installedPackages(value.root).generated['node_modules/.vue-global-types/vue_3.5_1.d.ts']
      ?.sha256,
  ).toBe('c0839b07826141fc02396e0bd396f77da30e7d5eb5c46331a03c103fcdccd1e2')
})
it.each([
  '.cache/package.json',
  '.cache/prettier/package.json',
  '.vite-temp/package.json',
  '.vue-global-types/package.json',
  '.cache/prettier/file',
  '.vite-temp/module.mjs',
  '.vue-global-types/vue_3.5_0.d.ts',
  '.vue-global-types/Vue_3.5_1.d.ts',
  '.cache/other/file',
  '.vite/result.json',
])('rejects unapproved installed generated output %s', (path) => {
  const value = fixture()
  value.put(`node_modules/${path}`, '{}')
  expect(() => installedPackages(value.root)).toThrow()
})
it.each(['byte', 'size', 'hardlink', 'symlink', 'executable'])(
  'rejects modified generated declaration %s',
  (kind) => {
    const value = fixture()
    const path = 'node_modules/.vue-global-types/vue_3.5_1.d.ts'
    const content = readFileSync('tests/fixtures/dependencies/vue-global-types.txt', 'utf8')
    value.put(
      path,
      kind === 'byte' ? 'X' + content.slice(1) : kind === 'size' ? content + '\n' : content,
    )
    if (kind === 'hardlink')
      linkSync(join(value.root, path), join(value.root, 'linked-declaration'))
    if (kind === 'symlink') {
      rmSync(join(value.root, path))
      symlinkSync(join(value.root, 'package.json'), join(value.root, path), 'file')
    }
    if (kind === 'executable') {
      chmodSync(join(value.root, path), 0o755)
      generatedStat.executablePath = join(value.root, path)
    }
    expect(() => installedPackages(value.root)).toThrow()
  },
)
it('enumerates relocated optimizer output and exact type-only manifest', () => {
  const value = fixture()
  for (const extension of ['js', 'mjs', 'json', 'map', 'css'])
    value.put(`.vite/cache/deps/entry.${extension}`, '{}')
  value.put('.vite/cache/deps/package.json', '{\n  "type": "module"\n}\n')
  const inventory = installedPackages(value.root)
  expect(Object.keys(inventory.generated).filter((path) => path.endsWith('.js'))).toEqual([
    '.vite/cache/deps/entry.js',
  ])
  expect(inventory.pairs).toHaveLength(342)
})
it.each([
  'node_modules/hidden.js',
  '.pnpm/hidden.js',
  '.bin/hidden.js',
  'deps/package.json',
  'deps/Package.json',
  'deps/addon.node',
  'deps/.hidden',
  'deps/entry.JS',
  'deps/back\\slash.js',
])('rejects invalid relocated cache content %s', (path) => {
  const value = fixture()
  if (path.includes('\\')) {
    value.put('.vite/cache/deps/valid.js', '{}')
    generatedStat.badNameDirectory = join(value.root, '.vite/cache/deps')
  } else value.put(`.vite/cache/${path}`, '{}')
  expect(() => installedPackages(value.root)).toThrow()
})
it.each(['elf', 'pe', 'macho', 'wasm', 'executable', 'hardlink', 'link', 'package-link'])(
  'rejects unsafe relocated cache payload %s',
  (kind) => {
    const value = fixture()
    value.put('.vite/cache/deps/payload.js', '{}')
    const path = join(value.root, '.vite/cache/deps/payload.js')
    if (['elf', 'pe', 'macho', 'wasm'].includes(kind))
      writeFileSync(
        path,
        Buffer.from(
          kind === 'elf'
            ? [127, 69, 76, 70]
            : kind === 'pe'
              ? [77, 90]
              : kind === 'macho'
                ? [254, 237, 250, 207]
                : [0, 97, 115, 109],
        ),
      )
    if (kind === 'executable') {
      chmodSync(path, 0o755)
      generatedStat.executablePath = path
    }
    if (kind === 'hardlink') linkSync(path, join(value.root, 'cache-link'))
    if (kind === 'link') symlinkSync(path, join(value.root, '.vite/cache/deps/linked.js'), 'file')
    if (kind === 'package-link')
      symlinkSync(path, join(value.root, 'node_modules/cache-package'), 'file')
    expect(() => installedPackages(value.root)).toThrow()
  },
)
it.each([
  'node_modules/.cache',
  'node_modules/.cache/prettier',
  'node_modules/.vite-temp',
  'node_modules/.vue-global-types',
  '.vite',
  '.vite/cache',
])('rejects linked generated directory component %s', (path) => {
  const value = fixture()
  mkdirSync(dirname(join(value.root, path)), { recursive: true })
  symlinkSync(value.root, join(value.root, path), 'junction')
  expect(() => installedPackages(value.root)).toThrow()
})

it('rejects a directory masquerading as the generated declaration file', () => {
  const value = fixture()
  mkdirSync(join(value.root, 'node_modules/.vue-global-types/vue_3.5_1.d.ts'), { recursive: true })
  expect(() => installedPackages(value.root)).toThrow()
})

it('classifies actual pinned producer output from a fresh inert fixture', async () => {
  const { mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { runTool } = await import('../../scripts/run-tool.ts')
  const { generatedOutput } = await import('../../scripts/installed-packages.ts')
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'rv-generated-output-')))
  try {
    mkdirSync(join(root, 'node_modules'))
    writeFileSync(
      join(root, 'package.json'),
      '{"name":"inert-generated-output","private":true,"type":"module"}\n',
    )
    writeFileSync(join(root, 'sample.ts'), 'export const value = 1;\n')
    expect(
      (
        await runTool(
          process.execPath,
          [resolve('node_modules/prettier/bin/prettier.cjs'), '--check', 'sample.ts'],
          root,
        )
      ).code,
    ).toBe(0)
    expect(generatedOutput(root)).toHaveProperty('node_modules/.cache/prettier')
    writeFileSync(
      join(root, 'vitest.config.mjs'),
      "import { fileURLToPath } from 'node:url'\nexport default { cacheDir: fileURLToPath(new URL('./.vite/cache', import.meta.url)), test: { globals: true, include: ['sample.test.ts'], environment: 'node' } }\n",
    )
    writeFileSync(
      join(root, 'sample.test.ts'),
      "test('inert generated output', () => { expect(1).toBe(1) })\n",
    )
    expect(
      (
        await runTool(
          process.execPath,
          [resolve('node_modules/vitest/vitest.mjs'), 'run', '--config', 'vitest.config.mjs'],
          root,
        )
      ).code,
    ).toBe(0)
    expect(
      Object.keys(generatedOutput(root)).some(
        (path) => path.startsWith('.vite/cache/vitest/') && path.endsWith('/results.json'),
      ),
    ).toBe(true)
    symlinkSync(realpathSync('node_modules/vue'), join(root, 'node_modules/vue'), 'dir')
    writeFileSync(
      join(root, 'sample.vue'),
      '<script setup lang="ts">\nconst value = 1\n</script>\n<template><div>{{ value }}</div></template>\n',
    )
    writeFileSync(
      join(root, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          strict: true,
          noEmit: true,
          skipLibCheck: true,
          target: 'ES2022',
          module: 'ESNext',
          moduleResolution: 'Bundler',
          lib: ['ES2022', 'DOM'],
          types: [],
        },
        include: ['sample.vue'],
        vueCompilerOptions: { strictTemplates: true },
      }),
    )
    expect(
      (
        await runTool(
          process.execPath,
          [resolve('node_modules/vue-tsc/bin/vue-tsc.js'), '--noEmit', '-p', 'tsconfig.json'],
          root,
        )
      ).code,
    ).toBe(0)
    expect(generatedOutput(root)['node_modules/.vue-global-types/vue_3.5_1.d.ts']?.sha256).toBe(
      'c0839b07826141fc02396e0bd396f77da30e7d5eb5c46331a03c103fcdccd1e2',
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}, 30000)

it.each([
  '{\n  "type": "module"\n}',
  '{\r\n  "type": "module"\r\n}\r\n',
  '{"type":"module"}\n',
  '{\n  "type": "module",\n  "name": "hidden-package"\n}\n',
])('rejects nonexact Vite cache package manifest %s', (content) => {
  const value = fixture()
  value.put('.vite/cache/deps/package.json', content)
  expect(() => installedPackages(value.root)).toThrow('Package manifest in cache')
})
it.each(['deps/unicode-é.js', 'node_modules/.hidden/package.json'])(
  'rejects nonconforming cache names or nested packages %s',
  (path) => {
    const value = fixture()
    value.put(`.vite/cache/${path}`, '{}')
    expect(() => installedPackages(value.root)).toThrow()
  },
)
