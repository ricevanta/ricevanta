import { expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
it('audits HTML, graph provenance, lazy routes and Brotli closure budgets', async () => {
  expect(existsSync('scripts/audit-dist.ts')).toBe(true)
  if (!existsSync('scripts/audit-dist.ts')) return
  const { auditOutput } = await import('../../scripts/audit-dist.ts')
  const graph = {
    modules: ['/console/src/app/main.ts'],
    outputs: [] as { file: string; sha256: string; sources: string[] }[],
    copies: [],
    manifest: {
      'index.html': {
        file: 'assets/index-a.js',
        isEntry: true,
        dynamicImports: ['home', 'not-found'],
      },
      home: { file: 'assets/home-b.js', isDynamicEntry: true },
      'not-found': { file: 'assets/not-found-c.js', isDynamicEntry: true },
    },
  }
  const files = new Map([
    ['index.html', '<script type="module" src="/assets/index-a.js"></script>'],
    ['assets/index-a.js', 'export {}'],
    ['assets/home-b.js', 'export {}'],
    ['assets/not-found-c.js', 'export {}'],
    ['assets/OFL-BeVietnamPro.txt', 'SIL OPEN FONT LICENSE'],
  ])
  graph.outputs = [...files].map(([file, bytes]) => ({
    file,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    sources: ['/console/src/app/main.ts'],
  }))
  expect(auditOutput(files, graph, [])).toEqual([])
  expect(auditOutput(new Map([...files, ['assets/index-a.js', 'tampered']]), graph, [])).toContain(
    'provenance:assets/index-a.js',
  )
  expect(
    auditOutput(
      files,
      { ...graph, outputs: graph.outputs.map((output) => ({ ...output, sources: [] })) },
      [],
    ),
  ).toContain('provenance:assets/index-a.js')
  const axe = readFileSync(
    'node_modules/.pnpm/axe-core@4.11.4/node_modules/axe-core/axe.js',
    'utf8',
  )
  expect(auditOutput(new Map([...files, ['assets/axe.js', axe]]), graph, [])).toContain(
    'unrecorded:assets/axe.js',
  )
  expect(auditOutput(new Map([...files, ['assets/unknown.woff2', 'font']]), graph, [])).toContain(
    'unrecorded:assets/unknown.woff2',
  )
  for (const html of [
    '<script>alert(1)</script>',
    '<div style="color:red">',
    '<style>body{}</style>',
    '<img src="https://evil/x">',
    '<a href="javascript:alert(1)">',
    '<div onclick="alert(1)">',
    '<img src="data:x">',
  ])
    expect(
      auditOutput(new Map([...files, ['index.html', html]]), graph, []).length,
    ).toBeGreaterThan(0)
  for (const path of ['assets/x.js.map', 'tests/probe.js', 'assets/worker.js'])
    expect(auditOutput(new Map([...files, [path, '']]), graph, []).length).toBeGreaterThan(0)
  for (const name of ['@vue/compiler-core', '@intlify/message-compiler'])
    expect(
      auditOutput(files, { ...graph, modules: [`/node_modules/${name}/index.js`] }, []).length,
    ).toBeGreaterThan(0)
  for (const normalized of ['MPL-2.0', 'BlueOak-1.0.0', 'Python-2.0.1']) {
    const inventory = [
      {
        name: 'argparse',
        version: '2.0.1',
        declared: normalized === 'Python-2.0.1' ? 'Python-2.0' : normalized,
        normalized,
        paths: ['/node_modules/argparse'],
      },
    ]
    expect(
      auditOutput(files, { ...graph, modules: ['/node_modules/argparse/index.js'] }, inventory)
        .length,
    ).toBeGreaterThan(0)
    expect(
      auditOutput(
        files,
        {
          ...graph,
          copies: [{ source: '/node_modules/argparse/LICENSE', target: 'assets/LICENSE' }],
        },
        inventory,
      ).length,
    ).toBeGreaterThan(0)
  }
  expect(
    auditOutput(
      files,
      {
        ...graph,
        manifest: {
          ...graph.manifest,
          'index.html': { ...graph.manifest['index.html'], imports: ['home'] },
        },
      },
      [],
    ).length,
  ).toBeGreaterThan(0)
})
it('rejects entry and lazy route closures over their Brotli budgets', async () => {
  const { auditOutput } = await import('../../scripts/audit-dist.ts')
  let seed = 0x52495641
  const bytes = Uint8Array.from({ length: 350000 }, () => {
    seed ^= seed << 13
    seed ^= seed >>> 17
    seed ^= seed << 5
    return seed & 255
  })
  const source = Buffer.from(bytes).toString('base64')
  const graph = {
    modules: [],
    outputs: [] as { file: string; sha256: string; sources: string[] }[],
    copies: [],
    manifest: {
      entry: { file: 'assets/entry-a.js', isEntry: true, dynamicImports: ['home', 'not-found'] },
      home: { file: 'assets/home-b.js', isDynamicEntry: true },
      'not-found': { file: 'assets/not-found-c.js', isDynamicEntry: true },
    },
  }
  const files = new Map([
    ['index.html', '<script type="module" src="/assets/entry-a.js"></script>'],
    ['assets/entry-a.js', source],
    ['assets/home-b.js', source],
    ['assets/not-found-c.js', 'export {}'],
    ['assets/OFL-BeVietnamPro.txt', 'SIL OPEN FONT LICENSE'],
  ])
  expect(auditOutput(files, graph, [])).toContain('entry-budget')
  expect(auditOutput(files, graph, [])).toContain('route-budget:home')
})
it('compresses deterministically and preserves binary assets', async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const { compress } = await import('../../scripts/compress.ts')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-compression-'))
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'export const value=1')
    fs.writeFileSync(path.join(root, 'a.woff2'), 'font')
    compress(root)
    const first = fs.readFileSync(path.join(root, 'a.js.gz'))
    const br = fs.readFileSync(path.join(root, 'a.js.br'))
    compress(root)
    expect(fs.readFileSync(path.join(root, 'a.js.gz'))).toEqual(first)
    expect(fs.readFileSync(path.join(root, 'a.js.br'))).toEqual(br)
    expect(existsSync(path.join(root, 'a.woff2.br'))).toBe(false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

it('inventories binary assets and rejects unrecorded binary bytes', async () => {
  const fs = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const path = await import('node:path')
  const { auditOutput, distFiles } = await import('../../scripts/audit-dist.ts')
  const root = fs.mkdtempSync(path.join(tmpdir(), 'rv-provenance-'))
  try {
    fs.mkdirSync(path.join(root, 'assets'))
    const bytes = Buffer.from([0, 255, 128, 1])
    fs.writeFileSync(path.join(root, 'assets/font.woff2'), bytes)
    fs.writeFileSync(path.join(root, 'assets/icon.png'), bytes)
    const files = distFiles(root)
    expect(files.get('assets/font.woff2')).toEqual(bytes)
    expect(files.get('assets/icon.png')).toEqual(bytes)
    expect(auditOutput(files, { modules: [], copies: [], manifest: {} }, [])).toContain(
      'unrecorded:assets/font.woff2',
    )
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
it('checks licenses of each recorded output source on every path format', async () => {
  const { auditOutput } = await import('../../scripts/audit-dist.ts')
  const bytes = 'forbidden code'
  for (const source of [
    '/node_modules/axe-core/axe.js',
    'C:\\console\\node_modules\\axe-core\\axe.js',
  ]) {
    const root = source.slice(0, -7)
    const graph = {
      modules: [],
      copies: [],
      manifest: {},
      outputs: [
        {
          file: 'assets/axe.js',
          sha256: createHash('sha256').update(bytes).digest('hex'),
          sources: [source],
        },
      ],
    }
    const inventory = [
      {
        name: 'axe-core',
        version: '4.11.4',
        declared: 'MPL-2.0',
        normalized: 'MPL-2.0',
        paths: [root],
      },
    ]
    expect(auditOutput(new Map([['assets/axe.js', bytes]]), graph, inventory)).toContain(
      `license:${source}`,
    )
  }
})

it.each(['module', 'copy', 'output'])(
  'rejects real braces exception code through %s provenance',
  async (kind) => {
    const { auditOutput } = await import('../../scripts/audit-dist.ts')
    const bytes = readFileSync('node_modules/.pnpm/braces@3.0.3/node_modules/braces/index.js')
    expect(bytes.byteLength).toBe(4380)
    const files = new Map<string, string | Uint8Array>([
      ['index.html', '<script type="module" src="/assets/entry.js"></script>'],
      ['assets/entry.js', 'export {}'],
      ['assets/home.js', 'export {}'],
      ['assets/not-found.js', 'export {}'],
      ['assets/OFL-BeVietnamPro.txt', 'SIL OPEN FONT LICENSE'],
      ['assets/braces.js', bytes],
    ])
    for (const root of [
      '/console/node_modules/.pnpm/braces@3.0.3/node_modules/braces',
      'C:\\console\\node_modules\\.pnpm\\braces@3.0.3\\node_modules\\braces',
    ]) {
      const source = `${root}/index.js`
      const graph = {
        modules: kind === 'module' ? [source] : [],
        copies: kind === 'copy' ? [{ source, target: 'assets/braces.js' }] : [],
        outputs: [...files].map(([file, content]) => ({
          file,
          sha256: createHash('sha256').update(content).digest('hex'),
          sources:
            file === 'assets/braces.js' && kind === 'output'
              ? [source]
              : ['/console/src/app/main.ts'],
        })),
        manifest: {
          entry: { file: 'assets/entry.js', isEntry: true },
          home: { file: 'assets/home.js', isDynamicEntry: true },
          'not-found': { file: 'assets/not-found.js', isDynamicEntry: true },
        },
      }
      const inventory = [
        { name: 'braces', version: '3.0.3', declared: 'MIT', normalized: 'MIT', paths: [root] },
      ]
      expect(auditOutput(files, graph, inventory)).toEqual([`osv-exception:${source}`])
      const exceptions = JSON.parse(readFileSync('security/osv-exceptions.json', 'utf8')) as {
        package: string
        dependencyPath: { package: string; version: string }[]
      }[]
      const otherExceptions = exceptions.map((entry) => ({
        ...entry,
        package: 'other-tool',
        dependencyPath: entry.dependencyPath.map((node) => ({
          ...node,
          package: node.package === 'braces' ? 'other-tool' : node.package,
        })),
      }))
      expect(
        auditOutput(
          files,
          graph,
          inventory.map((pkg) => ({ ...pkg, name: 'other-tool' })),
          JSON.stringify(otherExceptions),
        ),
      ).toEqual([`osv-exception:${source}`])
      expect(() => auditOutput(files, graph, inventory, '{')).toThrow('Invalid OSV exception file')
      expect(() => auditOutput(files, graph, inventory, '[{}]')).toThrow('invalid exception')
      const cleanFiles = new Map(files)
      cleanFiles.delete('assets/braces.js')
      expect(
        auditOutput(
          cleanFiles,
          {
            ...graph,
            modules: [],
            copies: [],
            outputs: graph.outputs.filter((output) => output.file !== 'assets/braces.js'),
          },
          inventory,
        ),
      ).toEqual([])
    }
  },
)
