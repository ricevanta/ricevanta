import { expect, it } from 'vitest'
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { promisify } from 'node:util'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { auditOutput, canonical, distFiles } from '../../scripts/audit-dist.ts'
import type { BuildGraph } from '../../scripts/audit-dist.ts'

it('attributes extracted zero-length CSS modules and rejects forbidden licenses', async () => {
  const root = mkdtempSync(join(tmpdir(), 'rv-css-provenance-'))
  try {
    mkdirSync(join(root, 'public/brand'), { recursive: true })
    mkdirSync(join(root, 'node_modules/forbidden-css'), { recursive: true })
    mkdirSync(join(root, 'node_modules/@fontsource'), { recursive: true })
    symlinkSync(
      resolve('node_modules/@fontsource/be-vietnam-pro'),
      join(root, 'node_modules/@fontsource/be-vietnam-pro'),
    )
    const packageRoot = join(root, 'node_modules/forbidden-css')
    const source = join(packageRoot, 'style.css')
    writeFileSync(
      join(packageRoot, 'package.json'),
      JSON.stringify({ name: 'forbidden-css', version: '1.0.0', license: 'MPL-2.0' }),
    )
    writeFileSync(source, '.forbidden { color: red }')
    writeFileSync(join(root, 'main.js'), "import 'forbidden-css/style.css'; console.log('fixture')")
    writeFileSync(join(root, 'index.html'), '<script type="module" src="/main.js"></script>')
    await promisify(execFile)(process.execPath, [
      resolve('tests/fixtures/build/css-provenance.ts'),
      root,
    ])
    const zeroLength: unknown = JSON.parse(readFileSync(join(root, 'zero-length-css.json'), 'utf8'))
    expect(zeroLength).toContain(source)
    const graph = JSON.parse(
      readFileSync(join(root, '.vite/build-graph.json'), 'utf8'),
    ) as BuildGraph
    expect(graph.modules).not.toContain(source)
    const css = graph.outputs?.find((output) => output.file.endsWith('.css'))
    if (!css) throw new Error('Missing CSS output')
    expect(css.sources).toContain(source)
    const files = distFiles(join(root, 'dist'))
    expect(Buffer.from(files.get(css.file) ?? '').toString()).toContain('.forbidden')
    const inventory = [
      {
        name: 'forbidden-css',
        version: '1.0.0',
        declared: 'MPL-2.0',
        normalized: 'MPL-2.0',
        paths: [canonical(packageRoot)],
      },
    ]
    expect(auditOutput(files, graph, inventory)).toContain(`license:${source}`)
    expect(
      auditOutput(
        files,
        graph,
        inventory.map((pkg) => ({ ...pkg, declared: 'MIT', normalized: 'MIT' })),
      ),
    ).not.toContain(`license:${source}`)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
