import { expect, it } from 'vitest'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import {
  existsSync,
  mkdtempSync,
  writeFileSync,
  mkdirSync,
  symlinkSync,
  rmSync,
  readFileSync,
  readdirSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
it('enforces traversal, hosts, methods, MIME, compression and fallback boundaries', async () => {
  expect(existsSync('scripts/serve-dist.ts')).toBe(true)
  if (!existsSync('scripts/serve-dist.ts')) return
  const { serveFile } = await import('../../scripts/serve-dist.ts')
  const root = mkdtempSync(join(tmpdir(), 'rv-serving-'))
  try {
    writeFileSync(join(root, 'index.html'), '<h1>shell</h1>')
    mkdirSync(join(root, 'assets'))
    writeFileSync(join(root, 'assets/test-a.js'), 'export {}')
    writeFileSync(join(root, 'assets/test-a.js.br'), 'compressed')
    symlinkSync('/etc/passwd', join(root, 'assets/external.js'))
    const request = {
      url: '/',
      method: 'GET',
      host: '127.0.0.1:4173',
      accept: 'text/html',
      encoding: '',
    }
    mkdirSync(join(root, 'probes'))
    expect(
      serveFile(root, { ...request, url: '/__test__/missing' }, join(root, 'probes')).status,
    ).toBe(404)
    writeFileSync(join(root, 'probes/index.html'), '<h1>probe</h1>')
    expect(
      serveFile(root, { ...request, url: '/__test__/missing' }, join(root, 'probes')).status,
    ).toBe(404)
    expect(serveFile(root, request).status).toBe(200)
    expect(serveFile(root, { ...request, accept: '*/*' }).status).toBe(200)
    for (const url of [
      '/../etc/passwd',
      '/%2e%2e/etc/passwd',
      '/assets%2fexternal.js',
      '/assets%5cexternal.js',
      '/%00',
      '/assets/external.js',
    ])
      expect(serveFile(root, { ...request, url }).status).toBe(400)
    expect(serveFile(root, { ...request, host: 'evil.test' }).status).toBe(400)
    expect(serveFile(root, { ...request, method: 'POST' }).status).toBe(405)
    for (const url of [
      '/api/missing',
      '/agent/a',
      '/ext/a',
      '/assets/missing',
      '/brand/missing',
      '/mdm/a',
      '/scep',
      '/acme/a',
      '/__test__/missing',
    ])
      expect(serveFile(root, { ...request, url }).status).toBe(404)
    expect(serveFile(root, { ...request, url: '/unknown?secret=hidden' }).body.toString()).toBe(
      '<h1>shell</h1>',
    )
    expect(
      serveFile(root, { ...request, url: '/unknown', accept: 'application/json' }).status,
    ).toBe(404)
    const compressed = serveFile(root, {
      ...request,
      url: '/assets/test-a.js',
      encoding: 'gzip;q=0, br;q=1',
    })
    expect(compressed.headers['Content-Encoding']).toBe('br')
    expect(compressed.headers['Content-Type']).toBe('text/javascript; charset=utf-8')
    expect(
      serveFile(root, { ...request, url: '/assets/test-a.js', encoding: 'br;q=0' }).headers[
        'Content-Encoding'
      ],
    ).toBeUndefined()
    expect(serveFile(root, { ...request, method: 'HEAD' }).body.length).toBe(0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

it.each([
  ['OFL-BeVietnamPro.txt', 'text/plain; charset=utf-8', 'no-cache'],
  ['fixed-name.css', 'text/css; charset=utf-8', 'no-cache'],
  ['app-settings.json', 'application/json; charset=utf-8', 'no-cache'],
  ['OFL-LICENSES.txt', 'text/plain; charset=utf-8', 'no-cache'],
  ['theme-standard.css', 'text/css; charset=utf-8', 'no-cache'],
  ['index-Da_9-bX2.js', 'text/javascript; charset=utf-8', 'public, max-age=31536000, immutable'],
  ['styles-Ab12Cd34.css', 'text/css; charset=utf-8', 'public, max-age=31536000, immutable'],
])('serves %s with its cache policy', async (name, mime, cache) => {
  const { serveFile } = await import('../../scripts/serve-dist.ts')
  const root = mkdtempSync(join(tmpdir(), 'rv-cache-'))
  try {
    mkdirSync(join(root, 'assets'))
    writeFileSync(join(root, 'assets', name), 'asset')
    mkdirSync(join(root, '.vite'))
    writeFileSync(
      join(root, '.vite/manifest.json'),
      JSON.stringify({
        entry: { file: 'assets/index-Da_9-bX2.js', css: ['assets/styles-Ab12Cd34.css'] },
      }),
    )
    const result = serveFile(root, {
      url: `/assets/${name}`,
      method: 'GET',
      host: '127.0.0.1:4173',
      accept: '*/*',
      encoding: '',
    })
    expect(result.status).toBe(200)
    expect(result.headers['Content-Type']).toBe(mime)
    expect(result.headers['Cache-Control']).toBe(cache)
    expect(result.body.toString()).toBe('asset')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

const assetRequest = {
  url: '/assets/index-Ab12Cd34.js',
  method: 'GET',
  host: '127.0.0.1:4173',
  accept: '*/*',
  encoding: '',
}

it.each([
  undefined,
  '{',
  'null',
  '[]',
  '{"entry":null}',
  '{"entry":{"file":42}}',
  '{"entry":{"file":"assets/index-Ab12Cd34.js","css":"assets/style.css"}}',
  '{"entry":{"file":"assets/index-Ab12Cd34.js","assets":[42]}}',
  '{"entry":{"file":"assets/index-Ab12Cd34.js"},"broken":null}',
])('uses no-cache when the manifest is missing or malformed: %s', async (manifest) => {
  const { serveFile } = await import('../../scripts/serve-dist.ts')
  const root = mkdtempSync(join(tmpdir(), 'rv-cache-manifest-'))
  try {
    mkdirSync(join(root, 'assets'))
    writeFileSync(join(root, 'assets/index-Ab12Cd34.js'), 'asset')
    if (manifest !== undefined) {
      mkdirSync(join(root, '.vite'))
      writeFileSync(join(root, '.vite/manifest.json'), manifest)
    }
    const result = serveFile(root, assetRequest)
    expect(result.status).toBe(200)
    expect(result.headers['Cache-Control']).toBe('no-cache')
    expect(result.body.toString()).toBe('asset')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

it.each(['file', 'css', 'assets'])(
  'uses manifest %s outputs without guessing hash length',
  async (field) => {
    const { serveFile } = await import('../../scripts/serve-dist.ts')
    const root = mkdtempSync(join(tmpdir(), 'rv-cache-output-'))
    try {
      mkdirSync(join(root, 'assets'))
      mkdirSync(join(root, '.vite'))
      const file = 'assets/index-contenthashlong.js'
      writeFileSync(join(root, file), 'asset')
      writeFileSync(
        join(root, '.vite/manifest.json'),
        JSON.stringify({
          entry: { file: 'assets/entry.js', [field]: field === 'file' ? file : [file] },
        }),
      )
      const result = serveFile(root, { ...assetRequest, url: `/${file}`, method: 'HEAD' })
      expect(result.status).toBe(200)
      expect(result.headers['Cache-Control']).toBe('public, max-age=31536000, immutable')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  },
)

it('keeps every hashed asset from a real console build immutable', async () => {
  const { serveFile } = await import('../../scripts/serve-dist.ts')
  const root = mkdtempSync(join(tmpdir(), 'rv-cache-build-'))
  try {
    await promisify(execFile)('pnpm', ['exec', 'vite', 'build', '--outDir', root])
    const manifest = JSON.parse(readFileSync(join(root, '.vite/manifest.json'), 'utf8')) as Record<
      string,
      { file: string; css?: string[]; assets?: string[] }
    >
    const outputs = new Set(
      Object.values(manifest).flatMap((entry) => [
        entry.file,
        ...(entry.css ?? []),
        ...(entry.assets ?? []),
      ]),
    )
    const assets = readdirSync(join(root, 'assets')).filter(
      (name) => name !== 'OFL-BeVietnamPro.txt',
    )
    expect(assets.length).toBeGreaterThan(0)
    for (const name of assets) {
      expect(outputs.has(`assets/${name}`), name).toBe(true)
      const result = serveFile(root, { ...assetRequest, url: `/assets/${name}` })
      expect(result.status, name).toBe(200)
      expect(result.headers['Cache-Control'], name).toBe('public, max-age=31536000, immutable')
    }
    expect(
      serveFile(root, { ...assetRequest, url: '/assets/OFL-BeVietnamPro.txt' }).headers[
        'Cache-Control'
      ],
    ).toBe('no-cache')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}, 30000)
