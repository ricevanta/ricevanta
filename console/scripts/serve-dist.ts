import { createServer } from 'node:http'
import { readFileSync, existsSync, realpathSync, statSync } from 'node:fs'
import { extname, resolve, sep } from 'node:path'
export const csp = readFileSync(new URL('../security/csp.txt', import.meta.url), 'utf8').replace(
  /\n$/,
  '',
)
const security: Record<string, string> = {
  'Content-Security-Policy': csp,
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), usb=(), payment=()',
}
const mime: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
}
interface RequestInput {
  url: string
  method: string
  host: string
  accept: string
  encoding: string
}
interface ResponseOutput {
  status: number
  headers: Record<string, string>
  body: Buffer
}
const reserved = [
  '/api',
  '/agent',
  '/ext',
  '/assets',
  '/brand',
  '/mdm',
  '/scep',
  '/acme',
  '/__test__',
]
function inside(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}${sep}`)
}
function isManifestAsset(root: string, path: string): boolean {
  try {
    const file = resolve(root, '.vite/manifest.json')
    if (!inside(realpathSync(file), root)) return false
    const manifest: unknown = JSON.parse(readFileSync(file, 'utf8'))
    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) return false
    const outputs = new Set<string>()
    for (const entry of Object.values(manifest)) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return false
      const output = entry as Record<string, unknown>
      if (typeof output['file'] !== 'string' || output['file'].length === 0) return false
      outputs.add(output['file'])
      for (const field of ['css', 'assets']) {
        const assets = output[field]
        if (assets === undefined) continue
        if (!Array.isArray(assets)) return false
        for (const asset of assets) {
          if (typeof asset !== 'string' || asset.length === 0) return false
          outputs.add(asset)
        }
      }
    }
    return outputs.has(path.slice(1))
  } catch {
    return false
  }
}
export function serveFile(root: string, request: RequestInput, probes?: string): ResponseOutput {
  const headers: Record<string, string> = { ...security }
  const error = (status: number): ResponseOutput => ({ status, headers, body: Buffer.alloc(0) })
  if (request.host !== '127.0.0.1:4173') return error(400)
  if (!['GET', 'HEAD'].includes(request.method)) {
    headers['Allow'] = 'GET, HEAD'
    return error(405)
  }
  const raw = request.url.split('?')[0] ?? ''
  if (!raw.startsWith('/') || /%2f|%5c|%00|\\|\0/i.test(raw)) return error(400)
  let path: string
  try {
    path = decodeURIComponent(raw)
  } catch {
    return error(400)
  }
  if (
    /\\|\0|%/.test(path) ||
    path.split('/').some((segment) => segment === '..' || segment === '.')
  )
    return error(400)
  const isReserved = reserved.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
  const isProbe = path === '/__test__' || path.startsWith('/__test__/')
  if (isProbe && !probes) return error(404)
  let mutation: string | undefined
  if (path.startsWith('/__test__/mutations/')) {
    const match =
      /^\/__test__\/mutations\/(script-src|style-src|require-trusted-types-for|trusted-types|missing-header)\/([a-z-]+-protected\.html)$/.exec(
        path,
      )
    if (!match?.[1] || !match[2]) return error(404)
    mutation = match[1]
    path = `/__test__/${match[2]}`
  }
  let tree = realpathSync(root)
  if (path.startsWith('/__test__/') && probes) {
    tree = realpathSync(probes)
    path = path.slice('/__test__'.length)
  }
  let file = resolve(tree, path === '/' ? 'index.html' : `.${path}`)
  if (!inside(file, tree)) return error(400)
  if (!existsSync(file) || statSync(file).isDirectory()) {
    if (
      isReserved ||
      !request.accept.split(',').some((type) => type.trim().startsWith('text/html'))
    )
      return error(404)
    file = resolve(tree, 'index.html')
  }
  if (!existsSync(file) || !inside(realpathSync(file), tree)) return error(400)
  const type = mime[extname(file)]
  if (!type) return error(404)
  headers['Content-Type'] = type
  headers['Cache-Control'] =
    extname(file) === '.html'
      ? 'no-cache'
      : path.startsWith('/brand/')
        ? 'public, max-age=86400'
        : !isProbe && path.startsWith('/assets/') && isManifestAsset(tree, path)
          ? 'public, max-age=31536000, immutable'
          : 'no-cache'
  headers['Vary'] = 'Accept-Encoding'
  const encodings = request.encoding
    .split(',')
    .map((part) => part.trim().split(';'))
    .map(([name, quality]) => ({
      name,
      quality: quality?.startsWith('q=') ? Number(quality.slice(2)) : 1,
    }))
    .filter((item) => Number.isFinite(item.quality) && item.quality > 0)
    .sort((a, b) => b.quality - a.quality || (a.name === 'br' ? -1 : 1))
  for (const item of encodings)
    if (
      (item.name === 'br' || item.name === 'gzip') &&
      existsSync(`${file}.${item.name === 'br' ? 'br' : 'gz'}`)
    ) {
      const compressed = `${file}.${item.name === 'br' ? 'br' : 'gz'}`
      if (!inside(realpathSync(compressed), tree)) return error(400)
      file = compressed
      headers['Content-Encoding'] = item.name
      break
    }
  let body = readFileSync(file)
  if (probes && request.url.startsWith('/__test__/') && extname(file) === '.html') {
    const manifest = JSON.parse(
      readFileSync(resolve(root, '.vite/manifest.json'), 'utf8'),
    ) as Record<string, { file: string; isEntry?: boolean }>
    const entry = Object.values(manifest).find((value) => value.isEntry)?.file
    if (!entry) return error(500)
    body = Buffer.from(body.toString('utf8').replaceAll('__ENTRY__', `/${entry}`))
  }
  headers['Content-Length'] = String(body.byteLength)
  if (probes && request.url.startsWith('/__test__/') && path.endsWith('-control.html'))
    delete headers['Content-Security-Policy']
  if (mutation === 'missing-header') delete headers['Content-Security-Policy']
  else if (mutation)
    headers['Content-Security-Policy'] = csp
      .split('; ')
      .filter((directive) => directive.split(' ')[0] !== mutation)
      .join('; ')
  return { status: 200, headers, body: request.method === 'HEAD' ? Buffer.alloc(0) : body }
}
if (import.meta.main) {
  const probes = process.argv.includes('--probes') ? resolve('tests/fixtures/csp') : undefined
  const server = createServer((request, response) => {
    try {
      const result = serveFile(
        resolve('dist'),
        {
          url: request.url ?? '/',
          method: request.method ?? '',
          host: request.headers.host ?? '',
          accept: request.headers.accept ?? '',
          encoding: request.headers['accept-encoding'] ?? '',
        },
        probes,
      )
      response.writeHead(result.status, result.headers)
      response.end(result.body)
    } catch {
      response.writeHead(500, security)
      response.end()
    }
  })
  server.listen(4173, '127.0.0.1', () => {
    console.log('Console test harness: 127.0.0.1:4173')
  })
  const close = () => server.close()
  process.on('SIGINT', close)
  process.on('SIGTERM', close)
}
