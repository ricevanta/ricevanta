import { readFileSync, readdirSync, realpathSync } from 'node:fs'
import { resolve, relative, sep } from 'node:path'
import { createHash } from 'node:crypto'
import { brotliCompressSync, constants } from 'node:zlib'
import { osvExceptionPackages, resolvedLicenses } from './audit-deps.ts'
import type { ResolvedLicense } from './audit-deps.ts'
export interface ManifestEntry {
  file: string
  isEntry?: boolean
  isDynamicEntry?: boolean
  imports?: string[]
  dynamicImports?: string[]
}
export interface BuildGraph {
  outputs?: { file: string; sha256: string; sources: string[] }[]
  modules: string[]
  copies: { source: string; target: string }[]
  manifest: Record<string, ManifestEntry>
}
export function auditOutput(
  files: ReadonlyMap<string, string | Uint8Array>,
  graph: BuildGraph,
  inventory: readonly ResolvedLicense[],
  exceptionsText = readFileSync('security/osv-exceptions.json', 'utf8'),
): string[] {
  const exceptions = new Set(
    osvExceptionPackages(exceptionsText).map((pkg) => `${pkg.name}@${pkg.version}`),
  )
  const issues: string[] = []
  const html = Buffer.from(files.get('index.html') ?? '').toString('utf8')
  if (
    !html ||
    /<script\b(?![^>]*\bsrc\s*=)[^>]*>|<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:|https?:\/\/|data:/i.test(
      html,
    )
  )
    issues.push('html')
  const recorded = new Map((graph.outputs ?? []).map((output) => [output.file, output]))
  for (const [name, bytes] of files) {
    const output = recorded.get(name)
    if (!output) issues.push(`unrecorded:${name}`)
    else if (
      !output.sources.length ||
      createHash('sha256').update(bytes).digest('hex') !== output.sha256
    )
      issues.push(`provenance:${name}`)
    const content = Buffer.from(bytes).toString('utf8')
    if (/\.map$|(?:^|\/)(?:tests?|probes?|worker|service-worker)/i.test(name))
      issues.push(`file:${name}`)
    if (
      /(?:src|href|url)\s*[=(]\s*['"]?(?:https?:\/\/|data:)/i.test(content) &&
      !/\.(js|txt)$/.test(name) &&
      !name.endsWith('site.webmanifest')
    )
      issues.push(`remote:${name}`)
  }
  for (const name of recorded.keys()) if (!files.has(name)) issues.push(`missing-output:${name}`)
  if (!files.has('assets/OFL-BeVietnamPro.txt')) issues.push('font-notice')
  const forbidden = ['MPL-2.0', 'BlueOak-1.0.0', 'Python-2.0.1']
  for (const module of [
    ...graph.modules,
    ...graph.copies.map((copy) => copy.source),
    ...(graph.outputs ?? []).flatMap((output) => output.sources),
  ]) {
    const source = module.replaceAll('\\', '/')
    if (
      /\/(?:@vue\/compiler-(?:core|dom|sfc)|@intlify\/message-compiler)(?:\/|@)|\/tests\//.test(
        source,
      )
    )
      issues.push(`compiler-or-test:${module}`)
    const matched = inventory.filter((pkg) =>
      pkg.paths.some((path) => {
        const root = path.replaceAll('\\', '/')
        return source === root || source.startsWith(`${root}/`)
      }),
    )
    if (source.includes('/node_modules/') && !matched.length)
      issues.push(`unknown-provenance:${module}`)
    if (matched.some((pkg) => forbidden.includes(pkg.normalized))) issues.push(`license:${module}`)
    if (matched.some((pkg) => exceptions.has(`${pkg.name}@${pkg.version}`)))
      issues.push(`osv-exception:${module}`)
  }
  const manifest = graph.manifest
  const entries = Object.entries(manifest).filter(([, entry]) => entry.isEntry)
  if (entries.length !== 1) issues.push('entry-count')
  function closure(keys: readonly string[]): Set<string> {
    const found = new Set<string>()
    function visit(key: string): void {
      if (found.has(key)) return
      found.add(key)
      const item = manifest[key]
      if (!item || !files.has(item.file)) {
        issues.push(`manifest:${key}`)
        return
      }
      for (const imported of item.imports ?? []) visit(imported)
    }
    keys.forEach(visit)
    return found
  }
  const entryClosure = closure(entries.map(([key]) => key))
  const routes = Object.entries(manifest).filter(([, item]) => item.isDynamicEntry)
  if (routes.length !== 2 || routes.some(([key]) => entryClosure.has(key)))
    issues.push('lazy-routes')
  const size = (keys: Set<string>) =>
    [...keys].reduce((total, key) => {
      const file = manifest[key]?.file
      const source = file ? files.get(file) : undefined
      return (
        total +
        (source && file?.endsWith('.js')
          ? brotliCompressSync(source, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } })
              .byteLength
          : 0)
      )
    }, 0)
  if (size(entryClosure) > 250000) issues.push('entry-budget')
  for (const [key] of routes)
    if (size(new Set([...closure([key])].filter((part) => !entryClosure.has(part)))) > 150000)
      issues.push(`route-budget:${key}`)
  return [...new Set(issues)].sort()
}
export function distFiles(root = 'dist'): Map<string, Uint8Array> {
  const result = new Map<string, Uint8Array>()
  function walk(dir: string): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`
      if (entry.isDirectory()) walk(path)
      else if (!/\.(br|gz)$/.test(path))
        result.set(relative(root, path).split(sep).join('/'), readFileSync(path))
    }
  }
  walk(root)
  return result
}
export function canonical(path: string): string {
  const file = path.split('?')[0] ?? path
  try {
    return realpathSync(file)
  } catch {
    return resolve(file)
  }
}
if (import.meta.main) {
  const graph = JSON.parse(readFileSync('.vite/build-graph.json', 'utf8')) as BuildGraph
  graph.manifest = JSON.parse(readFileSync('dist/.vite/manifest.json', 'utf8')) as Record<
    string,
    ManifestEntry
  >
  const inventory = await resolvedLicenses()
  const issues = auditOutput(distFiles(), graph, inventory)
  if (issues.length) {
    console.error(issues.join('\n'))
    process.exitCode = 1
  } else console.log('PASS output graph, provenance, assets and Brotli budgets')
}
