import { checkedTool } from './run-tool.ts'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

interface Package {
  name: string
  version: string
}
interface LockedPackage extends Package {
  os?: string[]
  cpu?: string[]
  libc?: string[]
}
interface LicenseInput extends Package {
  declared: string
  runtime: boolean
  modified: boolean
  evidence: string
}
export interface ResolvedLicense extends Package {
  declared: string
  normalized: string
  paths: string[]
}
const argparseHash = 'de4d1f2d2ad5ad0cfd1657a106476b31cb5db5ef9d1ff842b237c0c81f0c8a23'
export function normalizeLicense(input: LicenseInput): string {
  let license = input.declared
  if (license === 'Python-2.0') {
    if (
      input.name !== 'argparse' ||
      input.version !== '2.0.1' ||
      createHash('sha256').update(input.evidence).digest('hex') !== argparseHash
    )
      throw new Error('Unverified Python license evidence')
    license = 'Python-2.0.1'
  }
  const tooling = ['BlueOak-1.0.0', 'Python-2.0.1', 'MPL-2.0']
  if (tooling.includes(license)) {
    if (input.runtime || (license === 'MPL-2.0' && input.modified))
      throw new Error('Tooling-only license')
  } else if (
    !['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'OFL-1.1'].includes(license)
  )
    throw new Error(`Unapproved license: ${license}`)
  return license
}
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new Error('Incomplete response')
  return value as Record<string, unknown>
}
interface PathNode {
  package: string
  version: string
}
interface ExceptionEntry extends PathNode {
  advisoryId: string
  dependencyPath: PathNode[]
  untrustedInputRationale: string
  removeWhen: string
}
interface AuditOptions {
  exceptionsText: string | undefined
  lockfile: string
  manifest: unknown
}
const exactVersion =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/
const classes = ['dependencies', 'devDependencies', 'optionalDependencies'] as const
const pairKey = (pkg: Package): string => `${pkg.name}@${pkg.version}`
const pathKey = (path: readonly PathNode[]): string =>
  path.map((node) => `${node.package}@${node.version}`).join(' -> ')
const identity = (entry: ExceptionEntry): string =>
  `${entry.advisoryId} ${entry.package}@${entry.version} ${pathKey(entry.dependencyPath)}`

function exceptionEntries(text: string | undefined): {
  entries: ExceptionEntry[]
  indices: number[]
  errors: string[]
} {
  let values: unknown
  try {
    if (text === undefined) throw new Error('missing file')
    values = JSON.parse(text) as unknown
  } catch (error) {
    throw new Error(`Invalid OSV exception file: ${String(error)}`)
  }
  if (!Array.isArray(values)) throw new Error('Invalid OSV exception file: expected array')
  const entries: ExceptionEntry[] = []
  const indices: number[] = []
  const errors: string[] = []
  const seen = new Set<string>()
  for (const [index, value] of values.entries()) {
    try {
      const item = record(value)
      const fields = [
        'advisoryId',
        'package',
        'version',
        'dependencyPath',
        'untrustedInputRationale',
        'removeWhen',
      ]
      if (Object.keys(item).length !== fields.length || fields.some((key) => !(key in item)))
        throw new Error('expected exactly six fields')
      for (const key of fields.filter((key) => key !== 'dependencyPath'))
        if (typeof item[key] !== 'string' || !item[key].trim()) throw new Error(`invalid ${key}`)
      if (typeof item['version'] !== 'string' || !exactVersion.test(item['version']))
        throw new Error('version must be exact')
      const path = item['dependencyPath']
      if (!Array.isArray(path) || !path.length) throw new Error('empty dependencyPath')
      for (const value of path) {
        const node = record(value)
        if (
          Object.keys(node).length !== 2 ||
          typeof node['package'] !== 'string' ||
          !node['package'].trim() ||
          typeof node['version'] !== 'string' ||
          !exactVersion.test(node['version'])
        )
          throw new Error('invalid dependencyPath node')
      }
      const last = record(path.at(-1))
      if (last['package'] !== item['package'] || last['version'] !== item['version'])
        throw new Error('dependencyPath endpoint mismatch')
      const entry = item as unknown as ExceptionEntry
      const key = identity(entry)
      if (seen.has(key)) throw new Error('duplicate identity')
      seen.add(key)
      entries.push(entry)
      indices.push(index)
    } catch (error) {
      errors.push(
        `entry ${String(index)} invalid exception ${JSON.stringify(value)}: ${String(error)}`,
      )
    }
  }
  return { entries, indices, errors }
}

export function osvExceptionPackages(text: string | undefined): Package[] {
  const parsed = exceptionEntries(text)
  if (parsed.errors.length) throw new Error(parsed.errors.join('\n'))
  return parsed.entries.map((entry) => ({ name: entry.package, version: entry.version }))
}

// Parse only pnpm 9's importer and snapshot mappings. Unknown graph encodings fail closed.
function lockGraph(text: string, manifestValue: unknown) {
  const locked = new Set(lockedPackages(text).map(pairKey))
  const manifest = record(manifestValue)
  const roots: { key: string; kind: string; name: string; specifier: string }[] = []
  const edges = new Map<string, string[]>()
  const scalar = (value: string): string => {
    if (value.startsWith("'")) {
      if (!value.endsWith("'") || value.slice(1, -1).includes("'"))
        throw new Error('Unknown lockfile scalar')
      return value.slice(1, -1)
    }
    if (!value || /[\s{}[\]"']/.test(value)) throw new Error('Unknown lockfile scalar')
    return value
  }
  let section = ''
  let parent = ''
  let kind = ''
  let name = ''
  let specifier = ''
  for (const line of text.split('\n')) {
    if (!line.trim()) continue
    if (!line.startsWith(' ')) {
      section = line
      parent = ''
      continue
    }
    if (section !== 'importers:' && section !== 'snapshots:') continue
    const match = /^( *)(.+?):(?: (.*))?$/.exec(line)
    if (!match) {
      if (section === 'snapshots:' && kind === 'transitivePeerDependencies') continue
      throw new Error(`Unknown lockfile graph line: ${line}`)
    }
    const depth = match[1]?.length
    const key = scalar(match[2] ?? '')
    const value = match[3]
    if (depth === 2) {
      parent = key
      kind = ''
      if (section === 'snapshots:') edges.set(key, [])
      if (value !== undefined && value !== '{}') throw new Error('Unknown lockfile graph node')
    } else if (depth === 4) {
      kind = key
      if (section === 'importers:' && parent !== '.') throw new Error('Unknown lockfile importer')
      if (section === 'importers:' && !classes.some((item) => item === kind))
        throw new Error('Unknown importer dependency class')
    } else if (section === 'importers:' && depth === 6) {
      name = key
      specifier = ''
    } else if (section === 'importers:' && depth === 8) {
      if (value === undefined) throw new Error('Missing importer value')
      if (key === 'specifier') specifier = scalar(value)
      else if (key === 'version')
        roots.push({ name, key: `${name}@${scalar(value)}`, kind, specifier })
      else throw new Error('Unknown importer field')
    } else if (
      section === 'snapshots:' &&
      depth === 6 &&
      (kind === 'dependencies' || kind === 'optionalDependencies')
    ) {
      if (value === undefined) throw new Error('Missing dependency reference')
      const reference = scalar(value)
      edges.get(parent)?.push(/^\d/.test(reference) ? `${key}@${reference}` : reference)
    } else if (section === 'snapshots:' && kind === 'transitivePeerDependencies') continue
    else throw new Error('Unknown lockfile graph encoding')
  }
  if (!edges.size || !roots.length) throw new Error('Missing lockfile graph')
  const node = (key: string): PathNode => {
    const base = key.split('(')[0] ?? ''
    const at = base.lastIndexOf('@')
    const packageName = base.slice(0, at)
    const version = base.slice(at + 1)
    if (at < 1 || !exactVersion.test(version) || !locked.has(base))
      throw new Error(`Invalid lockfile node ${key}`)
    return { package: packageName, version }
  }
  // Validate even unreachable or optional snapshots; OSV covers every locked pair.
  for (const [key, children] of edges) {
    node(key)
    for (const child of children) {
      node(child)
      if (!edges.has(child)) throw new Error(`Missing lockfile snapshot ${child}`)
    }
  }
  const classErrors: string[] = []
  for (const root of roots) {
    node(root.key)
    if (!edges.has(root.key)) throw new Error(`Missing lockfile root ${root.key}`)
    for (const field of classes) {
      const entries = manifest[field] === undefined ? {} : record(manifest[field])
      const present = root.name in entries
      if (present !== (field === root.kind) || (present && entries[root.name] !== root.specifier))
        classErrors.push(
          `${root.name}: manifest and lockfile dependency classes or versions disagree`,
        )
    }
  }
  for (const field of classes) {
    const entries = manifest[field] === undefined ? {} : record(manifest[field])
    for (const name of Object.keys(entries))
      if (!roots.some((root) => root.name === name && root.kind === field))
        classErrors.push(`${name}: manifest and lockfile dependency classes disagree`)
  }
  function paths(pkg: Package): { path: PathNode[]; kind: string }[] {
    const result: { path: PathNode[]; kind: string }[] = []
    function walk(key: string, path: PathNode[], visited: Set<string>, kind: string): void {
      if (visited.has(key)) return // Enumerate simple paths through peer cycles.
      const current = node(key)
      const nextPath = [...path, current]
      if (current.package === pkg.name && current.version === pkg.version)
        result.push({ path: nextPath, kind })
      const nextVisited = new Set(visited).add(key)
      for (const child of edges.get(key) ?? []) walk(child, nextPath, nextVisited, kind)
    }
    for (const root of roots) walk(root.key, [], new Set(), root.kind)
    return [...new Map(result.map((item) => [`${item.kind}:${pathKey(item.path)}`, item])).values()]
  }
  return { paths, classErrors }
}

export async function scanOSV(
  packages: readonly Package[],
  request: (body: unknown) => Promise<unknown>,
  options?: AuditOptions,
): Promise<string[]> {
  const parsed = exceptionEntries(options ? options.exceptionsText : '[]')
  let graph: ReturnType<typeof lockGraph> | undefined
  if (options) {
    try {
      graph = lockGraph(options.lockfile, options.manifest)
    } catch (error) {
      parsed.errors.push(`Invalid lockfile graph: ${String(error)}`)
      for (const [index, entry] of parsed.entries.entries())
        parsed.errors.push(
          `entry ${String(parsed.indices[index])} stale exception ${identity(entry)}: invalid lockfile graph ${String(error)}`,
        )
    }
  }
  const findings = new Map<string, Set<string>>()
  const complete = new Set<string>()
  const malformed = new Set<string>()
  const incomplete: string[] = []
  const unique = [...new Map(packages.map((pkg) => [pairKey(pkg), pkg])).values()]
  for (let start = 0; start < unique.length; start += 100) {
    let pending = unique.slice(start, start + 100).map((pkg) => ({
      package: { name: pkg.name, ecosystem: 'npm' },
      version: pkg.version,
      page_token: '',
    }))
    const seen = new Set<string>()
    while (pending.length) {
      try {
        const queries = pending.map(({ page_token, ...query }) =>
          page_token ? { ...query, page_token } : query,
        )
        const results = record(await request({ queries }))['results']
        if (!Array.isArray(results) || results.length !== pending.length)
          throw new Error('Incomplete OSV response')
        const next: typeof pending = []
        for (const [index, value] of results.entries()) {
          const query = pending[index]
          if (!query) throw new Error('Invalid OSV query index')
          const pair = `${query.package.name}@${query.version}`
          try {
            const result = record(value)
            const ids = findings.get(pair) ?? new Set<string>()
            findings.set(pair, ids)
            if ('vulns' in result && !Array.isArray(result['vulns'])) {
              malformed.add(pair)
              incomplete.push(`Incomplete OSV ${pair}: Malformed vulnerabilities`)
            } else {
              for (const [advisoryIndex, vuln] of (
                (result['vulns'] ?? []) as unknown[]
              ).entries()) {
                try {
                  const id = record(vuln)['id']
                  if (typeof id !== 'string' || !id.trim()) throw new Error('Malformed advisory ID')
                  ids.add(id)
                } catch (error) {
                  malformed.add(pair)
                  incomplete.push(
                    `Incomplete OSV ${pair} page ${JSON.stringify(query.page_token)} advisory ${String(advisoryIndex)}: ${String(error)}`,
                  )
                }
              }
            }
            const token = result['next_page_token'] ?? ''
            if (typeof token !== 'string') throw new Error('Invalid OSV pagination')
            if (token) {
              const key = `${pair}:${token}`
              if (seen.has(key)) throw new Error('Repeated OSV page')
              seen.add(key)
              next.push({ ...query, page_token: token })
            } else if (!malformed.has(pair)) complete.add(pair)
          } catch (error) {
            incomplete.push(`Incomplete OSV ${pair}: ${String(error)}`)
          }
        }
        pending = next
      } catch (error) {
        incomplete.push(
          `Incomplete OSV request ${pending.map((query) => `${query.package.name}@${query.version}`).join(', ')}: ${String(error)}`,
        )
        break
      }
    }
  }
  const diagnostics: string[] = []
  let unlisted = false
  for (const pkg of unique) {
    for (const id of findings.get(pairKey(pkg)) ?? []) {
      const paths = graph?.paths(pkg) ?? []
      for (const item of paths.length
        ? paths
        : [{ path: [{ package: pkg.name, version: pkg.version }], kind: '' }]) {
        const key = `${id} ${pairKey(pkg)} ${pathKey(item.path)}`
        const allowed =
          parsed.entries.some((entry) => identity(entry) === key) &&
          !(pkg.name === 'braces' && item.kind !== 'devDependencies') &&
          !graph?.classErrors.length
        if (!allowed) unlisted = true
        diagnostics.push(`${key} ${allowed ? 'excepted' : 'unlisted'}`)
      }
    }
  }
  for (const [index, entry] of parsed.entries.entries()) {
    const pair = `${entry.package}@${entry.version}`
    const paths = graph?.paths({ name: entry.package, version: entry.version }) ?? []
    const matches = paths.filter((item) => pathKey(item.path) === pathKey(entry.dependencyPath))
    const reasons: string[] = []
    if (!matches.length)
      reasons.push('dependency path or package/version no longer matches lockfile')
    if (entry.package === 'braces' && matches.some((item) => item.kind !== 'devDependencies'))
      reasons.push('braces root must be only in devDependencies')
    if (graph?.classErrors.length) reasons.push(...graph.classErrors)
    if (complete.has(pair) && !findings.get(pair)?.has(entry.advisoryId))
      reasons.push('advisory absent from complete OSV result')
    if (!unique.some((pkg) => pairKey(pkg) === pair))
      reasons.push('package/version absent from lockfile audit')
    if (reasons.length)
      parsed.errors.push(
        `entry ${String(parsed.indices[index])} stale exception ${identity(entry)}: ${reasons.join('; ')}`,
      )
  }
  diagnostics.sort()
  const diagnosticKey = (message: string): string => {
    const stale = /stale exception (.*?):/.exec(message)?.[1]
    if (stale) return stale
    const invalid = /invalid exception (.*): Error:/.exec(message)?.[1]
    if (invalid) {
      try {
        const value = record(JSON.parse(invalid) as unknown)
        return [
          value['advisoryId'],
          value['package'],
          value['version'],
          JSON.stringify(value['dependencyPath']),
        ]
          .map(String)
          .join(' ')
      } catch {
        return message
      }
    }
    return message
  }
  const namedDiagnostics = [...diagnostics, ...parsed.errors].sort((a, b) => {
    const left = diagnosticKey(a)
    const right = diagnosticKey(b)
    return left < right ? -1 : left > right ? 1 : a < b ? -1 : a > b ? 1 : 0
  })
  if (unlisted || parsed.errors.length || incomplete.length || graph?.classErrors.length)
    throw new Error([...namedDiagnostics, ...(graph?.classErrors ?? []), ...incomplete].join('\n'))
  return diagnostics
}
export function runtimePairs(tree: unknown): Set<string> {
  const result = new Set<string>()
  function walk(value: unknown, dependencyName?: string): void {
    if (Array.isArray(value)) {
      value.forEach((item) => {
        walk(item)
      })
      return
    }
    if (typeof value !== 'object' || value === null) return
    const item = record(value)
    const name = dependencyName ?? item['name']
    // The pinned Vite peer is a build tool even when pnpm lists it below Vue Router.
    if (name === 'vite' && item['version'] === '8.3.2') return
    if (typeof name === 'string' && typeof item['version'] === 'string')
      result.add(`${name}@${item['version']}`)
    for (const field of ['dependencies', 'optionalDependencies']) {
      const children = item[field]
      if (typeof children === 'object' && children !== null)
        for (const [key, child] of Object.entries(children)) walk(child, key)
    }
  }
  walk(tree)
  return result
}
export function lockedPackages(text: string): LockedPackage[] {
  // Read only lockfile format 9's package-key block. Reject unfamiliar encodings instead of omitting keys.
  if (!text.startsWith("lockfileVersion: '9.0'\n")) throw new Error('Unknown lockfile format')
  const sections = text.split('\npackages:\n')
  if (sections.length !== 2) throw new Error('Missing lockfile packages')
  const block = (sections[1] ?? '').split(/\n[^ \n]/)[0] ?? ''
  const packages: LockedPackage[] = []
  for (const line of block.split('\n')) {
    const platform = /^ {4}(os|cpu|libc):\s*(.*)$/.exec(line)
    if (platform) {
      const pkg = packages.at(-1)
      const field = platform[1]
      const value = platform[2] ?? ''
      if (!pkg || (field !== 'os' && field !== 'cpu' && field !== 'libc') || field in pkg)
        throw new Error('Invalid locked platform field')
      // pnpm format 9 emits inline string lists. Fail on other encodings rather than waive evidence.
      if (!/^\[.*\]$/.test(value)) throw new Error('Invalid locked platform list')
      const items = value.slice(1, -1).trim()
      pkg[field] = items
        ? items.split(',').map((item) => {
            const match =
              /^(?:'(!?[a-z][a-z0-9_-]*)'|"(!?[a-z][a-z0-9_-]*)"|(!?[a-z][a-z0-9_-]*))$/.exec(
                item.trim(),
              )
            const token = match?.[1] ?? match?.[2] ?? match?.[3]
            if (!token) throw new Error('Invalid locked platform value')
            return token
          })
        : []
      continue
    }
    if (!line.trim() || line.startsWith('    ')) continue
    const match = /^ {2}(?:'([^']+)'|([^'\s]+)):(?: \{\})?$/.exec(line)
    const pair = match?.[1] ?? match?.[2] ?? ''
    const parts = /^(@?[^@\s]+)@(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)$/.exec(pair)
    const name = parts?.[1]
    const version = parts?.[2]
    if (!name || !version) throw new Error('Invalid locked package key')
    packages.push({ name, version })
  }
  if (!packages.length) throw new Error('Empty lockfile packages')
  return packages
}
function supportsArchitecture(pkg: LockedPackage): boolean {
  function allows(values: readonly string[] | undefined, target: string): boolean {
    if (!values?.length) return true
    if (values.length === 1 && values[0] === 'any') return true
    if (values.includes(`!${target}`)) return false
    const positive = values.filter((value) => !value.startsWith('!'))
    return !positive.length || positive.includes(target)
  }
  // Keep the combinations aligned with the spec's exact supportedArchitectures lists.
  return ['linux', 'darwin', 'win32'].some((os) =>
    ['x64', 'arm64'].some(
      (cpu) => allows(pkg.os, os) && allows(pkg.cpu, cpu) && allows(pkg.libc, 'glibc'),
    ),
  )
}
export function reconcileLicenses(
  locked: readonly LockedPackage[],
  inventory: readonly ResolvedLicense[],
  report: (line: string) => void = () => {},
): ResolvedLicense[] {
  const byPair = new Map(inventory.map((pkg) => [`${pkg.name}@${pkg.version}`, pkg]))
  const excluded = locked.filter((pkg) => !supportsArchitecture(pkg))
  for (const pkg of [...excluded].sort((a, b) => pairKey(a).localeCompare(pairKey(b))))
    report(`Excluded locked license package: ${pairKey(pkg)}`)
  const installed = excluded.filter((pkg) => byPair.has(pairKey(pkg)))
  if (installed.length)
    throw new Error(`Excluded locked package is installed: ${installed.map(pairKey).join(', ')}`)
  const supported = locked.filter(supportsArchitecture)
  const missing = supported.filter((pkg) => !byPair.get(`${pkg.name}@${pkg.version}`)?.paths.length)
  if (missing.length)
    throw new Error(
      `Missing locked license evidence: ${missing.map((pkg) => `${pkg.name}@${pkg.version}`).join(', ')}`,
    )
  return supported.map((pkg) => {
    const evidence = byPair.get(`${pkg.name}@${pkg.version}`)
    if (!evidence) throw new Error('Missing locked license evidence')
    return evidence
  })
}
export async function resolvedLicenses(): Promise<ResolvedLicense[]> {
  const modules = record(JSON.parse(readFileSync('node_modules/.modules.yaml', 'utf8')) as unknown)
  const storeDir = modules['storeDir']
  if (typeof storeDir !== 'string' || !storeDir.endsWith('/v11'))
    throw new Error('Unknown pnpm store')
  const licenses = record(
    JSON.parse(
      await checkedTool('pnpm', [
        `--config.store-dir=${storeDir.slice(0, -4)}`,
        'licenses',
        'list',
        '--json',
      ]),
    ) as unknown,
  )
  const runtimeTree: unknown = JSON.parse(
    await checkedTool('pnpm', ['list', '--prod', '--depth', 'Infinity', '--json']),
  )
  const runtime = runtimePairs(runtimeTree)
  const output: ResolvedLicense[] = []
  for (const [declared, entries] of Object.entries(licenses)) {
    if (!Array.isArray(entries)) throw new Error('Invalid license inventory')
    for (const value of entries) {
      const entry = record(value)
      const name = entry['name']
      const versions = entry['versions']
      const paths = entry['paths']
      if (
        typeof name !== 'string' ||
        !Array.isArray(versions) ||
        !Array.isArray(paths) ||
        !paths.every((path: unknown) => typeof path === 'string')
      )
        throw new Error('Invalid package inventory')
      for (const version of versions) {
        if (typeof version !== 'string') throw new Error('Invalid version')
        let evidence = ''
        if (declared === 'Python-2.0') {
          const path = paths[0]
          if (typeof path !== 'string') throw new Error('Missing LICENSE')
          evidence = readFileSync(`${path}/LICENSE`, 'utf8')
        }
        output.push({
          name,
          version,
          declared,
          normalized: normalizeLicense({
            name,
            version,
            declared,
            runtime: runtime.has(`${name}@${version}`),
            modified: false,
            evidence,
          }),
          paths,
        })
      }
    }
  }
  return reconcileLicenses(
    lockedPackages(readFileSync('pnpm-lock.yaml', 'utf8')),
    output,
    (line) => {
      console.log(line)
    },
  ).sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`))
}
if (import.meta.main) {
  try {
    const packages = await resolvedLicenses()
    console.log(JSON.stringify(packages, null, 2))
    const lockfile = readFileSync('pnpm-lock.yaml', 'utf8')
    const locked = lockedPackages(lockfile)
    const diagnostics = await scanOSV(
      locked,
      async (body) => {
        const response = await fetch('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(30_000),
        })
        if (!response.ok) throw new Error(`OSV HTTP ${String(response.status)}`)
        const result: unknown = await response.json()
        return result
      },
      {
        exceptionsText: readFileSync('security/osv-exceptions.json', 'utf8'),
        lockfile,
        manifest: JSON.parse(readFileSync('package.json', 'utf8')) as unknown,
      },
    )
    diagnostics.forEach((line) => {
      console.log(line)
    })
    console.log(
      `PASS: ${String(packages.length)} resolved licenses and ${String(locked.length)} OSV queries`,
    )
  } catch (error) {
    console.error(error)
    process.exitCode = 1
  }
}
