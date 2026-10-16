import { createHash } from 'node:crypto'
import { lstatSync, readFileSync, readlinkSync, readdirSync, realpathSync } from 'node:fs'
import { join, resolve, relative, dirname, isAbsolute, sep } from 'node:path'
import { checkedTool } from './run-tool.ts'

export interface LockedPackage {
  name: string
  version: string
  os?: string[]
  cpu?: string[]
  libc?: string[]
}
export const removalPairs = [
  '@rolldown/binding-linux-arm64-musl@1.2.13',
  '@rolldown/binding-linux-x64-musl@1.2.13',
  'lightningcss-linux-arm64-musl@1.33.0',
  'lightningcss-linux-x64-musl@1.33.0',
] as const
export const lightningNotice = '5eba353fe5076ac3432177f8ab1cf75e3afcd0584251e37c3bfead5f447d040e'
const lockHash = '7538326a90d93fd841d174b613bde0b669ca1eca4cad7e21367792da978673e3'
const workspaceHash = '0e7199c78de2939ca9151bff2df4025f377dc682024be4bbb9ac144870efcfda'
export function digest(bytes: string | Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid object')
  return value as Record<string, unknown>
}
function json(path: string): Record<string, unknown> {
  return object(JSON.parse(readFileSync(path, 'utf8')) as unknown)
}
export function beneath(root: string, path: string): boolean {
  const part = relative(root, path)
  return part !== '' && !part.startsWith(`..${sep}`) && part !== '..' && !isAbsolute(part)
}
export function regularDirectory(path: string): void {
  const stat = lstatSync(path)
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new Error(`Linked or missing directory: ${path}`)
}
export function scalar(value: string): string {
  if (/^'[^']+'$/.test(value)) return value.slice(1, -1)
  if (!value || /[\s'"{}[\]]/.test(value)) throw new Error('Unknown lockfile scalar')
  return value
}
export function instanceFilename(key: string): string {
  let filename = key.replace(/[\\/:*?"<>|#]/g, '+')
  filename = filename.replace(/\)$/, '').replace(/\)\(|\(|\)/g, '_')
  if (filename.length > 120 || filename !== filename.toLowerCase())
    return `${filename.slice(0, 87)}_${digest(filename).slice(0, 32)}`
  return filename
}
export interface Edge {
  name: string
  target: string
  optional: boolean
}
export interface Snapshot {
  key: string
  pair: string
  edges: Edge[]
}
export function snapshots(text: string): Map<string, Snapshot> {
  const result = new Map<string, Snapshot>()
  let node: Snapshot | undefined
  let kind = ''
  const block = text.split('\nsnapshots:\n')
  if (block.length !== 2) throw new Error('Missing snapshots')
  for (const line of (block[1] ?? '').split('\n')) {
    if (!line.trim()) continue
    const entry = /^ {2}(\S.+?):(?: (\{\}))?$/.exec(line)
    if (entry) {
      const key = scalar(entry[1] ?? '')
      if (result.has(key)) throw new Error('Duplicate snapshot')
      node = { key, pair: key.split('(')[0] ?? '', edges: [] }
      result.set(key, node)
      kind = ''
      continue
    }
    const field = /^ {4}([a-zA-Z]+):(?: (true))?$/.exec(line)
    if (field) {
      kind = field[1] ?? ''
      if (
        ![
          'dependencies',
          'optionalDependencies',
          'transitivePeerDependencies',
          'optional',
        ].includes(kind)
      )
        throw new Error('Unknown snapshot field')
      continue
    }
    if (kind === 'transitivePeerDependencies' && /^ {6}- /.test(line)) continue
    const edge = /^ {6}(.+?): (.+)$/.exec(line)
    if (!node || !edge || !['dependencies', 'optionalDependencies'].includes(kind))
      throw new Error('Unknown snapshot encoding')
    const name = scalar(edge[1] ?? '')
    const version = scalar(edge[2] ?? '')
    if (node.edges.some((item) => item.name === name)) throw new Error('Duplicate dependency edge')
    node.edges.push({
      name,
      target: /^\d/.test(version) ? `${name}@${version}` : version,
      optional: kind === 'optionalDependencies',
    })
  }
  for (const node of result.values())
    for (const edge of node.edges)
      if (!result.has(edge.target)) throw new Error(`Unknown snapshot target: ${edge.target}`)
  return result
}
export interface Instance {
  key: string
  pair: string
  path: string
  directory: string
  manifest: Record<string, unknown>
  eligible: boolean
}
export interface PhysicalInventory {
  root: string
  locked: LockedPackage[]
  instances: Instance[]
  pairs: string[]
  files: Record<string, string>
  links: Record<string, string>
  directories: string[]
  identities: Record<string, string>
  metadata: Record<string, string>
  candidates: Instance[]
  generated: Record<string, GeneratedEntry>
}
const metadataPaths = [
  'package.json',
  'pnpm-workspace.yaml',
  'pnpm-lock.yaml',
  'node_modules/.modules.yaml',
  'node_modules/.package-map.json',
  'node_modules/.pnpm/lock.yaml',
  'node_modules/.pnpm-workspace-state-v1.json',
]
function importerEdges(lock: string, manifest: Record<string, unknown>): Edge[] {
  const block = lock.split('\nimporters:\n')[1]?.split('\npackages:\n')[0]
  if (!block) throw new Error('Missing importer')
  let kind = ''
  let name = ''
  const declarations = new Map<string, Record<string, string>>()
  const edges: Edge[] = []
  for (const line of block.split('\n')) {
    if (!line.trim() || line === '  .:') continue
    const group = /^ {4}(dependencies|devDependencies|optionalDependencies):$/.exec(line)
    if (group?.[1]) {
      kind = group[1]
      declarations.set(kind, {})
      continue
    }
    const entry = /^ {6}(\S.+?):$/.exec(line)
    if (entry?.[1]) {
      name = scalar(entry[1])
      continue
    }
    const field = /^ {8}(specifier|version): (.+)$/.exec(line)
    if (!field || !kind || !name) throw new Error('Unknown importer encoding')
    const value = scalar(field[2] ?? '')
    if (field[1] === 'specifier') {
      const group = declarations.get(kind)
      if (!group) throw new Error('Missing dependency class')
      group[name] = value
    } else
      edges.push({ name, target: `${name}@${value}`, optional: kind === 'optionalDependencies' })
  }
  for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const declared = object(manifest[kind] ?? {})
    const expected = declarations.get(kind) ?? {}
    if (
      Object.keys(declared).length !== Object.keys(expected).length ||
      Object.entries(expected).some(([name, version]) => declared[name] !== version)
    )
      throw new Error('Importer manifest mismatch')
  }
  return edges
}
function checkProfile(root: string): LockedPackage[] {
  if (process.versions.node !== '24.21.0') throw new Error('Unadmitted Node version')
  regularDirectory(root)
  regularDirectory(join(root, 'node_modules'))
  regularDirectory(join(root, 'node_modules/.pnpm'))
  for (const path of metadataPaths)
    if (!lstatSync(join(root, path)).isFile() || lstatSync(join(root, path)).isSymbolicLink())
      throw new Error('Linked metadata')
  const lock = readFileSync(join(root, 'pnpm-lock.yaml'), 'utf8')
  if (
    digest(lock) !== lockHash ||
    digest(readFileSync(join(root, 'pnpm-workspace.yaml'))) !== workspaceHash
  )
    throw new Error('Install profile mismatch')
  if (readFileSync(join(root, 'node_modules/.pnpm/lock.yaml'), 'utf8') !== lock)
    throw new Error('Current lockfile mismatch')
  const manifest = json(join(root, 'package.json'))
  const engines = object(manifest['engines'])
  if (
    manifest['packageManager'] !== 'pnpm@11.18.0' ||
    engines['node'] !== '24.21.0' ||
    engines['pnpm'] !== '11.18.0'
  )
    throw new Error('Unknown toolchain profile')
  importerEdges(lock, manifest)
  const modules = json(join(root, 'node_modules/.modules.yaml'))
  if (
    modules['layoutVersion'] !== 5 ||
    modules['nodeLinker'] !== 'isolated' ||
    modules['packageManager'] !== 'pnpm@11.18.0' ||
    modules['virtualStoreDir'] !== '.pnpm' ||
    modules['virtualStoreDirMaxLength'] !== 120
  )
    throw new Error('Unknown pnpm layout')
  const included = object(modules['included'])
  if (
    ['dependencies', 'devDependencies', 'optionalDependencies'].some(
      (key) => included[key] !== true,
    )
  )
    throw new Error('Incomplete installation')
  const store = modules['storeDir']
  if (
    typeof store !== 'string' ||
    !isAbsolute(store) ||
    beneath(join(root, 'node_modules'), resolve(store))
  )
    throw new Error('Unknown content store')
  const locked = lockedPackages(lock)
  if (
    locked.length !== 376 ||
    new Set(locked.map((pkg) => `${pkg.name}@${pkg.version}`)).size !== 376 ||
    locked.filter(supportsArchitecture).length !== 342
  )
    throw new Error('Install profile identities mismatch')
  return locked
}
function platformMatches(manifest: Record<string, unknown>, pkg: LockedPackage): boolean {
  return (['os', 'cpu', 'libc'] as const).every((key) => {
    const value = manifest[key]
    if (value === undefined) return pkg[key] === undefined
    return (
      Array.isArray(value) &&
      value.every((item) => typeof item === 'string') &&
      JSON.stringify(value) === JSON.stringify(pkg[key])
    )
  })
}
export interface GeneratedEntry {
  type: 'directory' | 'file'
  identity: string
  sha256?: string
  bytes?: number
}
const installedOutputRoots = [
  'node_modules/.cache',
  'node_modules/.vite-temp',
  'node_modules/.vue-global-types',
]
export function isToolCachePath(path: string): boolean {
  return /(?:^|\/)\.vite\/cache(?:\/|$)/.test(path.replaceAll('\\', '/').split(/[?#]/)[0] ?? '')
}
export function generatedOutput(
  project = process.cwd(),
  fresh = false,
): Record<string, GeneratedEntry> {
  const root = resolve(project)
  const output: Record<string, GeneratedEntry> = {}
  const optionalStat = (path: string) => {
    try {
      return lstatSync(join(root, path), { bigint: true })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw error
    }
  }
  function visit(path: string, cache: boolean): void {
    const stat = lstatSync(join(root, path), { bigint: true })
    if (stat.isSymbolicLink()) throw new Error(`Linked generated output: ${path}`)
    const identity = `${String(stat.dev)}:${String(stat.ino)}`
    if (stat.isDirectory()) {
      if (!cache && !installedOutputRoots.includes(path) && path !== 'node_modules/.cache/prettier')
        throw new Error(`Unexpected generated directory: ${path}`)
      if (
        cache &&
        ['node_modules', '.bin', '.pnpm'].includes(
          path.slice(path.lastIndexOf('/') + 1).toLowerCase(),
        )
      )
        throw new Error(`Package directory in cache: ${path}`)
      output[path] = { type: 'directory', identity }
      for (const name of readdirSync(join(root, path)).sort()) {
        if (!/^[\x20-\x7e]+$/.test(name) || name.includes('\\'))
          throw new Error(`Invalid generated name: ${path}`)
        const child = `${path}/${name}`
        if (
          !cache &&
          child !== 'node_modules/.cache/prettier' &&
          child !== 'node_modules/.vue-global-types/vue_3.5_1.d.ts'
        )
          throw new Error(`Unexpected generated output: ${child}`)
        visit(child, cache)
      }
    } else if (stat.isFile()) {
      if (stat.nlink !== 1n || (stat.mode & 0o111n) !== 0n)
        throw new Error(`Linked or executable generated file: ${path}`)
      const bytes = readFileSync(join(root, path))
      const sha256 = digest(bytes)
      if (!cache) {
        if (
          path !== 'node_modules/.vue-global-types/vue_3.5_1.d.ts' ||
          bytes.length !== 6275 ||
          sha256 !== 'c0839b07826141fc02396e0bd396f77da30e7d5eb5c46331a03c103fcdccd1e2'
        )
          throw new Error(`Unreviewed generated declaration: ${path}`)
      } else {
        if (!/\.(js|mjs|json|map|css)$/.test(path))
          throw new Error(`Unknown cache file type: ${path}`)
        const name = path.slice(path.lastIndexOf('/') + 1)
        if (
          name.toLowerCase() === 'package.json' &&
          (name !== 'package.json' || bytes.toString('utf8') !== '{\n  "type": "module"\n}\n')
        )
          throw new Error(`Package manifest in cache: ${path}`)
        const magic = bytes.subarray(0, 4).toString('hex')
        if (
          bytes.subarray(0, 2).toString() === 'MZ' ||
          [
            '7f454c46',
            'feedface',
            'feedfacf',
            'cefaedfe',
            'cffaedfe',
            'cafebabe',
            'bebafeca',
            'cafebabf',
            'bfbafeca',
            '0061736d',
          ].includes(magic) ||
          bytes.subarray(0, 8).toString() === '!<arch>\n'
        )
          throw new Error(`Native payload in cache: ${path}`)
      }
      output[path] = { type: 'file', identity, sha256, bytes: bytes.length }
    } else throw new Error(`Special generated output: ${path}`)
  }
  for (const path of installedOutputRoots) {
    if (!optionalStat(path)) continue
    if (fresh) throw new Error(`Generated output in fresh installation: ${path}`)
    if (!optionalStat(path)?.isDirectory() || optionalStat(path)?.isSymbolicLink())
      throw new Error(`Invalid generated scaffold: ${path}`)
    visit(path, false)
  }
  if (optionalStat('.vite')) regularDirectory(join(root, '.vite'))
  if (optionalStat('.vite/cache')) {
    if (fresh) throw new Error('Generated cache in fresh installation')
    regularDirectory(join(root, '.vite/cache'))
    const parent = lstatSync(join(root, '.vite'), { bigint: true })
    output['.vite'] = { type: 'directory', identity: `${String(parent.dev)}:${String(parent.ino)}` }
    visit('.vite/cache', true)
  }
  return output
}
export function installedPackages(
  project = process.cwd(),
  allowStaged = false,
  fresh = false,
): PhysicalInventory {
  const root = resolve(project)
  if (realpathSync(root) !== root) throw new Error('Linked project directory')
  const locked = checkProfile(root)
  const generated = generatedOutput(root, fresh)
  const lock = readFileSync(join(root, 'pnpm-lock.yaml'), 'utf8')
  const graph = snapshots(lock)
  const rootEdges = importerEdges(lock, json(join(root, 'package.json')))
  const byPair = new Map(locked.map((pkg) => [`${pkg.name}@${pkg.version}`, pkg]))
  const expected = new Map<string, { node: Snapshot; pkg: LockedPackage }>()
  for (const node of graph.values()) {
    const pkg = byPair.get(node.pair)
    if (!pkg) throw new Error('Unlisted snapshot')
    const directory = `node_modules/.pnpm/${instanceFilename(node.key)}`
    if (expected.has(directory)) throw new Error('Ambiguous virtual instance')
    expected.set(directory, { node, pkg })
  }
  const instances: Instance[] = []
  const scaffold = new Set([
    'node_modules',
    'node_modules/.pnpm',
    'node_modules/.pnpm/node_modules',
    'node_modules/.bin',
    'node_modules/.pnpm/node_modules/.bin',
  ])
  const addParents = (path: string) => {
    let current = path
    while (current !== '.' && current !== 'node_modules') {
      scaffold.add(current)
      current = dirname(current)
    }
  }
  for (const [directory, { node, pkg }] of expected) {
    const path = `${directory}/node_modules/${pkg.name}`
    addParents(path)
    scaffold.add(`${directory}/node_modules/.bin`)
    for (const edge of node.edges) addParents(`${directory}/node_modules/${edge.name}`)
    let stat
    try {
      stat = lstatSync(join(root, directory))
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
      if (supportsArchitecture(pkg)) throw new Error(`Missing eligible instance: ${node.key}`)
      continue
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Linked instance directory')
    // All ancestor components must be actual directories, never junctions or symlinks.
    let current = dirname(path)
    while (current !== 'node_modules') {
      regularDirectory(join(root, current))
      current = dirname(current)
    }
    regularDirectory(join(root, path))
    const manifestStat = lstatSync(join(root, path, 'package.json'))
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink())
      throw new Error('Linked package manifest')
    const manifest = json(join(root, path, 'package.json'))
    if (
      manifest['name'] !== pkg.name ||
      manifest['version'] !== pkg.version ||
      !platformMatches(manifest, pkg)
    )
      throw new Error(`Installed manifest mismatch: ${node.key}`)
    const eligible = supportsArchitecture(pkg)
    if (!eligible && (!allowStaged || !removalPairs.some((pair) => pair === node.pair)))
      throw new Error(`Excluded installed package: ${node.pair}`)
    if (!eligible) {
      if (
        node.edges.length ||
        [
          'dependencies',
          'optionalDependencies',
          'peerDependencies',
          'devDependencies',
          'scripts',
          'bundledDependencies',
          'bundleDependencies',
          'bin',
        ].some((key) => key in manifest)
      )
        throw new Error(`Non-leaf removal candidate: ${node.pair}`)
      const license = pkg.name.startsWith('lightningcss') ? 'MPL-2.0' : 'MIT'
      if (manifest['license'] !== license) throw new Error('Removal candidate license mismatch')
      if (
        license === 'MPL-2.0' &&
        digest(readFileSync(join(root, path, 'LICENSE'))) !== lightningNotice
      )
        throw new Error('Removal candidate notice mismatch')
      for (const owner of graph.values())
        for (const edge of owner.edges)
          if (edge.target === node.key && !edge.optional)
            throw new Error('Nonoptional removal edge')
    }
    instances.push({ key: node.key, pair: node.pair, path, directory, manifest, eligible })
  }
  const payloads = new Map(instances.map((item) => [resolve(root, item.path), item]))
  const links: Record<string, string> = {}
  const files: Record<string, string> = {}
  const directories: string[] = []
  const identities: Record<string, string> = {}
  const normalized = (path: string) => relative(root, path).split(sep).join('/')
  const metadata = Object.fromEntries(
    metadataPaths.map((path) => [path, digest(readFileSync(join(root, path)))]),
  )
  const knownMetadata = new Set(metadataPaths)
  function walk(path: string, owner?: Instance): void {
    const rel = normalized(path)
    // The dedicated classifier has fully walked these exact output subtrees.
    if (installedOutputRoots.includes(rel) && rel in generated) return
    const stat = lstatSync(path, { bigint: true })
    identities[rel] = `${String(stat.dev)}:${String(stat.ino)}`
    if (stat.isSymbolicLink()) {
      const target = readlinkSync(path)
      const destination = realpathSync(path)
      if (!beneath(root, destination)) throw new Error(`Escaping link: ${rel}`)
      if (owner) {
        if (!beneath(resolve(root, owner.path), destination))
          throw new Error(`Escaping payload link: ${rel}`)
      } else {
        const pkg = payloads.get(destination)
        if (!pkg) throw new Error(`Unknown dependency link: ${rel}`)
        const name = String(pkg.manifest['name'])
        const linkName = rel.slice(rel.lastIndexOf('/node_modules/') + 14)
        if (!pkg.eligible && linkName !== name) throw new Error(`Forged dependency alias: ${rel}`)
        const source = instances.find((item) => rel.startsWith(`${item.directory}/node_modules/`))
        if (source) {
          const edge = graph
            .get(source.key)
            ?.edges.find((item) => item.name === linkName && item.target === pkg.key)
          if (!edge || (!pkg.eligible && !edge.optional))
            throw new Error(`Unlisted incoming edge: ${rel}`)
        } else if (rel.startsWith('node_modules/.pnpm/node_modules/')) {
          if (
            linkName !== name &&
            ![...graph.values()].some((node) =>
              node.edges.some((edge) => edge.name === linkName && edge.target === pkg.key),
            )
          )
            throw new Error(`Forged hoisted alias: ${rel}`)
        } else {
          const edge = rootEdges.find((item) => item.name === linkName && item.target === pkg.key)
          if (!edge) throw new Error(`Unknown root link: ${rel}`)
          if (!pkg.eligible) throw new Error('Nonoptional root removal edge')
        }
      }
      if (owner && rel.endsWith('/package.json') && rel !== `${owner.path}/package.json`) {
        const nested = json(path)
        if ('name' in nested || 'version' in nested) throw new Error(`Nested package: ${rel}`)
      }
      links[rel] = target
      return
    }
    if (stat.isDirectory()) {
      const payload = payloads.get(path)
      if (
        !owner &&
        !payload &&
        !scaffold.has(rel) &&
        !/^node_modules\/(?:\.pnpm\/node_modules\/)?@[^/]+$/.test(rel)
      )
        throw new Error(`Unknown directory: ${rel}`)
      directories.push(rel)
      for (const entry of readdirSync(path).sort()) walk(join(path, entry), owner ?? payload)
    } else if (stat.isFile()) {
      if (
        !owner &&
        !knownMetadata.has(rel) &&
        !/^node_modules\/(?:\.pnpm\/(?:[^/]+\/)?node_modules\/)?\.bin\/[^/]+$/.test(rel)
      )
        throw new Error(`Unknown file: ${rel}`)
      if (owner && rel.endsWith('/package.json') && rel !== `${owner.path}/package.json`) {
        const nested = json(path)
        if ('name' in nested || 'version' in nested) throw new Error(`Nested package: ${rel}`)
      }
      files[rel] = digest(readFileSync(path))
    } else throw new Error(`Special file: ${rel}`)
  }
  walk(join(root, 'node_modules'))
  for (const instance of instances) {
    for (const edge of graph.get(instance.key)?.edges ?? []) {
      const target = instances.find((item) => item.key === edge.target)
      if (!target) {
        if (!edge.optional) throw new Error(`Missing dependency instance: ${edge.target}`)
        continue
      }
      const path = `${instance.directory}/node_modules/${edge.name}`
      if (!(path in links) || realpathSync(join(root, path)) !== resolve(root, target.path))
        throw new Error(`Missing dependency link: ${path}`)
    }
  }
  for (const edge of rootEdges) {
    const target = instances.find((item) => item.key === edge.target)
    if (
      !target ||
      links[`node_modules/${edge.name}`] === undefined ||
      realpathSync(join(root, 'node_modules', edge.name)) !== resolve(root, target.path)
    )
      throw new Error(`Missing importer link: ${edge.name}`)
  }
  const pairs = [...new Set(instances.map((item) => item.pair))].sort()
  for (const pkg of locked.filter(supportsArchitecture))
    if (!pairs.includes(`${pkg.name}@${pkg.version}`)) throw new Error('Missing eligible package')
  return {
    root,
    locked,
    instances,
    pairs,
    files,
    links,
    directories,
    identities,
    metadata,
    candidates: instances.filter((item) => !item.eligible),
    generated,
  }
}
export async function rawLicenses(root = process.cwd()): Promise<unknown> {
  const modules = json(join(root, 'node_modules/.modules.yaml'))
  const store = modules['storeDir']
  if (typeof store !== 'string' || !store.endsWith(`${sep}v11`))
    throw new Error('Unknown pnpm store')
  if ((await checkedTool('pnpm', ['--version'], root)).trim() !== '11.18.0')
    throw new Error('Unadmitted pnpm version')
  const text = await checkedTool(
    'pnpm',
    [`--config.store-dir=${store.slice(0, -4)}`, 'licenses', 'list', '--json'],
    root,
  )
  console.log(`Raw pnpm licenses list --json:\n${text}`)
  return JSON.parse(text) as unknown
}
export interface PhysicalLicense {
  name: string
  version: string
  declared: string
  paths: string[]
}
function manifestLicense(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    'type' in value &&
    typeof value.type === 'string' &&
    value.type.length
  )
    return value.type
  return undefined
}
export function validateCatalogue(inventory: PhysicalInventory, raw: unknown): PhysicalLicense[] {
  const result = new Map<string, PhysicalLicense>()
  const physical = new Map<string, Instance[]>()
  for (const instance of inventory.instances)
    physical.set(instance.pair, [...(physical.get(instance.pair) ?? []), instance])
  for (const [declared, values] of Object.entries(object(raw))) {
    if (!Array.isArray(values)) throw new Error('Invalid license catalogue')
    for (const value of values) {
      const row = object(value)
      const name = row['name']
      const versions = row['versions']
      const paths = row['paths']
      if (
        typeof name !== 'string' ||
        !Array.isArray(versions) ||
        !versions.length ||
        !Array.isArray(paths) ||
        !paths.length ||
        !paths.every((path) => typeof path === 'string')
      )
        throw new Error('Invalid license row')
      if ('license' in row && row['license'] !== declared)
        throw new Error('Catalogue declaration mismatch')
      // pnpm groups all versions and their paths for one name/license in the same row.
      const rowInstances = versions.flatMap((version) =>
        typeof version === 'string' ? (physical.get(`${name}@${version}`) ?? []) : [],
      )
      for (const version of versions) {
        if (typeof version !== 'string') throw new Error('Invalid catalogue version')
        const pair = `${name}@${version}`
        if (!inventory.locked.some((pkg) => `${pkg.name}@${pkg.version}` === pair))
          throw new Error(`Unknown catalogue row: ${pair}`)
        const instances = physical.get(pair)
        if (!instances) {
          if (
            !removalPairs.some((item) => item === pair) ||
            declared !== (name.startsWith('lightningcss') ? 'MPL-2.0' : 'MIT')
          )
            throw new Error(`Absent catalogue package: ${pair}`)
          continue // Complete independent enumeration above proved no corresponding payload or link.
        }
        if (
          instances.some((instance) => manifestLicense(instance.manifest['license']) !== declared)
        )
          throw new Error(`Catalogue license mismatch: ${pair}`)
        if (
          instances.some(
            (instance) =>
              !paths.some((path) => {
                try {
                  return realpathSync(path) === resolve(inventory.root, instance.path)
                } catch {
                  return false
                }
              }),
          )
        )
          throw new Error(`Missing physical catalogue path: ${pair}`)
        if (
          !paths.every((path) => {
            try {
              return (
                typeof path === 'string' &&
                isAbsolute(path) &&
                rowInstances.some(
                  (instance) => realpathSync(path) === resolve(inventory.root, instance.path),
                )
              )
            } catch {
              return false
            }
          })
        )
          throw new Error(`Unverified catalogue path: ${pair}`)
        const previous = result.get(pair)
        if (previous && previous.declared !== declared)
          throw new Error(`Conflicting catalogue license: ${pair}`)
        result.set(pair, {
          name,
          version,
          declared,
          paths: instances.map((instance) => resolve(inventory.root, instance.path)),
        })
      }
    }
  }
  for (const instance of inventory.instances)
    if (!result.has(instance.pair))
      throw new Error(`Missing eligible license evidence: ${instance.pair}`)
  return [...result.values()]
    .filter((row) =>
      inventory.instances.some(
        (instance) => instance.eligible && instance.pair === `${row.name}@${row.version}`,
      ),
    )
    .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`))
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
export function supportsArchitecture(pkg: LockedPackage): boolean {
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
