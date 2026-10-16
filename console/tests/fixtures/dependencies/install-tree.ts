import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  rmSync,
  readFileSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative, dirname } from 'node:path'
import { createHash } from 'node:crypto'

export const lock = readFileSync('pnpm-lock.yaml', 'utf8')
export const workspace = readFileSync('pnpm-workspace.yaml', 'utf8')
export const removable = [
  '@rolldown/binding-linux-arm64-musl@1.2.13',
  '@rolldown/binding-linux-x64-musl@1.2.13',
  'lightningcss-linux-arm64-musl@1.33.0',
  'lightningcss-linux-x64-musl@1.33.0',
]
export function fixtureFilename(key: string): string {
  let value = key
    .replaceAll('/', '+')
    .replace(/\)$/, '')
    .replace(/\)\(|\(|\)/g, '_')
  if (value.length > 120)
    value = `${value.slice(0, 87)}_${createHash('sha256').update(value).digest('hex').slice(0, 32)}`
  return value
}
export function tree(extras = false) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'rv-install-')))
  const put = (path: string, value: string) => {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), value)
  }
  put('pnpm-lock.yaml', lock)
  put('pnpm-workspace.yaml', workspace)
  put('package.json', readFileSync('package.json', 'utf8'))
  put('node_modules/.pnpm/lock.yaml', lock)
  put(
    'node_modules/.modules.yaml',
    JSON.stringify({
      layoutVersion: 5,
      nodeLinker: 'isolated',
      packageManager: 'pnpm@11.18.0',
      virtualStoreDir: '.pnpm',
      virtualStoreDirMaxLength: 120,
      storeDir: join(root, 'cache/v11'),
      included: { dependencies: true, devDependencies: true, optionalDependencies: true },
    }),
  )
  put('node_modules/.pnpm-workspace-state-v1.json', '{}')
  put('node_modules/.package-map.json', '{}')
  // Reproduce manifests from admitted installed data without executing package code.
  const packages = new Map<string, Record<string, unknown>>()
  const block = lock.split('\npackages:\n')[1]?.split('\nsnapshots:\n')[0] ?? ''
  let pair = ''
  for (const line of block.split('\n')) {
    const entry = /^  '?([^' \n][^']*?)'?:/.exec(line)
    if (entry?.[1]) {
      pair = entry[1]
      const at = pair.lastIndexOf('@')
      packages.set(pair, { name: pair.slice(0, at), version: pair.slice(at + 1), license: 'MIT' })
    }
    const field = /^    (os|cpu|libc): \[(.*)\]/.exec(line)
    if (field?.[1])
      (packages.get(pair) ?? {})[field[1]] = field[2]
        ?.split(',')
        .map((v) => v.trim().replaceAll("'", ''))
  }
  const allows = (value: unknown, target: string) =>
    !Array.isArray(value) || !value.length || value.includes(target) || value.includes('any')
  const catalogue: Record<string, unknown[]> = { MIT: [] }
  const paths = new Map<string, string>()
  for (const match of lock.split('\nsnapshots:\n')[1]?.matchAll(/^  '?([^' \n][^'\n]*?)'?:/gm) ??
    []) {
    const key = match[1] ?? ''
    const base = key.split('(')[0] ?? ''
    const manifest = packages.get(base)
    if (!manifest) throw new Error(`fixture missing ${base}`)
    const eligible = ['linux', 'darwin', 'win32'].some((os) =>
      ['x64', 'arm64'].some(
        (cpu) =>
          allows(manifest['os'], os) &&
          allows(manifest['cpu'], cpu) &&
          allows(manifest['libc'], 'glibc'),
      ),
    )
    if (!eligible && !(extras && removable.includes(base))) continue
    const path = `node_modules/.pnpm/${fixtureFilename(key)}/node_modules/${String(manifest['name'])}`
    paths.set(key, path)
    if (base.startsWith('lightningcss-')) manifest['license'] = 'MPL-2.0'
    put(`${path}/package.json`, JSON.stringify(manifest))
    put(`${path}/payload`, `payload ${key}`)
    if (base.startsWith('lightningcss-'))
      put(
        `${path}/LICENSE`,
        readFileSync('tests/fixtures/dependencies/lightningcss-LICENSE', 'utf8'),
      )
    const declared = String(manifest['license'])
    ;(catalogue[declared] ??= []).push({
      name: manifest['name'],
      versions: [manifest['version']],
      paths: [join(root, path)],
    })
  }
  let parent = ''
  let kind = ''
  for (const line of lock.split('\nsnapshots:\n')[1]?.split('\n') ?? []) {
    const node = /^  '?([^' \n][^']*?)'?:/.exec(line)
    if (node?.[1]) {
      parent = node[1]
      kind = ''
      continue
    }
    const field = /^    (\w+):/.exec(line)
    if (field?.[1]) {
      kind = field[1]
      continue
    }
    const edge = /^      '?([^']+?)'?: (.+)$/.exec(line)
    if (!edge || !['dependencies', 'optionalDependencies'].includes(kind)) continue
    const name = edge[1] ?? ''
    const reference = edge[2] ?? ''
    const key = /^\d/.test(reference) ? `${name}@${reference}` : reference
    const owner = paths.get(parent)
    const target = paths.get(key)
    if (!owner || !target) continue
    const path = join(root, `node_modules/.pnpm/${fixtureFilename(parent)}/node_modules`, name)
    mkdirSync(dirname(path), { recursive: true })
    symlinkSync(relative(dirname(path), join(root, target)), path, 'dir')
  }
  const manifest = JSON.parse(readFileSync('package.json', 'utf8')) as Record<
    string,
    Record<string, string>
  >
  for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, version] of Object.entries(manifest[kind] ?? {})) {
      const target = [...paths.entries()].find(
        ([key]) => (key.split('(')[0] ?? '') === `${name}@${version}`,
      )?.[1]
      if (!target) throw new Error('Missing fixture root')
      const path = join(root, 'node_modules', name)
      mkdirSync(dirname(path), { recursive: true })
      symlinkSync(relative(dirname(path), join(root, target)), path, 'dir')
    }
  }
  return {
    root,
    put,
    paths,
    catalogue,
    cleanup: () => {
      rmSync(root, { recursive: true, force: true })
    },
  }
}
