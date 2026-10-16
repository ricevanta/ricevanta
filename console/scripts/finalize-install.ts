import { lstatSync, readFileSync, readlinkSync, realpathSync, rmdirSync, unlinkSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import {
  installedPackages,
  rawLicenses,
  validateCatalogue,
  digest,
  beneath,
  regularDirectory,
} from './installed-packages.ts'
import { normalizeLicense } from './audit-deps.ts'
import type { PhysicalInventory } from './installed-packages.ts'

function state(inventory: PhysicalInventory) {
  return {
    pairs: inventory.pairs,
    instances: inventory.instances.map(({ key, path, manifest }) => ({
      key,
      path,
      license: manifest['license'],
    })),
    files: inventory.files,
    links: inventory.links,
    metadata: inventory.metadata,
    identities: inventory.identities,
  }
}
function retained(inventory: PhysicalInventory) {
  const excluded = (path: string) =>
    inventory.candidates.some(
      (item) => path === item.directory || path.startsWith(`${item.directory}/`),
    )
  const removedLinks = new Set(
    Object.keys(inventory.links).filter((path) => {
      const destination = realpathSync(join(inventory.root, path))
      return inventory.candidates.some((item) => destination === resolve(inventory.root, item.path))
    }),
  )
  return {
    instances: inventory.instances
      .filter((item) => item.eligible)
      .map(({ key, path }) => ({ key, path })),
    files: Object.fromEntries(Object.entries(inventory.files).filter(([path]) => !excluded(path))),
    links: Object.fromEntries(
      Object.entries(inventory.links).filter(
        ([path]) => !excluded(path) && !removedLinks.has(path),
      ),
    ),
    directories: inventory.directories.filter((path) => !excluded(path)),
    metadata: inventory.metadata,
    identities: Object.fromEntries(
      Object.entries(inventory.identities).filter(
        ([path]) => !excluded(path) && !removedLinks.has(path),
      ),
    ),
  }
}
// Callers must discard the isolated installation after any error, including partial mutation.
export async function finalizeInstall(
  root = process.cwd(),
  catalogue: (root: string) => Promise<unknown> = rawLicenses,
) {
  try {
    const before = installedPackages(root, true)
    const raw = await catalogue(before.root)
    const licenses = validateCatalogue(before, raw).map((pkg) => ({
      ...pkg,
      normalized: normalizeLicense({
        ...pkg,
        runtime: false,
        modified: false,
        evidence:
          pkg.declared === 'Python-2.0'
            ? readFileSync(join(pkg.paths[0] ?? '', 'LICENSE'), 'utf8')
            : '',
      }),
    }))
    const expected = retained(before)
    // Reading pnpm's catalogue is not an authority to mutate: repeat complete preflight afterward.
    const rechecked = installedPackages(root, true)
    if (JSON.stringify(state(before)) !== JSON.stringify(state(rechecked)))
      throw new Error('Installation changed during preflight')
    const incoming = Object.entries(before.links).filter(([path]) =>
      before.candidates.some(
        (item) => realpathSync(join(before.root, path)) === resolve(before.root, item.path),
      ),
    )
    const assertParents = (path: string) => {
      if (!beneath(join(before.root, 'node_modules'), path))
        throw new Error('Removal escaped installed tree')
      const assertIdentity = (item: string) => {
        const stat = lstatSync(item, { bigint: true })
        const rel = item
          .slice(before.root.length + 1)
          .split('\\')
          .join('/')
        if (before.identities[rel] !== `${String(stat.dev)}:${String(stat.ino)}`)
          throw new Error('Removal identity changed')
      }
      assertIdentity(path)
      let parent = dirname(path)
      while (parent !== before.root) {
        regularDirectory(parent)
        assertIdentity(parent)
        parent = dirname(parent)
      }
    }
    for (const [relative, target] of incoming) {
      const path = join(before.root, relative)
      assertParents(path)
      if (
        !lstatSync(path).isSymbolicLink() ||
        readlinkSync(path) !== target ||
        !before.candidates.some((item) => realpathSync(path) === resolve(before.root, item.path))
      )
        throw new Error('Incoming link changed before removal')
      unlinkSync(path)
    }
    for (const item of before.candidates) {
      const manifestPath = join(before.root, item.path, 'package.json')
      assertParents(manifestPath)
      if (
        !lstatSync(manifestPath).isFile() ||
        lstatSync(manifestPath).isSymbolicLink() ||
        digest(readFileSync(manifestPath)) !== before.files[`${item.path}/package.json`]
      )
        throw new Error('Candidate identity changed before removal')
      for (const [relative, hash] of Object.entries(before.files).filter(([path]) =>
        path.startsWith(`${item.directory}/`),
      )) {
        const path = join(before.root, relative)
        assertParents(path)
        const stat = lstatSync(path)
        if (!stat.isFile() || stat.isSymbolicLink() || digest(readFileSync(path)) !== hash)
          throw new Error('Candidate file changed before removal')
        unlinkSync(path) // Never write through hardlinks into the content store.
      }
      for (const [relative, target] of Object.entries(before.links).filter(
        ([path]) =>
          path.startsWith(`${item.directory}/`) && !incoming.some(([link]) => path === link),
      )) {
        const path = join(before.root, relative)
        assertParents(path)
        if (!lstatSync(path).isSymbolicLink() || readlinkSync(path) !== target)
          throw new Error('Candidate link changed before removal')
        unlinkSync(path)
      }
      for (const relative of before.directories
        .filter((path) => path === item.directory || path.startsWith(`${item.directory}/`))
        .sort((a, b) => b.length - a.length)) {
        const path = join(before.root, relative)
        assertParents(path)
        regularDirectory(path)
        rmdirSync(path)
      }
    }
    const after = installedPackages(before.root)
    validateCatalogue(after, raw)
    if (JSON.stringify(expected) !== JSON.stringify(retained(after)))
      throw new Error('Retained installation changed')
    return {
      before: state(before),
      after: state(after),
      removed: before.candidates.map(({ pair, path, manifest }) => ({
        pair,
        path,
        license: manifest['license'],
      })),
      licenses,
      rawCatalogue: raw,
    }
  } catch (cause) {
    throw new Error('Installation is unaccepted; discard it and perform a fresh frozen install', {
      cause,
    })
  }
}
if (import.meta.main) {
  try {
    console.log(JSON.stringify(await finalizeInstall(), null, 2))
  } catch (error) {
    console.error(error)
    process.exitCode = 1
  }
}
