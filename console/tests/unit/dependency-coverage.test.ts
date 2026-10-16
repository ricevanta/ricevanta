import { expect, it, vi } from 'vitest'
import { resolvedLicenses } from '../../scripts/audit-deps.ts'
import { tree } from '../fixtures/dependencies/install-tree.ts'
const metadata = vi.hoisted((): { catalogue: unknown } => ({ catalogue: {} }))
vi.mock('../../scripts/run-tool.ts', () => ({
  checkedTool: (command: string, args: readonly string[]) => {
    if (command !== 'pnpm') return Promise.reject(new Error('Unexpected metadata tool'))
    if (args.includes('--version')) return Promise.resolve('11.18.0\n')
    if (args.includes('licenses')) return Promise.resolve(JSON.stringify(metadata.catalogue))
    if (args.includes('list')) return Promise.resolve('[]')
    return Promise.reject(new Error('Unexpected metadata command'))
  },
}))
it('rejects license evidence that omits locked packages on other operating systems', async () => {
  const value = tree()
  const cwd = vi.spyOn(process, 'cwd').mockReturnValue(value.root)
  const log = vi.spyOn(console, 'log').mockImplementation(() => {})
  const without = (name: string) =>
    Object.fromEntries(
      Object.entries(value.catalogue).map(([license, rows]) => [
        license,
        rows.filter(
          (item) => !(item && typeof item === 'object' && 'name' in item && item.name === name),
        ),
      ]),
    )
  try {
    metadata.catalogue = value.catalogue
    await expect(resolvedLicenses()).resolves.toHaveLength(342)
    metadata.catalogue = without('lightningcss-darwin-arm64')
    await expect(resolvedLicenses()).rejects.toThrow('lightningcss-darwin-arm64@1.33.0')
    metadata.catalogue = without('lightningcss-win32-x64-msvc')
    await expect(resolvedLicenses()).rejects.toThrow('lightningcss-win32-x64-msvc@1.33.0')
  } finally {
    metadata.catalogue = {}
    cwd.mockRestore()
    log.mockRestore()
    value.cleanup()
  }
})
