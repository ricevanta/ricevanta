import { expect, it, vi } from 'vitest'
import { resolvedLicenses } from '../../scripts/audit-deps.ts'
vi.mock('../../scripts/run-tool.ts', () => ({
  checkedTool: (_command: string, args: readonly string[]) =>
    Promise.resolve(args.includes('licenses') ? '{}' : '[]'),
}))
it('rejects license evidence that omits locked packages on other operating systems', async () => {
  await expect(resolvedLicenses()).rejects.toThrow('lightningcss-darwin-arm64@1.33.0')
  await expect(resolvedLicenses()).rejects.toThrow('lightningcss-win32-x64-msvc@1.33.0')
})
