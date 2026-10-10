import { expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
it('copies only approved brand bytes and the package OFL notice', async () => {
  expect(existsSync('scripts/prepare-assets.ts')).toBe(true)
  if (!existsSync('scripts/prepare-assets.ts')) return
  const { prepareAssets } = await import('../../scripts/prepare-assets.ts')
  const out = mkdtempSync(join(tmpdir(), 'rv-assets-'))
  try {
    prepareAssets('../branding', out)
    for (const name of readdirSync('../branding/dist/web'))
      expect(readFileSync(join(out, 'brand', name))).toEqual(
        readFileSync(`../branding/dist/web/${name}`),
      )
    for (const name of ['horizontal-color.svg', 'horizontal-dark.svg'])
      expect(readFileSync(join(out, 'brand', name))).toEqual(
        readFileSync(`../branding/dist/svg/${name}`),
      )
    expect(readFileSync(join(out, 'assets/OFL-BeVietnamPro.txt'), 'utf8')).toContain(
      'SIL OPEN FONT LICENSE',
    )
    const css = readFileSync('src/ui/styles/fonts.css', 'utf8')
    expect(css).not.toMatch(/https?:/)
  } finally {
    rmSync(out, { recursive: true, force: true })
  }
})
