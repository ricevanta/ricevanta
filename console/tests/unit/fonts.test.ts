import { expect, it } from 'vitest'
import { execFile } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import {
  fontSubsets,
  fontWeights,
  normalizeUnicodeRange,
  packageFontFaces,
  parseFontFaces,
} from '../helpers/fonts.ts'

it('ships all twelve package subset ranges with local hashed WOFF2 sources', async () => {
  const root = mkdtempSync(join(tmpdir(), 'rv-fonts-'))
  try {
    mkdirSync(join(root, 'src/ui/styles'), { recursive: true })
    symlinkSync(resolve('node_modules'), join(root, 'node_modules'))
    writeFileSync(join(root, 'src/ui/styles/fonts.css'), readFileSync('src/ui/styles/fonts.css'))
    writeFileSync(join(root, 'main.js'), "import './src/ui/styles/fonts.css'")
    writeFileSync(join(root, 'index.html'), '<script type="module" src="/main.js"></script>')
    await promisify(execFile)(process.execPath, [resolve('tests/fixtures/build/fonts.ts'), root])
    const assets = readdirSync(join(root, 'dist/assets'))
    const rules = assets
      .filter((name) => name.endsWith('.css'))
      .flatMap((name) => parseFontFaces(readFileSync(join(root, 'dist/assets', name), 'utf8')))
    const expected = packageFontFaces()
    expect(expected.map(({ weight, subset }) => `${weight}:${subset}`).sort()).toEqual(
      fontWeights.flatMap((weight) => fontSubsets.map((subset) => `${weight}:${subset}`)).sort(),
    )
    expect(rules).toHaveLength(12)
    const actual = rules.map((rule) => {
      expect(rule.get('font-family')?.replace(/["']/g, '')).toBe('Be Vietnam Pro')
      expect(rule.get('font-style')).toBe('normal')
      expect(rule.get('font-display')).toBe('swap')
      const src = rule.get('src') ?? ''
      expect(src).toMatch(
        /^url\(["']?\/assets\/be-vietnam-pro-(latin-ext|latin|vietnamese)-(400|500|600|700)-normal-[\w-]+\.woff2["']?\)\s*format\(["']?woff2["']?\)$/,
      )
      const subset = /be-vietnam-pro-(latin-ext|latin|vietnamese)-/.exec(src)?.[1]
      const url = /url\(["']?([^"')]+)["']?\)/.exec(src)?.[1]
      expect(assets).toContain(url?.split('/').at(-1))
      return {
        weight: rule.get('font-weight') ?? '',
        subset: subset ?? '',
        unicodeRange: normalizeUnicodeRange(rule.get('unicode-range') ?? ''),
      }
    })
    const sort = (a: { weight: string; subset: string }, b: { weight: string; subset: string }) =>
      `${a.weight}:${a.subset}`.localeCompare(`${b.weight}:${b.subset}`)
    expect(actual.sort(sort)).toEqual(expected.sort(sort))
    expect(assets.filter((name) => /\.woff2?$/.test(name))).toHaveLength(12)
    expect(assets.some((name) => name.endsWith('.woff'))).toBe(false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
