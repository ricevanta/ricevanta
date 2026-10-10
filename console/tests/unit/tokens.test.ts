import { expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
it('generates deterministic tokens from strict named tables and checks contrast', async () => {
  expect(existsSync('scripts/generate-tokens.ts')).toBe(true)
  if (!existsSync('scripts/generate-tokens.ts')) return
  const { generateTokens, contrast } = await import('../../scripts/generate-tokens.ts')
  const brand = readFileSync('../branding/BRAND_SPEC.md', 'utf8')
  const design = readFileSync('../docs/design/console.md', 'utf8')
  const css = generateTokens(brand, design)
  expect(css).toBe(generateTokens(brand, design))
  expect(css).toContain('--rv-indigo: #173B54')
  expect(css).toContain('--rv-harvest-gold: #DDB85C')
  expect(css).toContain('--rv-rice-ivory: #F6F2E7')
  expect(css).toContain('[data-theme="system"]')
  expect(css).toContain('--rv-control-height: 28px')
  for (const changed of [
    brand.replace('#173B54', '#173B5'),
    brand.replace('### Mandatory brand palette', '### Renamed'),
    brand.replace('| `--rv-rice-ivory`', '| `--rv-indigo`'),
    brand.replace('| `--rv-rice-ivory`', '| `--rv-extra`'),
    '',
  ])
    expect(() => generateTokens(changed, design)).toThrow()
  for (const changed of [
    design.replace('| Surface |', '| Text |'),
    design.replace('| Surface |', '| Extra |'),
    design.replace('## 8. Design system', '## 8. Renamed'),
    '',
  ])
    expect(() => generateTokens(brand, changed)).toThrow()
  const lines = design.split('\n')
  const a = lines.findIndex((x) => x.startsWith('| Surface |'))
  const b = lines.findIndex((x) => x.startsWith('| Text |'))
  const first = lines[a]
  const second = lines[b]
  if (first && second) {
    lines[a] = second
    lines[b] = first
  }
  expect(generateTokens(brand, lines.join('\n'))).toBe(css)
  expect(contrast('#000000', '#FFFFFF')).toBe(21)
})

it.each(['Text', 'Secondary text', 'Control border', 'Focus ring'])(
  'rejects generated %s with insufficient contrast',
  async (role) => {
    const { generateTokens } = await import('../../scripts/generate-tokens.ts')
    const brand = readFileSync('../branding/BRAND_SPEC.md', 'utf8')
    const design = readFileSync('../docs/design/console.md', 'utf8')
    const changed = design
      .split('\n')
      .map((line) =>
        line.startsWith(`| ${role} |`) ? line.replace(/#[0-9A-Fa-f]{6}/, '#FFFFFF') : line,
      )
      .join('\n')
    expect(changed).not.toBe(design)
    expect(() => generateTokens(brand, changed)).toThrow('Contrast failure')
  },
)

it.each([
  ['Surface', 1, 0],
  ['Surface', 2, 0],
  ['Primary action fill and text on it', 1, 0],
  ['Primary action fill and text on it', 2, 0],
  ['Primary action fill and text on it', 2, 1],
  ['Severity critical, high, medium, low, informational (text and icon)', 1, 0],
  ['Severity critical, high, medium, low, informational (text and icon)', 2, 0],
])('rejects white text in %s column %i colour %i', async (role, column, colour) => {
  const { generateTokens } = await import('../../scripts/generate-tokens.ts')
  const brand = readFileSync('../branding/BRAND_SPEC.md', 'utf8')
  const design = readFileSync('../docs/design/console.md', 'utf8')
  const changed = design
    .split('\n')
    .map((line) => {
      if (!line.startsWith(`| ${role} |`)) return line
      const cells = line.split('|')
      let index = 0
      cells[column + 1] = (cells[column + 1] ?? '').replace(/`#[0-9A-Fa-f]{6}`/g, (hex) =>
        index++ === colour ? 'white text' : hex,
      )
      return cells.join('|')
    })
    .join('\n')
  expect(changed).not.toBe(design)
  expect(() => generateTokens(brand, changed)).toThrow('Invalid colour cell')
})

it('rejects white text in the brand palette', async () => {
  const { generateTokens } = await import('../../scripts/generate-tokens.ts')
  const brand = readFileSync('../branding/BRAND_SPEC.md', 'utf8')
  const design = readFileSync('../docs/design/console.md', 'utf8')
  expect(() => generateTokens(brand.replace('`#173B54`', 'white text'), design)).toThrow(
    'Invalid colour cell',
  )
})
