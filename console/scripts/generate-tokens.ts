import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'

function table(text: string, heading: string, columns: readonly string[]): Map<string, string[]> {
  const start = text.indexOf(`${heading}\n`)
  if (start < 0) throw new Error('Missing table section')
  const section = text.slice(start + heading.length).split(/\n#{1,3} /)[0] ?? ''
  const rows = section
    .split('\n')
    .filter((line) => line.startsWith('|'))
    .map((line) =>
      line
        .split('|')
        .slice(1, -1)
        .map((cell) => cell.trim()),
    )
  if (
    JSON.stringify(rows[0]) !== JSON.stringify(columns) ||
    !rows[1]?.every((cell) => /^:?-+:?$/.test(cell))
  )
    throw new Error('Invalid table columns')
  const result = new Map<string, string[]>()
  for (const row of rows.slice(2)) {
    const key = row[0]?.replaceAll('`', '')
    if (!key || result.has(key) || row.length !== columns.length)
      throw new Error('Invalid table row')
    result.set(key, row.slice(1))
  }
  return result
}
function colours(cell: string, size: number, whiteTextIndex?: number): string[] {
  const values = [...cell.matchAll(/`(#[^`]+)`|\b(white text)\b/g)].map((match, index) => {
    if (match[2] && index !== whiteTextIndex) throw new Error('Invalid colour cell')
    return match[1] ?? '#FFFFFF'
  })
  if (values.length !== size || values.some((value) => !/^#[0-9a-fA-F]{6}$/.test(value)))
    throw new Error('Invalid colour cell')
  return values.map((value) => value.toUpperCase())
}
export function contrast(a: string, b: string): number {
  function luminance(hex: string): number {
    const channels = [1, 3, 5]
      .map((offset) => parseInt(hex.slice(offset, offset + 2), 16) / 255)
      .map((value) => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4))
    return (channels[0] ?? 0) * 0.2126 + (channels[1] ?? 0) * 0.7152 + (channels[2] ?? 0) * 0.0722
  }
  const x = luminance(a)
  const y = luminance(b)
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)
}
export function generateTokens(brandText: string, designText: string): string {
  const brands = table(brandText, '### Mandatory brand palette', ['Token', 'Hex', 'Role'])
  const names = ['--rv-indigo', '--rv-harvest-gold', '--rv-rice-ivory']
  if (brands.size !== names.length || names.some((name) => !brands.has(name)))
    throw new Error('Invalid brand roles')
  const brand = Object.fromEntries(
    names.map((name) => [name, colours(brands.get(name)?.[0] ?? '', 1)[0] ?? '']),
  )
  const roles: Record<string, string[]> = {
    'Page background': ['page'],
    Surface: ['surface'],
    Text: ['text'],
    'Secondary text': ['text-secondary'],
    'Primary action fill and text on it': ['action', 'on-action'],
    'Control border': ['border'],
    'Focus ring': ['focus'],
    'Severity critical, high, medium, low, informational (text and icon)': [
      'severity-critical',
      'severity-high',
      'severity-medium',
      'severity-low',
      'severity-informational',
    ],
  }
  const semantics = table(designText, '## 8. Design system', ['Token', 'Light', 'Dark', 'Contrast'])
  if (
    semantics.size !== Object.keys(roles).length ||
    [...semantics.keys()].some((name) => !(name in roles))
  )
    throw new Error('Invalid semantic roles')
  const light: Record<string, string> = {}
  const dark: Record<string, string> = {}
  for (const [role, keys] of Object.entries(roles)) {
    const row = semantics.get(role)
    if (!row) throw new Error('Missing semantic role')
    const a = colours(
      row[0] ?? '',
      keys.length,
      role === 'Primary action fill and text on it' ? 1 : undefined,
    )
    const b = colours(row[1] ?? '', keys.length)
    keys.forEach((key, index) => {
      light[`--rv-color-${key}`] = a[index] ?? ''
      dark[`--rv-color-${key}`] = b[index] ?? ''
    })
  }
  for (const theme of [light, dark]) {
    for (const bg of ['page', 'surface'])
      for (const fg of ['text', 'text-secondary', 'border', 'focus']) {
        if (
          contrast(theme[`--rv-color-${fg}`] ?? '', theme[`--rv-color-${bg}`] ?? '') <
          (fg === 'text' || fg === 'text-secondary' ? 4.5 : 3)
        )
          throw new Error('Contrast failure')
      }
    if (contrast(theme['--rv-color-action'] ?? '', theme['--rv-color-on-action'] ?? '') < 4.5)
      throw new Error('Action contrast failure')
  }
  function block(selector: string, values: Record<string, string>): string {
    return `${selector} {\n${Object.keys(values)
      .sort()
      .map((name) => {
        const value = values[name] ?? ''
        const reference = name.startsWith('--rv-color-')
          ? names.find((key) => brand[key] === value)
          : undefined
        return `  ${name}: ${reference ? `var(${reference})` : value};`
      })
      .join('\n')}\n}\n`
  }
  const dimensions = Object.fromEntries(
    [4, 8, 12, 16, 24, 32].map((value, index) => [
      `--rv-space-${String(index + 1)}`,
      `${String(value)}px`,
    ]),
  )
  Object.assign(dimensions, {
    '--rv-control-height': '36px',
    '--rv-row-height': '40px',
    '--rv-focus-width': '2px',
    '--rv-focus-offset': '2px',
    '--rv-radius-small': '4px',
    '--rv-radius-medium': '8px',
  })
  return (
    block(':root', { ...brand, ...dimensions, ...light }) +
    block('[data-theme="light"]', light) +
    block('[data-theme="dark"]', dark) +
    `@media (prefers-color-scheme: dark) {\n${block('[data-theme="system"]', dark)
      .split('\n')
      .filter(Boolean)
      .map((line) => `  ${line}`)
      .join('\n')}\n}\n` +
    block('[data-density="compact"]', { '--rv-control-height': '28px', '--rv-row-height': '32px' })
  )
}
if (import.meta.main) {
  const output = generateTokens(
    readFileSync('../branding/BRAND_SPEC.md', 'utf8'),
    readFileSync('../docs/design/console.md', 'utf8'),
  )
  mkdirSync('src/generated', { recursive: true })
  writeFileSync('src/generated/tokens.css', output)
}
