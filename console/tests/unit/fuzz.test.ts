import { expect, it } from 'vitest'
import { validateCatalogues } from '../../scripts/check-catalogues.ts'
import { readPreferences } from '../../src/stores/preferences.ts'
import { selectLocale } from '../../src/app/locale.ts'
const iterations = process.env['CONSOLE_FUZZ'] === '1' ? 10000 : 100
it('terminates deterministically for seeded catalogue, preference and locale mutations', () => {
  let seed = 0x52495641
  const random = () => {
    seed ^= seed << 13
    seed ^= seed >>> 17
    seed ^= seed << 5
    return seed >>> 0
  }
  const encode = (value: string) => new TextEncoder().encode(value)
  for (let index = 0; index < iterations; index++) {
    const raw = String.fromCodePoint(
      ...Array.from({ length: random() % 80 }, () => random() % 0xd800),
    )
    const tree: unknown = [
      { home: { title: raw } },
      { home: { itemCount: '{count} | {count} | {count}' } },
      { home: { nested: { title: raw } } },
      { home: [raw] },
      null,
      { home: { constructor: raw } },
      { home: { title: raw, extra: raw } },
    ][random() % 7]
    const catalogue = encode(index % 5 === 0 ? raw : JSON.stringify(tree))
    const diagnostics = validateCatalogues(catalogue, catalogue, ['home.title'])
    expect(diagnostics).toEqual(validateCatalogues(catalogue, catalogue, ['home.title']))
    expect(diagnostics.length).toBeLessThanOrEqual(4)
    const preference =
      index % 2
        ? raw
        : JSON.stringify({
            theme: ['light', 'dark', 'system', 'bad'][random() % 4],
            density: ['comfortable', 'compact', 'bad'][random() % 3],
          })
    expect(readPreferences(preference)).toEqual(readPreferences(preference))
    const tags = [raw, index % 2 ? 'VI-vn' : 'en-US']
    expect(selectLocale({}, tags)).toBe(selectLocale({}, tags))
  }
})
