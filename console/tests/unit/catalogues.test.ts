import { expect, it } from 'vitest'
import { existsSync } from 'node:fs'
const bytes = (value: string) => new TextEncoder().encode(value)
it('executes catalogue vectors and phase precedence', async () => {
  expect(existsSync('scripts/check-catalogues.ts')).toBe(true)
  if (!existsSync('scripts/check-catalogues.ts')) return
  const { validateCatalogues } = await import('../../scripts/check-catalogues.ts')
  const good = '{"home":{"title":"Hello"}}'
  const vectors: [string, string, string[], string | undefined][] = [
    [good, good, ['home.title'], undefined],
    ['{"home":{"title":"one","title":"bad |"}}', good, [], 'shape'],
    ['{"home":{"title":"{name"}}', '{"home":{"other":"Good"}}', [], 'keys'],
    ['{"home":{"itemCount":"{name"}}', '{"home":{"itemCount":"Good"}}', [], 'syntax'],
    [
      '{"home":{"itemCount":"{count}|{count}"}}',
      '{"home":{"itemCount":"{other}|{other}|{other}"}}',
      [],
      'plural',
    ],
    ['{"home":{"title":"{name}"}}', good, [], 'parameters'],
    [good, good, [], 'usage'],
    [good, good, ['home.missing', 'home.title'], 'usage'],
    ['{"home":{"title":"<b>Hello</b>"}}', good, [], 'syntax'],
    ['{"home":{"title":"@:home.title"}}', good, [], 'syntax'],
    ['{"home":{"title":"{0}"}}', good, [], 'syntax'],
    ['{"home":{"title":"hello | there"}}', good, [], 'plural'],
    ['[]', good, [], 'shape'],
    ['null', good, [], 'shape'],
    ['{}', good, [], 'shape'],
    ['{"home":{}}', good, [], 'shape'],
    ['{"home":{"title":""}}', good, [], 'shape'],
    ['{"home.title":"Hello"}', good, [], 'shape'],
    ['{"other":{"title":"Hello"}}', good, [], 'shape'],
    ['{"home":{"__proto__":"Hello"}}', good, [], 'shape'],
    ['{"home":{"constructor":"Hello"}}', good, [], 'shape'],
    ['{"home":{"prototype":"Hello"}}', good, [], 'shape'],
    [JSON.stringify({ home: { title: 'x'.repeat(2049) } }), good, [], 'shape'],
    [JSON.stringify({ home: { one: { two: { three: { four: 'text' } } } } }), good, [], 'shape'],
    [' '.repeat(65537), '[]', [], 'input'],
  ]
  for (const [en, vi, keys, phase] of vectors) {
    const result = validateCatalogues(bytes(en), bytes(vi), keys)
    if (phase) expect(result.length, en).toBeGreaterThan(0)
    else expect(result).toEqual([])
    expect(
      result.every((issue) => issue.code === phase),
      en,
    ).toBe(true)
    expect(JSON.stringify(result)).not.toContain('Hello')
  }
  expect(validateCatalogues(new Uint8Array([255]), bytes(good), [])[0]?.code).toBe('input')
})

import { validateCatalogues } from '../../scripts/check-catalogues.ts'
it('compares compiler named parameters including underscores', () => {
  expect(
    validateCatalogues(
      bytes('{"home":{"title":"{first_name}"}}'),
      bytes('{"home":{"title":"{last_name}"}}'),
      ['home.title'],
    ),
  ).toEqual([{ code: 'parameters', file: 'src/locales/vi.json', key: 'home.title' }])
})
it('accepts literal pipe and literal placeholder syntax', () => {
  const input = bytes(JSON.stringify({ home: { title: "{'|'} {'{name}'}" } }))
  expect(validateCatalogues(input, input, ['home.title'])).toEqual([])
})
it.each(['{"home":{"title":"Hello",}}', '{"home":{"title":"Hello"}} // comment'])(
  'rejects non-JSON catalogue: %s',
  (text) => {
    expect(
      validateCatalogues(bytes(text), bytes(text), ['home.title']).map((issue) => issue.code),
    ).toEqual(['shape', 'shape'])
  },
)
it.each([
  'No items | One item | Many items',
  '{count} {name} items | {count} {name} item | {count} {name} items',
])('requires only count in every valid count branch: %s', (message) => {
  const input = bytes(JSON.stringify({ home: { itemCount: message } }))
  expect(validateCatalogues(input, input, ['home.itemCount'])).toEqual([
    { code: 'parameters', file: 'src/locales/vi.json', key: 'home.itemCount' },
  ])
})
