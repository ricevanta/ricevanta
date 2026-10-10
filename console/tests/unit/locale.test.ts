import { expect, it } from 'vitest'
import { existsSync } from 'node:fs'
it('selects bounded locale inputs and validates explicit plural counts', async () => {
  expect(existsSync('src/app/locale.ts')).toBe(true)
  if (!existsSync('src/app/locale.ts')) return
  const { selectLocale, pluralIndex } = await import('../../src/app/locale.ts')
  for (const [saved, languages, expected] of [
    ['vi', ['en-US'], 'vi'],
    ['fr', ['fr', 'VI-vn'], 'vi'],
    [null, ['en-GB', 'vi'], 'en'],
    [{}, [], 'en'],
    [null, Array(16).fill('fr').concat('vi'), 'en'],
    [null, ['vi-' + 'x'.repeat(64)], 'en'],
  ] as const)
    expect(selectLocale(saved, languages)).toBe(expected)
  for (const [count, expected] of [
    [0, 0],
    [-0, 0],
    [1, 1],
    [2, 2],
    [Number.MAX_SAFE_INTEGER, 2],
  ] as const)
    expect(Object.is(pluralIndex(count), expected)).toBe(true)
  for (const count of [-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1])
    expect(() => pluralIndex(count)).toThrow(RangeError)
})
