import { expect, it } from 'vitest'
import { existsSync } from 'node:fs'
it('rejects the whole preference record on any invalid input and tolerates denied storage', async () => {
  expect(existsSync('src/stores/preferences.ts')).toBe(true)
  if (!existsSync('src/stores/preferences.ts')) return
  const { readPreferences, loadPreferences, savePreferences } = await import(
    '../../src/stores/preferences.ts'
  )
  const defaults = { theme: 'system', density: 'comfortable' } as const
  for (const input of [
    null,
    '',
    'oops',
    'null',
    '[]',
    '{"token":"secret"}',
    '{"theme":"auto"}',
    '{"locale":"fr"}',
    '{"density":"dense"}',
    '{"theme":"dark","density":0}',
    ' '.repeat(1025),
  ])
    expect(readPreferences(input)).toEqual(defaults)
  expect(readPreferences('{"locale":"vi","theme":"dark"}')).toEqual({
    locale: 'vi',
    theme: 'dark',
    density: 'comfortable',
  })
  expect(readPreferences('{}')).toEqual(defaults)
  const storage = {
    getItem: () => {
      throw new Error('denied')
    },
    setItem: () => {
      throw new Error('denied')
    },
  }
  expect(loadPreferences(storage)).toEqual(defaults)
  expect(() => {
    savePreferences(storage, defaults)
  }).not.toThrow()
})
