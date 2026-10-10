import { expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { createMemoryHistory } from 'vue-router'
it('exposes only home and generic catch-all routes and stores no exception data', async () => {
  expect(existsSync('src/app/router.ts')).toBe(true)
  if (!existsSync('src/app/router.ts')) return
  const { createConsoleRouter } = await import('../../src/app/router.ts')
  const { fatal } = await import('../../src/app/fatal.ts')
  const router = createConsoleRouter(createMemoryHistory('/'))
  expect(
    router
      .getRoutes()
      .map((route) => route.name)
      .sort(),
  ).toEqual(['home', 'not-found'])
  expect(router.resolve('/secret?token=hidden').name).toBe('not-found')
  fatal.fail(new Error('secret'))
  fatal.fail(new Error('again'))
  expect(fatal.failed.value).toBe(true)
  expect(Object.keys(fatal).sort()).toEqual(['fail', 'failed', 'reset'])
  fatal.reset()
})
