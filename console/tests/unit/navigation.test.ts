import { expect, it, vi } from 'vitest'
import { createMemoryHistory } from 'vue-router'
import { createConsoleRouter } from '../../src/app/router.ts'
import { clickAndWaitForURL } from '../browser/navigation.ts'

vi.mock('../../src/features/home/HomeView.vue', () => ({ default: { render: () => null } }))
vi.mock('../../src/features/not-found/NotFoundView.vue', () => ({
  default: { render: () => null },
}))

it('waits for the Home navigation to commit before traversing history', async () => {
  const router = createConsoleRouter(createMemoryHistory('/'))
  await router.push('/private?token=hidden')
  expect(router.currentRoute.value.name).toBe('not-found')

  let navigation: ReturnType<typeof router.push> | undefined
  const link = {
    click: () => {
      navigation = router.push({ name: 'home' })
      // RouterLink starts navigation without awaiting its completion.
      return Promise.resolve()
    },
  }
  const page = {
    waitForURL: vi.fn(async () => {
      await navigation
      expect(router.currentRoute.value.path).toBe('/')
    }),
  }
  await clickAndWaitForURL(page, link, '/')
  expect(router.currentRoute.value.name).toBe('home')
  expect(page.waitForURL).toHaveBeenCalledWith('/')

  const back = new Promise<void>((resolve) => {
    const remove = router.afterEach(() => {
      remove()
      resolve()
    })
  })
  router.back()
  await back
  expect(router.currentRoute.value.name).toBe('not-found')
  expect(router.currentRoute.value.fullPath).toBe('/private?token=hidden')

  const forward = new Promise<void>((resolve) => {
    const remove = router.afterEach(() => {
      remove()
      resolve()
    })
  })
  router.forward()
  await forward
  expect(router.currentRoute.value.name).toBe('home')
  router.listening = false
})
