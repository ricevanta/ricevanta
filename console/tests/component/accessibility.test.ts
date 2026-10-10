import { expect, it } from 'vitest'
import { page, commands } from 'vitest/browser'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { createMemoryHistory } from 'vue-router'
import App from '../../src/app/App.vue'
import { createConsoleRouter } from '../../src/app/router.ts'
import { i18n } from '../../src/app/i18n.ts'
it('keeps both route landmarks and keyboard targets accessible', async () => {
  const router = createConsoleRouter(createMemoryHistory('/'))
  await router.push('/')
  const host = document.createElement('div')
  host.id = 'app-test'
  document.body.append(host)
  const wrapper = mount(App, { attachTo: host, global: { plugins: [createPinia(), i18n, router] } })
  await flushPromises()
  await expect.element(page.getByRole('main')).toBeVisible()
  await expect.element(page.getByRole('navigation')).toBeVisible()
  expect(wrapper.findAll('h1')).toHaveLength(1)
  const scan: unknown = Reflect.get(commands, 'axeScan')
  if (typeof scan !== 'function') throw new Error('Missing axe command')
  const result: unknown = await Reflect.apply(scan, undefined, [])
  expect(result).toEqual([])
  await router.push('/unknown')
  await flushPromises()
  expect(wrapper.findAll('h1')).toHaveLength(1)
  const nextResult: unknown = await Reflect.apply(scan, undefined, [])
  expect(nextResult).toEqual([])
  wrapper.unmount()
  host.remove()
})
