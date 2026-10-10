import { expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { createMemoryHistory } from 'vue-router'
import App from '../../src/app/App.vue'
import { createConsoleRouter } from '../../src/app/router.ts'
import { i18n, t } from '../../src/app/i18n.ts'
import { usePreferences } from '../../src/stores/preferences.ts'
import { fatal } from '../../src/app/fatal.ts'
it('focuses the main landmark without canceling skip-link navigation', async () => {
  const router = createConsoleRouter(createMemoryHistory('/'))
  await router.push('/')
  const wrapper = mount(App, {
    attachTo: document.body,
    global: { plugins: [createPinia(), i18n, router] },
  })
  try {
    await flushPromises()
    const link = wrapper.get<HTMLAnchorElement>('.skip-link').element
    const main = wrapper.get<HTMLElement>('main').element
    link.focus()
    expect(document.activeElement).toBe(link)
    expect(link.getAttribute('href')).toBe('#main')
    expect(main.getAttribute('tabindex')).toBe('-1')
    let navigationCanceled = true
    link.addEventListener(
      'click',
      (event) => {
        navigationCanceled = event.defaultPrevented
        // Isolate explicit focus from the engine's native fragment behavior.
        event.preventDefault()
      },
      { once: true },
    )
    await wrapper.get('.skip-link').trigger('click')
    expect(document.activeElement).toBe(main)
    expect(navigationCanceled).toBe(false)
    await router.push({ path: '/', hash: '#main' })
    await flushPromises()
    expect(router.currentRoute.value.hash).toBe('#main')
    expect(document.activeElement).toBe(main)
  } finally {
    wrapper.unmount()
  }
})
it('focuses the view heading after a path navigation', async () => {
  const router = createConsoleRouter(createMemoryHistory('/'))
  await router.push('/')
  const wrapper = mount(App, {
    attachTo: document.body,
    global: { plugins: [createPinia(), i18n, router] },
  })
  try {
    await flushPromises()
    wrapper.get<HTMLElement>('main').element.focus()
    await router.push('/missing')
    await flushPromises()
    expect(document.activeElement).toBe(wrapper.get<HTMLElement>('main h1').element)
  } finally {
    wrapper.unmount()
  }
})
it('navigates, translates controls and presents only generic fatal errors', async () => {
  const pinia = createPinia()
  const preferences = usePreferences(pinia)
  preferences.initialize(undefined, ['en'])
  const setTheme = vi.spyOn(preferences, 'setTheme')
  const router = createConsoleRouter(createMemoryHistory('/'))
  await router.push('/')
  const wrapper = mount(App, {
    attachTo: document.body,
    global: {
      plugins: [pinia, i18n, router],
      config: {
        errorHandler: (cause: unknown) => {
          fatal.fail(cause)
        },
      },
    },
  })
  await flushPromises()
  expect(wrapper.findAll('h1')).toHaveLength(1)
  expect(wrapper.find('a[href="#main"]').exists()).toBe(true)
  await router.push('/secret?token=private')
  await flushPromises()
  expect(wrapper.text()).not.toContain('secret')
  preferences.setLocale('vi')
  await flushPromises()
  expect(document.documentElement.lang).toBe('vi')
  expect(document.title).toContain('Không tìm thấy')
  expect(wrapper.findAll('select')).toHaveLength(3)
  const theme = wrapper.find('#theme').element
  if (!(theme instanceof HTMLSelectElement)) throw new Error('Missing theme select')
  theme.focus()
  await wrapper.find('#theme').setValue('dark')
  expect(document.activeElement).toBe(theme)
  expect(preferences.theme).toBe('dark')
  await wrapper.find('#density').setValue('compact')
  expect(preferences.density).toBe('compact')
  setTheme.mockImplementationOnce(() => {
    throw new Error('private URL')
  })
  await wrapper.find('#theme').setValue('light')
  await flushPromises()
  expect(wrapper.text()).not.toContain('private URL')
  expect(wrapper.find('[role="alert"]').text()).toContain(t('errors.message'))
  expect(wrapper.find('button').text()).toBe(t('errors.reload'))
  wrapper.unmount()
  setTheme.mockRestore()
  fatal.reset()
})
