import { expect, it, vi } from 'vitest'
import AxeBuilder from '@axe-core/playwright'
import { PlaywrightBrowserProvider } from '@vitest/browser-playwright'
import config from '../../vitest.config.ts'

it('passes WCAG tags and enabled target-size to the component scan', async () => {
  const projects = config.test?.projects
  if (!projects) throw new Error('Missing projects')
  const component = projects.find(
    (project) =>
      typeof project === 'object' && 'test' in project && project.test.name === 'component',
  )
  if (!component || typeof component !== 'object' || !('test' in component))
    throw new Error('Missing component project')
  const scan = component.test.browser?.commands?.['axeScan']
  if (typeof scan !== 'function') throw new Error('Missing axe command')
  const provider = { getPage: () => ({}) }
  Object.setPrototypeOf(provider, PlaywrightBrowserProvider.prototype)
  let options: unknown
  // Stop at the browser boundary while retaining the real builder's option handling.
  const analyze = vi.spyOn(AxeBuilder.prototype, 'analyze').mockImplementation(function (
    this: AxeBuilder,
  ) {
    options = Reflect.get(this, 'option')
    throw new Error('Captured scan options')
  })
  try {
    const result: unknown = Reflect.apply(scan, undefined, [{ provider, sessionId: 'fixture' }])
    await expect(result).rejects.toThrow('Captured scan options')
    expect(options).toEqual({
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
      rules: { 'target-size': { enabled: true } },
    })
  } finally {
    analyze.mockRestore()
  }
})
