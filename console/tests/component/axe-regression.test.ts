import { expect, it } from 'vitest'
import { commands } from 'vitest/browser'

it('reports an unnamed button through the component axe command', async () => {
  const host = document.createElement('div')
  host.id = 'app-test'
  const button = document.createElement('button')
  button.type = 'button'
  host.append(button)
  document.body.append(host)
  try {
    const scan: unknown = Reflect.get(commands, 'axeScan')
    if (typeof scan !== 'function') throw new Error('Missing axe command')
    const violations: unknown = await Reflect.apply(scan, undefined, [])
    expect(violations).toContain('button-name')
  } finally {
    host.remove()
  }
})
