import { verifyHeader, expectedHeader } from './verify-probe.ts'
import { test as base, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
export { expectedHeader }
export const test = base.extend<{
  violations: string[]
  errors: string[]
  discardCspEvents: boolean
}>({
  discardCspEvents: [false, { option: true }],
  violations: [
    async ({ context, discardCspEvents }, use) => {
      const violations: string[] = []
      await context.exposeBinding('recordCsp', (_source, directive: unknown) => {
        if (typeof directive !== 'string') throw new Error('Invalid CSP event')
        if (!discardCspEvents) violations.push(directive)
      })
      await context.addInitScript(() => {
        const diagnostics = {
          listenerAttachedAt: performance.now(),
          eventCount: 0,
          documentEventCount: 0,
          bindingMissing: 0,
          bindingPending: 0,
          bindingDelivered: 0,
          bindingRejected: 0,
          events: [] as { directive: string; target: string; at: number }[],
        }
        Reflect.set(window, 'cspDiagnostics', diagnostics)
        window.addEventListener(
          'securitypolicyviolation',
          (event) => {
            diagnostics.eventCount++
            diagnostics.events.push({
              directive: event.effectiveDirective,
              target:
                event.target === document
                  ? 'document'
                  : event.target === window
                    ? 'window'
                    : event.target instanceof Element
                      ? event.target.tagName
                      : 'other',
              at: performance.now(),
            })
          },
          { capture: true, passive: true },
        )
        document.addEventListener('securitypolicyviolation', (event) => {
          diagnostics.documentEventCount++
          const value: unknown = Reflect.get(window, 'recordCsp')
          if (typeof value === 'function') {
            const promise: unknown = Reflect.apply(value, undefined, [event.effectiveDirective])
            if (promise instanceof Promise) {
              diagnostics.bindingPending++
              void promise.then(
                () => {
                  diagnostics.bindingPending--
                  diagnostics.bindingDelivered++
                },
                () => {
                  diagnostics.bindingPending--
                  diagnostics.bindingRejected++
                  throw new Error('CSP observation failed')
                },
              )
            }
          } else diagnostics.bindingMissing++
        })
      })
      await use(violations)
    },
    { auto: true },
  ],
  errors: [
    async ({ page }, use) => {
      const errors: string[] = []
      page.on('pageerror', (error) => errors.push(`page:${error.message}`))
      page.on('console', (message) => {
        if (message.type() === 'error')
          errors.push(`console:${message.location().url}:${message.text()}`)
      })
      page.on('response', (response) => {
        if (response.status() >= 400)
          errors.push(`http:${String(response.status())}:${response.url()}`)
      })
      page.on('requestfailed', (request) =>
        errors.push(`asset:${request.url()}:${request.failure()?.errorText ?? 'unknown failure'}`),
      )
      page.on('request', (request) => {
        if (!request.url().startsWith('http://127.0.0.1:4173/'))
          errors.push(`external:${request.url()}`)
      })
      await use(errors)
    },
    { auto: true },
  ],
})
export { expect }
export function assertHeader(value: string | undefined): void {
  verifyHeader(value, readFileSync('security/csp.txt', 'utf8').replace(/\n$/, ''), expectedHeader)
  expect(value).toBe(expectedHeader)
  expect(value).toBe(readFileSync('security/csp.txt', 'utf8').replace(/\n$/, ''))
}
