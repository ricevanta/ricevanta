import { verifyHeader, expectedHeader } from './verify-probe.ts'
import { test as base, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import type { Page } from '@playwright/test'
import { installCspEvidence } from './csp-evidence.ts'
export { expectedHeader }
const evidenceReaders = new WeakMap<Page, Awaited<ReturnType<typeof installCspEvidence>>>()
export async function readCspEvents(
  page: Page,
  deadline = Date.now() + 5000,
): Promise<string[] | undefined> {
  const evidence = evidenceReaders.get(page)
  if (!evidence) throw new Error('ProbeCspRecordError: Missing page collector')
  return evidence.readSnapshot(deadline)
}
export const test = base.extend<{
  violations: () => Promise<string[]>
  errors: string[]
  discardCspEvents: boolean
}>({
  discardCspEvents: [false, { option: true }],
  page: async ({ page, discardCspEvents }, use) => {
    const evidence = await installCspEvidence(page, discardCspEvents)
    evidenceReaders.set(page, evidence)
    try {
      await use(page)
    } finally {
      evidenceReaders.delete(page)
      evidence.dispose()
    }
  },
  violations: async ({ page }, use) => {
    const evidence = evidenceReaders.get(page)
    if (!evidence) throw new Error('ProbeCspRecordError: Missing page collector')
    await use(evidence.read)
  },
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
