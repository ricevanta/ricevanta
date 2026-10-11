import type { Page } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { collectProbeCspEvents, createProbeCspReader } from '../helpers/probe-csp-events.ts'
import type { ProbeCspCollectorOptions } from '../helpers/probe-csp-events.ts'
import { ProbeDeadlineError, readBeforeDeadline } from '../helpers/probe-deadline.ts'

interface CspPage extends Pick<Page, 'goto' | 'reload' | 'goBack' | 'goForward'> {
  addInitScript(
    script: typeof collectProbeCspEvents,
    options: ProbeCspCollectorOptions,
  ): Promise<unknown>
  locator(selector: string): {
    getAttribute(name: string, options: { timeout: number }): Promise<string | null>
  }
}

const installedPages = new WeakSet<CspPage>()

export async function installCspEvidence(page: CspPage, discardCspEvents: boolean) {
  if (installedPages.has(page))
    throw new Error('ProbeCspRecordError: CSP init script already registered for page')
  installedPages.add(page)
  const attribute = 'data-probe-csp-events'
  const key = randomBytes(32)
  const reader = createProbeCspReader(key)
  const historyReader = createProbeCspReader(key, true)
  let history: string[] | undefined
  let navigated = false
  await page.addInitScript(collectProbeCspEvents, {
    attribute,
    discardCspEvents,
    key: [...key],
    documentHistoryKey: `rv-probe-csp-${randomBytes(16).toString('hex')}`,
  })
  async function snapshot(
    deadline: number,
    allowDocumentChange: boolean,
  ): Promise<string[] | undefined> {
    const record = await readBeforeDeadline(Math.min(Date.now() + 5000, deadline), (timeout) =>
      page.locator('html').getAttribute(attribute, { timeout }),
    )
    const events = reader(record, allowDocumentChange)
    history = historyReader(record, allowDocumentChange)
    return events
  }
  async function readSnapshot(deadline = Date.now() + 5000): Promise<string[] | undefined> {
    if (!navigated) throw new Error('ProbeCspRecordError: Missing accounted document')
    return snapshot(deadline, false)
  }
  async function waitForEvidence(allowDocumentChange: boolean): Promise<string[]> {
    const deadline = Date.now() + 5000
    while (Date.now() < deadline) {
      try {
        const events = await snapshot(deadline, allowDocumentChange)
        if (events !== undefined && history !== undefined) return history
      } catch (error) {
        if (error instanceof ProbeDeadlineError) break
        throw error
      }
      const remaining = deadline - Date.now()
      if (remaining <= 0) break
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(25, remaining)))
    }
    throw new Error('ProbeCspRecordError: CSP authentication did not finish')
  }
  async function read(): Promise<string[]> {
    if (!navigated) throw new Error('ProbeCspRecordError: Missing accounted document')
    return waitForEvidence(false)
  }
  let navigating = false
  async function navigate<T>(action: () => Promise<T>): Promise<T> {
    if (navigating) throw new Error('ProbeCspRecordError: Concurrent CSP navigation')
    navigating = true
    try {
      // Read the old document while its utility context and signed stream still exist.
      if (navigated) await read()
      const response = await action()
      // The successor authenticates the departing document's final sequence against this read.
      await waitForEvidence(true)
      navigated = true
      return response
    } finally {
      navigating = false
    }
  }
  const goto = page.goto.bind(page)
  const reload = page.reload.bind(page)
  const goBack = page.goBack.bind(page)
  const goForward = page.goForward.bind(page)
  page.goto = (...args) => navigate(() => goto(...args))
  page.reload = (...args) => navigate(() => reload(...args))
  page.goBack = (...args) => navigate(() => goBack(...args))
  page.goForward = (...args) => navigate(() => goForward(...args))
  return {
    read,
    readSnapshot,
    dispose() {
      page.goto = goto
      page.reload = reload
      page.goBack = goBack
      page.goForward = goForward
    },
  }
}
