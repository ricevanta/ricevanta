import type { Locator } from '@playwright/test'
import { setTimeout } from 'node:timers/promises'
import type { ProbeObservation } from '../browser/verify-probe.ts'
import { ProbeDeadlineError, readBeforeDeadline } from './probe-deadline.ts'

export async function observeProbe(
  result: Pick<Locator, 'getAttribute'>,
  readEvents: (deadline: number) => Promise<string[] | undefined>,
  waitForEvents: boolean,
  waitForResult = true,
): Promise<Omit<ProbeObservation, 'header' | 'reportOnly'>> {
  const deadline = Date.now() + 5000
  let events: string[] | undefined
  let observed: Omit<ProbeObservation, 'header' | 'reportOnly' | 'events'> | undefined
  while (Date.now() < deadline) {
    try {
      const candidate: Omit<ProbeObservation, 'header' | 'reportOnly' | 'events'> = {
        done: null,
        outcome: null,
        exception: null,
        content: null,
        functionReturned: null,
      }
      for (const [field, attribute] of [
        ['done', 'data-done'],
        ['outcome', 'data-outcome'],
        ['exception', 'data-exception'],
        ['content', 'data-content'],
        ['functionReturned', 'data-function-returned'],
      ] as const) {
        candidate[field] = await readBeforeDeadline(deadline, (timeout) =>
          result.getAttribute(attribute, { timeout }),
        )
      }
      events = await readBeforeDeadline(deadline, () => readEvents(deadline))
      if (events !== undefined) observed = candidate
      const resultReady = !waitForResult || candidate.done === 'yes'
      if (events !== undefined && resultReady && (!waitForEvents || events.length > 0)) break
    } catch (error) {
      if (error instanceof ProbeDeadlineError) break
      throw error
    }
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    await setTimeout(Math.min(25, remaining))
  }
  if (events === undefined || observed === undefined)
    throw new Error('ProbeCspRecordError: CSP authentication did not finish')
  return {
    ...observed,
    events,
  }
}
