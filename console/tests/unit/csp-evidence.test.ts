import { expect, it, vi } from 'vitest'
import { createHmac } from 'node:crypto'
import { errors } from 'playwright'
import { installCspEvidence } from '../browser/csp-evidence.ts'
import type { ProbeCspCollectorOptions } from '../helpers/probe-csp-events.ts'

function pageDouble() {
  let options: ProbeCspCollectorOptions | undefined
  let record: string | null = null
  let document = 0
  let directives: string[] = []
  let previousDocumentSequence: number | null = null
  let stalled = false
  let stalledAt = Infinity
  let stallError = new Error('Evidence locator timeout')
  let extraTransition = false
  const order: string[] = []
  const timeouts: (number | undefined)[] = []
  function publish() {
    if (options === undefined) throw new Error('Collector not installed')
    const key = Buffer.from(options.key)
    const documentId = document.toString(16).padStart(32, '0')
    const previousDocumentId = document === 1 ? null : (document - 1).toString(16).padStart(32, '0')
    record = JSON.stringify(
      [null, ...directives].map((directive, sequence) => ({
        documentId,
        previousDocumentId,
        previousDocumentSequence,
        sequence,
        directive,
        tag: createHmac('sha256', key)
          .update(
            JSON.stringify([
              documentId,
              previousDocumentId,
              previousDocumentSequence,
              sequence,
              directive,
            ]),
          )
          .digest('hex'),
      })),
    )
  }
  const navigate = vi.fn(() => {
    order.push('navigate')
    previousDocumentSequence = document === 0 ? null : directives.length
    document++
    if (extraTransition) {
      extraTransition = false
      document++
    }
    directives = []
    publish()
    return Promise.resolve(null)
  })
  const page = {
    addInitScript: vi.fn((_script: unknown, argument: ProbeCspCollectorOptions) => {
      options = argument
      return Promise.resolve()
    }),
    locator: vi.fn(() => ({
      getAttribute: vi.fn((name: string, options?: { timeout: number }) => {
        expect(name).toBe('data-probe-csp-events')
        timeouts.push(options?.timeout)
        order.push('read')
        if (stalled || Date.now() >= stalledAt)
          return new Promise<string | null>((_resolve, reject) => {
            if (options === undefined) return
            setTimeout(() => {
              reject(stallError)
            }, options.timeout)
          })
        return Promise.resolve(record)
      }),
    })),
    goto: vi.fn((url: string) => {
      expect(url).toBe('/')
      return navigate()
    }),
    reload: navigate,
    goBack: navigate,
    goForward: navigate,
  }
  return {
    page,
    order,
    timeouts,
    navigateFromPage: navigate,
    navigateAgainBeforeReturn() {
      extraTransition = true
    },
    emit(directive: string) {
      directives.push(directive)
      publish()
    },
    write(value: string | null) {
      record = value
    },
    stall() {
      stalled = true
    },
    stallAt(at: number, error: Error) {
      stalledAt = at
      stallError = error
    },
  }
}

it('installs a private collector and verifies authenticated empty evidence', async () => {
  const capture = pageDouble()
  const evidence = await installCspEvidence(capture.page, false)
  await capture.page.goto('/')
  expect(capture.page.addInitScript).toHaveBeenCalledOnce()
  expect(await evidence.read()).toEqual([])
  evidence.dispose()
})

it('rejects a second collector installation on the same page', async () => {
  const capture = pageDouble()
  const evidence = await installCspEvidence(capture.page, false)
  await expect(installCspEvidence(capture.page, false)).rejects.toThrow('init script')
  expect(capture.page.addInitScript).toHaveBeenCalledOnce()
  evidence.dispose()
})

it.each(['read', 'readSnapshot'] as const)(
  'rejects an authenticated replacement document reached outside Playwright navigation in %s',
  async (method) => {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    // Replace the document before Node reads its genuine tail event.
    capture.emit('script-src')
    await capture.navigateFromPage()
    await expect(evidence[method]()).rejects.toThrow('document transition')
    await expect(evidence.read()).rejects.toThrow('already rejected')
    evidence.dispose()
  },
)

it.each([false, true])(
  'rejects a document skipped while wrapped navigation is pending, established=%s',
  async (established) => {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    if (established) await capture.page.goto('/')
    capture.navigateAgainBeforeReturn()
    await expect(capture.page.goto('/')).rejects.toThrow('Dropped document')
    evidence.dispose()
  },
)

it.each(['read', 'readSnapshot'] as const)(
  'rejects a first document reached without wrapped navigation in %s',
  async (method) => {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.navigateFromPage()
    await expect(evidence[method]()).rejects.toThrow('Missing accounted document')
    evidence.dispose()
  },
)

it.each(['goto', 'reload', 'goBack', 'goForward'] as const)(
  'drains authenticated evidence before %s and retains earlier violations',
  async (method) => {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    capture.emit('script-src')
    capture.order.length = 0
    if (method === 'goto') await capture.page.goto('/')
    else await capture.page[method]()
    expect(capture.order).toEqual(['read', 'navigate', 'read'])
    expect(await evidence.readSnapshot()).toEqual([])
    expect(await evidence.read()).toEqual(['script-src'])
    expect(await evidence.read()).toEqual(['script-src'])
    evidence.dispose()
  },
)

it.each([null, '[]', '["trusted-types"]'])(
  'rejects missing or unauthenticated evidence %j before navigation',
  async (record) => {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    capture.write(record)
    await expect(capture.page.reload()).rejects.toThrow()
    expect(capture.page.addInitScript).toHaveBeenCalledOnce()
    expect(await evidence.read().catch(() => 'rejected')).toBe('rejected')
    evidence.dispose()
  },
)

it('waits through pending publication without accepting it as an empty stream', async () => {
  vi.useFakeTimers()
  try {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    capture.emit('script-src')
    const authentic = await evidence.read()
    capture.write('pending')
    const reading = evidence.read()
    const failed = expect(reading).rejects.toThrow('authentication did not finish')
    await vi.advanceTimersByTimeAsync(5000)
    await failed
    expect(authentic).toEqual(['script-src'])
    expect(capture.order.filter((entry) => entry === 'read')).toHaveLength(202)
    evidence.dispose()
  } finally {
    vi.useRealTimers()
  }
})

it('keeps pending snapshots nonblocking for the existing probe deadline', async () => {
  const capture = pageDouble()
  const evidence = await installCspEvidence(capture.page, false)
  await capture.page.goto('/')
  capture.write('pending')
  expect(await evidence.readSnapshot()).toBeUndefined()
  evidence.dispose()
})

it('rejects concurrent navigation before a document can be replaced unchecked', async () => {
  const capture = pageDouble()
  const evidence = await installCspEvidence(capture.page, false)
  const first = capture.page.goto('/')
  await expect(capture.page.reload()).rejects.toThrow('Concurrent CSP navigation')
  await first
  evidence.dispose()
})

it('bounds every evidence locator read instead of inheriting an unlimited action timeout', async () => {
  vi.useFakeTimers()
  try {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    await evidence.read()
    expect(capture.timeouts).toEqual([5000, 5000])
    evidence.dispose()
  } finally {
    vi.useRealTimers()
  }
})

it('rejects a stalled evidence locator at the five-second deadline', async () => {
  vi.useFakeTimers()
  try {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    capture.stall()
    const failed = expect(evidence.read()).rejects.toThrow('Evidence locator timeout')
    await vi.advanceTimersByTimeAsync(5000)
    await failed
    expect(capture.timeouts).toEqual([5000, 5000])
    evidence.dispose()
  } finally {
    vi.useRealTimers()
  }
})

it.each([0, -1])(
  'rejects an expired snapshot budget of %s without reading evidence',
  async (timeout) => {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    capture.order.length = 0
    await expect(evidence.readSnapshot(Date.now() + timeout)).rejects.toThrow('deadline')
    expect(capture.order).toEqual([])
    evidence.dispose()
  },
)

it('fails authentication when the final pending evidence read times out at the deadline', async () => {
  vi.useFakeTimers()
  vi.setSystemTime(24)
  try {
    const capture = pageDouble()
    const evidence = await installCspEvidence(capture.page, false)
    await capture.page.goto('/')
    expect(await evidence.read()).toEqual([])
    capture.write('pending')
    capture.stallAt(4999, new errors.TimeoutError('Evidence locator timeout'))
    const finished = evidence.read().catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(5000)
    const error = await finished
    if (!(error instanceof Error)) throw new Error('Expected CSP authentication failure')
    expect(error.message).toContain('CSP authentication did not finish')
    evidence.dispose()
  } finally {
    vi.useRealTimers()
  }
})
