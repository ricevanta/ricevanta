import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { errors } from 'playwright'
import { observeProbe } from '../helpers/probe-observation.ts'
import {
  expectedHeader,
  probeExpectation,
  verifyBehavior,
  verifyRefusal,
} from '../browser/verify-probe.ts'

vi.mock('node:timers/promises', () => ({
  setTimeout: (delay: number) => new Promise<void>((resolve) => setTimeout(resolve, delay)),
}))

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(0)
})
afterEach(() => {
  vi.useRealTimers()
})

const attributes = new Map([
  ['data-done', 'yes'],
  ['data-outcome', 'blocked'],
  ['data-exception', 'TypeError'],
  ['data-content', ''],
  ['data-function-returned', 'no'],
])

function resultDouble(
  fail?: (name: string, timeout: number) => Promise<string | null>,
  failAt = 4999,
) {
  return {
    getAttribute(name: string, options?: { timeout?: number }) {
      if (fail !== undefined && Date.now() >= failAt) return fail(name, options?.timeout ?? 0)
      return Promise.resolve(attributes.get(name) ?? null)
    },
  }
}

function expire<T>(timeout: number): Promise<T> {
  return new Promise((_resolve, reject) => {
    setTimeout(() => {
      reject(new errors.TimeoutError('locator.getAttribute: Timeout exceeded'))
    }, timeout)
  })
}

function expectAuthenticationFailure(value: unknown) {
  if (!(value instanceof Error)) throw new Error('Expected CSP authentication failure')
  expect(value.message).toContain('CSP authentication did not finish')
}

it.each(['data-done', 'data-outcome', 'data-exception', 'data-content', 'data-function-returned'])(
  'returns the last observation when %s times out at the deadline',
  async (attribute) => {
    const result = resultDouble((name, timeout) => {
      if (name === attribute) return expire(timeout)
      return Promise.resolve(attributes.get(name) ?? null)
    })
    let first = true
    const observed = observeProbe(
      result,
      () => {
        if (first) vi.setSystemTime(24)
        first = false
        return Promise.resolve([])
      },
      true,
    )
    const finished = observed.then(
      (value) => ({ value, at: Date.now() }),
      (error: unknown) => ({ error, at: Date.now() }),
    )
    await vi.runAllTimersAsync()
    expect(await finished).toEqual({
      value: {
        done: 'yes',
        outcome: 'blocked',
        exception: 'TypeError',
        content: '',
        functionReturned: 'no',
        events: [],
      },
      at: 5000,
    })
    const observation = await observed
    const expected = probeExpectation('duplicate-policy', 'firefox')
    const complete = { ...observation, header: expectedHeader, reportOnly: undefined }
    expect(() => {
      verifyRefusal(complete, expected)
    }).not.toThrow()
    expect(() => {
      verifyBehavior(complete, expected)
    }).toThrow('ProbeDirectiveError')
  },
)

it('retains authenticated events when the final evidence read times out', async () => {
  let first = true
  const observed = observeProbe(
    resultDouble(),
    (deadline) => {
      if (Date.now() >= 4999) return expire(deadline - Date.now())
      if (first) vi.setSystemTime(24)
      first = false
      return Promise.resolve([])
    },
    true,
  )
  const finished = observed.catch((error: unknown) => error)
  await vi.runAllTimersAsync()
  expect(await finished).toMatchObject({ done: 'yes', events: [] })
})

it.each(['evidence', 'data-outcome', 'data-exception', 'data-content', 'data-function-returned'])(
  'keeps the last consistent observation when the next poll expires at %s',
  async (expiredRead) => {
    let polls = 0
    const result = {
      getAttribute(name: string, options?: { timeout?: number }) {
        if (name === 'data-done') polls++
        if (polls === 2 && name === expiredRead) return expire<string | null>(options?.timeout ?? 0)
        return Promise.resolve(
          name === 'data-done' ? (polls === 1 ? 'no' : 'yes') : (attributes.get(name) ?? null),
        )
      },
    }
    const observed = observeProbe(
      result,
      (deadline) =>
        polls === 1 ? Promise.resolve(['trusted-types']) : expire(deadline - Date.now()),
      true,
    )
    await vi.runAllTimersAsync()
    const observation = await observed
    expect(observation).toEqual({
      done: 'no',
      outcome: 'blocked',
      exception: 'TypeError',
      content: '',
      functionReturned: 'no',
      events: ['trusted-types'],
    })
    expect(() => {
      verifyBehavior(
        { ...observation, header: expectedHeader, reportOnly: undefined },
        probeExpectation('policy', 'firefox'),
      )
    }).toThrow('ProbeCompletionError')
    expect(Date.now()).toBe(5000)
    expect(polls).toBe(2)
  },
)

it('fails authentication when the evidence read expires before any authenticated snapshot', async () => {
  const observed = observeProbe(resultDouble(), (deadline) => expire(deadline - Date.now()), true)
  const finished = observed.catch((error: unknown) => error)
  await vi.runAllTimersAsync()
  expectAuthenticationFailure(await finished)
})

it('does not replace pending authentication with an earlier authenticated empty stream', async () => {
  let first = true
  const observed = observeProbe(
    resultDouble(),
    () => {
      if (first) {
        first = false
        return Promise.resolve([])
      }
      return Promise.resolve(undefined)
    },
    true,
  )
  const finished = observed.catch((error: unknown) => error)
  await vi.runAllTimersAsync()
  expectAuthenticationFailure(await finished)
})

it.each([
  new Error('ProbeCspRecordError: Unauthenticated CSP event record'),
  new Error('Target page, context or browser has been closed'),
  Object.assign(new Error('Unrelated failure named TimeoutError'), { name: 'TimeoutError' }),
])('propagates %s even at the deadline', async (error) => {
  const observed = observeProbe(
    resultDouble(),
    () => {
      vi.setSystemTime(5000)
      return Promise.reject(error)
    },
    true,
  )
  await expect(observed).rejects.toBe(error)
})

it('leaves incomplete probe rejection to the unchanged completion assertion', async () => {
  const result = {
    getAttribute(name: string) {
      return Promise.resolve(name === 'data-done' ? 'no' : (attributes.get(name) ?? null))
    },
  }
  const observed = observeProbe(result, () => Promise.resolve(['trusted-types']), true)
  await vi.runAllTimersAsync()
  const complete = { ...(await observed), header: expectedHeader, reportOnly: undefined }
  expect(() => {
    verifyBehavior(complete, probeExpectation('duplicate-policy', 'firefox'))
  }).toThrow('ProbeCompletionError')
})

it('does not accept an action timeout as authenticated empty evidence', async () => {
  const error = new errors.TimeoutError('Early action timeout')
  const finished = observeProbe(resultDouble(), () => Promise.reject(error), true).catch(
    (failure: unknown) => failure,
  )
  await vi.runAllTimersAsync()
  expectAuthenticationFailure(await finished)
  expect(Date.now()).toBe(5000)
})

it('ends at the deadline without another read when the action timer rounds down', async () => {
  let expiredReads = 0
  const result = resultDouble((name, timeout) => {
    if (name === 'data-done') {
      expiredReads++
      return expire(timeout - 1)
    }
    return Promise.resolve(attributes.get(name) ?? null)
  }, 4998)
  let first = true
  const observed = observeProbe(
    result,
    () => {
      if (first) vi.setSystemTime(23)
      first = false
      return Promise.resolve([])
    },
    true,
  )
  const finished = observed.then(
    (value) => ({ value, at: Date.now() }),
    (error: unknown) => ({ error, at: Date.now() }),
  )
  await vi.runAllTimersAsync()
  expect(await finished).toMatchObject({ value: { done: 'yes', events: [] }, at: 5000 })
  expect(expiredReads).toBe(1)
})

it('does not start another read after a result read consumes the deadline', async () => {
  const names: string[] = []
  const result = {
    getAttribute(name: string) {
      names.push(name)
      vi.setSystemTime(5000)
      return Promise.resolve('yes')
    },
  }
  const finished = observeProbe(result, () => Promise.resolve([]), true).catch(
    (error: unknown) => error,
  )
  await vi.runAllTimersAsync()
  expectAuthenticationFailure(await finished)
  expect(names).toEqual(['data-done'])
})
