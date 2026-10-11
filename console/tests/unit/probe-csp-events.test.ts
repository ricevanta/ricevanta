import { expect, it } from 'vitest'
import { createHmac, randomBytes, webcrypto } from 'node:crypto'
import { runInNewContext } from 'node:vm'
import { collectProbeCspEvents, createProbeCspReader } from '../helpers/probe-csp-events.ts'
import type { ProbeCspCollectorOptions } from '../helpers/probe-csp-events.ts'
import { installCspEvidence } from '../browser/csp-evidence.ts'
import {
  expectedHeader,
  probeExpectation,
  verifyBehavior,
  verifyHeaderIntegrity,
  verifyRefusal,
} from '../browser/verify-probe.ts'
import type { ProbeObservation } from '../browser/verify-probe.ts'

const attribute = 'data-probe-csp-events'
function collector(
  discardCspEvents = false,
  rootPresent = true,
  history = new Map<string, string>(),
  key = randomBytes(32),
  documentHistoryKey = 'test-csp-document-history',
) {
  const read = createProbeCspReader(key)
  const attributes = new Map<string, string>()
  const publications = new Set<() => void>()
  const sealWrites = new Set<() => void>()
  class Root {
    setAttribute(name: string, value: string) {
      attributes.set(name, value)
      if (document.actualRoot() === this) MockMutationObserver.current?.record('attributes')
      for (const published of publications) published()
    }
    getAttribute(name: string) {
      return attributes.get(name) ?? null
    }
  }
  class MockMutationRecord {
    constructor(private nativeType: string) {}
    get type() {
      return this.nativeType
    }
  }
  // Model native observer delivery and takeRecords, including writes made before delivery.
  class MockMutationObserver {
    static current: MockMutationObserver | undefined
    private active = false
    private records: MockMutationRecord[] = []
    constructor(private callback: (records: MockMutationRecord[]) => void) {
      MockMutationObserver.current = this
    }
    observe(_target: unknown, options: MutationObserverInit) {
      // WebIDL reads optional dictionary members before observing the target.
      Boolean(options.attributeOldValue)
      Array.from(options.attributeFilter ?? [])
      this.active = true
    }
    disconnect() {
      this.active = false
      this.records = []
    }
    takeRecords() {
      const records = this.records
      this.records = []
      return records
    }
    record(type: string) {
      if (!this.active) return
      this.records.push(new MockMutationRecord(type))
      queueMicrotask(() => {
        if (this.active && this.records.length > 0) this.callback(this.takeRecords())
      })
    }
  }
  const root = new Root()
  class DocumentStub extends EventTarget {
    private element = rootPresent ? root : null
    get documentElement() {
      return this.element
    }
    set documentElement(element: Root | null) {
      this.setNativeRoot(element)
    }
    setNativeRoot(element: Root | null) {
      this.element = element
      MockMutationObserver.current?.record('childList')
    }
    actualRoot() {
      return this.element
    }
  }
  const document = new DocumentStub()
  class TrustedViolation {
    readonly isTrusted = true
    constructor(private directive: string) {}
    get effectiveDirective() {
      return this.directive
    }
  }
  let violationListener:
    | ((event: Pick<SecurityPolicyViolationEvent, 'isTrusted' | 'effectiveDirective'>) => void)
    | undefined
  let pageHideListener:
    | ((event: Pick<PageTransitionEvent, 'isTrusted' | 'persisted'>) => void)
    | undefined
  let pageShowListener:
    | ((event: Pick<PageTransitionEvent, 'isTrusted' | 'persisted'>) => void)
    | undefined
  const window = {
    top: undefined as unknown,
    addEventListener(
      type: string,
      listener: (
        event: Pick<Event, 'isTrusted'> &
          Partial<Pick<SecurityPolicyViolationEvent, 'effectiveDirective'>> &
          Partial<Pick<PageTransitionEvent, 'persisted'>>,
      ) => void,
    ) {
      if (type === 'securitypolicyviolation') violationListener = listener
      if (type === 'pagehide') pageHideListener = listener
      if (type === 'pageshow') pageShowListener = listener
    },
  }
  window.top = window
  // Execute the serialized init script with no exposed binding or module scope.
  const sandbox = {
    window,
    document,
    Element: Root,
    HTMLElement: Root,
    Document: DocumentStub,
    MutationRecord: MockMutationRecord,
    SecurityPolicyViolationEvent: TrustedViolation,
    MutationObserver: MockMutationObserver,
    nativeCrypto: webcrypto,
    TextEncoder,
    sessionStorage: {
      getItem: (name: string) => history.get(name) ?? null,
      setItem: (name: string, value: string) => {
        history.set(name, value)
        for (const sealed of sealWrites) sealed()
      },
    },
    replayRecord: '',
  }
  // Browser WebCrypto promises belong to the page realm; Node's belong to a foreign realm.
  runInNewContext(
    `globalThis.crypto = { randomUUID: () => nativeCrypto.randomUUID(), subtle: {
      importKey: (format, data, algorithm, extractable, usages) =>
        Promise.resolve(nativeCrypto.subtle.importKey(format, data, algorithm, extractable, usages)),
      sign: (algorithm, key, data) => Promise.resolve(nativeCrypto.subtle.sign(algorithm, key, data)),
    } }`,
    sandbox,
  )
  const init: unknown = runInNewContext(`(${collectProbeCspEvents.toString()})`, sandbox)
  if (typeof init !== 'function') throw new Error('Expected collector function')
  Reflect.apply(init, undefined, [
    { attribute, discardCspEvents, key: [...key], documentHistoryKey },
  ])
  return {
    root,
    document,
    read,
    changeSerialization() {
      runInNewContext(
        `Array.prototype.toJSON = function () {
          if (this.length === 2 && typeof this[0] === 'number' && this[1] === 'script-src')
            return [this[0], 'trusted-types']
          if (this.length === 3 && typeof this[1] === 'number' && this[2] === 'script-src')
            return [this[0], this[1], 'trusted-types']
          if (this.length === 4 && typeof this[2] === 'number' && this[3] === 'script-src')
            return [this[0], this[1], this[2], 'trusted-types']
          if (this[0]?.sequence === 0)
            return this.map(record => record.directive === 'script-src'
              ? { ...record, directive: 'trusted-types' } : record)
          return this
        }`,
        sandbox,
      )
    },
    interceptKeyResolution() {
      runInNewContext(
        `const nativeThen = Promise.prototype.then
        Promise.prototype.constructor = function () {}
        Promise.prototype.then = function (fulfilled, rejected) {
          return Reflect.apply(nativeThen, this, [(value) => {
            if (value?.type === 'secret' && value.algorithm?.name === 'HMAC')
              window.leakedKey = value
            return typeof fulfilled === 'function' ? fulfilled(value) : value
          }, rejected])
        }`,
        sandbox,
      )
    },
    keyLeaked() {
      return Reflect.get(window, 'leakedKey') !== undefined
    },
    replaceRootWithReplay(record: string) {
      const replacement = new Root()
      replacement.setAttribute(attribute, record)
      Object.defineProperty(document, 'documentElement', { get: () => root })
      document.setNativeRoot(replacement)
    },
    changeMutationType() {
      runInNewContext(
        `Object.defineProperty(MutationRecord.prototype, 'type', { get: () => 'childList' })`,
        sandbox,
      )
    },
    changeEventDirective() {
      runInNewContext(
        `Object.defineProperty(SecurityPolicyViolationEvent.prototype, 'effectiveDirective', {
          get: () => 'trusted-types',
        })`,
        sandbox,
      )
    },
    changeInstanceCheck() {
      runInNewContext(
        `Object.defineProperty(HTMLElement, Symbol.hasInstance, { value() {
          throw new Error('Page-owned instance check')
        } })`,
        sandbox,
      )
    },
    changeRecordStorage() {
      runInNewContext(
        `Object.defineProperty(Array.prototype, '1', { set() {
          const sentinel = this[0]
          if (typeof sentinel !== 'string' || !sentinel.startsWith('{')) return
          const comma = sentinel.indexOf(',')
          Object.defineProperty(this, '0', {
            value: sentinel.slice(0, comma), writable: true, configurable: true,
          })
          Object.defineProperty(this, '1', {
            value: sentinel.slice(comma + 1), writable: true, configurable: true,
          })
        } })`,
        sandbox,
      )
    },
    changeObserverOptions(record: string) {
      sandbox.replayRecord = record
      runInNewContext(
        `Object.defineProperty(Object.prototype, 'attributeOldValue', { get() {
          document.documentElement.setAttribute('${attribute}', replayRecord)
          return false
        } })`,
        sandbox,
      )
    },
    changeObserverIterator(record: string) {
      sandbox.replayRecord = record
      runInNewContext(
        `Array.prototype[Symbol.iterator] = function () {
          document.documentElement.setAttribute('${attribute}', replayRecord)
          let done = false
          return { next() {
            if (done) return { done: true, value: undefined }
            done = true
            return { done: false, value: '${attribute}' }
          } }
        }`,
        sandbox,
      )
    },
    emit(directive: string) {
      // Only this unit double supplies a trusted event. Browser events use native isTrusted.
      violationListener?.(new TrustedViolation(directive))
    },
    emitSynthetic() {
      const event = Object.assign(new Event('securitypolicyviolation'), {
        effectiveDirective: 'trusted-types',
      })
      expect(event.isTrusted).toBe(false)
      violationListener?.(event)
    },
    leaveDocument(persisted = false) {
      pageHideListener?.({ isTrusted: true, persisted })
    },
    showDocument(persisted = true, isTrusted = true) {
      pageShowListener?.({ isTrusted, persisted })
    },
    settled(count: number | null = 1) {
      return new Promise<void>((resolve) => {
        const check = () => {
          const raw = root.getAttribute(attribute)
          if (raw === null || raw === 'pending') return
          const parsed: unknown = JSON.parse(raw)
          if (Array.isArray(parsed) && (count === null || parsed.length === count)) {
            publications.delete(check)
            resolve()
          }
        }
        publications.add(check)
        check()
      })
    },
    sealed(sequence: number) {
      return new Promise<void>((resolve) => {
        const check = () => {
          const value: unknown = JSON.parse(history.get(documentHistoryKey) ?? 'null')
          if (
            value !== null &&
            typeof value === 'object' &&
            'sequence' in value &&
            value.sequence === sequence
          ) {
            sealWrites.delete(check)
            resolve()
          }
        }
        sealWrites.add(check)
        check()
      })
    },
    raw() {
      const raw = document.actualRoot()?.getAttribute(attribute) ?? null
      if (raw === null) throw new Error('Expected CSP event record')
      return raw
    },
    records() {
      const parsed: unknown = JSON.parse(this.raw())
      if (!Array.isArray(parsed)) throw new Error('Expected CSP event array')
      const records: unknown[] = parsed
      return records
    },
    events() {
      const events = read(document.actualRoot()?.getAttribute(attribute) ?? null)
      if (events === undefined) throw new Error('Expected authenticated CSP event record')
      return events
    },
  }
}
function refusal(events: string[]): ProbeObservation {
  return {
    header: expectedHeader,
    reportOnly: undefined,
    done: 'yes',
    outcome: 'blocked',
    exception: 'TypeError',
    events,
    content: null,
    functionReturned: null,
  }
}
const expected = probeExpectation('duplicate-policy', 'firefox')

it('records the actual directive without a binding and accepts duplicate-policy refusal', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  expect(() => {
    verifyBehavior(refusal(capture.events()), expected)
  }).not.toThrow()
})
it('publishes an authenticated empty record when no violation occurred', async () => {
  const capture = collector()
  await capture.settled()
  expect(capture.records()).toHaveLength(1)
  expect(capture.records()[0]).toMatchObject({ sequence: 0, directive: null })
  expect(capture.records()[0]).toHaveProperty('tag', expect.stringMatching(/^[a-f0-9]{64}$/))
  expect(capture.events()).toEqual([])
})
it('rejects a document that left and returned with its original authenticated stream', async () => {
  const capture = collector()
  await capture.settled()
  expect(capture.events()).toEqual([])
  capture.leaveDocument()
  expect(() => capture.events()).toThrow('ProbeCspRecordError')
})
it('retains violations before the document root exists', async () => {
  const capture = collector(false, false)
  capture.emit('trusted-types')
  capture.document.documentElement = capture.root
  capture.document.dispatchEvent(new Event('DOMContentLoaded'))
  await capture.settled(2)
  expect(capture.events()).toEqual(['trusted-types'])
})
it('preserves duplicate matching events with distinct sequence numbers', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  capture.emit('trusted-types')
  await capture.settled(3)
  expect(capture.records()).toEqual([
    expect.objectContaining({ sequence: 0 }),
    expect.objectContaining({ sequence: 1 }),
    expect.objectContaining({ sequence: 2 }),
  ])
  expect(capture.events()).toEqual(['trusted-types', 'trusted-types'])
  expect(() => {
    verifyBehavior(refusal(capture.events()), expected)
  }).not.toThrow()
})
it('preserves unrelated violations so the verifier rejects them', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  capture.emit('script-src')
  await capture.settled(3)
  expect(capture.events()).toEqual(['trusted-types', 'script-src'])
  expect(() => {
    verifyBehavior(refusal(capture.events()), expected)
  }).toThrow('ProbeDirectiveError')
})
it('discards only events while header integrity and refusal still pass', async () => {
  const capture = collector(true)
  capture.emit('trusted-types')
  await capture.settled()
  const observed = refusal(capture.events())
  expect(observed.events).toEqual([])
  expect(() => {
    verifyHeaderIntegrity(observed, expectedHeader, expectedHeader)
  }).not.toThrow()
  expect(() => {
    verifyRefusal(observed, expected)
  }).not.toThrow()
  expect(() => {
    verifyBehavior(observed, expected)
  }).toThrow('ProbeDirectiveError')
})
it.each([null, '', '{', '{}', 'null', '["trusted-types", 1]', '[null]'])(
  'fails closed for invalid CSP event record %j',
  (record) => {
    expect(() => createProbeCspReader(randomBytes(32))(record)).toThrow()
  },
)
it('rejects a forged record that claims the required directive', async () => {
  const capture = collector()
  await capture.settled()
  expect(() => capture.read('["trusted-types"]')).toThrow('ProbeCspRecordError')
})
it('rejects a replaced attribute even when it contains an authentic older snapshot', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const prefix = capture.raw()
  capture.emit('script-src')
  await capture.settled(3)
  // Replay the passing prefix before Node has accepted any snapshot.
  capture.root.setAttribute(attribute, prefix)
  await Promise.resolve()
  expect(() => capture.events()).toThrow()
})
it('rejects a replayed record with its valid tag', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const records = capture.records()
  expect(() => capture.read(JSON.stringify([...records, records[1]]))).toThrow('sequence')
})
it('rejects a reordered sequence with valid tags', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  capture.emit('script-src')
  await capture.settled(3)
  const [start, first, second] = capture.records()
  expect(() => capture.read(JSON.stringify([start, second, first]))).toThrow('sequence')
})
it('rejects a record with a bad tag', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const [start] = capture.records()
  if (start === null || typeof start !== 'object' || !('documentId' in start))
    throw new Error('Expected document identity')
  expect(() =>
    capture.read(
      JSON.stringify([
        start,
        {
          documentId: start.documentId,
          previousDocumentId: null,
          previousDocumentSequence: null,
          sequence: 1,
          directive: 'trusted-types',
          tag: '0'.repeat(64),
        },
      ]),
    ),
  ).toThrow('Unauthenticated')
})
it('ignores an untrusted synthetic violation event', async () => {
  const capture = collector()
  capture.emitSynthetic()
  await capture.settled()
  expect(capture.events()).toEqual([])
  expect(() => {
    verifyBehavior(refusal(capture.events()), expected)
  }).toThrow('ProbeDirectiveError')
})
it('rejects an altered directive with its original tag', async () => {
  const capture = collector()
  capture.emit('script-src')
  await capture.settled(2)
  const [start, event] = capture.records()
  if (event === null || typeof event !== 'object') throw new Error('Expected record')
  expect(() =>
    capture.read(JSON.stringify([start, { ...event, directive: 'trusted-types' }])),
  ).toThrow('Unauthenticated')
})
it('rejects a missing sequence with valid tags', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  capture.emit('trusted-types')
  await capture.settled(3)
  const [start, , second] = capture.records()
  expect(() => capture.read(JSON.stringify([start, second]))).toThrow('sequence')
})
it('rejects a snapshot from another page', async () => {
  const capture = collector()
  const other = collector()
  other.emit('trusted-types')
  await other.settled(2)
  expect(() => capture.read(other.raw())).toThrow('Unauthenticated')
  await capture.settled()
})
it('accepts repeated polling but rejects rollback to an earlier authenticated prefix', async () => {
  const capture = collector()
  await capture.settled()
  const empty = capture.raw()
  expect(capture.events()).toEqual([])
  capture.emit('trusted-types')
  await capture.settled(2)
  expect(capture.events()).toEqual(['trusted-types'])
  expect(capture.events()).toEqual(['trusted-types'])
  expect(() => capture.read(empty)).toThrow('Replaced or replayed')
  expect(() => capture.events()).toThrow('already rejected')
})
it('rejects an unsigned empty stream', () => {
  expect(() => createProbeCspReader(randomBytes(32))('[]')).toThrow('authenticated')
})
it('keeps the pending state separate from authenticated empty evidence', async () => {
  const capture = collector()
  expect(capture.read(capture.raw())).toBeUndefined()
  await capture.settled()
  expect(capture.events()).toEqual([])
  capture.emit('trusted-types')
  expect(capture.read(capture.raw())).toBeUndefined()
  await capture.settled(2)
  expect(capture.events()).toEqual(['trusted-types'])
})
it('does not overwrite a pending page write when a genuine event arrives', async () => {
  const capture = collector()
  await capture.settled()
  capture.root.setAttribute(attribute, '["trusted-types"]')
  capture.emit('trusted-types')
  await Promise.resolve()
  expect(() => capture.events()).toThrow()
})
it('matches the independent Node HMAC oracle', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key)
  const documentId = 'a'.repeat(32)
  const records = [null, 'trusted-types', 'trusted-types'].map((directive, sequence) => ({
    documentId,
    previousDocumentId: null,
    previousDocumentSequence: null,
    sequence,
    directive,
    tag: createHmac('sha256', key)
      .update(JSON.stringify([documentId, null, null, sequence, directive]))
      .digest('hex'),
  }))
  expect(read(JSON.stringify(records))).toEqual(['trusted-types', 'trusted-types'])
})
it('preserves the actual directive when page code replaces array serialization', async () => {
  const capture = collector()
  await capture.settled()
  capture.changeSerialization()
  capture.emit('script-src')
  await capture.settled(2)
  expect(capture.events()).toEqual(['script-src'])
})
it('retains an unrelated tail event after page code changes array serialization', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  expect(capture.events()).toEqual(['trusted-types'])
  capture.changeSerialization()
  capture.emit('script-src')
  await capture.settled(3)
  expect(capture.events()).toEqual(['trusted-types', 'script-src'])
  expect(() => {
    verifyBehavior(refusal(capture.events()), expected)
  }).toThrow('ProbeDirectiveError')
})
it('keeps the signing key private when page code intercepts promise resolution', async () => {
  const capture = collector()
  await capture.settled()
  capture.interceptKeyResolution()
  capture.emit('trusted-types')
  await capture.settled(2)
  expect(capture.events()).toEqual(['trusted-types'])
  expect(capture.keyLeaked()).toBe(false)
})
it('keeps the initial key import private when page code intercepts promises immediately', async () => {
  const capture = collector()
  capture.interceptKeyResolution()
  capture.emit('trusted-types')
  await capture.settled(2)
  expect(capture.events()).toEqual(['trusted-types'])
  expect(capture.keyLeaked()).toBe(false)
})
it('rejects root replacement when page code hides the native document root', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const prefix = capture.raw()
  capture.emit('script-src')
  await capture.settled(3)
  capture.replaceRootWithReplay(prefix)
  await Promise.resolve()
  expect(() => capture.events()).toThrow()
})
it('rejects attribute replay when page code hides the native mutation type', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const prefix = capture.raw()
  capture.emit('script-src')
  await capture.settled(3)
  capture.changeMutationType()
  capture.root.setAttribute(attribute, prefix)
  await Promise.resolve()
  expect(() => capture.events()).toThrow()
})
it('preserves the native directive when page code changes the event getter', async () => {
  const capture = collector()
  await capture.settled()
  capture.changeEventDirective()
  capture.emit('script-src')
  await capture.settled(2)
  expect(capture.events()).toEqual(['script-src'])
})
it('preserves the full stream when page code changes inherited observer options', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const prefix = capture.raw()
  capture.changeObserverOptions(prefix)
  capture.emit('script-src')
  await capture.settled(3)
  expect(capture.events()).toEqual(['trusted-types', 'script-src'])
})
it('preserves the full stream when page code changes observer filter iteration', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  const prefix = capture.raw()
  capture.changeObserverIterator(prefix)
  capture.emit('script-src')
  await capture.settled(3)
  expect(capture.events()).toEqual(['trusted-types', 'script-src'])
})

function documentRecords(
  key: Uint8Array,
  documentId: string,
  directives: string[],
  previousDocumentId: string | null = null,
  previousDocumentSequence: number | null = previousDocumentId === null ? null : 0,
) {
  return JSON.stringify(
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

function navigationCollector(
  departure:
    | 'signed'
    | 'pending'
    | 'missing-history'
    | 'complete'
    | 'after-hide'
    | 'no-hide'
    | 'signed-no-hide'
    | 'pending-no-hide'
    | 'invalid-no-hide'
    | 'delayed-root'
    | 'same-document',
) {
  const history = new Map<string, string>()
  let options: ProbeCspCollectorOptions | undefined
  let current: ReturnType<typeof collector> | undefined
  async function navigate() {
    if (options === undefined) throw new Error('Collector not installed')
    const delayedRoot = current !== undefined && departure === 'delayed-root'
    if (current !== undefined) {
      if (departure === 'same-document') return null
      // Model a native event after the adapter's pre-navigation read, before commit.
      if (['signed', 'pending', 'signed-no-hide', 'pending-no-hide'].includes(departure))
        current.emit('script-src')
      if (departure === 'signed' || departure === 'signed-no-hide') await current.settled(2)
      if (departure === 'invalid-no-hide') {
        current.root.setAttribute(attribute, '[]')
        // Native mutation observers run at the microtask checkpoint before the next document.
        await Promise.resolve()
      }
      if (!departure.endsWith('no-hide')) current.leaveDocument()
      if (departure === 'after-hide') current.emit('script-src')
      if (departure === 'missing-history') history.delete(options.documentHistoryKey)
    }
    current = collector(
      false,
      !delayedRoot,
      history,
      Buffer.from(options.key),
      options.documentHistoryKey,
    )
    if (delayedRoot) {
      // Firefox can finish signing before the parser inserts html, then expose html before
      // DOMContentLoaded. Deliver the native child-list mutation before the utility-world read.
      await current.sealed(0)
      current.document.documentElement = current.root
      await Promise.resolve()
    } else await current.settled()
    return null
  }
  return {
    page: {
      addInitScript(_script: unknown, argument: ProbeCspCollectorOptions) {
        options = argument
        return Promise.resolve()
      },
      locator() {
        return {
          getAttribute: () =>
            Promise.resolve(current?.document.actualRoot()?.getAttribute(attribute) ?? null),
        }
      },
      goto: navigate,
      reload: navigate,
      goBack: navigate,
      goForward: navigate,
    },
    async emit() {
      if (current === undefined) throw new Error('Missing document')
      current.emit('script-src')
      await current.settled(2)
    },
  }
}

it.each(['goto', 'reload', 'goBack', 'goForward'] as const)(
  'preserves evidence signed before root insertion during Playwright %s',
  async (method) => {
    const capture = navigationCollector('delayed-root')
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      await capture.emit()
      await capture.page[method]()
      expect(await evidence.readSnapshot()).toEqual([])
      expect(await evidence.read()).toEqual(['script-src'])
    } finally {
      evidence.dispose()
    }
  },
)

it.each(['goto', 'reload', 'goBack', 'goForward'] as const)(
  'rejects an unaccounted signed tail during Playwright %s',
  async (method) => {
    const capture = navigationCollector('signed')
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      await expect(capture.page[method]()).rejects.toThrow('departing document')
      await expect(evidence.read()).rejects.toThrow('already rejected')
    } finally {
      evidence.dispose()
    }
  },
)

it.each(['pending', 'after-hide', 'pending-no-hide', 'signed-no-hide', 'invalid-no-hide'] as const)(
  'rejects %s final evidence when a Playwright reload replaces the document',
  async (departure) => {
    const capture = navigationCollector(departure)
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      await expect(capture.page.reload()).rejects.toThrow('departing document')
      await expect(evidence.readSnapshot()).rejects.toThrow('already rejected')
    } finally {
      evidence.dispose()
    }
  },
)

it.each(['goto', 'reload', 'goBack', 'goForward'] as const)(
  'preserves accounted collector evidence across Playwright %s',
  async (method) => {
    const capture = navigationCollector('complete')
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      await capture.emit()
      await capture.page[method]()
      expect(await evidence.readSnapshot()).toEqual([])
      expect(await evidence.read()).toEqual(['script-src'])
      expect(await evidence.read()).toEqual(['script-src'])
    } finally {
      evidence.dispose()
    }
  },
)

it('rejects a lost history cursor rather than accepting a new document', async () => {
  const capture = navigationCollector('missing-history')
  const evidence = await installCspEvidence(capture.page, false)
  try {
    await capture.page.goto()
    await expect(capture.page.reload()).rejects.toThrow('Dropped document')
    await expect(evidence.read()).rejects.toThrow('already rejected')
  } finally {
    evidence.dispose()
  }
})

it.each(['goto', 'reload', 'goBack', 'goForward'] as const)(
  'preserves complete evidence when Firefox omits pagehide during Playwright %s',
  async (method) => {
    const capture = navigationCollector('no-hide')
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      // CI's failing reload has only the signed sentinel. Also cover a read violation.
      await capture.page[method]()
      expect(await evidence.read()).toEqual([])
      await capture.emit()
      await capture.page[method]()
      expect(await evidence.readSnapshot()).toEqual([])
      expect(await evidence.read()).toEqual(['script-src'])
    } finally {
      evidence.dispose()
    }
  },
)

it.each(['goBack', 'goForward'] as const)(
  'preserves the current stream during same-document Playwright %s',
  async (method) => {
    const capture = navigationCollector('same-document')
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      await capture.emit()
      await capture.page[method]()
      expect(await evidence.readSnapshot()).toEqual(['script-src'])
      expect(await evidence.read()).toEqual(['script-src'])
    } finally {
      evidence.dispose()
    }
  },
)

function cachedNavigationCollector(pagehide = true) {
  const history = new Map<string, string>()
  let options: ProbeCspCollectorOptions | undefined
  const documents: ReturnType<typeof collector>[] = []
  let index = -1
  let tail = false
  async function navigate(destination?: number) {
    if (options === undefined) throw new Error('Collector not installed')
    const departing = documents[index]
    if (departing !== undefined) {
      if (tail) {
        departing.emit('script-src')
        await departing.settled(2)
      }
      if (pagehide) departing.leaveDocument(true)
    }
    index = destination ?? documents.length
    let current = documents[index]
    if (current === undefined) {
      current = collector(
        false,
        true,
        history,
        Buffer.from(options.key),
        options.documentHistoryKey,
      )
      documents[index] = current
    } else {
      // A cache restore fires pageshow without rerunning init or creating a Document.
      current.showDocument()
    }
    await current.settled()
    return null
  }
  return {
    page: {
      addInitScript(_script: unknown, argument: ProbeCspCollectorOptions) {
        options = argument
        return Promise.resolve()
      },
      locator() {
        return { getAttribute: () => Promise.resolve(documents[index]?.raw() ?? null) }
      },
      goto: () => navigate(),
      reload: () => navigate(),
      goBack: () => navigate(index - 1),
      goForward: () => navigate(index + 1),
    },
    async emit(directive: string) {
      const current = documents[index]
      if (current === undefined) throw new Error('Missing document')
      current.emit(directive)
      await current.settled(2)
    },
    addTail() {
      tail = true
    },
    raw: () => documents[index]?.raw(),
    navigate,
  }
}

it.each([false, true])(
  'preserves evidence through cached history, pagehide=%s',
  async (pagehide) => {
    const capture = cachedNavigationCollector(pagehide)
    const evidence = await installCspEvidence(capture.page, false)
    try {
      await capture.page.goto()
      await capture.emit('script-src')
      const first = capture.raw()
      await capture.page.goto()
      await capture.emit('trusted-types')
      await capture.page.goBack()
      expect(capture.raw()).not.toBe(first)
      expect(await evidence.readSnapshot()).toEqual([])
      expect(await evidence.read()).toEqual(['script-src', 'trusted-types'])
      await capture.emit('style-src-elem')
      await capture.page.goForward()
      expect(await evidence.readSnapshot()).toEqual([])
      expect(await evidence.read()).toEqual(['script-src', 'trusted-types', 'style-src-elem'])
      await capture.page.goBack()
      expect(await evidence.read()).toEqual(['script-src', 'trusted-types', 'style-src-elem'])
    } finally {
      evidence.dispose()
    }
  },
)

it('rejects an unchecked departure and return through the cache', async () => {
  const capture = cachedNavigationCollector()
  const evidence = await installCspEvidence(capture.page, false)
  try {
    await capture.page.goto()
    await capture.navigate()
    await capture.navigate(0)
    await expect(evidence.read()).rejects.toThrow(/document transition|Invalidated document/)
  } finally {
    evidence.dispose()
  }
})

it('rejects a departing tail before accepting a cached document', async () => {
  const capture = cachedNavigationCollector()
  const evidence = await installCspEvidence(capture.page, false)
  try {
    await capture.page.goto()
    await capture.page.goto()
    capture.addTail()
    await expect(capture.page.goBack()).rejects.toThrow('departing document')
    await expect(evidence.read()).rejects.toThrow('already rejected')
  } finally {
    evidence.dispose()
  }
})

it.each(['pending', 'tampered', 'late-event'] as const)(
  'keeps a %s cached stream invalid on restoration',
  async (state) => {
    const capture = collector()
    await capture.settled()
    if (state === 'pending') capture.emit('script-src')
    if (state === 'tampered') capture.root.setAttribute(attribute, '[]')
    capture.leaveDocument(true)
    if (state === 'late-event') capture.emit('script-src')
    capture.showDocument()
    expect(() => capture.events()).toThrow('Invalidated document')
  },
)

it.each([
  [false, true],
  [true, false],
] as const)(
  'does not reactivate departed evidence for pageshow persisted=%s trusted=%s',
  async (persisted, trusted) => {
    const capture = collector()
    await capture.settled()
    capture.leaveDocument(true)
    capture.showDocument(persisted, trusted)
    expect(() => capture.events()).toThrow('Invalidated document')
  },
)

it('authenticates the predecessor and preserves real collector evidence across documents', async () => {
  const history = new Map<string, string>()
  const key = randomBytes(32)
  const read = createProbeCspReader(key, true)
  const first = collector(false, true, history, key)
  first.emit('script-src')
  await first.settled(2)
  expect(read(first.raw())).toEqual(['script-src'])
  first.leaveDocument()
  const second = collector(false, true, history, key)
  await second.settled()
  expect(read(second.raw(), true)).toEqual(['script-src'])
  expect(read(second.raw())).toEqual(['script-src'])
})

it.each([false, true])(
  'rejects a real collector whose predecessor was never read, established=%s',
  async (established) => {
    const history = new Map<string, string>()
    const key = randomBytes(32)
    const read = createProbeCspReader(key)
    const first = collector(false, true, history, key)
    await first.settled()
    if (established) expect(read(first.raw())).toEqual([])
    first.leaveDocument()
    const second = collector(false, true, history, key)
    await second.settled()
    second.leaveDocument()
    const third = collector(false, true, history, key)
    await third.settled()
    expect(() => read(third.raw(), established)).toThrow('Dropped document')
  },
)

it('rejects an altered predecessor with its original signature', async () => {
  const capture = collector()
  await capture.settled()
  const [start] = capture.records()
  if (start === null || typeof start !== 'object') throw new Error('Expected record')
  expect(() =>
    capture.read(JSON.stringify([{ ...start, previousDocumentId: 'f'.repeat(32) }])),
  ).toThrow('Unauthenticated')
})

it('rejects an altered final predecessor sequence with its original signature', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key)
  expect(read(documentRecords(key, 'a'.repeat(32), []))).toEqual([])
  const successor = documentRecords(key, 'b'.repeat(32), [], 'a'.repeat(32), 0)
  expect(() =>
    read(successor.replace('"previousDocumentSequence":0', '"previousDocumentSequence":1'), true),
  ).toThrow('Unauthenticated')
})

it.each([null, 0, 2])(
  'rejects an authenticated successor whose final predecessor sequence is %j instead of 1',
  (finalSequence) => {
    const key = randomBytes(32)
    const read = createProbeCspReader(key, true)
    expect(read(documentRecords(key, 'a'.repeat(32), ['script-src']))).toEqual(['script-src'])
    expect(() =>
      read(documentRecords(key, 'b'.repeat(32), [], 'a'.repeat(32), finalSequence), true),
    ).toThrow('departing document')
    expect(() => read(documentRecords(key, 'a'.repeat(32), ['script-src']))).toThrow(
      'already rejected',
    )
  },
)

it.each([undefined, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, '0'])(
  'rejects a missing or malformed final predecessor sequence %j',
  (finalSequence) => {
    const key = randomBytes(32)
    const read = createProbeCspReader(key)
    expect(read(documentRecords(key, 'a'.repeat(32), []))).toEqual([])
    const parsed: unknown = JSON.parse(documentRecords(key, 'b'.repeat(32), [], 'a'.repeat(32)))
    if (!Array.isArray(parsed)) throw new Error('Expected records')
    const records: unknown[] = parsed
    const start = records[0]
    if (start === null || typeof start !== 'object') throw new Error('Expected record')
    expect(() =>
      read(JSON.stringify([{ ...start, previousDocumentSequence: finalSequence }]), true),
    ).toThrow('Invalid record')
  },
)

it('retains authenticated violations across replacement documents and repeated reads', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key, true)
  const first = documentRecords(key, 'a'.repeat(32), ['script-src'])
  const second = documentRecords(key, 'b'.repeat(32), [], 'a'.repeat(32), 1)
  expect(read(first)).toEqual(['script-src'])
  expect(read(second, true)).toEqual(['script-src'])
  expect(read(second)).toEqual(['script-src'])
  // Explicit transitions retain each document's authenticated history.
  expect(read(first, true)).toEqual(['script-src'])
})

it('rejects rollback in an earlier document after another document is authenticated', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key, true)
  expect(read(documentRecords(key, 'a'.repeat(32), ['trusted-types']))).toEqual(['trusted-types'])
  expect(read(documentRecords(key, 'b'.repeat(32), [], 'a'.repeat(32), 1), true)).toEqual([
    'trusted-types',
  ])
  expect(() => read(documentRecords(key, 'a'.repeat(32), []), true)).toThrow('Replaced or replayed')
})

it('rejects mixed document records even when each tag is authentic', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key)
  const first: unknown = JSON.parse(documentRecords(key, 'a'.repeat(32), []))
  const second: unknown = JSON.parse(documentRecords(key, 'b'.repeat(32), ['trusted-types']))
  if (!Array.isArray(first) || !Array.isArray(second)) throw new Error('Expected records')
  const starts: unknown[] = first
  const events: unknown[] = second
  expect(() => read(JSON.stringify([starts[0], events[1]]))).toThrow('Mixed document')
})

it('rejects a changed document identity with its original tag', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key)
  expect(() =>
    read(documentRecords(key, 'a'.repeat(32), []).replace('a'.repeat(32), 'b'.repeat(32))),
  ).toThrow('Unauthenticated')
})

it('keeps a probe snapshot limited to its authenticated document', () => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key)
  expect(read(documentRecords(key, 'a'.repeat(32), ['trusted-types']))).toEqual(['trusted-types'])
  expect(read(documentRecords(key, 'b'.repeat(32), [], 'a'.repeat(32), 1), true)).toEqual([])
})

it.each([false, true])('rejects an unchecked document transition with history=%s', (history) => {
  const key = randomBytes(32)
  const read = createProbeCspReader(key, history)
  expect(read(documentRecords(key, 'a'.repeat(32), []))).toEqual([])
  expect(() => read(documentRecords(key, 'b'.repeat(32), []))).toThrow('document transition')
  expect(() => read(documentRecords(key, 'a'.repeat(32), []))).toThrow('already rejected')
})

it('retains new events when page code replaces the root instance check', async () => {
  const capture = collector()
  capture.emit('trusted-types')
  await capture.settled(2)
  capture.changeInstanceCheck()
  expect(() => {
    capture.emit('script-src')
  }).not.toThrow()
  await capture.settled(3)
  expect(capture.events()).toEqual(['trusted-types', 'script-src'])
})

it('retains a genuine event when page code replaces inherited record setters', async () => {
  const capture = collector()
  await capture.settled()
  capture.changeRecordStorage()
  capture.emit('script-src')
  await capture.settled(null)
  expect(capture.events()).toEqual(['script-src'])
})
