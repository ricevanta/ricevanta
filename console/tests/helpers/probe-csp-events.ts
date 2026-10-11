import { createHmac, timingSafeEqual } from 'node:crypto'

export interface ProbeCspCollectorOptions {
  attribute: string
  discardCspEvents: boolean
  key: number[]
  documentHistoryKey: string
}

interface ProbeCspRecord {
  documentId: string
  previousDocumentId: string | null
  previousDocumentSequence: number | null
  sequence: number
  directive: string | null
  tag: string
}

// Playwright serializes this function, so all runtime state stays inside it.
// Deliberate document.open() resets that strip listeners are outside the harness threat model.
export function collectProbeCspEvents(options: ProbeCspCollectorOptions): void {
  if (window !== window.top) return
  const { attribute, discardCspEvents } = options
  const stringify = JSON.stringify.bind(JSON)
  const encoder = new TextEncoder()
  const encode = encoder.encode.bind(encoder)
  const hexAt = '0123456789abcdef'.charAt.bind('0123456789abcdef')
  const randomUUID = crypto.randomUUID.bind(crypto)
  const parse = JSON.parse.bind(JSON)
  const readHistory = sessionStorage.getItem.bind(sessionStorage)
  const saveHistory = sessionStorage.setItem.bind(sessionStorage)
  let encodedDocument: string
  let encodedPreviousDocument: string
  let encodedPreviousSequence: string
  // Each cache activation gets a new identity linked to the document it replaces.
  function beginDocument(): void {
    const storedHistory = readHistory(options.documentHistoryKey)
    let previousDocumentId: string | null = null
    let previousDocumentSequence: number | null = null
    if (storedHistory !== null) {
      const previous: unknown = parse(storedHistory)
      if (
        previous === null ||
        typeof previous !== 'object' ||
        Object.keys(previous).length !== 2 ||
        !('documentId' in previous) ||
        typeof previous.documentId !== 'string' ||
        !/^[a-f0-9]{32}$/.test(previous.documentId) ||
        !('sequence' in previous) ||
        !(
          previous.sequence === null ||
          (typeof previous.sequence === 'number' &&
            Number.isSafeInteger(previous.sequence) &&
            previous.sequence >= 0)
        )
      )
        throw new Error('Invalid CSP document history')
      previousDocumentId = previous.documentId
      previousDocumentSequence = previous.sequence
    }
    encodedDocument = stringify(randomUUID().replaceAll('-', ''))
    encodedPreviousDocument = stringify(previousDocumentId)
    encodedPreviousSequence = stringify(previousDocumentSequence)
    saveSequence(null)
  }
  function saveSequence(sequence: number | null): void {
    saveHistory(
      options.documentHistoryKey,
      `{"documentId":${encodedDocument},"sequence":${stringify(sequence)}}`,
    )
  }
  beginDocument()
  const apply = Reflect.apply
  function nativeGetter(prototype: object, name: string): (target: object) => unknown {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- Reflect.apply supplies the target to this captured native getter.
    const getter: unknown = Object.getOwnPropertyDescriptor(prototype, name)?.get
    if (typeof getter !== 'function') throw new Error('Missing native CSP collector getter')
    return (target) => {
      const value: unknown = apply(getter, target, [])
      return value
    }
  }
  const documentRoot = nativeGetter(Document.prototype, 'documentElement')
  const mutationType = nativeGetter(MutationRecord.prototype, 'type')
  const effectiveDirective = nativeGetter(
    SecurityPolicyViolationEvent.prototype,
    'effectiveDirective',
  )
  const root = (): object | null => {
    const element = documentRoot(document)
    if (element === null || typeof element === 'object') return element
    throw new Error('Invalid native document root')
  }
  const sign = crypto.subtle.sign.bind(crypto.subtle)
  let signingKey: CryptoKey | undefined
  // Register before page scripts run. Later awaits expose only void, never the key.
  const ready = crypto.subtle
    .importKey('raw', new Uint8Array(options.key), { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
    ])
    .then((imported) => {
      signingKey = imported
    })
  // eslint-disable-next-line @typescript-eslint/unbound-method -- Reflect.apply supplies the element to this captured native method.
  const setAttribute = Element.prototype.setAttribute
  const records: string[] = []
  const joinRecords = records.join.bind(records)
  const setPrototype = Object.setPrototypeOf.bind(Object)
  setPrototype(records, null)
  const attributeFilter = [attribute]
  Object.defineProperty(attributeFilter, Symbol.iterator, {
    value: () => {
      let done = false
      const iterator = {
        next() {
          if (done) return { done: true, value: undefined }
          done = true
          return { done: false, value: attribute }
        },
      }
      setPrototype(iterator, null)
      return iterator
    },
  })
  const observerOptions: MutationObserverInit = {
    attributes: true,
    attributeFilter,
    childList: true,
    subtree: true,
  }
  // WebIDL dictionary conversion must not invoke page-owned inherited getters.
  setPrototype(observerOptions, null)
  let sequence = 0
  let invalid = false
  let departed = false
  let publishedRoot: object | null = null
  function hasAttributeMutation(mutations: MutationRecord[]): boolean {
    for (let index = 0; index < mutations.length; index++) {
      const mutation = mutations[index]
      if (mutation !== undefined && mutationType(mutation) === 'attributes') return true
    }
    return false
  }
  const observer = new MutationObserver((mutations) => {
    const element = root()
    if (hasAttributeMutation(mutations) || (publishedRoot !== null && element !== publishedRoot)) {
      invalid = true
      publish()
    } else if (publishedRoot === null && element !== null)
      // Signing can finish before html exists. Publish on insertion before a history
      // navigation's utility-world read, rather than waiting for DOMContentLoaded.
      publish()
  })
  const observe = observer.observe.bind(observer)
  const disconnect = observer.disconnect.bind(observer)
  const takeRecords = observer.takeRecords.bind(observer)
  function publish(): void {
    // Check pending page writes before disconnecting for the collector's own write.
    if (hasAttributeMutation(takeRecords()) || (publishedRoot !== null && root() !== publishedRoot))
      invalid = true
    // Reload can replace a Firefox document without delivering pagehide. Persist completeness
    // on every change so a successor verifies the final sequence, even on that path.
    const complete = !invalid && records.length === sequence && sequence > 0
    if (!departed || invalid) saveSequence(complete ? sequence - 1 : null)
    disconnect()
    const element = root()
    if (element) {
      const value =
        invalid || departed
          ? 'invalid'
          : records.length === 0 || records.length !== sequence
            ? 'pending'
            : '[' + joinRecords(',') + ']'
      apply(setAttribute, element, [attribute, value])
      publishedRoot = element
    }
    observe(document, observerOptions)
  }
  let pending = Promise.resolve()
  function append(directive: string | null): void {
    // A late event after departure cannot revive that activation's complete cursor.
    if (departed) invalid = true
    const current = sequence++
    // Pending signatures cannot expose an older prefix as complete evidence.
    publish()
    // Serial signing preserves event order even when WebCrypto finishes asynchronously.
    pending = pending
      .then(async () => {
        // Native stringify on a primitive cannot call page-owned toJSON hooks.
        const encodedDirective = stringify(directive)
        const encodedSequence = stringify(current)
        const payload = `[${encodedDocument},${encodedPreviousDocument},${encodedPreviousSequence},${encodedSequence},${encodedDirective}]`
        await ready
        if (signingKey === undefined) throw new Error('Missing HMAC key')
        const signature = new Uint8Array(await sign('HMAC', signingKey, encode(payload)))
        let tag = ''
        for (let index = 0; index < signature.length; index++) {
          const byte = signature[index]
          if (byte === undefined) throw new Error('Missing HMAC byte')
          tag += hexAt(byte >> 4) + hexAt(byte & 15)
        }
        records[records.length] =
          `{"documentId":${encodedDocument},"previousDocumentId":${encodedPreviousDocument},"previousDocumentSequence":${encodedPreviousSequence},"sequence":${encodedSequence},"directive":${encodedDirective},"tag":"${tag}"}`
        publish()
      })
      .catch(() => {
        invalid = true
        publish()
      })
  }
  window.addEventListener(
    'securitypolicyviolation',
    (event) => {
      if (!event.isTrusted || discardCspEvents) return
      const directive = effectiveDirective(event)
      if (typeof directive !== 'string') {
        invalid = true
        publish()
        return
      }
      append(directive)
    },
    { capture: true, passive: true },
  )
  window.addEventListener(
    'pagehide',
    (event) => {
      if (!event.isTrusted) return
      publish()
      // Pending signing at departure remains invalid even if a later promise settles.
      if (records.length !== sequence || sequence === 0) invalid = true
      departed = true
      publish()
    },
    { capture: true, passive: true },
  )
  window.addEventListener(
    'pageshow',
    (event) => {
      if (!event.isTrusted || !event.persisted) return
      // Even if pagehide was omitted, do not overwrite the current predecessor's cursor.
      departed = true
      publish()
      if (invalid || records.length !== sequence) return
      try {
        // Use the captured primitives and key, rather than reinstalling in page-owned globals.
        beginDocument()
        records.length = 0
        sequence = 0
        departed = false
        append(null)
      } catch {
        invalid = true
        publish()
      }
    },
    { capture: true, passive: true },
  )
  document.addEventListener('DOMContentLoaded', publish, { once: true, passive: true })
  publish()
  // Authenticate the empty stream too; a page-written [] never proves no violations.
  append(null)
}

export function createProbeCspReader(
  key: Uint8Array,
  preserveDocuments = false,
): (record: string | null, allowDocumentChange?: boolean) => string[] | undefined {
  const documents = new Map<string, { records: ProbeCspRecord[]; events: string[] }>()
  let currentDocument: string | undefined
  let invalid = false
  return (record, allowDocumentChange = false) => {
    if (invalid) throw new Error('ProbeCspRecordError: Evidence channel already rejected')
    try {
      if (record === 'pending') return undefined
      if (record === 'invalid')
        throw new Error('ProbeCspRecordError: Invalidated document evidence')
      if (record === null) throw new Error('ProbeCspRecordError: Missing CSP event record')
      const parsed: unknown = JSON.parse(record)
      if (!Array.isArray(parsed) || parsed.length === 0)
        throw new Error('ProbeCspRecordError: Expected authenticated CSP event array')
      const values: unknown[] = parsed
      const records: ProbeCspRecord[] = []
      const events: string[] = []
      let documentId: string | undefined
      let previousDocumentId: string | null | undefined
      let previousDocumentSequence: number | null | undefined
      for (const [sequence, value] of values.entries()) {
        if (
          value === null ||
          typeof value !== 'object' ||
          Object.keys(value).length !== 6 ||
          !('documentId' in value) ||
          typeof value.documentId !== 'string' ||
          !/^[a-f0-9]{32}$/.test(value.documentId) ||
          !('previousDocumentId' in value) ||
          !(
            value.previousDocumentId === null ||
            (typeof value.previousDocumentId === 'string' &&
              /^[a-f0-9]{32}$/.test(value.previousDocumentId))
          ) ||
          !('previousDocumentSequence' in value) ||
          !(
            value.previousDocumentSequence === null ||
            (value.previousDocumentId !== null &&
              typeof value.previousDocumentSequence === 'number' &&
              Number.isSafeInteger(value.previousDocumentSequence) &&
              value.previousDocumentSequence >= 0)
          ) ||
          !('sequence' in value) ||
          value.sequence !== sequence ||
          !('directive' in value) ||
          (sequence === 0 ? value.directive !== null : typeof value.directive !== 'string') ||
          !('tag' in value) ||
          typeof value.tag !== 'string' ||
          !/^[a-f0-9]{64}$/.test(value.tag)
        )
          throw new Error('ProbeCspRecordError: Invalid record or noncontiguous sequence')
        documentId ??= value.documentId
        if (sequence === 0) {
          previousDocumentId = value.previousDocumentId
          previousDocumentSequence = value.previousDocumentSequence
        }
        if (
          value.documentId !== documentId ||
          value.previousDocumentId !== previousDocumentId ||
          value.previousDocumentSequence !== previousDocumentSequence
        )
          throw new Error('ProbeCspRecordError: Mixed document records')
        const directive = value.directive
        if (directive !== null && typeof directive !== 'string')
          throw new Error('ProbeCspRecordError: Expected string CSP directive')
        const expected = createHmac('sha256', key)
          .update(
            JSON.stringify([
              documentId,
              previousDocumentId,
              previousDocumentSequence,
              sequence,
              directive,
            ]),
          )
          .digest()
        if (!timingSafeEqual(expected, Buffer.from(value.tag, 'hex')))
          throw new Error('ProbeCspRecordError: Unauthenticated CSP event record')
        records.push({
          documentId,
          previousDocumentId: value.previousDocumentId,
          previousDocumentSequence: value.previousDocumentSequence,
          sequence,
          directive,
          tag: value.tag,
        })
        if (typeof directive === 'string') events.push(directive)
      }
      if (documentId === undefined)
        throw new Error('ProbeCspRecordError: Missing document identity')
      if (currentDocument !== undefined && documentId !== currentDocument && !allowDocumentChange)
        throw new Error('ProbeCspRecordError: Unchecked document transition')
      if (!documents.has(documentId) && previousDocumentId !== (currentDocument ?? null))
        throw new Error('ProbeCspRecordError: Dropped document before CSP evidence read')
      if (
        !documents.has(documentId) &&
        currentDocument !== undefined &&
        previousDocumentSequence !== (documents.get(currentDocument)?.records.length ?? 0) - 1
      )
        throw new Error('ProbeCspRecordError: Unaccounted final stream from departing document')
      const previous = documents.get(documentId)?.records ?? []
      if (
        records.length < previous.length ||
        previous.some((entry, index) => records[index]?.tag !== entry.tag)
      )
        throw new Error('ProbeCspRecordError: Replaced or replayed CSP event record')
      documents.set(documentId, { records, events })
      currentDocument = documentId
      return preserveDocuments
        ? [...documents.values()].flatMap((document) => document.events)
        : events
    } catch (error) {
      invalid = true
      throw error
    }
  }
}
