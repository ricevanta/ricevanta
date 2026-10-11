import { afterEach, expect, it, vi } from 'vitest'
import { runInNewContext } from 'node:vm'
import { createDocumentFontEngine, parseDocumentFontReport } from '../helpers/document-fonts.ts'
import {
  qualifyDocumentFonts,
  registerDocumentFonts,
  settleDocumentFonts,
} from '../browser/document-fonts.ts'

afterEach(() => vi.unstubAllGlobals())

function deferred() {
  let finish = () => {}
  const promise = new Promise<void>((resolve) => {
    finish = resolve
  })
  return { promise, finish }
}

async function tick() {
  await new Promise<void>((resolve) => setTimeout(resolve, 0))
}

function setup() {
  const attributes = new Map<string, string>()
  const element = {
    scrollWidth: 320,
    setAttribute: (name: string, value: string) => attributes.set(name, value),
  }
  const faces = Array.from({ length: 12 }, (_, index) => {
    const face = {
      family: '"Be Vietnam Pro"',
      weight: String(400 + Math.floor(index / 3) * 100),
      style: 'normal',
      unicodeRange: 'U+0-FF',
      status: 'unloaded',
      load: vi.fn<() => Promise<unknown>>(),
    }
    face.load.mockImplementation(() => {
      face.status = 'loaded'
      return Promise.resolve(face)
    })
    return face
  })
  const fonts = Object.assign(faces, { ready: Promise.resolve(), check: vi.fn(() => true) })
  const body = { getBoundingClientRect: vi.fn(() => ({})) }
  const doc = {
    querySelector: (selector: string) => (selector === 'body' ? body : null),
    documentElement: element,
    fonts,
    styleSheets: [],
  }
  vi.stubGlobal('document', doc)
  vi.stubGlobal('window', { innerWidth: 320 })
  vi.stubGlobal('location', { href: 'http://127.0.0.1:4173/', origin: 'http://127.0.0.1:4173' })
  return { attributes, element, faces, fonts, body, doc, engine: createDocumentFontEngine() }
}

it('settles each matrix document without loading unused font subsets', async () => {
  const { engine, body, faces, attributes } = setup()
  for (let index = 0; index < 15; index++) {
    const selector = `settle:${String(index)}`
    expect(engine.queryAll(document, selector)).toEqual([])
    await tick()
    expect(engine.queryAll(document, selector)).toEqual([document.documentElement])
    expect(attributes.get('data-document-fonts')).toBe('true')
  }
  expect(body.getBoundingClientRect).toHaveBeenCalledTimes(15)
  for (const face of faces) expect(face.load).not.toHaveBeenCalled()
})

it('waits for readiness created by layout and measures overflow afterwards', async () => {
  const { engine, body, fonts, element, attributes } = setup()
  const ready = deferred()
  body.getBoundingClientRect.mockImplementation(() => {
    fonts.ready = ready.promise
    return {}
  })
  expect(engine.query(document, 'settle:1')).toBeNull()
  await tick()
  expect(engine.query(document, 'settle:1')).toBeNull()
  expect(attributes.has('data-document-fonts')).toBe(false)
  expect(body.getBoundingClientRect).toHaveBeenCalledTimes(1)
  element.scrollWidth = 321
  ready.finish()
  await tick()
  expect(engine.query(document, 'settle:1')).toBe(document.documentElement)
  expect(attributes.get('data-document-fonts')).toBe('false')
})

it('does not reuse readiness after a locale change or publish a superseded result', async () => {
  const { engine, fonts, attributes } = setup()
  engine.query(document, 'settle:1')
  await tick()
  expect(engine.query(document, 'settle:1')).toBe(document.documentElement)
  const old = deferred()
  fonts.ready = old.promise
  expect(engine.query(document, 'settle:2')).toBeNull()
  const current = deferred()
  fonts.ready = current.promise
  expect(engine.query(document, 'settle:3')).toBeNull()
  old.finish()
  await tick()
  expect(engine.query(document, 'settle:3')).toBeNull()
  current.finish()
  await tick()
  expect(engine.query(document, 'settle:3')).toBe(document.documentElement)
  expect(attributes.get('data-document-fonts')).toBe('true')
})

it('starts fresh in a successor document', async () => {
  const { engine } = setup()
  engine.query(document, 'settle:1')
  await tick()
  expect(engine.query(document, 'settle:1')).toBe(document.documentElement)
  const successor = createDocumentFontEngine()
  expect(successor.query(document, 'settle:1')).toBeNull()
  await tick()
  expect(successor.query(document, 'settle:1')).toBe(document.documentElement)
})

it('runs the serialized factory without module imports or page globals', async () => {
  setup()
  const clone: unknown = runInNewContext(`(${createDocumentFontEngine.toString()})()`, {
    document,
    window,
    location,
  })
  function engine(value: unknown): value is ReturnType<typeof createDocumentFontEngine> {
    return (
      typeof value === 'object' &&
      value !== null &&
      'query' in value &&
      typeof value.query === 'function' &&
      'queryAll' in value &&
      typeof value.queryAll === 'function'
    )
  }
  if (!engine(clone)) throw new Error('Invalid serialized selector engine')
  expect(clone.query(document, 'settle:1')).toBeNull()
  await tick()
  expect(clone.query(document, 'settle:1')).toBe(document.documentElement)
})

it('waits for a body and propagates readiness failures', async () => {
  const { engine, doc, body, fonts } = setup()
  vi.stubGlobal('document', { ...doc, querySelector: () => null })
  expect(engine.query(document, 'settle:1')).toBeNull()
  expect(body.getBoundingClientRect).not.toHaveBeenCalled()
  vi.stubGlobal('document', doc)
  const failure = new Error('font readiness failed')
  fonts.ready = Promise.reject(failure)
  expect(engine.query(document, 'settle:1')).toBeNull()
  await tick()
  expect(() => engine.query(document, 'settle:1')).toThrow(failure)
})

it('qualifies all faces once and retains rejected loads and availability failures', async () => {
  const { engine, doc, faces, fonts, attributes } = setup()
  class FontRule {
    style = {
      getPropertyValue: (name: string) =>
        new Map([
          ['font-family', '"Be Vietnam Pro"'],
          ['font-weight', '400'],
          ['font-style', 'normal'],
          ['src', 'url("/assets/font.woff2")'],
        ]).get(name) ?? '',
    }
  }
  vi.stubGlobal('CSSFontFaceRule', FontRule)
  vi.stubGlobal('document', { ...doc, styleSheets: [{ cssRules: [new FontRule()] }] })
  const failed = faces[0]
  if (!failed) throw new Error('Missing fixture face')
  vi.mocked(failed.load).mockRejectedValue(new Error('font load failed'))
  fonts.check.mockReturnValue(false)
  expect(engine.query(document, 'qualify:1')).toBeNull()
  await tick()
  expect(engine.query(document, 'qualify:1')).toBe(document.documentElement)
  const report = parseDocumentFontReport(attributes.get('data-document-fonts') ?? null)
  expect(report.rules).toEqual([
    {
      weight: '400',
      style: 'normal',
      unicodeRange: 'U+0-10FFFF',
      sources: ['http://127.0.0.1:4173/assets/font.woff2'],
    },
  ])
  expect(report.faces).toHaveLength(12)
  expect(report.faces[0]).toMatchObject({
    status: 'unloaded',
    resolved: false,
    error: 'Error: font load failed',
  })
  expect(report.faces.slice(1).every((face) => face.resolved && face.status === 'loaded')).toBe(
    true,
  )
  expect(report.checks.every((check) => !check.available)).toBe(true)
  for (const face of faces) expect(face.load).toHaveBeenCalledTimes(1)
  engine.query(document, 'qualify:1')
  for (const face of faces) expect(face.load).toHaveBeenCalledTimes(1)
})

it('waits for the final font readiness after loading unused faces', async () => {
  const { engine, faces, fonts, attributes } = setup()
  const last = faces.at(-1)
  if (!last) throw new Error('Missing fixture face')
  const ready = deferred()
  last.load.mockImplementation(() => {
    fonts.ready = ready.promise
    return Promise.resolve(last)
  })
  expect(engine.query(document, 'qualify:1')).toBeNull()
  await tick()
  expect(last.load).toHaveBeenCalledTimes(1)
  expect(engine.query(document, 'qualify:1')).toBeNull()
  expect(attributes.has('data-document-fonts')).toBe(false)
  ready.finish()
  await tick()
  expect(engine.query(document, 'qualify:1')).toBe(document.documentElement)
})

it('registers only a utility-world selector', async () => {
  const register = vi.fn(async () => {})
  await registerDocumentFonts({ register })
  expect(register).toHaveBeenCalledExactlyOnceWith('document-fonts', createDocumentFontEngine, {
    contentScript: true,
  })
})

it('uses fresh bounded locator reads and rejects missing readiness', async () => {
  const getAttribute = vi.fn(() => Promise.resolve('true'))
  const locator = vi.fn((selector: string) => {
    expect(selector).toMatch(/^document-fonts=settle:\d+$/)
    return { getAttribute }
  })
  expect(await settleDocumentFonts({ locator })).toBe(true)
  expect(await settleDocumentFonts({ locator })).toBe(true)
  const selectors = locator.mock.calls.map((call) => call[0])
  expect(new Set(selectors).size).toBe(2)
  expect(getAttribute).toHaveBeenNthCalledWith(1, 'data-document-fonts', { timeout: 5000 })
  expect(getAttribute).toHaveBeenNthCalledWith(2, 'data-document-fonts', { timeout: 5000 })
  getAttribute.mockResolvedValue('false')
  expect(await settleDocumentFonts({ locator })).toBe(false)
  getAttribute.mockResolvedValue('null')
  await expect(settleDocumentFonts({ locator })).rejects.toThrow('Invalid document font readiness')
})

it('preserves locator timeouts without another read', async () => {
  const failure = new Error('locator timeout')
  const getAttribute = vi.fn(() => Promise.reject(failure))
  const locator = () => ({ getAttribute })
  await expect(settleDocumentFonts({ locator })).rejects.toThrow(failure)
  expect(getAttribute).toHaveBeenCalledTimes(1)
})

it.each([null, 'null', '{}', '{"origin":1}', '{"origin":"x","rules":[],"faces":[],"checks":[{}]}'])(
  'rejects malformed qualification: %s',
  async (value) => {
    expect(() => parseDocumentFontReport(value)).toThrow('Invalid document font report')
    await expect(
      qualifyDocumentFonts({ locator: () => ({ getAttribute: () => Promise.resolve(value) }) }),
    ).rejects.toThrow('Invalid document font report')
  },
)
