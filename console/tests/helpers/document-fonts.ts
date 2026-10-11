export interface DocumentFontReport {
  origin: string
  rules: { weight: string; style: string; unicodeRange: string; sources: string[] }[]
  faces: {
    weight: string
    style: string
    unicodeRange: string
    status: string
    resolved: boolean
    error: string | null
  }[]
  checks: { weight: string; available: boolean }[]
}

// Playwright serializes this factory into its utility world. Keep it self-contained.
export function createDocumentFontEngine() {
  let request: { selector: string; result?: string; error?: Error } | undefined

  async function collect(qualify: boolean): Promise<boolean | DocumentFontReport> {
    const body = document.querySelector('body')
    if (!body) throw new Error('Missing document body')
    // Read ready after layout starts CSS font loads, including a changed locale.
    body.getBoundingClientRect()
    await document.fonts.ready
    if (!qualify) return document.documentElement.scrollWidth <= window.innerWidth

    const isVietnamPro = (family: string) => family.replace(/["']/g, '').trim() === 'Be Vietnam Pro'
    const rules = Array.from(document.styleSheets)
      .flatMap((sheet) => Array.from(sheet.cssRules))
      .filter(
        (rule): rule is CSSFontFaceRule =>
          rule instanceof CSSFontFaceRule &&
          isVietnamPro(rule.style.getPropertyValue('font-family')),
      )
      .map((rule) => ({
        weight: rule.style.getPropertyValue('font-weight'),
        style: rule.style.getPropertyValue('font-style'),
        unicodeRange: rule.style.getPropertyValue('unicode-range') || 'U+0-10FFFF',
        sources: Array.from(
          rule.style.getPropertyValue('src').matchAll(/url\(["']?([^"')]+)["']?\)/g),
          (match) => new URL(match[1] ?? '', location.href).href,
        ),
      }))
    const faces = Array.from(document.fonts).filter((face) => isVietnamPro(face.family))
    // Qualify all twelve faces once, after the navigation matrix has finished.
    const results: PromiseSettledResult<FontFace>[] = []
    for (const face of faces) results.push(...(await Promise.allSettled([face.load()])))
    await document.fonts.ready
    return {
      origin: location.origin,
      rules,
      faces: faces.map((face, index) => {
        const result = results[index]
        return {
          weight: face.weight,
          style: face.style,
          unicodeRange: face.unicodeRange,
          status: face.status,
          resolved: result?.status === 'fulfilled' && result.value === face,
          error: result?.status === 'rejected' ? String(result.reason) : null,
        }
      }),
      checks: ['400', '500', '600', '700'].map((weight) => ({
        weight,
        available: document.fonts.check(`${weight} 16px "Be Vietnam Pro"`, 'Tiếng Việt Ấ ệ ư Ā'),
      })),
    }
  }

  function queryAll(_root: Node, selector: string): Element[] {
    if (!/^(settle|qualify):\d+$/.test(selector)) throw new Error('Invalid document font request')
    if (!document.querySelector('body')) return []
    if (request?.selector !== selector) {
      const next: NonNullable<typeof request> = { selector }
      request = next
      void collect(selector.startsWith('qualify:')).then(
        (result) => {
          next.result = JSON.stringify(result)
        },
        (error: unknown) => {
          next.error = error instanceof Error ? error : new Error(String(error))
        },
      )
    }
    if (request.error) throw request.error
    if (request.result === undefined) return []
    document.documentElement.setAttribute('data-document-fonts', request.result)
    return [document.documentElement]
  }
  return {
    query(root: Node, selector: string): Element | null {
      return queryAll(root, selector)[0] ?? null
    },
    queryAll,
  }
}

export function parseDocumentFontReport(value: string | null): DocumentFontReport {
  const report: unknown = JSON.parse(value ?? 'null')
  function record(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
  }
  function rule(value: unknown): value is DocumentFontReport['rules'][number] {
    return (
      record(value) &&
      typeof value.weight === 'string' &&
      typeof value.style === 'string' &&
      typeof value.unicodeRange === 'string' &&
      Array.isArray(value.sources) &&
      value.sources.every((source: unknown) => typeof source === 'string')
    )
  }
  function face(value: unknown): value is DocumentFontReport['faces'][number] {
    return (
      record(value) &&
      typeof value.weight === 'string' &&
      typeof value.style === 'string' &&
      typeof value.unicodeRange === 'string' &&
      typeof value.status === 'string' &&
      typeof value.resolved === 'boolean' &&
      (value.error === null || typeof value.error === 'string')
    )
  }
  function check(value: unknown): value is DocumentFontReport['checks'][number] {
    return record(value) && typeof value.weight === 'string' && typeof value.available === 'boolean'
  }
  if (
    !record(report) ||
    typeof report.origin !== 'string' ||
    !Array.isArray(report.rules) ||
    !report.rules.every(rule) ||
    !Array.isArray(report.faces) ||
    !report.faces.every(face) ||
    !Array.isArray(report.checks) ||
    !report.checks.every(check)
  )
    throw new Error('Invalid document font report')
  return { origin: report.origin, rules: report.rules, faces: report.faces, checks: report.checks }
}
