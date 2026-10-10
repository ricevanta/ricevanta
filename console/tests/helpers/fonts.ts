import { readFileSync } from 'node:fs'

export const fontWeights = ['400', '500', '600', '700']
export const fontSubsets = ['latin', 'latin-ext', 'vietnamese']

export function normalizeUnicodeRange(value: string): string {
  return value
    .toUpperCase()
    .replace(/\s/g, '')
    .replace(
      /U\+([0-9A-F]*)(\?+)/g,
      (_match, prefix: string, wildcard: string) =>
        `U+${prefix}${'0'.repeat(wildcard.length)}-${prefix}${'F'.repeat(wildcard.length)}`,
    )
    .replace(/\b[0-9A-F]+\b/g, (hex) => Number.parseInt(hex, 16).toString(16).toUpperCase())
}

export function parseFontFaces(css: string): Map<string, string>[] {
  return Array.from(css.matchAll(/@font-face\s*\{([^}]+)\}/g), (match) => {
    const declarations = new Map<string, string>()
    for (const declaration of (match[1] ?? '').split(';')) {
      const colon = declaration.indexOf(':')
      if (colon >= 0)
        declarations.set(declaration.slice(0, colon).trim(), declaration.slice(colon + 1).trim())
    }
    return declarations
  })
}

export function packageFontFaces(): { weight: string; subset: string; unicodeRange: string }[] {
  return fontWeights.flatMap((weight) =>
    parseFontFaces(
      readFileSync(`node_modules/@fontsource/be-vietnam-pro/${weight}.css`, 'utf8'),
    ).map((rule) => {
      const subset = /be-vietnam-pro-(latin-ext|latin|vietnamese)-/.exec(rule.get('src') ?? '')?.[1]
      const unicodeRange = rule.get('unicode-range')
      if (!subset || !unicodeRange) throw new Error(`Missing package subset range: ${weight}`)
      return { weight, subset, unicodeRange: normalizeUnicodeRange(unicodeRange) }
    }),
  )
}
