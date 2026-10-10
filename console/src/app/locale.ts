export type Locale = 'en' | 'vi'
export type Theme = 'light' | 'dark' | 'system'
export type Density = 'comfortable' | 'compact'
export function selectLocale(saved: unknown, languages: readonly string[]): Locale {
  if (saved === 'en' || saved === 'vi') return saved
  for (const tag of languages.slice(0, 16)) {
    if (tag.length > 64) continue
    if (/^vi(?:-|$)/i.test(tag)) return 'vi'
    if (/^en(?:-|$)/i.test(tag)) return 'en'
  }
  return 'en'
}
export function pluralIndex(count: number): 0 | 1 | 2 {
  if (!Number.isSafeInteger(count) || count < 0) throw new RangeError('Invalid count')
  return count === 0 ? 0 : count === 1 ? 1 : 2
}
