import { createI18n } from 'vue-i18n'
import en from '../locales/en.json'
import vi from '../locales/vi.json'
import { pluralIndex } from './locale.ts'
import type { CountKey, MessageKey } from './keys.ts'
export const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: { en, vi },
  pluralRules: { en: pluralIndex, vi: pluralIndex },
})
export function t(key: MessageKey): string {
  return i18n.global.t(key)
}
export function translateCount(key: CountKey, count: number): string {
  pluralIndex(count)
  return i18n.global.t(key, { count }, count)
}
