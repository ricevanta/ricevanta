import { ref } from 'vue'
import { defineStore } from 'pinia'
import { selectLocale } from '../app/locale.ts'
import type { Locale, Theme, Density } from '../app/locale.ts'
export interface Preferences {
  locale?: Locale
  theme: Theme
  density: Density
}
export const preferenceKey = 'rv.preferences.v1'
const defaults = (): Readonly<Preferences> => ({ theme: 'system', density: 'comfortable' })
export function readPreferences(raw: string | null): Readonly<Preferences> {
  if (raw === null || raw.length > 1024) return defaults()
  try {
    const input: unknown = JSON.parse(raw)
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return defaults()
    const value = input as Record<string, unknown>
    if (Object.keys(value).some((key) => !['locale', 'theme', 'density'].includes(key)))
      return defaults()
    if ('locale' in value && value['locale'] !== 'en' && value['locale'] !== 'vi') return defaults()
    if (
      'theme' in value &&
      value['theme'] !== 'light' &&
      value['theme'] !== 'dark' &&
      value['theme'] !== 'system'
    )
      return defaults()
    if ('density' in value && value['density'] !== 'comfortable' && value['density'] !== 'compact')
      return defaults()
    const output: Preferences = {
      theme: value['theme'] === 'light' || value['theme'] === 'dark' ? value['theme'] : 'system',
      density: value['density'] === 'compact' ? 'compact' : 'comfortable',
    }
    if (value['locale'] === 'en' || value['locale'] === 'vi') output.locale = value['locale']
    return output
  } catch {
    return defaults()
  }
}
export function loadPreferences(storage: Pick<Storage, 'getItem'>): Readonly<Preferences> {
  try {
    return readPreferences(storage.getItem(preferenceKey))
  } catch {
    return defaults()
  }
}
export function savePreferences(
  storage: Pick<Storage, 'setItem'>,
  value: Readonly<Preferences>,
): void {
  try {
    storage.setItem(preferenceKey, JSON.stringify(value))
  } catch {
    /* Denied storage leaves in-memory preferences usable. */
  }
}
export const usePreferences = defineStore('preferences', () => {
  const locale = ref<Locale>('en')
  const theme = ref<Theme>('system')
  const density = ref<Density>('comfortable')
  let storage: Pick<Storage, 'getItem' | 'setItem'> | undefined
  function initialize(
    input: Pick<Storage, 'getItem' | 'setItem'> | undefined,
    languages: readonly string[],
  ): void {
    storage = input
    const saved = input ? loadPreferences(input) : defaults()
    locale.value = selectLocale(saved.locale, languages)
    theme.value = saved.theme
    density.value = saved.density
  }
  function persist(): void {
    if (storage)
      savePreferences(storage, { locale: locale.value, theme: theme.value, density: density.value })
  }
  function setLocale(value: Locale): void {
    locale.value = value
    persist()
  }
  function setTheme(value: Theme): void {
    theme.value = value
    persist()
  }
  function setDensity(value: Density): void {
    density.value = value
    persist()
  }
  return { locale, theme, density, initialize, setLocale, setTheme, setDensity }
})
