import type en from '../locales/en.json'
import type { Density, Locale, Theme } from './locale.ts'
type Leaves<T> = {
  [K in keyof T & string]: T[K] extends string ? K : `${K}.${Leaves<T[K]>}`
}[keyof T & string]
export type MessageKey = Leaves<typeof en>
export type CountKey = Extract<MessageKey, `${string}Count`>
export const routeTitles = {
  home: 'home.title',
  'not-found': 'notFound.title',
} as const satisfies Record<string, MessageKey>
export const localeOptions = [
  { value: 'en', key: 'preferences.english' },
  { value: 'vi', key: 'preferences.vietnamese' },
] as const satisfies readonly { value: Locale; key: MessageKey }[]
export const themeOptions = [
  { value: 'light', key: 'preferences.light' },
  { value: 'dark', key: 'preferences.dark' },
  { value: 'system', key: 'preferences.system' },
] as const satisfies readonly { value: Theme; key: MessageKey }[]
export const densityOptions = [
  { value: 'comfortable', key: 'preferences.comfortable' },
  { value: 'compact', key: 'preferences.compact' },
] as const satisfies readonly { value: Density; key: MessageKey }[]
