import { expect, it } from 'vitest'
import { baseCompile } from '@intlify/message-compiler'
import { createI18n } from 'vue-i18n'
import { pluralIndex } from '../../src/app/locale.ts'
it.each(['en', 'vi'])('renders the synthetic count catalogue in %s', (locale) => {
  const message =
    locale === 'en'
      ? '{count} items | {count} item | {count} items'
      : '{count} mục | {count} mục | {count} mục'
  const ast = baseCompile(message).ast
  const i18n = createI18n({
    legacy: false,
    locale,
    messages: { [locale]: { home: { itemCount: ast } } },
    pluralRules: { en: pluralIndex, vi: pluralIndex },
  })
  for (const count of [0, 1, 2, 10])
    expect(i18n.global.t('home.itemCount', { count }, count)).toBe(
      locale === 'en'
        ? `${String(count)} ${count === 1 ? 'item' : 'items'}`
        : `${String(count)} mục`,
    )
})
