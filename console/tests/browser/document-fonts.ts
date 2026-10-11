import type { Locator, selectors as PlaywrightSelectors } from '@playwright/test'
import { createDocumentFontEngine, parseDocumentFontReport } from '../helpers/document-fonts.ts'

export async function registerDocumentFonts(
  selectors: Pick<typeof PlaywrightSelectors, 'register'>,
) {
  await selectors.register('document-fonts', createDocumentFontEngine, { contentScript: true })
}

let sequence = 0

interface FontPage {
  locator(selector: string): Pick<Locator, 'getAttribute'>
}

async function read(page: FontPage, mode: 'settle' | 'qualify') {
  // A fresh selector starts one operation. Locator polling only observes that operation.
  return page
    .locator(`document-fonts=${mode}:${String(++sequence)}`)
    .getAttribute('data-document-fonts', { timeout: 5000 })
}

export async function settleDocumentFonts(page: FontPage): Promise<boolean> {
  const value = await read(page, 'settle')
  if (value !== 'true' && value !== 'false') throw new Error('Invalid document font readiness')
  return value === 'true'
}

export async function qualifyDocumentFonts(page: FontPage) {
  return parseDocumentFontReport(await read(page, 'qualify'))
}
