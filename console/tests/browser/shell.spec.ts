import { test, expect, assertHeader } from './fixtures.ts'
import { clickAndWaitForURL } from './navigation.ts'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { normalizeUnicodeRange, packageFontFaces } from '../helpers/fonts.ts'
import { settleDocumentFonts, qualifyDocumentFonts } from './document-fonts.ts'
const require = createRequire(import.meta.url)
const expectedFontFaces = packageFontFaces()

test('records actual engine versions and pinned browser revisions', async ({
  browser,
}, testInfo) => {
  const revisions: unknown = JSON.parse(
    readFileSync(
      resolve(dirname(require.resolve('playwright-core/package.json')), 'browsers.json'),
      'utf8',
    ),
  )
  await testInfo.attach('browser-version', { body: browser.version(), contentType: 'text/plain' })
  console.log(
    JSON.stringify({ project: testInfo.project.name, version: browser.version(), revisions }),
  )
})
for (const width of [320, 1440])
  test(`shell matrix, history, focus and fonts at ${String(width)}px`, async ({
    page,
    violations,
    errors,
  }) => {
    const fontResponses = new Set<string>()
    page.on('response', (response) => {
      if (response.request().resourceType() === 'font' && response.ok())
        fontResponses.add(response.url())
    })
    await page.setViewportSize({ width, height: 900 })
    const response = await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 5000 })
    await expect(page.locator('h1')).toBeFocused()
    await settleDocumentFonts(page)
    assertHeader(response?.headers()['content-security-policy'])
    expect(response?.headers()['content-security-policy-report-only']).toBeUndefined()
    for (const locale of ['en', 'vi'])
      for (const theme of ['light', 'dark', 'system'])
        for (const density of ['comfortable', 'compact']) {
          await page.locator('#language').selectOption(locale)
          await page.locator('#theme').selectOption(theme)
          await page.locator('#density').selectOption(density)
          await expect(page.locator('html')).toHaveAttribute('lang', locale)
          await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
          await expect(page.locator('html')).toHaveAttribute('data-density', density)
          await page.emulateMedia({ colorScheme: 'dark' })
          await expect(page.locator('html')).toHaveCSS(
            '--rv-color-page',
            theme === 'light' ? /^\s*#F6F2E7\s*$/i : /^\s*#0F1E2B\s*$/i,
          )
          await page.emulateMedia({ colorScheme: 'light' })
          await expect(page.locator('html')).toHaveCSS(
            '--rv-color-page',
            theme === 'dark' ? /^\s*#0F1E2B\s*$/i : /^\s*#F6F2E7\s*$/i,
          )
          await expect(page.locator('h1')).toHaveCount(1)
          expect(await settleDocumentFonts(page)).toBe(true)
          expect(await page.locator('style,[style],script:not([src])').count()).toBe(0)
          await settleDocumentFonts(page)
          await page.goto('/matrix-unknown', { waitUntil: 'domcontentloaded', timeout: 5000 })
          await expect(page.locator('h1')).toBeFocused()
          await settleDocumentFonts(page)
          await expect(page.locator('h1')).toHaveCount(1)
          await expect(page.locator('h1')).toBeFocused()
          expect(await page.locator('style,[style],script:not([src])').count()).toBe(0)
          await clickAndWaitForURL(page, page.getByRole('navigation').getByRole('link'), '/')
          await expect(page.locator('h1')).toHaveText(locale === 'en' ? 'Home' : 'Trang chủ')
          await expect(page.locator('h1')).toBeFocused()
        }
    await settleDocumentFonts(page)
    await page.goto('/private?token=hidden', { waitUntil: 'domcontentloaded', timeout: 5000 })
    await expect(page.locator('h1')).toBeFocused()
    await settleDocumentFonts(page)
    await expect(page.locator('h1')).toHaveText('Không tìm thấy trang')
    await expect(page.locator('h1')).toBeFocused()
    expect(await page.locator('body').innerText()).not.toMatch(/private|hidden/)
    await settleDocumentFonts(page)
    await page.reload({ waitUntil: 'domcontentloaded', timeout: 5000 })
    await expect(page.locator('h1')).toBeFocused()
    await settleDocumentFonts(page)
    await expect(page.locator('h1')).toBeFocused()
    await clickAndWaitForURL(page, page.getByRole('link', { name: 'Về trang chủ' }), '/')
    await expect(page.locator('h1')).toHaveText('Trang chủ')
    await settleDocumentFonts(page)
    await page.goBack()
    await expect(page.locator('h1')).toHaveText('Không tìm thấy trang')
    await settleDocumentFonts(page)
    await page.goForward()
    await expect(page.locator('h1')).toHaveText('Trang chủ')
    await settleDocumentFonts(page)
    await page.locator('.skip-link').focus()
    await page.keyboard.press('Enter')
    await expect(page.locator('main')).toBeFocused()
    await page.locator('#theme').focus()
    await page.keyboard.press('ArrowUp')
    await page.keyboard.press('Enter')
    await expect(page.locator('#theme')).toHaveValue('dark')
    await page.locator('#language').focus()
    await page.keyboard.press('ArrowUp')
    await page.keyboard.press('Enter')
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
    await page.locator('#density').focus()
    await page.keyboard.press('ArrowUp')
    await page.keyboard.press('Enter')
    await expect(page.locator('#density')).toHaveValue('comfortable')
    const fonts = await qualifyDocumentFonts(page)
    const fontDiagnostics = JSON.stringify(fonts, null, 2)
    const expectedSubsets = ['400', '500', '600', '700'].flatMap((weight) =>
      ['latin', 'latin-ext', 'vietnamese'].map((subset) => `${weight}:normal:${subset}`),
    )
    expect(fonts.rules, fontDiagnostics).toHaveLength(12)
    expect(fonts.faces, fontDiagnostics).toHaveLength(12)
    const subsets = fonts.rules.map((rule) => {
      const source = rule.sources[0]
      expect(source, fontDiagnostics).toBeDefined()
      const url = new URL(source ?? '')
      expect(url.origin, fontDiagnostics).toBe(fonts.origin)
      expect(url.pathname, fontDiagnostics).toMatch(/^\/assets\/.*\.woff2$/)
      const subset = /be-vietnam-pro-(latin-ext|latin|vietnamese)-(400|500|600|700)-normal/.exec(
        url.pathname,
      )
      expect(subset, fontDiagnostics).not.toBeNull()
      expect(subset?.[2], fontDiagnostics).toBe(rule.weight)
      const expected = expectedFontFaces.find(
        (face) => face.weight === rule.weight && face.subset === subset?.[1],
      )
      expect(normalizeUnicodeRange(rule.unicodeRange), fontDiagnostics).toBe(expected?.unicodeRange)
      expect(fontResponses.has(url.href), fontDiagnostics).toBe(true)
      for (const source of rule.sources)
        expect(new URL(source).origin, fontDiagnostics).toBe(fonts.origin)
      return `${rule.weight}:${rule.style}:${subset?.[1] ?? 'unknown'}`
    })
    expect(subsets.sort(), fontDiagnostics).toEqual(expectedSubsets.sort())
    for (const weight of ['400', '500', '600', '700']) {
      const faces = fonts.faces.filter((face) => face.weight === weight)
      expect(faces, fontDiagnostics).toHaveLength(3)
      expect(
        faces.map((face) => normalizeUnicodeRange(face.unicodeRange)).sort(),
        fontDiagnostics,
      ).toEqual(
        expectedFontFaces
          .filter((face) => face.weight === weight)
          .map((face) => face.unicodeRange)
          .sort(),
      )
      for (const face of faces) {
        expect(face.style, fontDiagnostics).toBe('normal')
        expect(face.resolved, fontDiagnostics).toBe(true)
        expect(face.status, fontDiagnostics).toBe('loaded')
      }
    }
    for (const check of fonts.checks) expect(check.available, fontDiagnostics).toBe(true)
    expect(await violations(), fontDiagnostics).toEqual([])
    expect(errors, fontDiagnostics).toEqual([])
  })
test('chunk failure remains generic until explicit reload', async ({
  page,
  violations,
  errors,
}) => {
  await page.route('**/NotFoundView-*.js', (route) => route.abort('failed'))
  await page.goto('/sensitive?token=private')
  await expect(page.getByRole('button', { name: 'Reload', exact: true })).toBeVisible()
  expect(await page.locator('body').innerText()).not.toMatch(/sensitive|private|NotFoundView/)
  expect(
    errors.every(
      (error) =>
        (error.startsWith('asset:') && /NotFoundView-/.test(error)) ||
        (error.startsWith('console:') &&
          /NotFoundView-/.test(error) &&
          /Failed to load resource|failed|error|module/i.test(error)),
    ),
  ).toBe(true)
  await page.waitForTimeout(250)
  await expect(page.getByRole('button', { name: 'Reload', exact: true })).toBeVisible()
  expect(await violations()).toEqual([])
})
