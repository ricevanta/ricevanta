import { test, expect, assertHeader } from './fixtures.ts'
import { clickAndWaitForURL } from './navigation.ts'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { normalizeUnicodeRange, packageFontFaces } from '../helpers/fonts.ts'
import type { Page } from '@playwright/test'
const require = createRequire(import.meta.url)
const expectedFontFaces = packageFontFaces()

async function loadDocumentFonts(page: Page): Promise<void> {
  await page.evaluate(async () => {
    // Flush layout and settle CSS font loads before explicitly loading unused subsets.
    document.body.getBoundingClientRect()
    await document.fonts.ready
    for (const face of document.fonts)
      if (face.family.replace(/["']/g, '').trim() === 'Be Vietnam Pro') await face.load()
    await document.fonts.ready
  })
}

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
    const response = await page.goto('/')
    await loadDocumentFonts(page)
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
          const dark = await page
            .locator('html')
            .evaluate((el) => getComputedStyle(el).getPropertyValue('--rv-color-page').trim())
          expect(dark.toUpperCase()).toBe(theme === 'light' ? '#F6F2E7' : '#0F1E2B')
          await page.emulateMedia({ colorScheme: 'light' })
          const light = await page
            .locator('html')
            .evaluate((el) => getComputedStyle(el).getPropertyValue('--rv-color-page').trim())
          expect(light.toUpperCase()).toBe(theme === 'dark' ? '#0F1E2B' : '#F6F2E7')
          await expect(page.locator('h1')).toHaveCount(1)
          expect(
            await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          ).toBe(true)
          expect(await page.locator('style,[style],script:not([src])').count()).toBe(0)
          await page.goto('/matrix-unknown')
          await loadDocumentFonts(page)
          await expect(page.locator('h1')).toHaveCount(1)
          await expect(page.locator('h1')).toBeFocused()
          expect(await page.locator('style,[style],script:not([src])').count()).toBe(0)
          await clickAndWaitForURL(page, page.getByRole('navigation').getByRole('link'), '/')
          await expect(page.locator('h1')).toHaveText(locale === 'en' ? 'Home' : 'Trang chủ')
          await expect(page.locator('h1')).toBeFocused()
        }
    await page.goto('/private?token=hidden')
    await loadDocumentFonts(page)
    await expect(page.locator('h1')).toHaveText('Không tìm thấy trang')
    await expect(page.locator('h1')).toBeFocused()
    expect(await page.locator('body').innerText()).not.toMatch(/private|hidden/)
    await page.reload()
    await loadDocumentFonts(page)
    await expect(page.locator('h1')).toBeFocused()
    await clickAndWaitForURL(page, page.getByRole('link', { name: 'Về trang chủ' }), '/')
    await expect(page.locator('h1')).toHaveText('Trang chủ')
    await page.goBack()
    await expect(page.locator('h1')).toHaveText('Không tìm thấy trang')
    await page.goForward()
    await expect(page.locator('h1')).toHaveText('Trang chủ')
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
    const fonts = await page.evaluate(async () => {
      const isVietnamPro = (family: string) =>
        family.replace(/["']/g, '').trim() === 'Be Vietnam Pro'
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
      // Earlier document loads finished before interactions or navigation started.
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
    })
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
    expect(violations, fontDiagnostics).toEqual([])
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
  expect(violations).toEqual([])
})
