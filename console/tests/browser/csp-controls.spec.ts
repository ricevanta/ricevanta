import type { Page, Response } from '@playwright/test'
import { setTimeout } from 'node:timers/promises'
import { readFileSync } from 'node:fs'
import {
  probes,
  probeExpectation,
  verifyHeaderIntegrity,
  verifyBehavior,
  verifyRefusal,
  verifyException,
  verifyContent,
  expectedHeader,
} from './verify-probe.ts'
import type { ProbeObservation } from './verify-probe.ts'
import { test, expect, assertHeader } from './fixtures.ts'

const fileHeader = readFileSync('security/csp.txt', 'utf8').replace(/\n$/, '')
async function observe(
  page: Page,
  response: Response | null,
  violations: readonly string[],
  waitForEvents: boolean,
  waitForResult = true,
): Promise<ProbeObservation> {
  expect(response?.status()).toBe(200)
  const headers = await response?.allHeaders()
  const result = page.locator('#result')
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    if (
      (!waitForResult || (await result.getAttribute('data-done')) === 'yes') &&
      (!waitForEvents || violations.length > 0)
    )
      break
    await setTimeout(25)
  }
  return {
    header: headers?.['content-security-policy'],
    reportOnly: headers?.['content-security-policy-report-only'],
    done: await result.getAttribute('data-done'),
    outcome: await result.getAttribute('data-outcome'),
    exception: await result.getAttribute('data-exception'),
    events: [...violations],
    content: await result.getAttribute('data-content'),
    functionReturned: await result.getAttribute('data-function-returned'),
  }
}

for (const [name] of probes) {
  test.describe(name, () => {
    test('policy-free control succeeds', async ({ page, violations }, testInfo) => {
      // Resolve the configured engine before navigation, including policy-free controls.
      probeExpectation(name, testInfo.project.name)
      const response = await page.goto(`/__test__/${name}-control.html`)
      expect(response?.headers()['content-security-policy']).toBeUndefined()
      await expect(page.locator('#result')).toHaveAttribute('data-done', 'yes')
      await expect(page.locator('#result')).toHaveAttribute('data-outcome', 'succeeded')
      expect(violations).toEqual([])
      expect(() => {
        assertHeader(response?.headers()['content-security-policy'])
      }).toThrow()
    })
    test('protected operation rejects with the configured directive', async ({
      page,
      browser,
      violations,
    }, testInfo) => {
      const expected = probeExpectation(name, testInfo.project.name)
      const response = await page.goto(`/__test__/${name}-protected.html`)
      const observed = await observe(page, response, violations, true)
      const diagnostics = await page.evaluate(() => {
        const events: unknown = Reflect.get(window, 'cspDiagnostics')
        const result = document.querySelector<HTMLElement>('#result')
        return {
          events,
          probeOrder: result?.dataset['probeOrder'],
          exceptionMessage: result?.dataset['exceptionMessage'],
        }
      })
      expect(
        () => {
          verifyHeaderIntegrity(observed, fileHeader, expectedHeader)
          verifyBehavior(observed, expected)
        },
        `${name} in ${testInfo.project.name} ${browser.version()}: expected ${expected.directive}, observed ${JSON.stringify(observed)}, diagnostics ${JSON.stringify(diagnostics)}`,
      ).not.toThrow()
    })
    test('missing header is a header-integrity case', async ({ page, violations }, testInfo) => {
      probeExpectation(name, testInfo.project.name)
      const response = await page.goto(`/__test__/mutations/missing-header/${name}-protected.html`)
      const observed = await observe(page, response, violations, false, false)
      expect(observed.header).toBeUndefined()
      expect(() => {
        verifyHeaderIntegrity(observed, fileHeader, expectedHeader)
      }).toThrow('CspHeaderIntegrityError')
    })
    const mutationLabel =
      name === 'trusted-function'
        ? 'header-integrity case in Firefox/WebKit, executable mutation in Chromium'
        : name.startsWith('inline-')
          ? 'header-integrity case'
          : 'executable mutation'
    test(`${mutationLabel}: remove the configured directive`, async ({
      page,
      violations,
    }, testInfo) => {
      const expected = probeExpectation(name, testInfo.project.name)
      const removed = expected.removedDirective
      const sourceIntegrity = removed === 'script-src' || removed === 'style-src'
      const response = await page.goto(`/__test__/mutations/${removed}/${name}-protected.html`)
      const observed = await observe(page, response, violations, !sourceIntegrity, !sourceIntegrity)
      const mutatedHeader = fileHeader
        .split('; ')
        .filter((part) => part.split(' ')[0] !== removed)
        .join('; ')
      if (!sourceIntegrity) expect(observed.done).toBe('yes')
      expect(observed.header).toBe(mutatedHeader)
      expect(() => {
        verifyHeaderIntegrity(observed, fileHeader, expectedHeader)
      }).toThrow('CspHeaderIntegrityError')
      if (sourceIntegrity) return
      if (name.includes('function')) {
        expect(observed.outcome).toBe('blocked')
        expect(observed.exception).toBe('EvalError')
        expect(observed.functionReturned).toBe('no')
        expect(() => {
          verifyRefusal(observed, expected)
        }).not.toThrow()
        expect(observed.events).toContain('script-src')
        expect(() => {
          verifyBehavior(observed, expected)
        }).toThrow('ProbeDirectiveError')
      } else {
        expect(observed.outcome).toBe('succeeded')
        expect(observed.exception).toBe('')
        expect(() => {
          verifyBehavior(observed, expected)
        }).toThrow('ProbeOutcomeError')
        expect(() => {
          verifyException(observed.exception, expected.exception)
        }).toThrow('ProbeExceptionError')
        if (name === 'html') {
          expect(observed.content).toBe('probe')
          expect(() => {
            verifyContent(observed.content)
          }).toThrow('ProbeContentError')
        }
      }
    })
    test.describe('event-discarding mutation', () => {
      test.use({ discardCspEvents: true })
      test('rejects only the required-event assertion with the unchanged header', async ({
        page,
        violations,
      }, testInfo) => {
        const expected = probeExpectation(name, testInfo.project.name)
        const response = await page.goto(`/__test__/${name}-protected.html`)
        const observed = await observe(page, response, violations, true)
        expect(() => {
          verifyHeaderIntegrity(observed, fileHeader, expectedHeader)
        }).not.toThrow()
        expect(observed.done).toBe('yes')
        expect(observed.outcome).toBe('blocked')
        expect(observed.exception).toBe(expected.exception)
        expect(() => {
          verifyRefusal(observed, expected)
        }).not.toThrow()
        expect(observed.events).toEqual([])
        expect(() => {
          verifyBehavior(observed, expected)
        }).toThrow('ProbeDirectiveError')
      })
    })
  })
}
