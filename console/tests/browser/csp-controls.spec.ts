import type { Page, Response } from '@playwright/test'
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
import { test, expect, assertHeader, readCspEvents } from './fixtures.ts'
import { observeProbe } from '../helpers/probe-observation.ts'

const fileHeader = readFileSync('security/csp.txt', 'utf8').replace(/\n$/, '')
async function observe(
  page: Page,
  response: Response | null,
  waitForEvents: boolean,
  waitForResult = true,
): Promise<ProbeObservation> {
  expect(response?.status()).toBe(200)
  const headers = await response?.allHeaders()
  return {
    header: headers?.['content-security-policy'],
    reportOnly: headers?.['content-security-policy-report-only'],
    ...(await observeProbe(
      page.locator('#result'),
      (deadline) => readCspEvents(page, deadline),
      waitForEvents,
      waitForResult,
    )),
  }
}

for (const [name] of probes) {
  test.describe(name, () => {
    test('policy-free control succeeds', async ({ page }, testInfo) => {
      // Resolve the configured engine before navigation, including policy-free controls.
      probeExpectation(name, testInfo.project.name)
      const response = await page.goto(`/__test__/${name}-control.html`)
      await observe(page, response, false)
      expect(response?.headers()['content-security-policy']).toBeUndefined()
      await expect(page.locator('#result')).toHaveAttribute('data-done', 'yes')
      await expect(page.locator('#result')).toHaveAttribute('data-outcome', 'succeeded')
      expect(await readCspEvents(page)).toEqual([])
      expect(() => {
        assertHeader(response?.headers()['content-security-policy'])
      }).toThrow()
    })
    test('protected operation rejects with the configured directive', async ({
      page,
      browser,
    }, testInfo) => {
      const expected = probeExpectation(name, testInfo.project.name)
      const response = await page.goto(`/__test__/${name}-protected.html`)
      const observed = await observe(page, response, true)
      const diagnostics = {
        probeOrder: await page.locator('#result').getAttribute('data-probe-order'),
        exceptionMessage: await page.locator('#result').getAttribute('data-exception-message'),
      }
      expect(
        () => {
          verifyHeaderIntegrity(observed, fileHeader, expectedHeader)
          verifyBehavior(observed, expected)
        },
        `${name} in ${testInfo.project.name} ${browser.version()}: expected ${expected.directive}, observed ${JSON.stringify(observed)}, diagnostics ${JSON.stringify(diagnostics)}`,
      ).not.toThrow()
    })
    test('missing header is a header-integrity case', async ({ page }, testInfo) => {
      probeExpectation(name, testInfo.project.name)
      const response = await page.goto(`/__test__/mutations/missing-header/${name}-protected.html`)
      const observed = await observe(page, response, false, false)
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
    test(`${mutationLabel}: remove the configured directive`, async ({ page }, testInfo) => {
      const expected = probeExpectation(name, testInfo.project.name)
      const removed = expected.removedDirective
      const sourceIntegrity = removed === 'script-src' || removed === 'style-src'
      const response = await page.goto(`/__test__/mutations/${removed}/${name}-protected.html`)
      const observed = await observe(page, response, !sourceIntegrity, !sourceIntegrity)
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
      }, testInfo) => {
        const expected = probeExpectation(name, testInfo.project.name)
        const response = await page.goto(`/__test__/${name}-protected.html`)
        const observed = await observe(page, response, true)
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
