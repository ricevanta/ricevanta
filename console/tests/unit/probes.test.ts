import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  expectedHeader,
  probes,
  probeExpectation,
  verifyBehavior,
  verifyHeaderIntegrity,
  verifyRefusal,
  verifyException,
  verifyContent,
} from '../browser/verify-probe.ts'
import type { ProbeObservation } from '../browser/verify-probe.ts'
import { csp, serveFile } from '../../scripts/serve-dist.ts'
import { expect, it } from 'vitest'
import { existsSync } from 'node:fs'
it('fails the CSP gate when a test is skipped or an engine is missing', async () => {
  expect(existsSync('scripts/csp-reporter.ts')).toBe(true)
  if (!existsSync('scripts/csp-reporter.ts')) return
  const { acceptedResults } = await import('../../scripts/csp-reporter.ts')
  expect(acceptedResults(['chromium', 'firefox', 'webkit'], ['passed', 'passed'])).toBe(true)
  expect(acceptedResults(['chromium', 'firefox'], ['passed'])).toBe(false)
  expect(acceptedResults(['chromium', 'firefox', 'webkit'], ['skipped'])).toBe(false)
})

const fileHeader = readFileSync('security/csp.txt', 'utf8').replace(/\n$/, '')
for (const engine of ['chromium', 'firefox', 'webkit']) {
  it(`${engine}: selects exact constructor expectations and rejects unknown engines`, () => {
    expect(probeExpectation('raw-function', engine).directive).toBe('require-trusted-types-for')
    expect(probeExpectation('trusted-function', engine).directive).toBe(
      engine === 'chromium' ? 'require-trusted-types-for' : 'script-src',
    )
    expect(() => probeExpectation('trusted-function', 'unknown')).toThrow('Unknown engine')
  })
  for (const [name] of probes) {
    const expected = probeExpectation(name, engine)
    const observed: ProbeObservation = {
      header: fileHeader,
      reportOnly: undefined,
      done: 'yes',
      outcome: 'blocked',
      exception: expected.exception,
      events: [expected.directive],
      content: name === 'html' ? '' : null,
      functionReturned: name.includes('function') ? 'no' : null,
    }
    const behavior = (result: ProbeObservation) => {
      verifyBehavior(result, expected)
    }
    const integrity = (result: ProbeObservation) => {
      verifyHeaderIntegrity(result, fileHeader, expectedHeader)
    }
    it(`${engine}/${name}: identifies each independent behavior rejection`, () => {
      expect(() => {
        integrity(observed)
      }).not.toThrow()
      expect(() => {
        behavior(observed)
      }).not.toThrow()
      expect(() => {
        behavior({ ...observed, events: [...observed.events, ...observed.events] })
      }).not.toThrow()
      expect(() => {
        behavior({ ...observed, header: undefined })
      }).not.toThrow()
      expect(() => {
        behavior({ ...observed, done: null })
      }).toThrow('ProbeCompletionError')
      expect(() => {
        behavior({ ...observed, outcome: 'succeeded' })
      }).toThrow('ProbeOutcomeError')
      expect(() => {
        behavior({ ...observed, exception: 'Error' })
      }).toThrow('ProbeExceptionError')
      expect(() => {
        behavior({ ...observed, events: [] })
      }).toThrow('ProbeDirectiveError')
      expect(() => {
        behavior({ ...observed, events: ['wrong-directive'] })
      }).toThrow('ProbeDirectiveError')
      expect(() => {
        behavior({ ...observed, events: [expected.directive, 'wrong-directive'] })
      }).toThrow('ProbeDirectiveError')
      if (name === 'html')
        expect(() => {
          behavior({ ...observed, content: 'probe' })
        }).toThrow('ProbeContentError')
      if (name.includes('function'))
        expect(() => {
          behavior({ ...observed, functionReturned: 'yes' })
        }).toThrow('ProbeFunctionReturnedError')
    })
    it(`${engine}/${name}: missing header is a header-integrity case`, () => {
      expect(() => {
        integrity({ ...observed, header: undefined })
      }).toThrow('CspHeaderIntegrityError')
      expect(() => {
        verifyHeaderIntegrity(observed, 'changed file', expectedHeader)
      }).toThrow('CspHeaderIntegrityError')
      expect(() => {
        verifyHeaderIntegrity(observed, fileHeader, 'changed literal')
      }).toThrow('CspHeaderIntegrityError')
      expect(() => {
        integrity({ ...observed, reportOnly: fileHeader })
      }).toThrow('CspReportOnlyError')
    })
    it(`${engine}/${name}: discarding events rejects only the required directive`, () => {
      const mutation = { ...observed, events: [] }
      expect(mutation.done).toBe('yes')
      expect(() => {
        integrity(mutation)
      }).not.toThrow()
      expect(() => {
        verifyRefusal(mutation, expected)
      }).not.toThrow()
      expect(() => {
        behavior(mutation)
      }).toThrow('ProbeDirectiveError')
    })
    const removed = expected.removedDirective
    const header = fileHeader
      .split('; ')
      .filter((part) => part.split(' ')[0] !== removed)
      .join('; ')
    if (removed === 'script-src' || removed === 'style-src') {
      it(`${engine}/${name}: removing ${removed} is a header-integrity case`, () => {
        const mutation = {
          ...observed,
          header,
          done: null,
          outcome: null,
          exception: null,
          events: [],
        }
        expect(() => {
          integrity(mutation)
        }).toThrow('CspHeaderIntegrityError')
      })
    } else {
      it(`${engine}/${name}: removing ${removed} rejects the mutation behavior independently`, () => {
        const isFunction = name.includes('function')
        const mutation = {
          ...observed,
          header,
          outcome: isFunction ? 'blocked' : 'succeeded',
          exception: isFunction ? 'EvalError' : '',
          events: isFunction ? ['script-src'] : [],
          content: name === 'html' ? 'probe' : observed.content,
        }
        expect(mutation.done).toBe('yes')
        expect(() => {
          integrity(mutation)
        }).toThrow('CspHeaderIntegrityError')
        if (isFunction) {
          expect(() => {
            verifyRefusal(mutation, expected)
          }).not.toThrow()
          expect(() => {
            behavior(mutation)
          }).toThrow('ProbeDirectiveError')
        } else {
          expect(mutation.outcome).toBe('succeeded')
          expect(() => {
            behavior(mutation)
          }).toThrow('ProbeOutcomeError')
          expect(() => {
            verifyException(mutation.exception, expected.exception)
          }).toThrow('ProbeExceptionError')
          if (name === 'html')
            expect(() => {
              verifyContent(mutation.content)
            }).toThrow('ProbeContentError')
        }
      })
    }
  }
}
it.each([
  '/__test__/inline-script-protected.html',
  '/__test__/mutations/script-src/inline-script-protected.html',
  '/__test__/mutations/style-src/inline-script-protected.html',
  '/__test__/mutations/require-trusted-types-for/inline-script-protected.html',
  '/__test__/mutations/trusted-types/inline-script-protected.html',
  '/__test__/mutations/missing-header/inline-script-protected.html',
])('rejects %s with probe mode off even when the probe file exists', (url) => {
  const root = mkdtempSync(join(tmpdir(), 'rv-probes-disabled-'))
  try {
    mkdirSync(join(root, '__test__'))
    writeFileSync(
      join(root, '__test__/inline-script-protected.html'),
      readFileSync('tests/fixtures/csp/inline-script-protected.html'),
    )
    expect(
      serveFile(root, {
        url,
        method: 'GET',
        host: '127.0.0.1:4173',
        accept: 'text/html',
        encoding: '',
      }).status,
    ).toBe(404)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
it('serves only probe-mode mutations and removes exactly one header directive', () => {
  const root = mkdtempSync(join(tmpdir(), 'rv-probe-mutations-'))
  const request = {
    url: '/',
    method: 'GET',
    host: '127.0.0.1:4173',
    accept: 'text/html',
    encoding: '',
  }
  try {
    writeFileSync(join(root, 'index.html'), 'production')
    mkdirSync(join(root, '.vite'))
    writeFileSync(
      join(root, '.vite/manifest.json'),
      JSON.stringify({ entry: { file: 'assets/entry.js', isEntry: true } }),
    )
    const fixtureRoot = resolve('tests/fixtures/csp')
    for (const mutation of [
      'script-src',
      'style-src',
      'require-trusted-types-for',
      'trusted-types',
      'missing-header',
    ]) {
      const url = `/__test__/mutations/${mutation}/inline-script-protected.html`
      const result = serveFile(root, { ...request, url }, fixtureRoot)
      expect(result.status).toBe(200)
      expect(result.body.toString()).toContain('data-probe="inline-script"')
      expect(result.headers['Content-Security-Policy']).toBe(
        mutation === 'missing-header'
          ? undefined
          : csp
              .split('; ')
              .filter((part) => part.split(' ')[0] !== mutation)
              .join('; '),
      )
      const original = serveFile(
        root,
        { ...request, url: '/__test__/inline-script-protected.html' },
        fixtureRoot,
      )
      expect(original.headers['Content-Security-Policy']).toBe(csp)
      expect(serveFile(root, request, fixtureRoot).headers['Content-Security-Policy']).toBe(csp)
    }
    for (const suffix of [
      'unknown/inline-script-protected.html',
      'script-src/inline-script-control.html',
      'script-src/index.html',
    ]) {
      expect(
        serveFile(root, { ...request, url: `/__test__/mutations/${suffix}` }, fixtureRoot).status,
      ).toBe(404)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
