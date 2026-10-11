import { afterEach, expect, it, vi } from 'vitest'
import { settleDocumentFonts } from '../helpers/document-fonts.ts'

afterEach(() => vi.unstubAllGlobals())

it('settles each matrix document without loading unused font subsets', async () => {
  let unusedLoads = 0
  const faces = Array.from({ length: 12 }, () => ({
    family: '"Be Vietnam Pro"',
    load: () => {
      unusedLoads++
      return Promise.resolve()
    },
  }))
  const fonts = Object.assign(faces, { ready: Promise.resolve() })
  vi.stubGlobal('document', { body: { getBoundingClientRect: () => ({}) }, fonts })

  // Initial document, twelve matrix documents, private route and reload.
  for (let document = 0; document < 15; document++) await settleDocumentFonts()
  expect(unusedLoads).toBe(0)
})

it('waits for font readiness created by flushing layout before navigation', async () => {
  let finish = () => {}
  const ready = new Promise<void>((resolve) => {
    finish = resolve
  })
  const fonts = Object.assign([], { ready: Promise.resolve() })
  vi.stubGlobal('document', {
    body: {
      getBoundingClientRect: () => {
        fonts.ready = ready
        return {}
      },
    },
    fonts,
  })
  let navigated = false
  const navigation = settleDocumentFonts().then(() => {
    navigated = true
  })
  // Let the helper's promise chain settle before checking that navigation is blocked.
  await new Promise<void>((resolve) => setTimeout(resolve, 0))
  expect(navigated).toBe(false)
  finish()
  await navigation
  expect(navigated).toBe(true)
})
