import { test, expect, assertHeader } from './fixtures.ts'
test('refuses reserved paths and serves cache and MIME contracts', async ({ request }) => {
  for (const path of [
    '/api/missing',
    '/agent/a',
    '/ext/a',
    '/assets/missing',
    '/brand/missing',
    '/mdm/a',
    '/scep',
    '/acme/a',
    '/__test__/missing',
  ])
    expect((await request.get(path, { headers: { Accept: 'text/html' } })).status()).toBe(404)
  const shell = await request.get('/unknown', { headers: { Accept: 'text/html' } })
  expect(shell.status()).toBe(200)
  assertHeader(shell.headers()['content-security-policy'])
  expect(shell.headers()['cache-control']).toBe('no-cache')
  const brand = await request.get('/brand/favicon.svg')
  expect(brand.headers()['content-type']).toBe('image/svg+xml; charset=utf-8')
  expect(brand.headers()['cache-control']).toBe('public, max-age=86400')
  expect((await request.post('/')).status()).toBe(405)
  expect((await request.get('/', { headers: { Host: 'evil.test' } })).status()).toBe(400)
})
