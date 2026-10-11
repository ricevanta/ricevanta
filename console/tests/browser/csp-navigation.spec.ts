import { test, expect, assertHeader } from './fixtures.ts'

test('preserves CSP evidence through Playwright document history', async ({
  page,
  violations,
  errors,
}) => {
  const home = await page.goto('/')
  assertHeader(home?.headers()['content-security-policy'])
  await expect(page.locator('h1')).toHaveText('Home')
  expect(await violations()).toEqual([])
  const other = await page.goto('/history-target')
  assertHeader(other?.headers()['content-security-policy'])
  await expect(page.locator('h1')).toHaveCount(1)
  expect(await violations()).toEqual([])
  await page.goBack()
  await expect(page).toHaveURL('/')
  await expect(page.locator('h1')).toHaveText('Home')
  expect(await violations()).toEqual([])
  await page.goForward()
  await expect(page).toHaveURL('/history-target')
  await expect(page.locator('h1')).toHaveCount(1)
  expect(await violations()).toEqual([])
  await page.goBack()
  await expect(page).toHaveURL('/')
  expect(await violations()).toEqual([])
  expect(errors).toEqual([])
})

for (const method of ['replace', 'assign', 'reload', 'meta', 'back', 'form']) {
  test(`rejects CSP evidence after page-driven ${method}`, async ({ page, violations }) => {
    if (method === 'back') await page.goto('/__test__/policy-control.html')
    // Form submission needs the policy-free control because form-action denies it otherwise.
    const control = method === 'form'
    const response = await page.goto(
      `/__test__/page-navigation-${control ? 'control' : 'protected'}.html`,
    )
    if (control) expect(response?.headers()['content-security-policy']).toBeUndefined()
    else assertHeader(response?.headers()['content-security-policy'])
    await expect(page.locator('#result')).toHaveAttribute('data-done', 'yes')
    await expect(page.locator('#result')).toHaveAttribute(
      'data-outcome',
      control ? 'succeeded' : 'blocked',
    )
    await expect(page.locator('#result')).toHaveAttribute(
      'data-exception',
      control ? '' : 'TypeError',
    )
    const committed = page.waitForEvent('framenavigated', {
      predicate: (frame) => frame === page.mainFrame(),
      timeout: 5000,
    })
    await page.getByRole('button', { name: method, exact: true }).click()
    await committed
    await expect(page.locator('#result')).toHaveAttribute('data-done', 'yes')
    const reading = (async () => await violations())()
    await expect(reading).rejects.toThrow(
      /ProbeCspRecordError: (Unchecked document transition|Invalidated document evidence)/,
    )
  })
}
