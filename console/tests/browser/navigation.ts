import type { Locator, Page } from '@playwright/test'

export async function clickAndWaitForURL(
  page: Pick<Page, 'waitForURL'>,
  link: Pick<Locator, 'click'>,
  url: string,
): Promise<void> {
  await link.click()
  await page.waitForURL(url)
}
