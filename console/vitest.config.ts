import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'
import AxeBuilder from '@axe-core/playwright'
import { defineBrowserCommand, PlaywrightBrowserProvider } from '@vitest/browser-playwright'
import { playwright } from '@vitest/browser-playwright'
import foundationConfig from './vite.config.ts'
export default defineConfig({
  cacheDir: fileURLToPath(new URL('./.vite/cache', import.meta.url)),
  test: {
    projects: [
      {
        cacheDir: fileURLToPath(new URL('./.vite/cache', import.meta.url)),
        test: {
          name: 'unit',
          include: ['tests/unit/**/*.test.ts'],
          environment: 'node',
          maxWorkers: 2,
        },
      },
      {
        ...foundationConfig,
        cacheDir: fileURLToPath(new URL('./.vite/cache', import.meta.url)),
        test: {
          name: 'component',
          setupFiles: ['tests/component/setup.ts'],
          include: ['tests/component/**/*.test.ts'],
          maxWorkers: 2,
          browser: {
            commands: {
              axeScan: defineBrowserCommand(async (context) => {
                if (!(context.provider instanceof PlaywrightBrowserProvider))
                  throw new Error('Expected Playwright provider')
                const results = await new AxeBuilder({
                  page: context.provider.getPage(context.sessionId),
                })
                  .include(['iframe', '#app-test'])
                  .options({ rules: { 'target-size': { enabled: true } } })
                  .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
                  .analyze()
                return results.violations.map((value) => value.id)
              }),
            },
            enabled: true,
            headless: true,
            screenshotFailures: true,
            screenshotDirectory: 'test-results/vitest',
            trace: { mode: 'retain-on-failure', tracesDir: 'test-results/vitest-traces' },
            provider: playwright(),
            instances: [{ browser: 'chromium' }],
          },
        },
      },
    ],
  },
})
