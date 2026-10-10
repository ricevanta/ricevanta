import { defineConfig, devices } from '@playwright/test'
export default defineConfig({
  testDir: 'tests/browser',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 30000,
  expect: { timeout: 5000 },
  reporter: [['list'], ['./scripts/csp-reporter.ts']],
  use: { baseURL: 'http://127.0.0.1:4173', headless: true, bypassCSP: false },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: {
    command: 'node scripts/serve-dist.ts --probes',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    timeout: 10000,
  },
})
