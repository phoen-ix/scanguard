import { defineConfig, devices } from '@playwright/test'

/* The console e2e suite (./tests); e2e/COVERAGE.md maps every console feature
 * to its test.
 *
 *   npx playwright test
 *
 * It needs the examples/ harness running (scripts/e2e.sh starts one, runs
 * this, and tears it down). One worker: every test shares the harness's one
 * scanguard runtime, and the rule-editor tests change it for everybody while
 * they run. Tests own their data through unique source addresses. */
export default defineConfig({
  testDir: './tests',
  globalSetup: './tests/global-setup.ts',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    ...devices['Desktop Chrome'],
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:9900',
    viewport: { width: 1280, height: 800 },
    locale: 'en-GB',
    timezoneId: 'Europe/Vienna',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
})
