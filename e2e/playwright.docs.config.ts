import { defineConfig, devices } from '@playwright/test'

/* The docs tour (./docs): screenshots of the console for the README and
 * docs/screenshots/README.md, and a render check of every state it visits.
 *
 *   npx playwright test -c playwright.docs.config.ts
 *
 * It needs the examples/ harness running with scanner-sim.sh's bans in it;
 * scripts/docs-screenshots.sh does all of that. PNGs land in
 * ../docs/screenshots (DOCS_SCREENSHOT_DIR overrides). */
export default defineConfig({
  testDir: './docs',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  use: {
    ...devices['Desktop Chrome'],
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:9900',
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 2,
    locale: 'en-GB',
    launchOptions: {
      args: ['--lang=en-GB'],
      env: { ...process.env, LANG: 'en_GB.UTF-8', LANGUAGE: 'en_GB:en', LC_ALL: 'en_GB.UTF-8' },
    },
    timezoneId: 'Europe/Vienna',
    colorScheme: 'light',
    contextOptions: { reducedMotion: 'reduce' },
    screenshot: 'only-on-failure',
    trace: 'off',
  },
})
