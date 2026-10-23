import { mkdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect, test, type Locator, type Page } from '@playwright/test'

import { TOKEN, api, seed } from './seed'

/* The docs tour: one screenshot per console state (docs/screenshots/README.md
 * is the gallery). It is also a render check (ci.yml runs it after
 * scanner-sim.sh): every test asserts before it shoots, and a page that throws
 * fails the test.
 *
 * scripts/docs-screenshots.sh runs it twice: `--grep @empty` against the fresh
 * harness, then the rest after scanner-sim.sh. Run as a whole against a
 * harness that already has bans, the empty test skips itself. */

const OUT = path.resolve(
  process.env.DOCS_SCREENSHOT_DIR ?? fileURLToPath(new URL('../../docs/screenshots', import.meta.url)),
)
mkdirSync(OUT, { recursive: true })

/* Determinism: every time the console shows is the server's wall clock, so two
 * runs would differ in every row. The browser gets a fixed clock, and each API
 * response is rewritten onto it: events by sequence number (two seconds
 * apart), tracked sources by rank, bans as created a minute ago with their
 * real duration, the uptime fixed. Nothing else in the responses is touched. */
const NOW = Date.parse('2026-06-15T10:00:00+02:00')
const iso = (ms: number) => new Date(ms).toISOString()

type Json = Record<string, any>
function pin(d: Json): void {
  const last = d.lastSeq ?? 0
  for (const e of d.events ?? []) e.time = iso(NOW - 45_000 - (last - e.seq) * 2_000)
  for (const b of d.bans ?? []) {
    const created = NOW - 60_000
    if (!b.expires.startsWith('0001-')) b.expires = iso(created + Date.parse(b.expires) - Date.parse(b.created))
    b.created = iso(created)
  }
  ;(d.sources ?? []).forEach((s: Json, i: number) => (s.lastSeen = iso(NOW - 45_000 - i * 2_000)))
  if (d.updated) d.updated = iso(NOW - 60_000)
  if (d.uptime) d.uptime = '2h14m9s'
}

let pageErrors: string[] = []

test.beforeEach(async ({ page }) => {
  pageErrors = []
  page.on('pageerror', (e) => pageErrors.push(e.message))
  await page.clock.setFixedTime(NOW)
  await page.route(/\/api\/(state|events|sources|bans|rules)(\?|$)/, async (route) => {
    const res = await route.fetch()
    const body = (await res.json()) as Json
    if (res.ok()) pin(body)
    await route.fulfill({ response: res, json: body })
  })
  // The live-poll dot blinks on every poll; show it at rest. Appended to the
  // console's own stylesheet because its CSP refuses injected styles.
  await page.route('**/app.css', async (route) => {
    const res = await route.fetch()
    await route.fulfill({ response: res, body: `${await res.text()}\n.pulse.on { opacity: 0.35; }\n` })
  })
})

test.afterEach(async ({ page }) => {
  // A poll may still be in flight when the test ends.
  await page.unrouteAll({ behavior: 'ignoreErrors' })
  expect(pageErrors).toEqual([])
})

/** The console, unlocked: the token goes where the gate would store it. */
async function open(page: Page): Promise<void> {
  await page.addInitScript((t) => sessionStorage.setItem('scanguard.token', t), TOKEN)
  await page.goto('/')
  await expect(page.locator('#app')).toBeVisible()
  // The last thing refresh() paints.
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(10)
}

/** Viewport shot, or the box around `els` (capped at 2400 CSS px). */
async function shoot(page: Page, name: string, els: Locator[] = []): Promise<void> {
  await page.evaluate(() => document.fonts.ready)
  await expect(page.locator('#toast')).toBeHidden()
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.mouse.move(0, 0)
  let clip: { x: number; y: number; width: number; height: number } | undefined
  if (els.length) {
    const boxes = await Promise.all(els.map((el) => el.boundingBox()))
    if (boxes.some((b) => !b)) throw new Error(`[docs] ${name}: an element is not on the page`)
    const x = Math.min(...boxes.map((b) => b!.x)) - 12
    const y = Math.min(...boxes.map((b) => b!.y)) - 12
    const bottom = Math.max(...boxes.map((b) => b!.y + b!.height)) + 12
    const right = Math.max(...boxes.map((b) => b!.x + b!.width)) + 12
    clip = { x: Math.max(0, x), y: Math.max(0, y), width: right - Math.max(0, x), height: Math.min(2400, bottom - y) }
  }
  await page.screenshot({
    path: path.join(OUT, `${name}.png`),
    animations: 'disabled',
    caret: 'hide',
    fullPage: Boolean(clip),
    clip,
  })
}

test('empty console @empty', async ({ page }) => {
  const state = await api<{ bans: unknown[] }>('/api/state')
  test.skip(state.bans.length > 0, 'the harness already has bans')
  await open(page)
  await expect(page.locator('#bans-empty')).toBeVisible()
  await expect(page.locator('#events-empty')).toBeVisible()
  await shoot(page, 'console-empty')
})

test('access gate', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('#gate')).toBeVisible()
  await expect(page.locator('#token')).toBeFocused()
  await shoot(page, 'console-gate')
  await page.fill('#token', TOKEN)
  await page.click('#gate-form button[type=submit]')
  await expect(page.locator('#app')).toBeVisible()
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(10)
})

test.describe('with bans', () => {
  test.beforeAll(seed)

  async function overview(page: Page): Promise<void> {
    await open(page)
    await expect(page.locator('#bans tbody tr', { hasText: '203.0.113.0/24' })).toContainText('in 7d')
    await expect(page.locator('#bans tbody tr', { hasText: 'signature' }).first()).toBeVisible()
  }

  test('overview', async ({ page }) => {
    await overview(page)
    await shoot(page, 'console-overview')
  })

  test('overview, dark', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' })
    await overview(page)
    await shoot(page, 'console-overview.dark')
  })

  test('overview, mobile', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await overview(page)
    await shoot(page, 'console-overview.mobile')
  })

  test('tile drill-down', async ({ page }) => {
    await open(page)
    await page.click('.tile[data-kind=detections]')
    await expect(page.locator('#tile-detail-title')).toHaveText('Detections')
    await expect(page.locator('#tile-detail-body tbody tr').first()).toBeVisible()
    await shoot(page, 'console-tile-detail', [page.locator('#tiles'), page.locator('#tile-detail')])
  })

  test('live activity', async ({ page }) => {
    await open(page)
    await page.click('#event-filter [data-kind=ban]')
    const rows = page.locator('#events tbody tr')
    await expect(rows.first()).toBeVisible()
    await expect(rows.locator('td.k-reject')).toHaveCount(0)
    await shoot(page, 'console-activity', [page.locator('section.panel', { has: page.locator('#events') })])
  })

  test('most probed and rules that fired', async ({ page }) => {
    await open(page)
    await expect(page.locator('#top-paths tbody tr').first()).toBeVisible()
    await expect(page.locator('#top-rules tbody tr').first()).toBeVisible()
    await shoot(page, 'console-top', [
      page.locator('section.two-col', { has: page.locator('#top-paths') }),
      page.locator('section.panel', { has: page.locator('#top-rules') }),
    ])
  })

  test('detectors and compiled ruleset', async ({ page }) => {
    await open(page)
    await expect(page.locator('#rules h3').first()).toBeVisible()
    await expect(page.locator('#config')).toContainText('state backend')
    await shoot(page, 'console-ruleset', [page.locator('section.two-col', { has: page.locator('#rules') })])
  })

  test('rule editor, unsaved edit', async ({ page }) => {
    await open(page)
    const traps = page.locator('#f-detectors-honeypots-paths')
    await traps.fill(`${await traps.inputValue()}\n/backup.zip`)
    await expect(page.locator('#rules-dirty')).toBeVisible()
    await expect(page.locator('.rule-row.changed')).toHaveCount(1)
    await traps.blur()
    // The first two rows of detector groups; the panel goes on for two more.
    const groups = page.locator('#rules-form .rule-group')
    await shoot(page, 'console-rule-editor', [
      page.locator('#rules-panel .panel-head'),
      ...[0, 1, 2, 3, 4, 5].map((i) => groups.nth(i)),
    ])
  })

  test('rule editor, rejected edit', async ({ page }) => {
    await open(page)
    await page.fill('#f-detectors-signatures-patterns', '([unclosed')
    await page.click('#rules-save')
    // 422 from the same parser that reads the file configuration; nothing applied.
    await expect(page.locator('#rules-error')).toContainText('is not a valid regular expression')
    await expect(page.locator('#rules-badge')).toBeHidden()
    const groups = page.locator('#rules-form .rule-group')
    await shoot(page, 'console-rule-editor-error', [
      page.locator('#rules-panel .panel-head'),
      ...[0, 1, 2].map((i) => groups.nth(i)),
    ])
  })
})
