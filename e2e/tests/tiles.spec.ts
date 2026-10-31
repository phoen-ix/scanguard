import { TILES, api, expect, probe, test, tile, uniqueIp, unlock } from './helpers'

/* The six counter tiles and the drill-down each one opens beneath the row. */

const detail = (page: import('@playwright/test').Page) => page.locator('#tile-detail')

test.beforeAll(async ({ playwright }) => {
  // Something behind every tile: a detection (ban), a reject, an exempt request.
  const request = await playwright.request.newContext()
  const ip = uniqueIp()
  await probe(request, ip, '/wp-login.php')
  await probe(request, ip, '/')
  await probe(request, null, '/')
  await request.dispose()
})

for (const t of TILES) {
  test(`the ${t.label} tile opens its list and closes again`, async ({ page }) => {
    await unlock(page)
    const button = tile(page, t.label)
    await expect(button).toHaveAttribute('aria-expanded', 'false')
    await button.click()
    await expect(button).toHaveAttribute('aria-expanded', 'true')
    await expect(page.locator('#tile-detail-title')).toHaveText(t.title)
    await expect(detail(page).locator('th')).toHaveText(t.cols)
    await expect(detail(page).locator('tbody tr').first()).toBeVisible()
    await button.click()
    await expect(detail(page)).toBeHidden()
    await expect(button).toHaveAttribute('aria-expanded', 'false')
  })
}

test('the close button and Escape close the list; another tile replaces it', async ({ page }) => {
  await unlock(page)
  await tile(page, 'blocked').click()
  await expect(detail(page)).toBeVisible()
  await page.getByRole('button', { name: 'Close' }).click()
  await expect(detail(page)).toBeHidden()

  await tile(page, 'blocked').click()
  await tile(page, 'exempt').click()
  await expect(page.locator('#tile-detail-title')).toHaveText('Exempt requests')
  await expect(tile(page, 'blocked')).toHaveAttribute('aria-expanded', 'false')
  await page.keyboard.press('Escape')
  await expect(detail(page)).toBeHidden()
})

test('each list says what it holds', async ({ page, request }) => {
  await unlock(page)
  await tile(page, 'requests seen').click()
  await expect(detail(page).locator('tbody tr').filter({ hasText: new URL(process.env.E2E_SITE_URL ?? 'http://localhost:8800').host })).toHaveCount(1)

  // Event-backed lists are a recent window of an all-time counter, and say which.
  const window = /^(All \d+ so far\.|The \d+ most recent of \d+\. Older entries have left the event log\.)$/
  await tile(page, 'blocked').click()
  await expect(page.locator('#tile-detail-note')).toHaveText(window)
  await expect(tile(page, 'blocked')).toHaveClass(/alert/)
  await tile(page, 'detections').click()
  await expect(page.locator('#tile-detail-note')).toHaveText(window)

  await tile(page, 'active bans').click()
  const { bansTotal } = await api(request, '/api/state')
  await expect(detail(page).locator('tbody tr')).toHaveCount(bansTotal)

  // The host's own requests reach scanguard from the Docker bridge, a trusted proxy.
  await tile(page, 'exempt').click()
  await expect(detail(page).locator('tbody tr').filter({ hasText: 'trusted-proxy' })).toHaveCount(1)
})

test('tracked sources are fetched while the list is open, newest first', async ({ page, request }) => {
  const ip = uniqueIp()
  for (const p of ['/missing-a', '/missing-b', '/missing-c']) expect(await probe(request, ip, p)).toBe(404)
  await unlock(page)
  await tile(page, 'tracked sources').click()
  const row = (src: string) => detail(page).locator('tbody tr').filter({ hasText: `${src}/32` })
  await expect(row(ip).locator('td').nth(3)).toHaveText(/^[1-3]$/)

  // A new source shows up on the next poll, at the top, without reopening.
  const next = uniqueIp()
  expect(await probe(request, next, '/missing-d')).toBe(404)
  await expect(detail(page).locator('tbody tr').first()).toContainText(`${next}/32`)
})
