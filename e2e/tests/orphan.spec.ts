import { ORPHAN, TILES, expect, test, tile, unlock } from './helpers'

/* A console whose instanceName no detector shares (fixtures/consoles.yml,
 * /orphan/) - the classic typo. Nothing ever reaches its runtime, so this is
 * where the empty states live. */

test.use({ allowed5xx: /\/orphan\/api\/rules$/ })

test('every list shows its empty state', async ({ page }) => {
  await unlock(page, ORPHAN)
  await expect(page.getByText('No active bans.')).toBeVisible()
  await expect(page.locator('#ban-count')).toHaveText('')
  await expect(page.getByText('No rule has fired yet.')).toBeVisible()
  await expect(page.getByText('Nothing yet.')).toBeVisible()
  for (const id of ['#top-paths', '#top-sources', '#top-rules', '#events']) await expect(page.locator(`${id} tbody tr`)).toHaveCount(0)
  await expect(tile(page, 'blocked')).not.toHaveClass(/alert/)
})

test('every tile opens on "Nothing recorded yet."', async ({ page }) => {
  await unlock(page, ORPHAN)
  for (const t of TILES) {
    await tile(page, t.label).click()
    await expect(page.locator('#tile-detail-title')).toHaveText(t.title)
    await expect(page.locator('#tile-detail-body')).toHaveText('Nothing recorded yet.')
  }
})

test('the rule editor says no detector shares its instance name', async ({ page }) => {
  await unlock(page, ORPHAN)
  await expect(page.getByRole('alert')).toHaveText('no detection middleware has been configured for this instance yet')
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(0)
})
