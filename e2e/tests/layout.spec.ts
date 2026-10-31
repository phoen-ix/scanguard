import { expect, test, unlock } from './helpers'

/* Theme and phone layout. */

test('follows the dark colour scheme', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' })
  await unlock(page)
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 16, 20)')
  await page.emulateMedia({ colorScheme: 'light' })
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(246, 247, 249)')
})

test('on a phone the page does not scroll sideways; wide tables scroll in their box', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await unlock(page)
  await expect(page.getByRole('heading', { name: /^Rule editor/ })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  expect((await page.locator('#bans').boundingBox())!.width).toBeGreaterThan(390)
  expect(await page.locator('#bans').locator('xpath=..').evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true)
})
