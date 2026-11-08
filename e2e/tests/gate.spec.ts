import { TOKEN, api, banRow, expect, probe, test, uniqueIp } from './helpers'

/* The access gate: the token prompt every console session starts at. */

const stored = (page: import('@playwright/test').Page) => page.evaluate(() => sessionStorage.getItem('scanguard.token'))

for (const [what, value] of [['a wrong token', 'not-the-token-0123456789'], ['an empty token', '']]) {
  test(`${what} is refused, counted, and not remembered`, async ({ page, request }) => {
    const before = (await api(request, '/api/state')).stats.authFailures
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'scanguard' })).toBeVisible()
    await expect(page.getByLabel('Access token')).toBeFocused()
    await page.getByLabel('Access token').fill(value)
    await page.getByRole('button', { name: 'Unlock' }).click()
    await expect(page.getByRole('alert')).toHaveText('That token was not accepted.')
    await expect(page.locator('#app')).toBeHidden()
    expect(await stored(page)).toBeNull()
    expect((await api(request, '/api/state')).stats.authFailures).toBeGreaterThan(before)
  })
}

test('the right token unlocks, a reload keeps the session, Lock forgets it', async ({ page, request }) => {
  // Something for the tables to show, so "Lock clears them" means something.
  const ip = uniqueIp()
  expect(await probe(request, ip, '/wp-login.php')).toBe(403)

  await page.goto('/')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('heading', { name: /^Active bans/ })).toBeVisible()
  await expect(page.locator('#gate')).toBeHidden()
  await expect(banRow(page, `${ip}/32`)).toHaveCount(1)
  expect(await stored(page)).toBe(TOKEN)

  await page.reload()
  await expect(banRow(page, `${ip}/32`)).toHaveCount(1)
  await expect(page.locator('#gate')).toBeHidden()

  await page.getByRole('button', { name: 'Lock', exact: true }).click()
  await expect(page.getByLabel('Access token')).toBeFocused()
  // Empty, not the token that was typed: Enter alone must not reopen the console.
  await expect(page.getByLabel('Access token')).toHaveValue('')
  await expect(page.locator('#app')).toBeHidden()
  await expect(page.getByRole('alert')).toHaveCount(0)
  expect(await stored(page)).toBeNull()
  // #app is only hidden: nothing of the session may stay in it.
  await expect(page.locator('#bans tbody tr')).toHaveCount(0)
  await expect(page.locator('#events tbody tr')).toHaveCount(0)

  await page.reload()
  await expect(page.getByLabel('Access token')).toBeVisible()
  await expect(page.locator('#app')).toBeHidden()
})

test('a 401 from a proxy in front of the console is not blamed on the token', async ({ page }) => {
  // What chained basicAuth answers when the browser's credentials are missing:
  // a 401 without the plugin's realm.
  await page.route('**/api/health', (route) => route.fulfill({ status: 401, headers: { 'WWW-Authenticate': 'Basic realm="traefik"' }, body: '401 Unauthorized' }))
  await page.goto('/')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('alert')).toContainText('proxy in front of the console')
  await expect(page.getByRole('alert')).not.toContainText('token was not accepted')
})

test('a remembered token that stopped working sends the session back to the gate', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('scanguard.token', 'a-token-from-another-day-0123'))
  await page.goto('/')
  await expect(page.getByRole('alert')).toHaveText('That token was not accepted.')
  await expect(page.locator('#app')).toBeHidden()
  expect(await stored(page)).toBeNull()
})

test('a gate failure other than a refused token is shown, not a blank page', async ({ page }) => {
  // A console behind a misrouted prefix: the health check answers 404.
  await page.route('**/api/health', (route) => route.fulfill({ status: 404, json: { error: 'no such endpoint' } }))
  await page.goto('/')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('alert')).toHaveText('no such endpoint')
  await expect(page.getByLabel('Access token')).toBeVisible()
  expect(await stored(page)).toBeNull()
})
