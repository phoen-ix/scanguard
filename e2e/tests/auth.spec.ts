import { CONSOLE, TOKEN, banRow, expect, probe, test, uniqueIp } from './helpers'

/* The console behind the basicAuth the README tells operators to chain in
 * front of it (fixtures/consoles.yml: /auth/, dev / dev). The page loads with
 * the browser's credentials; every API call must carry them too. The script
 * used to send credentials: "omit", so the first api/health reached basicAuth
 * without an Authorization header, got 401, and the gate said the right token
 * was not accepted. */

const AUTH = { username: 'dev', password: 'dev' }
test.use({ httpCredentials: AUTH })

test.beforeAll(async () => {
  // Not one of the consoles global-setup waits for.
  const deadline = Date.now() + 30_000
  const basic = 'Basic ' + Buffer.from('dev:dev').toString('base64')
  for (;;) {
    const res = await fetch(`${CONSOLE}/auth/api/health`, { headers: { Authorization: basic, 'X-Scanguard-Token': TOKEN } }).catch(() => null)
    if (res?.status === 200) break
    if (Date.now() > deadline) throw new Error('[e2e] the basicAuth console at /auth/ did not come up')
    await new Promise((r) => setTimeout(r, 500))
  }
})

test('the console works behind basicAuth: the token unlocks and the data loads', async ({ page, request }) => {
  const ip = uniqueIp()
  expect(await probe(request, ip, '/wp-login.php')).toBe(403)
  await page.goto('/auth/')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.locator('#app')).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect(page.locator('#subtitle')).toContainText('default · up ')
  await expect(banRow(page, `${ip}/32`)).toHaveCount(1)
})

test('without the proxy credentials the gate blames the proxy, not the token', async ({ browser }) => {
  // The page loaded while the browser still had its basicAuth credentials (the
  // route adds them to the page's own files only); every API call goes without
  // and meets basicAuth's real 401.
  const context = await browser.newContext({ httpCredentials: undefined })
  const page = await context.newPage()
  const basic = 'Basic ' + Buffer.from('dev:dev').toString('base64')
  await page.route((url) => url.pathname.startsWith('/auth/') && !url.pathname.startsWith('/auth/api/'),
    (route) => route.continue({ headers: { ...route.request().headers(), authorization: basic } }))
  await page.goto('/auth/')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('alert')).toHaveText('The proxy in front of the console refused the request (HTTP 401). Sign in to it and reload.')
  await expect(page.locator('#app')).toBeHidden()
  await context.close()
})
