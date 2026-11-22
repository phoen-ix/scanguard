import { SSO, api, banRow, banViaForm, eventRows, expect, probe, test, toast, uniqueIp } from './helpers'

/* A console behind an auth proxy (admin.trustForwardedUser; fixtures/consoles.yml,
 * /sso/): Traefik sets X-Forwarded-User on every request, there is no token. */

test('the signed-in user unlocks without a token and stays unlocked across a reload', async ({ page }) => {
  await page.goto(SSO.base)
  await expect(page.getByLabel('Access token')).toBeVisible()
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('heading', { name: /^Active bans/ })).toBeVisible()

  await page.reload()
  await expect(page.locator('#subtitle')).toContainText('e2e-sso · up ')
  await expect(page.locator('#gate')).toBeHidden()

  await page.getByRole('button', { name: 'Lock', exact: true }).click()
  await expect(page.getByLabel('Access token')).toBeVisible()
  await page.reload()
  await expect(page.getByLabel('Access token')).toBeVisible()
  await expect(page.locator('#app')).toBeHidden()
})

test('Lock while a poll is in flight stops the polling; nothing is fetched until Unlock', async ({ page, request }) => {
  expect(await probe(request, uniqueIp(), '/e2e-sso/trap')).toBe(403) // events to paint
  await page.goto(SSO.base)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.locator('#subtitle')).toContainText('e2e-sso · up ')

  let release = () => {}
  const held = new Promise<void>((r) => (release = r))
  let inFlight = () => {}
  const polled = new Promise<void>((r) => (inFlight = r))
  await page.route('**/sso/api/state', async (route) => { inFlight(); await held; await route.continue() })
  await polled
  await page.getByRole('button', { name: 'Lock', exact: true }).click()
  await expect(page.getByLabel('Access token')).toBeFocused()

  const sent: string[] = []
  page.on('request', (r) => { if (r.url().includes('/api/')) sent.push(new URL(r.url()).pathname) })
  const stale = page.waitForResponse((r) => r.url().endsWith('/api/state'))
  release()
  await stale

  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.locator('#subtitle')).toContainText('e2e-sso · up ')
  expect(sent[0]).toBe('/sso/api/health')
})

test('the forwarded identity is who the audit trail names', async ({ page, request }) => {
  const ip = uniqueIp()
  await page.goto(SSO.base)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await banViaForm(page, ip, '1h', 'e2e sso')
  await expect(toast(page)).toHaveText(`Banned ${ip}/32`)
  await banRow(page, `${ip}/32`).getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${ip}/32`)
  const mine = eventRows(page, `${ip}/32`)
  await expect(mine.filter({ has: page.locator('td.k-unban') })).toHaveCount(1)
  await expect(mine.filter({ has: page.locator('td.k-ban') })).toHaveCount(1)
  await page.locator('#event-filter').getByRole('button', { name: 'unbans', exact: true }).click()
  // The ban's row leaves the feed; the unban's names who lifted it.
  await expect(mine).toHaveCount(1)
  await expect(mine.locator('td').nth(6)).toHaveText('operator@e2e.example')

  const field = page.locator('#rules-form .rule-group').filter({ has: page.getByRole('heading', { name: 'Honeypots', exact: true }) }).getByLabel('Trap paths')
  await field.fill(`${await field.inputValue()}\n/e2e-sso/other-trap`)
  await page.getByRole('button', { name: 'Save and apply' }).click()
  await expect(page.locator('#rules-meta')).toContainText(' by operator@e2e.example.')
  await api(request, '/api/rules', { method: 'DELETE', c: SSO })
})
