import { SSO, api, banRow, banViaForm, eventRows, expect, test, toast, uniqueIp } from './helpers'

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

test('the forwarded identity is who the audit trail names', async ({ page, request }) => {
  const ip = uniqueIp()
  await page.goto(SSO.base)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await banViaForm(page, ip, '1h', 'e2e sso')
  await expect(toast(page)).toHaveText(`Banned ${ip}/32`)
  await banRow(page, `${ip}/32`).getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${ip}/32`)
  await page.locator('#event-filter').getByRole('button', { name: 'unbans', exact: true }).click()
  await expect(eventRows(page, `${ip}/32`).locator('td').nth(6)).toHaveText('operator@e2e.example')

  const field = page.locator('#rules-form .rule-group').filter({ has: page.getByRole('heading', { name: 'Honeypots', exact: true }) }).getByLabel('Trap paths')
  await field.fill(`${await field.inputValue()}\n/e2e-sso/other-trap`)
  await page.getByRole('button', { name: 'Save and apply' }).click()
  await expect(page.locator('#rules-meta')).toContainText(' by operator@e2e.example.')
  await api(request, '/api/rules', { method: 'DELETE', c: SSO })
})
