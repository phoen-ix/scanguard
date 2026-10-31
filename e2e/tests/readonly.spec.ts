import { CONSOLE, RO, api, banRow, cells, expect, probe, test, uniqueIp, unlock } from './helpers'

/* A console with admin.readOnly (fixtures/consoles.yml, /ro/): it shows
 * everything and changes nothing. */

test('says it is read only and offers no control that would change anything', async ({ page, request }) => {
  const ip = uniqueIp()
  expect(await probe(request, ip, '/e2e-ro/trap')).toBe(403)
  await unlock(page, RO)
  await expect(page.getByText('read only', { exact: true })).toBeVisible()

  const row = banRow(page, `${ip}/32`)
  await expect(cells(row).nth(1)).toHaveText('honeypot')
  await expect(row.getByRole('button', { name: 'unblock' })).toBeDisabled()
  for (const name of ['Address or CIDR to ban', 'Ban duration', 'Ban reason']) await expect(page.getByLabel(name)).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Ban', exact: true })).toBeDisabled()

  await expect(page.locator('#rules-form .rule-group')).toHaveCount(10)
  await expect(page.getByRole('button', { name: 'Save and apply' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Revert to file config' })).toBeDisabled()
  await expect(page.locator('#rules-form').locator('input:enabled, textarea:enabled, select:enabled')).toHaveCount(0)
  // A disabled button looks it.
  await expect(page.getByRole('button', { name: 'Save and apply' })).toHaveCSS('cursor', 'not-allowed')

  // Reading still works: tiles open.
  await page.locator('#tiles').getByRole('button', { name: /detections$/ }).click()
  await expect(page.locator('#tile-detail td').getByText(ip, { exact: true })).toHaveCount(1)
})

test('the API refuses every change, whoever asks', async ({ request }) => {
  const headers = { 'X-Scanguard-Token': RO.token, 'X-Scanguard-Action': '1' }
  const refused = { error: 'scanguard is in read-only mode' }
  for (const [method, path, data] of [
    ['POST', 'api/bans', { key: uniqueIp() }],
    ['DELETE', `api/bans?key=${uniqueIp()}`, undefined],
    ['PUT', 'api/rules', {}],
    ['DELETE', 'api/rules', undefined],
  ] as const) {
    const res = await request.fetch(CONSOLE + RO.base + path, { method, headers, data })
    expect(res.status(), `${method} ${path}`).toBe(403)
    expect(await res.json()).toEqual(refused)
  }
})

test('a long ban list shows the newest 500 and says how many there are', async ({ page, request }) => {
  // The state poll carries at most 500 bans (maxStateBans in admin.go).
  for (let i = 0; i < 501; i++) expect(await probe(request, uniqueIp(), '/e2e-ro/trap')).toBe(403)
  const { bansTotal } = await api(request, '/api/state', { c: RO })
  expect(bansTotal).toBeGreaterThan(500)
  await unlock(page, RO)
  await expect(page.locator('#ban-count')).toHaveText(`(newest 500 of ${bansTotal})`)
  await expect(page.locator('#bans tbody tr')).toHaveCount(500)
  await expect(page.locator('#tiles').getByRole('button', { name: /active bans$/ })).toContainText(String(bansTotal))
})
