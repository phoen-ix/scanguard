import { api, banRow, banViaForm, cells, expect, probe, test, toast, uniqueIp, unlock } from './helpers'

/* The Active bans panel: manual bans from the form, unblock, and detector bans
 * arriving while the page is open. */

test('a manual ban from the form is listed, enforced, and lifted by unblock', async ({ page, request }) => {
  const ip = uniqueIp()
  const key = `${ip}/32`
  await unlock(page)
  await banViaForm(page, ip, undefined, 'e2e manual ban')
  await expect(toast(page)).toHaveText(`Banned ${key}`)
  const row = banRow(page, key)
  await expect(cells(row)).toHaveText([key, 'manual', 'e2e manual ban', '', '', '0', 'in 1h', 'unblock'])
  // The form is ready for the next one; the duration keeps its default.
  await expect(page.getByLabel('Address or CIDR to ban')).toHaveValue('')
  await expect(page.getByLabel('Ban reason')).toHaveValue('')
  await expect(page.getByLabel('Ban duration')).toHaveValue('1h')
  const { bansTotal } = await api(request, '/api/state')
  await expect(page.locator('#ban-count')).toHaveText(`(${bansTotal})`)
  expect(await probe(request, ip, '/')).toBe(403)
  // The toast clears itself.
  await expect(toast(page)).toBeHidden()

  await row.getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${key}`)
  await expect(row).toHaveCount(0)
  expect(await probe(request, ip, '/')).not.toBe(403)
})

test('a range and a permanent ban, with their expiry', async ({ page, request }) => {
  // A range of its own, outside the one uniqueIp() hands out.
  const range = '203.0.113.0/24'
  const single = uniqueIp()
  await unlock(page)
  await banViaForm(page, range, '168h', 'e2e range')
  await expect(toast(page)).toHaveText(`Banned ${range}`)
  await expect(cells(banRow(page, range)).nth(6)).toHaveText('in 7d')
  await banViaForm(page, single, '0', '')
  await expect(toast(page)).toHaveText(`Banned ${single}/32`)
  // No reason given: the server records "manual ban".
  await expect(cells(banRow(page, `${single}/32`))).toHaveText([`${single}/32`, 'manual', 'manual ban', '', '', '0', 'permanent', 'unblock'])
  // A range blocks every address inside it.
  expect(await probe(request, '203.0.113.77', '/')).toBe(403)
  await api(request, `/api/bans?key=${encodeURIComponent(range)}`, { method: 'DELETE' })
  await api(request, `/api/bans?key=${single}`, { method: 'DELETE' })
})

for (const [what, key, duration, message] of [
  ['an address that is not one', 'not-an-ip', '1h', 'key is not a valid IP address or CIDR'],
  ['a range wider than /8', '0.0.0.0/0', '1h', 'refusing to ban 0.0.0.0/0: wider than /8'],
  ['a range over the trusted proxies', '172.20.0.0/16', '1h', 'refusing to ban 172.20.0.0/16: it overlaps trusted proxy 172.16.0.0/12'],
  ['the host itself', '127.0.0.1', '1h', 'refusing to ban 127.0.0.1/32: it overlaps trusted proxy 127.0.0.1/32'],
  ['an IPv6 prefix narrower than the key width', '2001:db8::1/128', '1h', 'is narrower than the /64 that requests are keyed at'],
  ['a duration that is not one', '198.18.0.9', 'soon', 'duration: "soon" is not a valid duration'],
]) {
  test(`the form refuses ${what}, with the reason`, async ({ page }) => {
    await unlock(page)
    const before = await page.locator('#bans tbody tr').count()
    await banViaForm(page, key, duration)
    await expect(toast(page)).toContainText(message)
    // Nothing recorded, and the input stays for correcting.
    await expect(page.getByLabel('Address or CIDR to ban')).toHaveValue(key)
    await expect(page.locator('#bans tbody tr')).toHaveCount(before)
  })
}

test('an empty address sends nothing', async ({ page }) => {
  await unlock(page)
  let posted = false
  page.on('request', (r) => { if (r.method() === 'POST') posted = true })
  await page.getByRole('button', { name: 'Ban', exact: true }).click()
  // The next poll has come and gone; no POST went out before it.
  await page.waitForResponse((r) => r.url().endsWith('/api/state'))
  expect(posted).toBe(false)
  await expect(toast(page)).toBeHidden()
})

test('a detector ban appears while the page is open; its hits count up', async ({ page, request }) => {
  const ip = uniqueIp()
  await unlock(page)
  expect(await probe(request, ip, '/wp-login.php')).toBe(403)
  const row = banRow(page, `${ip}/32`)
  await expect(cells(row).nth(1)).toHaveText('signature')
  await expect(cells(row).nth(2)).toContainText('wp-login')
  await expect(cells(row).nth(5)).toHaveText('0')
  for (let i = 0; i < 3; i++) expect(await probe(request, ip, '/')).toBe(403)
  await expect(cells(row).nth(5)).toHaveText('3')
})

test('unblocking a ban that is already gone says so', async ({ page, request }) => {
  const ip = uniqueIp()
  await api(request, '/api/bans', { method: 'POST', data: { key: ip, duration: '1h', reason: 'e2e stale' } })
  // Hold the three-second poll so the row is still on screen after the ban is gone.
  await page.clock.install()
  await unlock(page)
  await page.clock.pauseAt((await page.evaluate(() => Date.now())) + 500)
  const row = banRow(page, `${ip}/32`)
  await expect(row).toHaveCount(1)
  await api(request, `/api/bans?key=${ip}`, { method: 'DELETE' })
  await row.getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`No ban found for ${ip}/32`)
  await expect(row).toHaveCount(0)
})
