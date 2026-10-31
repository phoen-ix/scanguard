import { api, cells, eventRows, expect, probe, test, uniqueIp, unlock } from './helpers'

/* Live activity: the event feed, its kind filter and the follow toggle. */

const chip = (page: import('@playwright/test').Page, name: string) =>
  page.locator('#event-filter').getByRole('button', { name, exact: true })

test('a detection and the rejects after it stream in without a reload', async ({ page, request }) => {
  const ip = uniqueIp()
  await unlock(page)
  expect(await probe(request, ip, '/wp-login.php')).toBe(403)
  const ban = eventRows(page, `${ip}/32`).filter({ has: page.locator('td.k-ban') })
  await expect(cells(ban)).toHaveText([/\d/, 'ban', `${ip}/32`, 'signature', 'GET', '/wp-login.php', /wp-login/])
  expect(await probe(request, ip, '/after-the-ban')).toBe(403)
  const reject = eventRows(page, `${ip}/32`).filter({ has: page.locator('td.k-reject') })
  await expect(cells(reject)).toHaveText([/\d/, 'reject', `${ip}/32`, 'signature', 'GET', '/after-the-ban', /wp-login/])
  await expect(page.locator('#events-empty')).toBeHidden()
})

test('the kind filter shows one kind at a time', async ({ page, request }) => {
  const ip = uniqueIp()
  expect(await probe(request, ip, '/.env')).toBe(403)
  expect(await probe(request, ip, '/')).toBe(403)
  await api(request, `/api/bans?key=${ip}`, { method: 'DELETE' })
  await unlock(page)
  const mine = eventRows(page, `${ip}/32`)
  await expect(chip(page, 'all')).toHaveAttribute('aria-pressed', 'true')
  await expect(mine).toHaveCount(3)

  for (const [name, kind] of [['bans', 'ban'], ['rejects', 'reject'], ['unbans', 'unban']]) {
    await chip(page, name).click()
    await expect(chip(page, name)).toHaveAttribute('aria-pressed', 'true')
    await expect(chip(page, 'all')).toHaveAttribute('aria-pressed', 'false')
    await expect(mine).toHaveCount(1)
    await expect(cells(mine).nth(1)).toHaveText(kind)
    await expect(page.locator(`#events tbody td:not(.k-${kind})[class^="k-"]`)).toHaveCount(0)
  }
  // An unban names who lifted it.
  await expect(cells(mine).nth(6)).toHaveText('token')

  await chip(page, 'all').click()
  await expect(mine).toHaveCount(3)
})

test('follow keeps the newest event in view; unticked, the feed stays where it was scrolled', async ({ page, request }) => {
  // Enough rows to scroll: one ban and twenty rejects.
  const ip = uniqueIp()
  expect(await probe(request, ip, '/.git/config')).toBe(403)
  for (let i = 0; i < 20; i++) await probe(request, ip, `/scroll-${i}`)
  await unlock(page)
  const box = page.locator('#events').locator('xpath=..')
  const follow = page.getByLabel('follow')
  await expect(follow).toBeChecked()
  await expect(eventRows(page, `${ip}/32`)).toHaveCount(21)

  await follow.uncheck()
  await box.evaluate((el) => (el.scrollTop = 300))
  const other = uniqueIp()
  await probe(request, other, '/.git/config')
  await expect(eventRows(page, `${other}/32`)).toHaveCount(1)
  expect(await box.evaluate((el) => el.scrollTop)).toBeGreaterThan(0)

  await follow.check()
  const third = uniqueIp()
  await probe(request, third, '/.git/config')
  await expect(eventRows(page, `${third}/32`)).toHaveCount(1)
  await expect.poll(() => box.evaluate((el) => el.scrollTop)).toBe(0)
})
