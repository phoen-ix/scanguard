import { type Page } from '@playwright/test'

import { SITE, api, banRow, banViaForm, cells, eventRows, expect, probe, ruleGroup, test, tile, toast, uniqueIp, unlock } from './helpers'

/* The rule editor. Saving changes the harness's one runtime for everybody, so
 * every test hands control back to the file configuration afterwards. */

test.afterEach(async ({ request }) => {
  await api(request, '/api/rules', { method: 'DELETE' })
})

const field = (page: Page, group: string, label: string) => ruleGroup(page, group).getByLabel(label, { exact: true })
const save = (page: Page) => page.getByRole('button', { name: 'Save and apply' })
const revert = (page: Page) => page.getByRole('button', { name: 'Revert to file config' })
const badge = (page: Page) => page.getByText('edited here', { exact: true })
const unsaved = (page: Page) => page.getByText('unsaved', { exact: true })
const FILE_META = "Running Traefik's file configuration. Saving here takes over these sections until you revert; changes apply immediately, with no Traefik restart."

async function editorReady(page: Page): Promise<void> {
  await unlock(page)
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(11)
}

test('shows the file configuration, one group per section, nothing marked', async ({ page }) => {
  await editorReady(page)
  await expect(page.locator('#rules-form h3')).toHaveText([
    'General', 'Path signatures', 'Honeypots', 'Scanner user-agents', 'Distinct failing paths',
    'Brute force', 'Request rate', 'User-agent rotation', 'Payload probes', 'Allowlist', 'Enforcement',
  ])
  await expect(page.locator('#rules-meta')).toHaveText(FILE_META)
  await expect(badge(page)).toBeHidden()
  await expect(unsaved(page)).toBeHidden()
  await expect(revert(page)).toBeDisabled()
  await expect(page.locator('.rule-row.changed')).toHaveCount(0)
  // Every input has its label; the values are the file's.
  await expect(field(page, 'Honeypots', 'Trap paths')).toHaveValue('/admin.php\n/.env.backup\n/wp-content/uploads/shell.php')
  await expect(field(page, 'Distinct failing paths', 'Distinct paths to trip')).toHaveValue('6')
  await expect(field(page, 'Distinct failing paths', 'Statuses counted')).toHaveValue('400, 401, 403, 404, 405, 501')
  await expect(field(page, 'Scanner user-agents', 'SEO crawlers')).toHaveValue('ignore')
  await expect(field(page, 'Request rate', 'Enabled')).not.toBeChecked()
  await expect(field(page, 'User-agent rotation', 'Enabled')).not.toBeChecked()
  await expect(field(page, 'Payload probes', 'Enabled')).toBeChecked()
  // Off in the harness: uniqueIp() hands out consecutive addresses, so ranges fill up.
  await expect(field(page, 'Enforcement', 'Ban the whole range of repeat offenders')).not.toBeChecked()
  await expect(field(page, 'Enforcement', 'Banned sources per range')).toHaveValue('5')
})

test('an edit is marked until saved, and a data refresh does not wipe it', async ({ page, request }) => {
  await editorReady(page)
  const traps = field(page, 'Honeypots', 'Trap paths')
  const original = await traps.inputValue()
  await traps.fill(`${original}\n/e2e-unsaved`)
  await expect(unsaved(page)).toBeVisible()
  await expect(page.locator('.rule-row.changed')).toHaveCount(1)

  // An unblock elsewhere on the page repaints everything else.
  const ip = uniqueIp()
  await api(request, '/api/bans', { method: 'POST', data: { key: ip, reason: 'e2e refresh' } })
  const row = page.locator('#bans tbody tr').filter({ hasText: `${ip}/32` })
  await row.getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${ip}/32`)
  await expect(traps).toHaveValue(`${original}\n/e2e-unsaved`)
  await expect(unsaved(page)).toBeVisible()

  // Typed back to the file's value, the field is no longer marked as changed.
  await traps.fill(original)
  await expect(page.locator('.rule-row.changed')).toHaveCount(0)
})

test('saving applies on the next request, is marked, and survives a reload', async ({ page, request }) => {
  const trap = `/e2e-trap-${Date.now()}`
  const ip = uniqueIp()
  expect(await probe(request, ip, trap)).toBe(404)
  await editorReady(page)
  const traps = field(page, 'Honeypots', 'Trap paths')
  await traps.fill(`${await traps.inputValue()}\n${trap}`)
  await save(page).click()
  await expect(toast(page)).toHaveText('Rules applied')
  await expect(badge(page)).toBeVisible()
  await expect(unsaved(page)).toBeHidden()
  await expect(revert(page)).toBeEnabled()
  await expect(page.locator('#rules-meta')).toHaveText(/^Managed here: detectors — last saved .+ by token\. Traefik's file configuration supplies everything else/)
  await expect(page.locator('#rules li').filter({ hasText: new RegExp(`^${trap}$`) })).toHaveCount(1)
  expect(await probe(request, uniqueIp(), trap)).toBe(403)

  await page.reload()
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(11)
  await expect(field(page, 'Honeypots', 'Trap paths')).toHaveValue(new RegExp(`${trap}$`))
  await expect(badge(page)).toBeVisible()
  await expect(page.locator('.rule-row.changed')).toHaveCount(1)
})

for (const [group, label, value, message] of [
  ['Path signatures', 'Extra patterns', '([unclosed', 'is not a valid regular expression'],
  ['Distinct failing paths', 'Leak interval', 'soon', '"soon" is not a valid duration'],
  ['Allowlist', 'Never-ban CIDRs', '10.0.0.0/33', '"10.0.0.0/33" is not a valid CIDR'],
  ['Enforcement', 'Reject status', '99', '99 is not a valid HTTP status code'],
]) {
  test(`a rejected edit (${label}: ${value}) shows the parser's reason and changes nothing`, async ({ page, request }) => {
    await editorReady(page)
    await field(page, group, label).fill(value)
    await save(page).click()
    await expect(page.getByRole('alert')).toContainText(message)
    await expect(badge(page)).toBeHidden()
    await expect(unsaved(page)).toBeVisible()
    expect((await api(request, '/api/rules')).overridden).toEqual([])
  })
}

test('Revert asks first, then hands control back to the file', async ({ page, request }) => {
  const trap = `/e2e-revert-${Date.now()}`
  // As the editor does it: the whole effective rule set, one path added.
  const { effective } = await api(request, '/api/rules')
  effective.detectors.honeypots.paths.push(trap)
  await api(request, '/api/rules', { method: 'PUT', data: effective })
  await editorReady(page)
  await expect(badge(page)).toBeVisible()

  let question = ''
  page.once('dialog', (d) => { question = d.message(); void d.dismiss() })
  await revert(page).click()
  await expect.poll(() => question).toBe("Discard the rules saved here and go back to Traefik's file configuration?")
  await expect(badge(page)).toBeVisible()
  expect(await probe(request, uniqueIp(), trap)).toBe(403)

  page.once('dialog', (d) => void d.accept())
  await revert(page).click()
  await expect(toast(page)).toHaveText('Reverted to the file configuration')
  await expect(badge(page)).toBeHidden()
  await expect(revert(page)).toBeDisabled()
  await expect(page.locator('#rules-meta')).toHaveText(FILE_META)
  expect(await probe(request, uniqueIp(), trap)).toBe(404)
})

test('dry run: detectors record what they would ban, nothing is blocked', async ({ page, request }) => {
  await editorReady(page)
  await field(page, 'General', 'Dry run').check()
  await save(page).click()
  await expect(page.getByText('DRY RUN — nothing is blocked')).toBeVisible()

  const ip = uniqueIp()
  expect(await probe(request, ip, '/wp-login.php')).toBe(404)
  await expect(eventRows(page, `${ip}/32`).locator('td.k-ban')).toHaveText('ban (dry)')
  expect(await probe(request, ip, '/')).not.toBe(403)

  page.once('dialog', (d) => void d.accept())
  await revert(page).click()
  await expect(page.getByText('DRY RUN — nothing is blocked')).toBeHidden()
  expect(await probe(request, uniqueIp(), '/wp-login.php')).toBe(403)
})

test('every kind of field in every group round-trips: checkbox, choice, number, text, lists', async ({ page, request }) => {
  await editorReady(page)
  const edits: [string, string, string, string][] = [
    // group, label, typed, shown after the reload
    ['Path signatures', 'Exclusions', '^/e2e-excluded/\n\n', '^/e2e-excluded/'],
    ['Scanner user-agents', 'SEO crawlers', 'block', 'block'],
    ['Distinct failing paths', 'Distinct paths to trip', '9', '9'],
    ['Distinct failing paths', 'Leak interval', '30s', '30s'],
    ['Distinct failing paths', 'Statuses counted', '404,  410,', '404, 410'],
    ['Brute force', 'Window', '2m', '2m'],
    ['Brute force', 'Only these paths', '^/login$', '^/login$'],
    ['Request rate', 'Requests per second', '75', '75'],
    ['User-agent rotation', 'Distinct user-agents to trip', '5', '5'],
    ['User-agent rotation', 'Leak interval', '90s', '90s'],
    ['Allowlist', 'Never-ban user-agents', 'e2e-uptime-monitor', 'e2e-uptime-monitor'],
    ['Enforcement', 'Ban ladder', '2h, 0', '2h, 0'],
    ['Enforcement', 'Reject body', 'Go away (e2e)', 'Go away (e2e)'],
    // Range escalation stays off: the widths and threshold round-trip without it.
    ['Enforcement', 'Banned sources per range', '4', '4'],
    ['Enforcement', 'Within', '12h', '12h'],
    ['Enforcement', 'IPv4 range width', '20', '20'],
    ['Enforcement', 'IPv6 range width', '40', '40'],
  ]
  for (const [group, label, typed] of edits) {
    const f = field(page, group, label)
    if (label === 'SEO crawlers') await f.selectOption(typed)
    else await f.fill(typed)
  }
  await field(page, 'Scanner user-agents', 'Ban requests with no User-Agent').check()
  await field(page, 'Payload probes', 'Scan the request body').check()
  await expect(page.locator('.rule-row.changed')).toHaveCount(edits.length + 2)
  await save(page).click()
  await expect(toast(page)).toHaveText('Rules applied')
  for (const section of ['allowlist', 'detectors', 'enforcement']) {
    await expect(page.locator('#rules-meta')).toContainText(new RegExp(`^Managed here: [a-z, ]*\\b${section}\\b[a-z, ]* — `))
  }

  await page.reload()
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(11)
  for (const [group, label, , shown] of edits) await expect(field(page, group, label)).toHaveValue(shown)
  await expect(field(page, 'Scanner user-agents', 'Ban requests with no User-Agent')).toBeChecked()
  await expect(field(page, 'Payload probes', 'Scan the request body')).toBeChecked()
  await expect(page.locator('.rule-row.changed')).toHaveCount(edits.length + 2)
  // The read-outs follow, and so does the next rejected request.
  const kv = (term: string) => page.locator('#config dt').filter({ hasText: new RegExp(`^${term}$`) }).locator('xpath=following-sibling::dd[1]')
  await expect(kv('escalation')).toHaveText('2h → permanent')
  await expect(kv('crawler policy')).toHaveText('block')
  await expect(page.locator('#rules > div').filter({ hasText: /^Allowlisted user agents \(1\)/ }).locator('li')).toHaveText(['e2e-uptime-monitor'])
  const res = await request.get(SITE + '/wp-login.php', { headers: { 'X-Real-Ip': uniqueIp() } })
  expect(res.status()).toBe(403)
  expect(await res.text()).toBe('Go away (e2e)\n')
})

test('an allowlist edit exempts the range at once, and the ban form refuses it', async ({ page, request }) => {
  await editorReady(page)
  const cidrs = field(page, 'Allowlist', 'Never-ban CIDRs')
  await cidrs.fill(`${await cidrs.inputValue()}\n192.0.2.0/24`)
  await save(page).click()
  await expect(toast(page)).toHaveText('Rules applied')

  expect(await probe(request, '192.0.2.10', '/wp-login.php')).not.toBe(403)
  await tile(page, 'exempt').click()
  await expect(page.locator('#tile-detail tbody tr').filter({ hasText: 'allowlist-cidr' })).toHaveCount(1)

  await banViaForm(page, '192.0.2.10')
  await expect(toast(page)).toHaveText('refusing to ban 192.0.2.10/32: it overlaps allowlisted 192.0.2.0/24')
})

test('range escalation: three banned sources in one /24 ban the range, and unblock lifts it', async ({ page, request }) => {
  // Fixed addresses, outside uniqueIp()'s 198.18.0.0/15: the three sources have to
  // share a /24 that nothing else in the suite touches. Cleared first so a rerun
  // against the same harness starts from fresh first offences.
  const range = '198.51.100.0/24'
  const members = ['198.51.100.1', '198.51.100.2', '198.51.100.3']
  const fresh = '198.51.100.200'
  for (const key of [range, ...members]) await api(request, `/api/bans?key=${encodeURIComponent(key)}`, { method: 'DELETE' })

  await editorReady(page)
  await field(page, 'Enforcement', 'Ban the whole range of repeat offenders').check()
  await field(page, 'Enforcement', 'Banned sources per range').fill('3')
  await save(page).click()
  await expect(toast(page)).toHaveText('Rules applied')

  for (const ip of members) expect(await probe(request, ip, '/wp-login.php')).toBe(403)
  expect(await probe(request, fresh, '/')).toBe(403)
  const row = banRow(page, range)
  await expect(cells(row).nth(1)).toHaveText('subnet')
  await expect(cells(row).nth(2)).toHaveText(`3 sources in ${range} within 1d`)

  await row.getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${range}`)
  expect(await probe(request, fresh, '/')).not.toBe(403)
})

test('leaving with unsaved edits asks first; with none it does not', async ({ page, context }) => {
  await editorReady(page)
  const dialogs: string[] = []
  page.on('dialog', (d) => { dialogs.push(d.type()); void d.accept() })
  // A click first: Chromium asks only on a page the user has interacted with.
  await field(page, 'Honeypots', 'Trap paths').click()
  await field(page, 'Honeypots', 'Trap paths').fill('/e2e-never-saved')
  await page.close({ runBeforeUnload: true })
  await expect.poll(() => dialogs).toEqual(['beforeunload'])

  const clean = await context.newPage()
  await clean.addInitScript((t) => sessionStorage.setItem('scanguard.token', t), 'dev-token-change-me-0123456789')
  await clean.goto('/')
  await expect(clean.locator('#rules-form .rule-group')).toHaveCount(11)
  clean.on('dialog', (d) => { dialogs.push(`clean ${d.type()}`); void d.accept() })
  const closed = clean.waitForEvent('close')
  await clean.close({ runBeforeUnload: true })
  await closed
  expect(dialogs).toEqual(['beforeunload'])
})
