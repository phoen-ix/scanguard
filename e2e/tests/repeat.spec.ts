import { type Page } from '@playwright/test'

import { TOKEN, api, banRow, banViaForm, cells, expect, probe, ruleGroup, test, toast, uniqueIp } from './helpers'

/* The same thing done twice in a row on one page, by mouse and keyboard only
 * (COVERAGE.md, "Done twice"). Every other spec does each action once on a
 * fresh page, which is how state left over from the first time went unseen:
 * Lock kept the ban form's values, a poll in flight at Lock outlived the
 * session, a rule change seen first by a ban never warned the editor. Between
 * the two nothing happens that a person would not do. */

async function signIn(page: Page): Promise<void> {
  await page.goto('/')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.locator('#rules-form .rule-group').first()).toBeVisible()
}

const traps = (page: Page) => ruleGroup(page, 'Honeypots').getByLabel('Trap paths', { exact: true })
const save = (page: Page) => page.getByRole('button', { name: 'Save and apply' })
const compiled = (page: Page, path: string) => page.locator('#rules li').filter({ hasText: new RegExp(`^${path}$`) })

test('a wrong token, then the right one', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Access token').fill('not-the-token-0123456789')
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('alert')).toHaveText('That token was not accepted.')
  await page.getByLabel('Access token').fill(TOKEN)
  await page.getByLabel('Access token').press('Enter')
  await expect(page.locator('#subtitle')).toContainText(' · up ')
  await expect(page.getByRole('alert')).toHaveCount(0)
})

test('two bans unblocked one after the other', async ({ page, request }) => {
  const [a, b] = [uniqueIp(), uniqueIp()]
  await signIn(page)
  await banViaForm(page, a, '1h', 'e2e twice a')
  await expect(toast(page)).toHaveText(`Banned ${a}/32`)
  await banViaForm(page, b, '1h', 'e2e twice b')
  await expect(toast(page)).toHaveText(`Banned ${b}/32`)

  await banRow(page, `${a}/32`).getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${a}/32`)
  await banRow(page, `${b}/32`).getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${b}/32`)
  await expect(banRow(page, `${a}/32`)).toHaveCount(0)
  await expect(banRow(page, `${b}/32`)).toHaveCount(0)
  for (const ip of [a, b]) expect(await probe(request, ip, '/')).toBe(200)
})

test('the same address banned twice: one row, with the second ban', async ({ page, request }) => {
  const ip = uniqueIp()
  await signIn(page)
  await banViaForm(page, ip, '1h', 'e2e first')
  await expect(cells(banRow(page, `${ip}/32`)).nth(2)).toHaveText('e2e first')
  await banViaForm(page, ip, '168h', 'e2e second')
  await expect(cells(banRow(page, `${ip}/32`)).nth(2)).toHaveText('e2e second')
  await expect(cells(banRow(page, `${ip}/32`)).nth(6)).toHaveText('in 7d')
  await expect(banRow(page, `${ip}/32`)).toHaveCount(1)
  expect(await probe(request, ip, '/')).toBe(403)
})

// The duration goes back to 1h after a ban, like the address and the reason
// (owner decision 2026-11-22): it used to stay, so a permanent ban made the
// next one permanent too, unless the field was changed.
test('two bans in a row: the second, with only an address typed, is not permanent', async ({ page }) => {
  const [a, b] = [uniqueIp(), uniqueIp()]
  await signIn(page)
  await banViaForm(page, a, '0', 'e2e permanent')
  await expect(toast(page)).toHaveText(`Banned ${a}/32`)
  await expect(page.getByLabel('Ban duration')).toHaveValue('1h')
  await banViaForm(page, b)
  await expect(cells(banRow(page, `${b}/32`)).nth(6)).toHaveText('in 1h')
})

test.describe('the rule editor', () => {
  test.afterEach(async ({ request }) => {
    await api(request, '/api/rules', { method: 'DELETE' })
  })

  test('saved twice in a row', async ({ page, request }) => {
    const [one, two] = [`/e2e-twice-1-${Date.now()}`, `/e2e-twice-2-${Date.now()}`]
    await signIn(page)
    await traps(page).fill(`${await traps(page).inputValue()}\n${one}`)
    await save(page).click()
    await expect(compiled(page, one)).toHaveCount(1)
    await traps(page).fill(`${await traps(page).inputValue()}\n${two}`)
    await save(page).click()
    await expect(compiled(page, two)).toHaveCount(1)
    await expect(page.getByText('unsaved', { exact: true })).toBeHidden()
    for (const trap of [one, two]) expect(await probe(request, uniqueIp(), trap)).toBe(403)
  })

  test('saved, reverted, and saved again', async ({ page, request }) => {
    const [one, two] = [`/e2e-again-1-${Date.now()}`, `/e2e-again-2-${Date.now()}`]
    await signIn(page)
    await traps(page).fill(`${await traps(page).inputValue()}\n${one}`)
    await save(page).click()
    await expect(toast(page)).toHaveText('Rules applied')
    page.once('dialog', (d) => void d.accept())
    await page.getByRole('button', { name: 'Revert to file config' }).click()
    await expect(toast(page)).toHaveText('Reverted to the file configuration')
    await traps(page).fill(`${await traps(page).inputValue()}\n${two}`)
    await save(page).click()
    await expect(toast(page)).toHaveText('Rules applied')
    await expect(page.getByText('edited here', { exact: true })).toBeVisible()
    expect(await probe(request, uniqueIp(), two)).toBe(403)
    expect(await probe(request, uniqueIp(), one)).toBe(404)
  })

  test('a refused save, corrected and saved', async ({ page, request }) => {
    const trap = `/e2e-fixed-${Date.now()}`
    await signIn(page)
    const patterns = ruleGroup(page, 'Path signatures').getByLabel('Extra patterns', { exact: true })
    await patterns.fill('([unclosed')
    await save(page).click()
    await expect(page.getByRole('alert')).toContainText('is not a valid regular expression')
    await patterns.fill(`^${trap}$`)
    await save(page).click()
    await expect(toast(page)).toHaveText('Rules applied')
    await expect(page.getByRole('alert')).toHaveCount(0)
    expect(await probe(request, uniqueIp(), trap)).toBe(403)
  })
})
