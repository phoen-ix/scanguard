import {
  THE_OPERATOR,
  addLine,
  banRow,
  banViaForm,
  browserOf,
  cells,
  clientAt,
  editedHere,
  editorLoaded,
  expect,
  field,
  given,
  revertRules,
  saveRules,
  test,
  tile,
  toast,
  unblock,
  uniqueIp,
  unsaved,
} from './lib'

/* The rule editor, from the operator's hand to the clients it judges and to
 * the other operator looking at it (COVERAGE.c.md, U1, U7, U9, U10). */

test.afterEach(() => given.fileRules())

test('U1 a trap the operator saves refuses the next scanner; reverted, it is an ordinary path again', async ({ browser }) => {
  const trap = `/e2e-uc-trap-${Date.now()}`
  expect(await clientAt(uniqueIp()).gets(trap)).toBe(404)

  const operator = await browserOf(browser, THE_OPERATOR)
  await editorLoaded(operator)
  await addLine(operator, 'Honeypots', 'Trap paths', trap)
  await saveRules(operator)
  await expect(editedHere(operator)).toBeVisible()

  const scanner = clientAt(uniqueIp())
  expect(await scanner.gets(trap)).toBe(403)
  expect(await scanner.gets('/')).toBe(403)
  const row = banRow(operator, scanner.key)
  await expect(cells(row).nth(1)).toHaveText('honeypot')
  await expect(cells(row).nth(2)).toContainText(trap)

  await revertRules(operator)
  await expect(editedHere(operator)).toBeHidden()
  expect(await clientAt(uniqueIp()).gets(trap)).toBe(404)
})

test('U7 a save by one operator reloads the other\'s clean editor, and warns it once it holds unsaved edits', async ({ browser }) => {
  const [first, second, mine] = ['/e2e-uc-ana-1', '/e2e-uc-ana-2', '/e2e-uc-ben'].map((p) => `${p}-${Date.now()}`)
  const traps = 'Trap paths'
  const ana = await browserOf(browser, THE_OPERATOR)
  const ben = await browserOf(browser, THE_OPERATOR)
  await editorLoaded(ana)
  await editorLoaded(ben)

  await addLine(ana, 'Honeypots', traps, first)
  await saveRules(ana)
  // Ben touched nothing: his editor shows Ana's rule set by itself.
  await expect(field(ben, 'Honeypots', traps)).toHaveValue(new RegExp(`${first}$`))
  await expect(editedHere(ben)).toBeVisible()

  await field(ben, 'Honeypots', traps).click()
  await addLine(ben, 'Honeypots', traps, mine)
  await expect(unsaved(ben)).toBeVisible()
  await addLine(ana, 'Honeypots', traps, second)
  await saveRules(ana)
  await expect(ben.getByRole('alert')).toContainText('The rule set changed on the server while you were editing')
  await expect(field(ben, 'Honeypots', traps)).toHaveValue(new RegExp(`${mine}$`))

  // He does what the warning says: reloads (and leaves his edit), and sees Ana's.
  ben.once('dialog', (d) => void d.accept())
  await ben.reload()
  await editorLoaded(ben)
  await expect(field(ben, 'Honeypots', traps)).toHaveValue(new RegExp(`${first}\n${second}$`))
  await expect(unsaved(ben)).toBeHidden()
})

test('U9 a dry run lists the would-ban, the operator lifts it, and turning it off enforces nothing hypothetical', async ({ browser }) => {
  const operator = await browserOf(browser, THE_OPERATOR)
  await editorLoaded(operator)
  await field(operator, 'General', 'Dry run').check()
  await saveRules(operator)
  await expect(operator.getByText('DRY RUN — nothing is blocked')).toBeVisible()

  const scanner = clientAt(uniqueIp())
  expect(await scanner.gets('/wp-login.php')).toBe(404)
  expect(await scanner.gets('/')).toBe(200)
  const row = banRow(operator, scanner.key)
  await expect(cells(row).nth(1)).toHaveText('signature (dry)')
  await unblock(operator, scanner.key)
  await expect(row).toHaveCount(0)
  // Lifted for real: the next probe is detected again, and listed again.
  expect(await scanner.gets('/wp-login.php')).toBe(404)
  await expect(cells(row).nth(1)).toHaveText('signature (dry)')

  await revertRules(operator)
  await expect(operator.getByText('DRY RUN — nothing is blocked')).toBeHidden()
  await expect(row).toHaveCount(0)
  expect(await scanner.gets('/')).toBe(200)
  expect(await scanner.gets('/wp-login.php')).toBe(403)
})

test('U10 a range the operator allowlists is exempt and cannot be banned from the form; reverted, both work again', async ({ browser }) => {
  // TEST-NET-1, outside uniqueIp()'s range; .20 and .21 only here.
  const exempt = clientAt('192.0.2.20')
  const later = clientAt('192.0.2.21')
  const operator = await browserOf(browser, THE_OPERATOR)
  await editorLoaded(operator)
  await addLine(operator, 'Allowlist', 'Never-ban CIDRs', '192.0.2.0/24')
  await saveRules(operator)

  await tile(operator, 'exempt').click()
  await expect(operator.locator('#tile-detail')).toBeVisible()
  const exemptions = operator.locator('#tile-detail tbody tr').filter({ hasText: 'allowlist-cidr' }).locator('td').nth(1)
  const before = Number((await exemptions.count()) ? await exemptions.textContent() : 0)
  expect(await exempt.gets('/wp-login.php')).toBe(404)
  expect(await exempt.gets('/')).toBe(200)
  await expect(exemptions).toHaveText(String(before + 2))
  await expect(banRow(operator, exempt.key)).toHaveCount(0)
  await banViaForm(operator, exempt.ip)
  await expect(toast(operator)).toHaveText(`refusing to ban ${exempt.key}: it overlaps allowlisted 192.0.2.0/24`)
  expect(await exempt.gets('/')).toBe(200)

  await revertRules(operator)
  expect(await later.gets('/wp-login.php')).toBe(403)
  await banViaForm(operator, exempt.ip)
  await expect(toast(operator)).toHaveText(`Banned ${exempt.key}`)
  expect(await exempt.gets('/')).toBe(403)
  for (const c of [exempt, later]) await unblock(operator, c.key)
})
