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
  theRunner,
  toast,
  unblock,
  uniqueIp,
  uptimeOf,
} from './lib'

/* What the person who runs scanguard does - rotate a console's token in the
 * config, restart Traefik - and what the operators and clients meet next
 * (COVERAGE.c.md, U6, U11, U12). */

test.setTimeout(120_000)
test.afterEach(() => given.fileRules())

test('U6 a token rotated in the config sends the open session back to the gate; the new one gets in, the old one never again', async ({ browser }) => {
  const [before, after] = ['one', 'two'].map((n) => `e2e-rotate-${n}-${Date.now()}`)
  try {
    const team = await given.secondConsole(before)
    const operator = await browserOf(browser, team)

    theRunner.rotatesToken(after)
    await expect(operator.getByRole('alert')).toHaveText('That token was not accepted.', { timeout: 30_000 })
    await expect(operator.locator('#app')).toBeHidden()
    await expect(operator.getByLabel('Access token')).toHaveValue('')

    // The old one, once more out of habit, then the one the runner handed over.
    await operator.getByLabel('Access token').fill(before)
    await operator.getByRole('button', { name: 'Unlock' }).click()
    await expect(operator.getByRole('alert')).toHaveText('That token was not accepted.')
    await expect(operator.getByLabel('Access token')).toHaveValue('')
    await operator.getByLabel('Access token').fill(after)
    await operator.getByRole('button', { name: 'Unlock' }).click()
    await expect(operator.locator('#subtitle')).toContainText('default · up ')
    await expect(operator.getByRole('alert')).toHaveCount(0)
  } finally {
    given.noSecondConsole()
  }
})

test('U11 a rule the operator saved is still in their editor and still enforced after the runner restarts Traefik', async ({ browser }) => {
  const trap = `/e2e-uc-restart-trap-${Date.now()}`
  const operator = await browserOf(browser, THE_OPERATOR)
  await editorLoaded(operator)
  await addLine(operator, 'Honeypots', 'Trap paths', trap)
  await saveRules(operator)
  const up = await uptimeOf(operator)

  await theRunner.restartsTraefik()
  await operator.reload()
  // The header says it is a new Traefik.
  expect(await uptimeOf(operator)).toBeLessThan(up)
  await editorLoaded(operator)
  await expect(editedHere(operator)).toBeVisible()
  await expect(field(operator, 'Honeypots', 'Trap paths')).toHaveValue(new RegExp(`${trap}$`))
  expect(await clientAt(uniqueIp()).gets(trap)).toBe(403)

  // And it still reverts.
  await revertRules(operator)
  expect(await clientAt(uniqueIp()).gets(trap)).toBe(404)
})

test('U12 the bans the operator sees survive the runner\'s Traefik restart: the same rows, still refused, still liftable', async ({ browser }) => {
  const operator = await browserOf(browser, THE_OPERATOR)
  const visitor = clientAt(uniqueIp())
  const scanner = clientAt(uniqueIp())
  await banViaForm(operator, visitor.ip, '168h', 'e2e U12')
  await expect(toast(operator)).toHaveText(`Banned ${visitor.key}`)
  expect(await scanner.gets('/wp-login.php')).toBe(403)
  const manual = [visitor.key, 'manual', 'e2e U12', '', '', '0', 'in 7d', 'unblock']
  await expect(cells(banRow(operator, visitor.key))).toHaveText(manual)
  await expect(cells(banRow(operator, scanner.key)).nth(1)).toHaveText('signature')
  const up = await uptimeOf(operator)

  await theRunner.restartsTraefik()
  await operator.reload()
  expect(await uptimeOf(operator)).toBeLessThan(up)
  await expect(cells(banRow(operator, visitor.key))).toHaveText(manual)
  await expect(cells(banRow(operator, scanner.key)).nth(1)).toHaveText('signature')
  expect(await visitor.gets('/')).toBe(403)
  expect(await scanner.gets('/')).toBe(403)

  await unblock(operator, visitor.key)
  expect(await visitor.gets('/')).toBe(200)
})
