import {
  THE_OPERATOR,
  THE_SSO_OPERATOR,
  banRow,
  banViaForm,
  browserOf,
  cells,
  clientAt,
  delivered,
  eventRows,
  expect,
  test,
  toast,
  unblock,
  uniqueIp,
} from './lib'

/* Bans, from the hand that makes or lifts one to the client it judges and the
 * webhook consumer it tells (COVERAGE.c.md, U2, U3, U8). */

test('U2 a scanner a signature banned is unblocked by the operator and served; probing again starts at the first rung', async ({ browser }) => {
  const operator = await browserOf(browser, THE_OPERATOR)
  const scanner = clientAt(uniqueIp())
  expect(await scanner.gets('/wp-login.php')).toBe(403)
  expect(await scanner.gets('/')).toBe(403)

  const row = banRow(operator, scanner.key)
  await expect(cells(row).nth(1)).toHaveText('signature')
  await expect(cells(row).nth(2)).toContainText('wp-login')
  await expect(cells(row).nth(6)).toHaveText('in 1h')
  await unblock(operator, scanner.key)
  await expect(row).toHaveCount(0)
  expect(await scanner.gets('/')).toBe(200)

  // Unblock forgives the offence: banned again, it is a first offence, not the ladder's next rung (24h).
  expect(await scanner.gets('/wp-login.php')).toBe(403)
  await expect(cells(row).nth(6)).toHaveText('in 1h')
})

test('U3 an address the operator bans from the form is refused until they unblock it', async ({ browser }) => {
  const operator = await browserOf(browser, THE_OPERATOR)
  const visitor = clientAt(uniqueIp())
  expect(await visitor.gets('/')).toBe(200)

  await banViaForm(operator, visitor.ip, undefined, 'e2e U3')
  await expect(toast(operator)).toHaveText(`Banned ${visitor.key}`)
  expect(await visitor.gets('/')).toBe(403)
  expect(await visitor.gets('/')).toBe(403)
  // The operator sees each refusal counted on the row.
  const row = banRow(operator, visitor.key)
  await expect(cells(row)).toHaveText([visitor.key, 'manual', 'e2e U3', '', '', '2', 'in 1h', 'unblock'])

  await unblock(operator, visitor.key)
  await expect(row).toHaveCount(0)
  expect(await visitor.gets('/')).toBe(200)
})

test('U8 an unblock behind the auth proxy reaches the webhook consumer with the key and who lifted it', async ({ browser }) => {
  const operator = await browserOf(browser, THE_SSO_OPERATOR)
  const scanner = clientAt(uniqueIp())
  expect(await scanner.gets('/e2e-sso/trap')).toBe(403)
  await expect.poll(() => delivered(scanner.key)).toEqual(['ban'])

  await expect(banRow(operator, scanner.key)).toHaveCount(1)
  await unblock(operator, scanner.key)
  expect(await scanner.gets('/e2e-sso/')).toBe(404)
  await expect.poll(() => delivered(scanner.key)).toEqual(['ban', 'unban by operator@e2e.example'])
  // The operator's own feed names them the same way.
  await expect(eventRows(operator, scanner.key).filter({ has: operator.locator('td.k-unban') }).locator('td').nth(6)).toHaveText('operator@e2e.example')
})
