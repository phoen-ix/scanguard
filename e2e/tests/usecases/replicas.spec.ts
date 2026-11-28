import {
  AT_REPLICA_A,
  AT_REPLICA_B,
  addLine,
  banRow,
  banViaForm,
  browserOf,
  clientAt,
  editedHere,
  editorLoaded,
  expect,
  given,
  revertRules,
  saveRules,
  test,
  toast,
  unblock,
  uniqueIp,
} from './lib'

/* Two Traefik replicas sharing one Redis, an operator at each one's console
 * (COVERAGE.c.md, U4, U5). A replica re-reads Redis every 30 s; what the
 * operator at the other one sees is what that replica enforces, so each step
 * waits for their screen, then asks as the client. */

const REFRESH = { timeout: 45_000 }
test.setTimeout(120_000)
test.afterEach(() => given.fileRules(AT_REPLICA_A))

test('U4 a ban from replica A\'s console is refused on B; lifted from B\'s console, A serves the address again', async ({ browser }) => {
  const atA = await browserOf(browser, AT_REPLICA_A)
  const atB = await browserOf(browser, AT_REPLICA_B)
  const visitor = clientAt(uniqueIp())

  await banViaForm(atA, visitor.ip, '1h', 'e2e U4')
  await expect(toast(atA)).toHaveText(`Banned ${visitor.key}`)
  expect(await visitor.gets('/', AT_REPLICA_A.site)).toBe(403)
  await expect(banRow(atB, visitor.key)).toHaveCount(1, REFRESH)
  expect(await visitor.gets('/', AT_REPLICA_B.site)).toBe(403)

  await unblock(atB, visitor.key)
  expect(await visitor.gets('/', AT_REPLICA_B.site)).toBe(200)
  await expect(banRow(atA, visitor.key)).toHaveCount(0, REFRESH)
  expect(await visitor.gets('/', AT_REPLICA_A.site)).toBe(200)
})

test('U5 a rule saved on replica A is in B\'s editor and enforced by B; reverted from B, A runs the file again', async ({ browser }) => {
  const trap = `/e2e-uc-redis-trap-${Date.now()}`
  expect(await clientAt(uniqueIp()).gets(trap, AT_REPLICA_B.site)).toBe(404)
  const atA = await browserOf(browser, AT_REPLICA_A)
  const atB = await browserOf(browser, AT_REPLICA_B)
  await editorLoaded(atA)
  await editorLoaded(atB)

  await addLine(atA, 'Honeypots', 'Trap paths', trap)
  await saveRules(atA)
  await expect(editedHere(atB)).toBeVisible(REFRESH)
  await expect(atB.locator('#rules li').filter({ hasText: new RegExp(`^${trap}$`) })).toHaveCount(1)
  expect(await clientAt(uniqueIp()).gets(trap, AT_REPLICA_B.site)).toBe(403)

  await revertRules(atB)
  await expect(editedHere(atB)).toBeHidden()
  await expect(editedHere(atA)).toBeHidden(REFRESH)
  expect(await clientAt(uniqueIp()).gets(trap, AT_REPLICA_A.site)).toBe(404)
})
