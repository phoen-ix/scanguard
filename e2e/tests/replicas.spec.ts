import { type APIRequestContext, type Page } from '@playwright/test'

import { banRow, banViaForm, expect, test, toast, uniqueIp } from './helpers'

/* Two Traefik replicas sharing one Redis (examples/docker-compose.e2e.yml,
 * e2e/fixtures/replicas/): what one replica's console or detector does, the
 * other enforces after its next refresh from Redis - every 30 s. */

const A = { site: process.env.E2E_REPLICA_A_SITE ?? 'http://localhost:8801', console: process.env.E2E_REPLICA_A_CONSOLE ?? 'http://localhost:9901' }
const B = { site: process.env.E2E_REPLICA_B_SITE ?? 'http://localhost:8802', console: process.env.E2E_REPLICA_B_CONSOLE ?? 'http://localhost:9902' }
const TOKEN = 'e2e-redis-token-0123456789'
const SYNC = { timeout: 45_000, intervals: [1_000] }

test.setTimeout(120_000)

const status = async (request: APIRequestContext, site: string, ip: string, path: string) =>
  (await request.get(site + path, { headers: { 'X-Real-Ip': ip }, maxRedirects: 0 })).status()

const rules = (request: APIRequestContext, base: string, method = 'GET', data?: unknown) =>
  request.fetch(`${base}/api/rules`, { method, data, headers: { 'X-Scanguard-Token': TOKEN, 'X-Scanguard-Action': '1' } })

async function open(page: Page, base: string): Promise<void> {
  await page.addInitScript((t) => sessionStorage.setItem('scanguard.token', t), TOKEN)
  await page.goto(`${base}/`)
  await expect(page.locator('#subtitle')).toContainText('e2e-redis · up ')
  await expect(page.locator('#footer-backend')).toHaveText('redis')
}

test('a ban from one console blocks on the other replica, and so does lifting it', async ({ page, request }) => {
  const ip = uniqueIp()
  await open(page, A.console)
  await banViaForm(page, ip, '1h', 'e2e replicated')
  await expect(toast(page)).toHaveText(`Banned ${ip}/32`)
  expect(await status(request, A.site, ip, '/')).toBe(403)
  await expect.poll(() => status(request, B.site, ip, '/'), SYNC).toBe(403)

  await open(page, B.console)
  const row = banRow(page, `${ip}/32`)
  await row.getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${ip}/32`)
  expect(await status(request, B.site, ip, '/')).not.toBe(403)
  await expect.poll(() => status(request, A.site, ip, '/'), SYNC).not.toBe(403)
})

test('a detection on one replica bans the source on the other', async ({ request }) => {
  const ip = uniqueIp()
  expect(await status(request, A.site, ip, '/e2e-redis/trap')).toBe(403)
  await expect.poll(() => status(request, B.site, ip, '/'), SYNC).toBe(403)
})

test('a rule edit on one console reaches the other replica, and so does reverting it', async ({ page, request }) => {
  const trap = `/e2e-redis/trap-${Date.now()}`
  try {
    const { effective } = await (await rules(request, A.console)).json()
    effective.detectors.honeypots.paths.push(trap)
    expect((await rules(request, A.console, 'PUT', effective)).status()).toBe(200)
    await expect.poll(async () => status(request, B.site, uniqueIp(), trap), SYNC).toBe(403)
    await open(page, B.console)
    await expect(page.getByText('edited here', { exact: true })).toBeVisible()
  } finally {
    await rules(request, A.console, 'DELETE')
  }
  await expect.poll(async () => status(request, B.site, uniqueIp(), trap), SYNC).toBe(404)
})
