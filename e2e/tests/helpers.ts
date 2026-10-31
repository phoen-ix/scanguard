import { expect, test as base, type APIRequestContext, type Locator, type Page } from '@playwright/test'

import { CONSOLE, CONSOLES, MAIN, SITE, type Console } from './consoles'

export * from './consoles'

export const PANELS = [
  'Active bans', 'Most probed paths', 'Top sources', 'Rules that fired', 'Live activity',
  'Detectors', 'Configuration', 'Compiled ruleset', 'Rule editor',
]

export const TILES = [
  { label: 'requests seen', title: 'Requests seen', cols: ['host', 'requests'] },
  { label: 'blocked', title: 'Blocked requests', cols: ['time', 'source', 'path', 'rule'] },
  { label: 'detections', title: 'Detections', cols: ['time', 'source', 'detector', 'path'] },
  { label: 'active bans', title: 'Active bans', cols: ['source', 'detector', 'rule', 'expires'] },
  { label: 'tracked sources', title: 'Tracked sources', cols: ['source', 'last seen', 'offences', 'distinct bad paths'] },
  { label: 'exempt', title: 'Exempt requests', cols: ['reason', 'requests'] },
]

/* Source addresses: consecutive from a random start in 198.18.0.0/15 (RFC 2544,
 * never routed), so every test bans its own sources and reruns against the same
 * harness do not meet each other's bans. */
let nextIp = Math.floor(Math.random() * 120_000)
export function uniqueIp(): string {
  const n = (nextIp++ % 130_816) + 256
  return `198.${18 + (n >> 16)}.${(n >> 8) & 255}.${n & 255}`
}

/** A request to the protected site as `ip` (none: the host itself, a trusted proxy). */
export async function probe(request: APIRequestContext, ip: string | null, path: string): Promise<number> {
  const res = await request.get(SITE + path, { headers: ip ? { 'X-Real-Ip': ip } : {}, maxRedirects: 0 })
  return res.status()
}

/** The console API with the operator's credentials; throws on an error status. */
export async function api<T = any>(
  request: APIRequestContext,
  path: string,
  { method = 'GET', data, c = MAIN as Console }: { method?: string; data?: unknown; c?: Console } = {},
): Promise<T> {
  const headers: Record<string, string> = { 'X-Scanguard-Action': '1' }
  if (c.token) headers['X-Scanguard-Token'] = c.token
  const res = await request.fetch(CONSOLE + c.base.slice(0, -1) + path, { method, data, headers })
  if (!res.ok()) throw new Error(`[e2e] ${method} ${path}: ${res.status()} ${await res.text()}`)
  return (await res.json()) as T
}

/* Every test fails on an uncaught page error or a 5xx answer to the page. The
 * orphan console's rule editor answers 503 by design; its tests allow that. */
export const test = base.extend<{ allowed5xx: RegExp | null; guard: void }>({
  allowed5xx: [null, { option: true }],
  guard: [
    async ({ page, allowed5xx }, use) => {
      const problems: string[] = []
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`))
      page.on('response', (r) => {
        if (r.status() >= 500 && !allowed5xx?.test(r.url())) problems.push(`${r.status()} ${r.url()}`)
      })
      await use()
      expect(problems).toEqual([])
    },
    { auto: true },
  ],
})
export { expect }

/** Opens console `c` already unlocked (the token where the gate stores it) and waits for its first paint. */
export async function unlock(page: Page, c: Console = MAIN): Promise<void> {
  await page.addInitScript((t) => sessionStorage.setItem('scanguard.token', t), c.token)
  await page.goto(c.base)
  await expect(page.locator('#app')).toBeVisible()
  await expect(page.locator('#subtitle')).toContainText(' · up ')
}

export const bansTable = (page: Page) => page.locator('#bans')
export const banRow = (page: Page, key: string) => page.locator('#bans tbody tr').filter({ hasText: key })
export const eventRows = (page: Page, text: string) => page.locator('#events tbody tr').filter({ hasText: text })
export const toast = (page: Page) => page.getByRole('status')
export const tile = (page: Page, label: string) => page.locator('#tiles').getByRole('button', { name: new RegExp(`${label}$`) })
export const ruleGroup = (page: Page, title: string): Locator =>
  page.locator('#rules-form .rule-group').filter({ has: page.getByRole('heading', { name: title, exact: true }) })
export const cells = (row: Locator) => row.locator('td')

/** Bans through the console form. */
export async function banViaForm(page: Page, key: string, duration?: string, reason?: string): Promise<void> {
  await page.getByLabel('Address or CIDR to ban').fill(key)
  if (duration !== undefined) await page.getByLabel('Ban duration').fill(duration)
  if (reason !== undefined) await page.getByLabel('Ban reason').fill(reason)
  await page.getByRole('button', { name: 'Ban', exact: true }).click()
}
