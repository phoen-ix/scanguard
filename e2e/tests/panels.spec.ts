import { expect, probe, test, uniqueIp, unlock } from './helpers'

/* The read-out panels: rankings, detectors, configuration, compiled ruleset,
 * header and footer. Against the harness configuration (examples/dynamic/scanguard.yml). */

test('most probed paths and top sources rank what was requested', async ({ page, request }) => {
  const ip = uniqueIp()
  const path = `/e2e-popular-${ip.replace(/\./g, '-')}`
  // One failing path, over and over: tolerated (no ban), but counted.
  for (let i = 0; i < 40; i++) expect(await probe(request, ip, path)).toBe(404)
  await unlock(page)
  await expect(page.locator('#top-paths tbody tr').filter({ hasText: path }).locator('td')).toHaveText([path, '40'])
  await expect(page.locator('#top-sources tbody tr').filter({ hasText: `${ip}/32` }).locator('td')).toHaveText([`${ip}/32`, '40'])
})

test('rules that fired names the detector and the pattern', async ({ page, request }) => {
  expect(await probe(request, uniqueIp(), '/wp-login.php')).toBe(403)
  await unlock(page)
  await expect(page.locator('#top-rules tbody tr').filter({ hasText: 'signature: ' }).filter({ hasText: 'wp-login' })).toHaveCount(1)
  await expect(page.locator('#top-rules-empty')).toBeHidden()
})

test('detectors show which are on and how often each fired', async ({ page, request }) => {
  expect(await probe(request, uniqueIp(), '/admin.php')).toBe(403)
  await unlock(page)
  const chips = page.locator('#detectors .dchip')
  await expect(chips).toHaveCount(9)
  await expect(chips.filter({ hasText: /^rate-abuse$/ })).toHaveAttribute('title', 'disabled')
  // Opt-in, and off in the harness. A count is possible: the rule-editor test turns subnet on for a while.
  await expect(chips.filter({ hasText: /^ua-rotation( · \d+)?$/ })).toHaveAttribute('title', 'disabled')
  await expect(chips.filter({ hasText: /^subnet( · \d+)?$/ })).toHaveAttribute('title', 'disabled')
  await expect(chips.filter({ hasText: /^honeypot · \d+$/ })).toHaveAttribute('title', 'enabled')
})

test('configuration and compiled ruleset show what is in force', async ({ page }) => {
  await unlock(page)
  const kv = (term: string) => page.locator('#config dt').filter({ hasText: new RegExp(`^${term}$`) }).locator('xpath=following-sibling::dd[1]')
  await expect(kv('state backend')).toHaveText('file')
  await expect(kv('observe responses')).toHaveText('yes')
  await expect(kv('ban key width')).toHaveText('IPv4 /32 · IPv6 /64')
  await expect(kv('trusted proxies')).toHaveText('2 · X-Real-Ip')
  await expect(kv('reject status')).toHaveText('403')
  await expect(kv('escalation')).toHaveText('1h → 1d → 7d → permanent')
  await expect(kv('tarpit')).toHaveText('off')
  await expect(kv('crawler policy')).toHaveText('ignore')
  await expect(kv('console on detection routes')).toHaveText('no — this router only')
  await expect(kv('notifications')).toHaveText('chat, webhooks')

  const group = (name: string) => page.locator('#rules > div').filter({ has: page.getByRole('heading', { name: new RegExp(`^${name} \\(\\d+\\)$`) }) })
  await expect(group('Honeypots').locator('li')).toHaveText(['/.env.backup', '/admin.php', '/wp-content/uploads/shell.php'])
  await expect(group('Trusted proxies').locator('li')).toHaveText(['127.0.0.1/32', '172.16.0.0/12'])
  await expect(group('Allowlisted CIDRs').locator('li')).toHaveText(['127.0.0.1/32'])
  await expect(group('Signatures').locator('li').first()).toBeVisible()
})

test('header and footer name the instance and its state backend', async ({ page }) => {
  await unlock(page)
  await expect(page.locator('#subtitle')).toHaveText(/^default · up \S+$/)
  await expect(page.getByRole('contentinfo')).toHaveText('scanguard · default · state: file')
  await expect(page.getByText('DRY RUN — nothing is blocked')).toBeHidden()
  await expect(page.locator('#readonly')).toBeHidden()
})
