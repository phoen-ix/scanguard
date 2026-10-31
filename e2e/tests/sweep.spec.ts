import { CONSOLE, CONSOLES, PANELS, TOKEN, expect, test, unlock } from './helpers'

/* Breadth: every admin route as every kind of caller, and every console page
 * as a guest and as its operator. The routes are serveAdmin's switch in
 * admin.go (COVERAGE.md has the extraction command). */

const ASSETS = [
  ['/', 'text/html'],
  ['/index.html', 'text/html'],
  ['/app.css', 'text/css'],
  ['/app.js', 'application/javascript'],
]
const API = ['/api/state', '/api/events', '/api/sources', '/api/bans', '/api/rules', '/api/rules/compiled', '/api/health']
const CALLERS: Record<string, Record<string, string>> = {
  guest: {},
  'a wrong token': { 'X-Scanguard-Token': 'not-the-token-0123456789' },
  'the token': { 'X-Scanguard-Token': TOKEN },
  'a Bearer token': { Authorization: `Bearer ${TOKEN}` },
}
const authorised = (caller: string) => caller === 'the token' || caller === 'a Bearer token'

test.describe('admin routes', () => {
  for (const [path, type] of ASSETS) {
    test(`${path} is served to every caller, with the console's security headers`, async ({ request }) => {
      for (const headers of Object.values(CALLERS)) {
        const res = await request.get(CONSOLE + path, { headers })
        expect(res.status(), path).toBe(200)
        expect(res.headers()['content-type']).toContain(type)
        expect(res.headers()['content-security-policy']).toContain("default-src 'none'")
        expect(res.headers()['cache-control']).toContain('no-store')
        expect(res.headers()['x-content-type-options']).toBe('nosniff')
        expect(res.headers()['referrer-policy']).toBe('no-referrer')
      }
      const head = await request.head(CONSOLE + path)
      expect(head.status()).toBe(200)
      const post = await request.post(CONSOLE + path)
      expect(post.status()).toBe(405)
      expect(await post.json()).toEqual({ error: 'GET only' })
    })
  }

  for (const path of API) {
    for (const [caller, headers] of Object.entries(CALLERS)) {
      test(`GET ${path} as ${caller}`, async ({ request }) => {
        const res = await request.get(CONSOLE + path, { headers })
        if (authorised(caller)) {
          expect(res.status()).toBe(200)
          expect(res.headers()['content-type']).toContain('application/json')
          await res.json()
        } else {
          expect(res.status()).toBe(401)
          expect(res.headers()['www-authenticate']).toBe('Bearer realm="scanguard"')
          expect((await res.json()).error).toContain('authentication required')
        }
        expect(res.headers()['content-security-policy']).toContain("frame-ancestors 'none'")
      })
    }
  }

  test('an unknown endpoint is a 404 for the operator and a 401 for anyone else', async ({ request }) => {
    const known = await request.get(`${CONSOLE}/api/nope`, { headers: CALLERS['the token'] })
    expect(known.status()).toBe(404)
    expect(await known.json()).toEqual({ error: 'no such endpoint' })
    expect((await request.get(`${CONSOLE}/api/nope`)).status()).toBe(401)
  })

  for (const [method, path, allowed] of [
    ['POST', '/api/state', 'GET only'],
    ['POST', '/api/events', 'GET only'],
    ['POST', '/api/sources', 'GET only'],
    ['POST', '/api/rules/compiled', 'GET only'],
    ['PATCH', '/api/bans', 'GET, POST or DELETE'],
    ['PATCH', '/api/rules', 'GET, PUT or DELETE'],
  ]) {
    test(`${method} ${path} is refused with 405`, async ({ request }) => {
      const res = await request.fetch(CONSOLE + path, { method, headers: { ...CALLERS['the token'], 'X-Scanguard-Action': '1' } })
      expect(res.status()).toBe(405)
      expect(await res.json()).toEqual({ error: allowed })
    })
  }

  for (const [method, path] of [
    ['POST', '/api/bans'],
    ['DELETE', '/api/bans?key=198.18.0.1'],
    ['PUT', '/api/rules'],
    ['DELETE', '/api/rules'],
  ]) {
    test(`${method} ${path.split('?')[0]} without the anti-CSRF header is refused with 403`, async ({ request }) => {
      const res = await request.fetch(CONSOLE + path, { method, headers: CALLERS['the token'], data: {} })
      expect(res.status()).toBe(403)
      expect(await res.json()).toEqual({ error: 'mutations require the X-Scanguard-Action header' })
    })
  }

  test('malformed requests are refused with the reason', async ({ request }) => {
    const headers = { ...CALLERS['the token'], 'X-Scanguard-Action': '1', 'Content-Type': 'application/json' }
    const events = await request.get(`${CONSOLE}/api/events?kind=detect`, { headers })
    expect(events.status()).toBe(400)
    expect(await events.json()).toEqual({ error: 'kind must be one of ban, unban, reject' })

    const ban = await request.post(`${CONSOLE}/api/bans`, { headers, data: '{"key":' })
    expect(ban.status()).toBe(400)
    expect(await ban.json()).toEqual({ error: 'invalid JSON body' })

    const unknown = await request.put(`${CONSOLE}/api/rules`, { headers, data: { detectors: { nope: true } } })
    expect(unknown.status()).toBe(400)
    expect((await unknown.json()).error).toContain('the submitted rule set could not be read')

    // clientIP, store, admin and notify are not console-editable (overrides.go).
    for (const section of ['clientIP', 'store', 'admin', 'notify']) {
      const res = await request.put(`${CONSOLE}/api/rules`, { headers, data: { [section]: {} } })
      expect(res.status(), section).toBe(400)
    }
    expect((await (await request.get(`${CONSOLE}/api/rules`, { headers })).json()).overridden).toEqual([])
  })
})

for (const c of CONSOLES) {
  test.describe(`${c.name} console (${c.base})`, () => {
    // The orphan console's rule editor has no detector to edit: a 503 by design.
    test.use({ allowed5xx: c.name === 'orphan' ? /\/api\/rules$/ : null })

    test('as a guest: the gate, nothing else', async ({ page }) => {
      await page.goto(c.base)
      await expect(page.getByRole('heading', { name: 'scanguard' })).toBeVisible()
      await expect(page.getByLabel('Access token')).toBeFocused()
      await expect(page.getByRole('heading', { name: /^Active bans/ })).toHaveCount(0)
    })

    test('as its operator: every panel', async ({ page }) => {
      await unlock(page, c)
      for (const name of PANELS) await expect(page.getByRole('heading', { name: new RegExp(`^${name}`) })).toBeVisible()
      await expect(page.locator('#tiles').getByRole('button')).toHaveCount(6)
      await expect(page.locator('#footer-instance')).toHaveText(c.name === 'main' ? 'default' : `e2e-${c.base.slice(1, -1)}`)
    })
  })
}
