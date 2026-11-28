import { execFile } from 'node:child_process'
import { renameSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { test as base, type Browser, type BrowserContext, type Page } from '@playwright/test'

import {
  CONSOLE,
  CONSOLES,
  MAIN,
  REPLICA_A,
  REPLICA_B,
  REPLICA_TOKEN,
  RULE_GROUPS,
  SITE,
  SSO,
  banRow,
  banViaForm,
  cells,
  consolesAnswer,
  eventRows,
  expect,
  ruleGroup,
  tile,
  toast,
  uniqueIp,
} from '../helpers'

/* Use cases: a chain in which one person hands something to another - a ban,
 * an unblock, a rule set, a token - and the next one USES it (COVERAGE.c.md).
 * The people are whoever runs scanguard (its config file, its Traefik), the
 * console's operators, and the clients it judges.
 *
 * The other specs set their preconditions up through the API and planted the
 * token where the gate keeps it, so what one person produced was rarely what
 * the next one met: a rule edit "on replica A" was a PUT, an unblock that told
 * the webhook consumer was a curl, a rotated token was a stale one planted in
 * sessionStorage. Of 16 hand-overs, 4 were followed to the end (audit, 2026-11).
 *
 * The rules here, pinned by hygiene_test.go (TestAUseCaseReachesTheServerOnlyAsAPersonOrAClient):
 * - Every operator acts in their own browser and signs in at the console's
 *   gate - with the token typed, or behind the auth proxy with Unlock.
 * - What is handed over is the SAME thing that is used: the token the runner
 *   wrote into the config, the row on the operator's screen.
 * - The outcome is read on the affected person's screen, or in what the
 *   client was answered and what the webhook consumer was sent.
 * - A use-case spec calls no API. Background facts a chain is not about come
 *   from `given` below, the one place that does. */

export { banRow, banViaForm, cells, eventRows, expect, ruleGroup, tile, toast, uniqueIp }

/* Every browser a test opens, closed after it; any page error or 5xx answer
 * on one of them fails the test. */
const contexts: BrowserContext[] = []
const problems: string[] = []
export const test = base.extend<{ watched: void }>({
  watched: [
    async ({}, use) => {
      problems.length = 0
      await use()
      try {
        expect(problems).toEqual([])
      } finally {
        for (const c of contexts.splice(0)) await c.close()
      }
    },
    { auto: true },
  ],
})

/** A console and the token its operator was given ('' behind the auth proxy). */
export interface Operator { url: string; token: string; site: string }
export const THE_OPERATOR: Operator = { url: CONSOLE + MAIN.base, token: MAIN.token, site: SITE }
/** Signed in at the stand-in auth proxy as operator@e2e.example (fixtures/consoles.yml). */
export const THE_SSO_OPERATOR: Operator = { url: CONSOLE + SSO.base, token: '', site: SITE }
export const AT_REPLICA_A: Operator = { url: `${REPLICA_A.console}/`, token: REPLICA_TOKEN, site: REPLICA_A.site }
export const AT_REPLICA_B: Operator = { url: `${REPLICA_B.console}/`, token: REPLICA_TOKEN, site: REPLICA_B.site }

/** A person's own browser, signed in at the gate when `who` is given. */
export async function browserOf(browser: Browser, who?: Operator): Promise<Page> {
  const context = await browser.newContext()
  contexts.push(context)
  const page = await context.newPage()
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`))
  page.on('response', (r) => { if (r.status() >= 500) problems.push(`${r.status()} ${r.url()}`) })
  if (who) await signIn(page, who)
  return page
}

/** The gate as a person uses it: the token typed (none behind the auth proxy), Unlock. */
export async function signIn(page: Page, who: Operator): Promise<void> {
  await page.goto(who.url)
  await page.getByLabel('Access token').fill(who.token)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.locator('#subtitle')).toContainText(' · up ')
}

/** A client of the protected site at its own address, as the trusted proxy in
 * front of scanguard names it (X-Real-Ip). Scanguard judges the address; what
 * the client sees is the status it is answered. Not a browser: a browser's
 * cache answers a page it was once served without asking the server. */
export function clientAt(ip: string) {
  return {
    ip,
    key: `${ip}/32`,
    async gets(path: string, site = SITE): Promise<number> {
      const r = await fetch(site + path, { headers: { 'X-Real-Ip': ip }, redirect: 'manual' })
      await r.text()
      return r.status
    },
  }
}

/** What the webhook consumer (the harness's sink, examples/hookrecv.py) was
 * sent about `key`, oldest first: "<kind>" or "<kind> by <actor>". */
export async function delivered(key: string): Promise<string[]> {
  type Received = { path: string; json: { event?: { kind: string; key: string; actor?: string } } | null }
  const all = (await (await fetch(`${process.env.E2E_HOOKS_URL ?? 'http://localhost:8899'}/received`)).json()) as Received[]
  return all.flatMap((x) => {
    const e = x.path === '/ban' ? x.json?.event : undefined
    return e?.key === key ? [e.actor ? `${e.kind} by ${e.actor}` : e.kind] : []
  })
}

/** How long the operator's console says its Traefik has been up, in seconds. */
export async function uptimeOf(page: Page): Promise<number> {
  await expect(page.locator('#subtitle')).toContainText(' · up ')
  const [, h = '0', m = '0', s = '0'] = / up (?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec((await page.locator('#subtitle').textContent()) ?? '') ?? []
  return Number(h) * 3600 + Number(m) * 60 + Number(s)
}

/* The rule editor. */
export const field = (page: Page, group: string, label: string) => ruleGroup(page, group).getByLabel(label, { exact: true })
export const editedHere = (page: Page) => page.getByText('edited here', { exact: true })
export const unsaved = (page: Page) => page.getByText('unsaved', { exact: true })
export async function editorLoaded(page: Page): Promise<void> {
  await expect(page.locator('#rules-form .rule-group')).toHaveCount(RULE_GROUPS.length)
}
/** Types one more line into a list field, after what it holds. */
export async function addLine(page: Page, group: string, label: string, line: string): Promise<void> {
  const f = field(page, group, label)
  await f.fill(`${await f.inputValue()}\n${line}`)
}
export async function saveRules(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Save and apply' }).click()
  await expect(unsaved(page)).toBeHidden()
  await expect(toast(page)).toHaveText('Rules applied')
}
/** Revert, and OK on the question it asks. */
export async function revertRules(page: Page): Promise<void> {
  page.once('dialog', (d) => void d.accept())
  await page.getByRole('button', { name: 'Revert to file config' }).click()
  await expect(toast(page)).toHaveText('Reverted to the file configuration')
}
export async function unblock(page: Page, key: string): Promise<void> {
  await banRow(page, key).getByRole('button', { name: 'unblock' }).click()
  await expect(toast(page)).toHaveText(`Unblocked ${key}`)
}

/* A second console for the main instance, at /rotate/, in a file of its own
 * that Traefik's file provider watches. Written to a temporary name and
 * renamed, so Traefik never reads half a file. */
const SECOND_CONSOLE = fileURLToPath(new URL('../../../examples/dynamic/zz-e2e-rotate.yml', import.meta.url))
function writeSecondConsole(token: string): void {
  writeFileSync(`${SECOND_CONSOLE}.tmp`, `http:
  middlewares:
    e2e-rotate-strip: { stripPrefix: { prefixes: [/rotate] } }
    e2e-rotate-ui:
      plugin:
        scanguard: { instanceName: default, uiMode: true, admin: { enabled: true, token: ${token} } }
  routers:
    e2e-rotate-console:
      rule: PathPrefix(\`/rotate/\`)
      entryPoints: [admin]
      service: noop
      priority: 200
      middlewares: [e2e-rotate-strip, e2e-rotate-ui]
`)
  renameSync(`${SECOND_CONSOLE}.tmp`, SECOND_CONSOLE)
}

/** Background facts, made through the API or the config: what a use case
 * needs but is not about. Never the act under test, and never the check of
 * its outcome. */
export const given = {
  /** The console runs Traefik's file configuration: nothing saved in its editor. */
  fileRules: async (who: Operator = THE_OPERATOR): Promise<void> => {
    const r = await fetch(`${who.url}api/rules`, { method: 'DELETE', headers: { 'X-Scanguard-Token': who.token, 'X-Scanguard-Action': '1' } })
    if (!r.ok) throw new Error(`[e2e] could not revert the rules at ${who.url}: ${r.status}`)
  },
  /** A second console for the main instance at /rotate/, with `token`, answering. */
  secondConsole: async (token: string): Promise<Operator> => {
    writeSecondConsole(token)
    await consolesAnswer([{ name: 'second', base: '/rotate/', token }])
    return { url: `${CONSOLE}/rotate/`, token, site: SITE }
  },
  noSecondConsole: (): void => rmSync(SECOND_CONSOLE, { force: true }),
}

/** What the person who runs scanguard does: edit its config, restart its Traefik. */
export const theRunner = {
  /** Writes a new token into the second console's config; Traefik reloads it by itself. */
  rotatesToken: (token: string): void => writeSecondConsole(token),
  /** `docker compose restart traefik` on the harness scripts/e2e.sh started; done once every console answers again. */
  restartsTraefik: async (): Promise<void> => {
    if (!process.env.COMPOSE_FILE) throw new Error('[e2e] run through scripts/e2e.sh: it names the harness to restart')
    await promisify(execFile)('docker', ['compose', 'restart', 'traefik'])
    await consolesAnswer(CONSOLES)
  },
}
