/* Where the harness is, and its four consoles: the harness's own plus the three
 * from fixtures/consoles.yml. No Playwright import, so global-setup can use it. */
export const CONSOLE = process.env.E2E_BASE_URL ?? 'http://localhost:9900'
export const SITE = process.env.E2E_SITE_URL ?? 'http://localhost:8800'
// The examples/ harness's development token (examples/dynamic/scanguard.yml).
export const TOKEN = process.env.SCANGUARD_TOKEN ?? 'dev-token-change-me-0123456789'

export const CONSOLES = [
  { name: 'main', base: '/', token: TOKEN },
  { name: 'read-only', base: '/ro/', token: 'e2e-readonly-token-0123456789' },
  { name: 'SSO', base: '/sso/', token: '' },
  { name: 'orphan', base: '/orphan/', token: 'e2e-orphan-token-0123456789' },
] as const
export const [MAIN, RO, SSO, ORPHAN] = CONSOLES
export type Console = (typeof CONSOLES)[number]

/* The two Traefik replicas sharing a Redis (examples/docker-compose.e2e.yml). */
export const REPLICA_TOKEN = 'e2e-redis-token-0123456789' // fixtures/replicas/replicas.yml
export const REPLICA_A = { site: process.env.E2E_REPLICA_A_SITE ?? 'http://localhost:8801', console: process.env.E2E_REPLICA_A_CONSOLE ?? 'http://localhost:9901' }
export const REPLICA_B = { site: process.env.E2E_REPLICA_B_SITE ?? 'http://localhost:8802', console: process.env.E2E_REPLICA_B_CONSOLE ?? 'http://localhost:9902' }

/** Resolves once each console in `list` answers its health check: the ones
 * Traefik's file provider adds at the start of the run, and all of them again
 * after a Traefik restart. */
export async function consolesAnswer(list: readonly { name: string; base: string; token: string }[]): Promise<void> {
  const deadline = Date.now() + 60_000
  for (const c of list) {
    const headers: Record<string, string> = c.token ? { 'X-Scanguard-Token': c.token } : {}
    while ((await fetch(`${CONSOLE}${c.base}api/health`, { headers }).catch(() => null))?.status !== 200) {
      if (Date.now() > deadline) throw new Error(`[e2e] the ${c.name} console at ${c.base} did not answer; is the harness running from this checkout?`)
      await new Promise((r) => setTimeout(r, 500))
    }
  }
}
