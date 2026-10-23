/* What the tour adds on top of examples/scanner-sim.sh: two manual bans, so the
 * ban table shows the operator's side too. Through the console's own API,
 * idempotent (a ban that is already there is left alone). Documentation
 * addresses only (RFC 5737). */

export const CONSOLE = process.env.E2E_BASE_URL ?? 'http://localhost:9900'
// The examples/ harness's development token (examples/dynamic/scanguard.yml).
export const TOKEN = process.env.SCANGUARD_TOKEN ?? 'dev-token-change-me-0123456789'

export const MANUAL_BANS = [
  { key: '203.0.113.0/24', duration: '168h', reason: 'credential stuffing from a hosting range' },
  { key: '192.0.2.66/32', duration: '0', reason: 'repeat offender' },
]

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(CONSOLE + path, {
    ...init,
    headers: { 'X-Scanguard-Token': TOKEN, 'X-Scanguard-Action': '1', 'Content-Type': 'application/json' },
  })
  if (!res.ok) throw new Error(`[seed] ${init.method ?? 'GET'} ${path}: ${res.status} ${await res.text()}`)
  return (await res.json()) as T
}

export async function seed(): Promise<void> {
  const { bans } = await api<{ bans: { key: string }[] }>('/api/bans')
  for (const ban of MANUAL_BANS) {
    if (bans.some((b) => b.key === ban.key)) continue
    await api('/api/bans', { method: 'POST', body: JSON.stringify(ban) })
  }
}
