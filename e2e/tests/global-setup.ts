import { copyFileSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { CONSOLE, CONSOLES } from './consoles'

/* Adds the read-only, SSO and orphan consoles (fixtures/consoles.yml) to the
 * running harness through Traefik's watched file provider, waits until all
 * three answer, and removes them again when the run ends. The harness has to
 * run from this checkout (scripts/e2e.sh, or examples/ by hand). */
const target = fileURLToPath(new URL('../../examples/dynamic/zz-e2e-consoles.yml', import.meta.url))

export default async function globalSetup(): Promise<() => void> {
  copyFileSync(fileURLToPath(new URL('../fixtures/consoles.yml', import.meta.url)), target)
  const teardown = () => rmSync(target, { force: true })
  const deadline = Date.now() + 30_000
  for (const c of CONSOLES.filter((c) => c.base !== '/')) {
    const headers: Record<string, string> = c.token ? { 'X-Scanguard-Token': c.token } : {}
    while ((await fetch(`${CONSOLE}${c.base}api/health`, { headers }).catch(() => null))?.status !== 200) {
      if (Date.now() > deadline) {
        teardown()
        throw new Error(`[e2e] the ${c.name} console at ${c.base} did not come up; is the harness running from this checkout?`)
      }
      await new Promise((r) => setTimeout(r, 500))
    }
  }
  return teardown
}
