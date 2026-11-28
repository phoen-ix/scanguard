import { copyFileSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { CONSOLES, consolesAnswer } from './consoles'

/* Adds the read-only, SSO and orphan consoles (fixtures/consoles.yml) to the
 * running harness through Traefik's watched file provider, waits until all
 * three answer, and removes them again when the run ends. The harness has to
 * run from this checkout (scripts/e2e.sh, or examples/ by hand). */
const target = fileURLToPath(new URL('../../examples/dynamic/zz-e2e-consoles.yml', import.meta.url))

export default async function globalSetup(): Promise<() => void> {
  copyFileSync(fileURLToPath(new URL('../fixtures/consoles.yml', import.meta.url)), target)
  const teardown = () => rmSync(target, { force: true })
  await consolesAnswer(CONSOLES.filter((c) => c.base !== '/')).catch((e: unknown) => {
    teardown()
    throw e
  })
  return teardown
}
