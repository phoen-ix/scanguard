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
