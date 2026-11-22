import { readFileSync } from 'node:fs'

/* What the tests read from the product's source instead of keeping a copy that
 * drifts: serveAdmin's routes (admin.go) and the console's panels, tiles and
 * rule groups (admin_ui.go). No Playwright import, so any file can use it. */

const read = (file: string) => readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8')
const ADMIN = read('admin.go')
const UI = read('admin_ui.go')

function block(src: string, start: string, end: string): string {
  const at = src.indexOf(start)
  if (at < 0) throw new Error(`[e2e] source.ts: ${start} not found`)
  return src.slice(at, src.indexOf(end, at))
}
const strings = (src: string, re: RegExp) => [...src.matchAll(re)].flatMap((m) => [...m[1].matchAll(/"([^"]*)"/g)].map((q) => q[1]))

const [publicCases, guardedCases] = block(ADMIN, 'func (rt *runtime) serveAdmin(', '\n}\n').split('rt.authenticate(')
const CASE = /^\tcase ("[^\n]*):$/gm
/** serveAdmin's paths: the console's files, served to anyone, and the API behind the token. */
export const ASSETS = strings(publicCases, CASE).filter((p) => p !== '/favicon.ico')
export const API = strings(guardedCases, CASE)

/** The panel headings of index.html. */
export const PANELS = [...UI.matchAll(/<h2>([^<]+)/g)].map((m) => m[1].trim())
/** The tiles' labels, in order (TILE_ORDER). */
export const TILE_LABELS = [...block(UI, 'var TILE_ORDER', '];').matchAll(/\["\w+", "([^"]+)"\]/g)].map((m) => m[1])
/** The rule editor's groups (RULE_SCHEMA). */
export const RULE_GROUPS = [...block(UI, 'var RULE_SCHEMA', '\n];').matchAll(/^ {2}\{ title: "([^"]+)"/gm)].map((m) => m[1])
/** The detector chips: configSummary's detectors map. */
export const DETECTORS = [...block(ADMIN, '"detectors": map[string]bool{', '\t\t},').matchAll(/^\t+detector\w+:/gm)].length
/** How many bans /api/state carries (maxStateBans). */
export const MAX_STATE_BANS = Number(/const maxStateBans = (\d+)/.exec(ADMIN)![1])

if (ASSETS.length < 4 || API.length < 7 || PANELS.length < 10 || TILE_LABELS.length < 6 || RULE_GROUPS.length < 11 || DETECTORS < 11) {
  throw new Error(`[e2e] source.ts read too little: ${JSON.stringify({ ASSETS, API, PANELS, TILE_LABELS, RULE_GROUPS, DETECTORS })}`)
}
