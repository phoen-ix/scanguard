# e2e coverage

Every user-facing feature of scanguard and the test that exercises it. The
console suite is `e2e/tests/` (`npx playwright test --list`; run it with
`scripts/e2e.sh`). The plugin's request-path behaviour has no page: it is
exercised against a live Traefik by the `examples/*.sh` checks (CI `integration`
job, fleet `traefik-integration`) and by `go test`, cited as (c). (d) marks a test that waits for an owner decision (`test.fixme`).

Inventory, from the repo root (`coverage_test.go` checks every count in this
file against these commands and the marks below):

```bash
# admin routes (serveAdmin) - 11 cases, 12 paths
grep -oE 'case "/[^"]*"(, "[^"]*")*:' admin.go
# console: panels, forms, inputs, buttons, filter chips, tiles, rule-editor groups, toasts - 46 items
grep -oE '<h2[^>]*>[A-Za-z ]+|<(form|button|input)[^>]*id="[a-z-]+"|data-kind="[a-z]*"|^  \["[a-z]+", "[a-z ]+"\]|\{ title: "[^"]+"|toast\("[^"]+' admin_ui.go
# request-path features - 32 rows: the 9 detectors of the README "What it does" table,
# then one row per behaviour the Configuration reference's keys switch on (tuning
# knobs such as capacities and timeouts fold into their detector's row)
awk '/^## What it does/{f=1;next} /^## /{f=0} f' README.md | grep -oE '^\| \*\*[^*]+'
awk '/^## Configuration/{f=1;next} /^## /{f=0} f' README.md | sed -n '/^```yaml/,/^```/p' | grep -oE '^ {0,2}[a-zA-Z]+:'
```

Roles: **guest** (no credential), **wrong token**, **operator** (`X-Scanguard-Token`
or `Authorization: Bearer`), **read-only operator** (`admin.readOnly`), **SSO user**
(`admin.trustForwardedUser`, identity from an auth proxy). The read-only, SSO
(`/sso/` with the identity header, `/sso-anon/` without it) and
"orphan" (no detector shares its `instanceName`) consoles come from
`e2e/fixtures/consoles.yml`, added to the running harness for the length of the run;
two Traefik replicas sharing a Redis come from the overlay `examples/docker-compose.e2e.yml`.

**Totals: 172 items — ✅ 144, ❌ 28** ((a) 2, (c) 25, (d) 1).

Test names are `file › [describe ›] title`.

## Admin routes × callers (42)

Every route `serveAdmin` serves (`sweep.spec.ts` reads them from `admin.go`), on
the plugin as Traefik interprets it. Every method on every route as every
caller (guest, wrong token, forged `X-Forwarded-User` on a token console, token,
Bearer, read-only, SSO user, SSO console without an identity) is the Go walk,
`admin_routes_test.go › TestEveryAdminRouteAnswersEachCallerAndMethod`, which
reads the routes from `serveAdmin`'s switch.

| Route | guest | wrong token | operator (token / Bearer) |
|---|---|---|---|
| `/` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › / is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/index.html` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › /index.html is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/app.css` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › /app.css is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/app.js` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › /app.js is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/api/state` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/state as guest`, `› every change to /api/state is a 401 for a guest and a wrong token` | ✅ `… GET /api/state as a wrong token`, same | ✅ `… GET /api/state as the token`, `… as a Bearer token` |
| `/api/events` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/events as guest`, `› every change to /api/events is a 401 for a guest and a wrong token` | ✅ `… GET /api/events as a wrong token`, same | ✅ `… GET /api/events as the token`, `… as a Bearer token` |
| `/api/sources` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/sources as guest`, `› every change to /api/sources is a 401 for a guest and a wrong token` | ✅ `… GET /api/sources as a wrong token`, same | ✅ `… GET /api/sources as the token`, `… as a Bearer token` |
| `/api/bans` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/bans as guest`, `› every change to /api/bans is a 401 for a guest and a wrong token` | ✅ `… GET /api/bans as a wrong token`, same | ✅ `… GET /api/bans as the token`, `… as a Bearer token` |
| `/api/rules` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/rules as guest`, `› every change to /api/rules is a 401 for a guest and a wrong token` | ✅ `… GET /api/rules as a wrong token`, same | ✅ `… GET /api/rules as the token`, `… as a Bearer token` |
| `/api/rules/compiled` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/rules/compiled as guest`, `› every change to /api/rules/compiled is a 401 for a guest and a wrong token` | ✅ `… GET /api/rules/compiled as a wrong token`, same | ✅ `… GET /api/rules/compiled as the token`, `… as a Bearer token` |
| `/api/health` (guest/wrong token: 401 + `WWW-Authenticate`, also for every change) | ✅ `sweep.spec.ts › admin routes › GET /api/health as guest`, `› every change to /api/health is a 401 for a guest and a wrong token` | ✅ `… GET /api/health as a wrong token`, same | ✅ `… GET /api/health as the token`, `… as a Bearer token` |

| Item | Test |
|---|---|
| unknown `/api/*` endpoint: 404 for the operator, 401 for anyone else | ✅ `sweep.spec.ts › admin routes › an unknown endpoint is a 404 for the operator and a 401 for anyone else` |
| 400s: unknown event kind, malformed ban JSON, unknown rule field, `clientIP`/`store`/`admin`/`notify` not editable | ✅ `sweep.spec.ts › admin routes › malformed requests are refused with the reason` |
| failed logins counted in `stats.authFailures` | ✅ `gate.spec.ts › a wrong token is refused, counted, and not remembered` |
| 405 for every method a route does not take (`/api/health` included) | ❌ (c) `admin_routes_test.go › TestEveryAdminRouteAnswersEachCallerAndMethod` |
| 403 for every change without `X-Scanguard-Action` (CSRF guard; POST/DELETE bans, PUT/POST/DELETE rules) | ❌ (c) same |
| 403 for every change on a read-only console | ❌ (c) same; `tools/yaegi-smoke` under the interpreter |
| a forged `X-Forwarded-User` on a token console: refused alone, never the actor beside a token | ❌ (c) same; `TestATokenConsoleNeverTakesTheForwardedUserAsTheActor` |
| two consoles on one `instanceName` (token, read-only, SSO), each one built last: each takes only its own token, `readOnly` and `trustForwardedUser`; bans and rules stay shared | ❌ (c) `TestSiblingConsolesKeepTheirOwnAdminBlock`; `tools/yaegi-smoke` under the interpreter |
| `/favicon.ico` 404 without a failed login; the bare prefix 308s to the directory form | ❌ (c) `TestEveryAdminRouteAnswersEachCallerAndMethod` |

## Console pages × roles (8)

| Console | guest | its operator |
|---|---|---|
| main `/` (operator) | ✅ `sweep.spec.ts › main console (/) › as a guest: the gate, nothing else` | ✅ `sweep.spec.ts › main console (/) › as its operator: every panel` |
| `/ro/` (read-only operator) | ✅ `sweep.spec.ts › read-only console (/ro/) › as a guest: …` | ✅ `… › as its operator: every panel` |
| `/sso/` (SSO user) | ✅ `sweep.spec.ts › SSO console without an identity (/sso-anon/) › as a guest: the API refuses with 401 and Unlock keeps the gate up` (no `X-Forwarded-User`; `sweep.spec.ts › SSO console (/sso/) › as a guest: …` is a signed-in user's first visit, before Unlock) | ✅ `sweep.spec.ts › SSO console (/sso/) › as its operator: every panel` |
| `/orphan/` (operator, no detector) | ✅ `sweep.spec.ts › orphan console (/orphan/) › as a guest: …` | ✅ `… › as its operator: every panel` |

## Console features (46, from the extraction command)

| # | Item | Test |
|---|---|---|
| 1 | `form id="gate-form"` — access gate | ✅ `gate.spec.ts › the right token unlocks, a reload keeps the session, Lock forgets it` |
| 2 | `input id="token"` — wrong and empty token refused | ✅ `gate.spec.ts › a wrong token is refused, counted, and not remembered`, `› an empty token is refused, counted, and not remembered` |
| 3 | `button id="lock"` — Lock forgets the session and clears the tables | ✅ `gate.spec.ts › the right token unlocks, a reload keeps the session, Lock forgets it` |
| 4 | `button id="tile-detail-close"` | ✅ `tiles.spec.ts › the close button and Escape close the list; another tile replaces it` |
| 5 | Active bans panel: rows, columns, count, live arrival, hits | ✅ `bans.spec.ts › a detector ban appears while the page is open; its hits count up` |
| 6 | `form id="ban-form"` — manual ban, enforced; unblock | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock` |
| 7 | `input id="ban-key"` — address, range, refusals (6 reasons), empty | ✅ `bans.spec.ts › a range and a permanent ban, with their expiry`; `› the form refuses an address that is not one, with the reason`, `… a range wider than /8 …`, `… a range over the trusted proxies …`, `… the host itself …`, `… an IPv6 prefix narrower than the key width …`; `› an empty address sends nothing` |
| 8 | `input id="ban-duration"` — 1h, 168h, permanent, invalid | ✅ `bans.spec.ts › a range and a permanent ban, with their expiry`, `› the form refuses a duration that is not one, with the reason` |
| 9 | `input id="ban-reason"` — given / defaulted | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock`, `› a range and a permanent ban, with their expiry` |
| 10 | Most probed paths | ✅ `panels.spec.ts › most probed paths and top sources rank what was requested` |
| 11 | Top sources | ✅ same |
| 12 | Rules that fired | ✅ `panels.spec.ts › rules that fired names the detector and the pattern, and counts each firing` |
| 13 | Live activity — events stream in | ✅ `activity.spec.ts › a detection and the rejects after it stream in without a reload` |
| 14 | filter chip `all` (with `aria-pressed`) | ✅ `activity.spec.ts › the kind filter shows one kind at a time` |
| 15 | filter chip `ban` | ✅ same |
| 16 | filter chip `reject` | ✅ same |
| 17 | filter chip `unban` | ✅ same; `sso.spec.ts › the forwarded identity is who the audit trail names` |
| 18 | `input id="follow"` | ✅ `activity.spec.ts › follow keeps the newest event in view; unticked, the feed stays where it was scrolled` |
| 19 | Detectors (on/off, hit counts) | ✅ `panels.spec.ts › detectors show which are on and how often each fired` |
| 20 | Configuration | ✅ `panels.spec.ts › configuration and compiled ruleset show what is in force` |
| 21 | Compiled ruleset | ✅ same |
| 22 | Rule editor (file configuration, labels, values) | ✅ `rules.spec.ts › shows the file configuration, one group per section, nothing marked` |
| 23 | `button id="rules-save"` — applies on the next request, marked, persists | ✅ `rules.spec.ts › saving applies on the next request, is marked, and survives a reload` |
| 24 | `button id="rules-revert"` — confirm dismissed / accepted | ✅ `rules.spec.ts › Revert asks first, then hands control back to the file` |
| 25 | tile "requests seen" | ✅ `tiles.spec.ts › the requests seen tile opens its list and closes again`, `› each list says what it holds` |
| 26 | tile "blocked" | ✅ `tiles.spec.ts › the blocked tile opens its list and closes again`, `› each list says what it holds` |
| 27 | tile "detections" | ✅ `tiles.spec.ts › the detections tile opens its list and closes again`, `› each list says what it holds` |
| 28 | tile "active bans" | ✅ `tiles.spec.ts › the active bans tile opens its list and closes again`, `› each list says what it holds` |
| 29 | tile "tracked sources" (fetched on demand, refreshed while open) | ✅ `tiles.spec.ts › the tracked sources tile opens its list and closes again`, `› tracked sources are fetched while the list is open, newest first` |
| 30 | tile "exempt" | ✅ `tiles.spec.ts › the exempt tile opens its list and closes again`, `› each list says what it holds` |
| 31 | editor group General (dry run) | ✅ `rules.spec.ts › dry run: detectors record what they would ban, nothing is blocked` |
| 32 | editor group Path signatures | ✅ `rules.spec.ts › a rejected edit (Extra patterns: ([unclosed) shows the parser's reason and changes nothing`, `› every kind of field in every group round-trips: checkbox, choice, number, text, lists` |
| 33 | editor group Honeypots | ✅ `rules.spec.ts › saving applies on the next request, is marked, and survives a reload` |
| 34 | editor group Scanner user-agents | ✅ `rules.spec.ts › every kind of field in every group round-trips: …` |
| 35 | editor group Distinct failing paths | ✅ same; `› a rejected edit (Leak interval: soon) …` |
| 36 | editor group Brute force | ✅ `rules.spec.ts › every kind of field in every group round-trips: …` |
| 37 | editor group Request rate | ✅ same |
| 38 | editor group User-agent rotation | ✅ same |
| 39 | editor group Payload probes | ✅ same |
| 40 | editor group Allowlist | ✅ `rules.spec.ts › an allowlist edit exempts the range at once, and the ban form refuses it`; `› a rejected edit (Never-ban CIDRs: 10.0.0.0/33) …` |
| 41 | editor group Enforcement (ladder, reject body, reject status, range escalation) | ✅ `rules.spec.ts › every kind of field in every group round-trips: …`; `› a rejected edit (Reject status: 99) …`; `› range escalation: three banned sources in one /24 ban the range, and unblock lifts it` |
| 42 | toast "Rules applied" | ✅ `rules.spec.ts › saving applies on the next request, is marked, and survives a reload` |
| 43 | toast "Reverted to the file configuration" | ✅ `rules.spec.ts › Revert asks first, then hands control back to the file` |
| 44 | toast "Banned …" (and "Unblocked …", "No ban found for …") | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock`, `› unblocking a ban that is already gone says so` |
| 45 | Health (failed logins, evicted sources, dropped notifications, expired bans) | ✅ `panels.spec.ts › health shows the counters that used to be sent and never shown` |
| 46 | toast "The rule editor has not loaded; reload the page." | ✅ `orphan.spec.ts › the rule editor says no detector shares its instance name` |

## Cross-cutting flows and states (37)

| Item | Test |
|---|---|
| login: right token unlocks | ✅ `gate.spec.ts › the right token unlocks, a reload keeps the session, Lock forgets it` |
| session survives a reload | ✅ same |
| logout (Lock), and a reload after it | ✅ same |
| Lock forgets what was typed into the ban form | ✅ `gate.spec.ts › Lock forgets what was typed into the ban form` |
| Lock while a poll is in flight: its answer is dropped, nothing more is fetched, the next sign-in works | ✅ `gate.spec.ts › Lock while a poll is in flight: its answer is dropped, and the next sign-in works`; SSO: `sso.spec.ts › Lock while a poll is in flight stops the polling; nothing is fetched until Unlock` |
| the Expires column counts down while the page is open | ✅ `bans.spec.ts › the expiry counts down while the page is open` |
| a rule change saved elsewhere warns an editor with unsaved edits, also when a ban sees it first | ✅ `rules.spec.ts › a change saved elsewhere warns an editor with unsaved edits, also when a ban sees it first` |
| Lock empties the token field and resets the activity filter | ✅ `gate.spec.ts › the right token unlocks, a reload keeps the session, Lock forgets it`; `activity.spec.ts › Lock resets the kind filter, so the next session starts on "all"` |
| console behind chained basicAuth (the browser's credentials reach every API call) | ✅ `auth.spec.ts › the console works behind basicAuth: the token unlocks and the data loads`, `› without the proxy credentials the gate blames the proxy, not the token` |
| a proxy's 401 is told apart from the plugin's | ✅ `gate.spec.ts › a 401 from a proxy in front of the console is not blamed on the token` |
| a filter click racing the poll adds no duplicate rows | ✅ `activity.spec.ts › a filter click racing the poll does not duplicate rows` |
| the Blocked list is newest first | ✅ `tiles.spec.ts › the blocked list is newest first, like the feed` |
| keyboard focus survives the three-second poll (tiles, unblock) | ✅ `tiles.spec.ts › an open tile and its list survive the poll without losing focus`, `bans.spec.ts › focus on an unblock button survives the poll` |
| the ban-list tile note says whether the list is complete | ✅ `tiles.spec.ts › each list says what it holds` |
| lost connection: badge, backoff, recovery | ✅ `panels.spec.ts › a lost connection is shown, polling backs off, and it recovers by itself` |
| editor fields for extra crawlers and the reject content type | ✅ `rules.spec.ts › every kind of field in every group round-trips: …` (iterates RULE_SCHEMA) |
| stale remembered token → gate with the reason | ✅ `gate.spec.ts › a remembered token that stopped working sends the session back to the gate` |
| gate error other than 401 (misrouted prefix) | ✅ `gate.spec.ts › a gate failure other than a refused token is shown, not a blank page` |
| SSO: unlock without a token, stay unlocked across a reload, Lock | ✅ `sso.spec.ts › the signed-in user unlocks without a token and stays unlocked across a reload` |
| SSO: the forwarded identity is the actor (unban event, rule-editor meta) | ✅ `sso.spec.ts › the forwarded identity is who the audit trail names` |
| read-only: badge, ban form / unblock / editor disabled and looking it | ✅ `readonly.spec.ts › says it is read only and offers no control that would change anything` |
| ban list capped at the newest 500, with the real total | ✅ `readonly.spec.ts › a long ban list shows the newest 500 and says how many there are` |
| empty states (bans, activity, rankings) | ✅ `orphan.spec.ts › every list shows its empty state` |
| empty tile lists | ✅ `orphan.spec.ts › every tile opens on "Nothing recorded yet."` |
| console whose instanceName has no detector | ✅ `orphan.spec.ts › the rule editor says no detector shares its instance name` |
| unsaved edit marked; a data refresh does not wipe it | ✅ `rules.spec.ts › an edit is marked until saved, and a data refresh does not wipe it` |
| rejected edit: parser's reason, nothing applied (4 parsers) | ✅ `rules.spec.ts › a rejected edit (…) shows the parser's reason and changes nothing` (×4) |
| leaving with unsaved edits asks first (`beforeunload`) | ✅ `rules.spec.ts › leaving with unsaved edits asks first; with none it does not` |
| unblock of a ban that is already gone | ✅ `bans.spec.ts › unblocking a ban that is already gone says so` |
| toast clears itself | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock` |
| header (instance, uptime) and footer (instance, backend) | ✅ `panels.spec.ts › header and footer name the instance and its state backend` |
| DRY RUN badge | ✅ `rules.spec.ts › dry run: detectors record what they would ban, nothing is blocked` |
| dark colour scheme | ✅ `layout.spec.ts › follows the dark colour scheme` |
| phone layout (no sideways page scroll, tables scroll in their box) | ✅ `layout.spec.ts › on a phone the page does not scroll sideways; wide tables scroll in their box` |
| tile drill-down: Escape, another tile replaces the list | ✅ `tiles.spec.ts › the close button and Escape close the list; another tile replaces it` |
| event-backed lists say which window they show | ✅ `tiles.spec.ts › each list says what it holds` |
| Country column (geo lookup) | ❌ (a) needs ip-api.com (external, no simulator in the harness); lookup and caching: `notify_test.go TestGeoLookupIsAsyncAndCached`, `TestGeoDisabledMakesNoCalls` |
| language switch, theme switch, registration, password reset, 2FA | not counted: the console is English only, follows the OS colour scheme, and has one credential (token or SSO header) |

## Request-path features (32)

| Item | Test |
|---|---|
| signature probe bans the source; it stays banned on an innocent path | ✅ `bans.spec.ts › a detector ban appears while the page is open; its hits count up`, `activity.spec.ts › a detection and the rejects after it stream in without a reload` |
| honeypot bans on the first hit | ✅ `rules.spec.ts › saving applies on the next request, …`, `readonly.spec.ts › says it is read only …` |
| manual ban blocks at once; a range blocks every address in it | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock`, `› a range and a permanent ban, with their expiry` |
| unblock takes effect on the next request | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock` |
| rule edit applies on the next request; revert restores the file | ✅ `rules.spec.ts › saving applies …`, `› Revert asks first …` |
| dry run detects but never blocks | ✅ `rules.spec.ts › dry run: detectors record what they would ban, nothing is blocked` |
| allowlisted CIDR exempt from every detector | ✅ `rules.spec.ts › an allowlist edit exempts the range at once, and the ban form refuses it` |
| custom reject body | ✅ `rules.spec.ts › every kind of field in every group round-trips: …` |
| one failing path repeated is tolerated (no ban) | ✅ `panels.spec.ts › most probed paths and top sources rank what was requested` |
| traffic from a trusted proxy (the host, through the Docker bridge) is exempt | ✅ `tiles.spec.ts › each list says what it holds` |
| scanner user-agent | ❌ (c) `examples/scanner-sim.sh` "Scanner user-agent"; `TestDefaultUserAgentsAvoidLegitimateClients` |
| injection payload in the query string | ❌ (c) `examples/scanner-sim.sh` "Injection payload in the query string"; `TestPayloadDecodedScanSurvivesAMalformedEscape` |
| distinct-404 flood | ❌ (c) `examples/scanner-sim.sh` "Distinct 404 flood"; `TestBadPathBucketTripsAtCapacity`, `TestBadPathBucketLeaks` |
| brute force (repeated 401/403) | ❌ (c) `TestResponseStatusDetectorBansOneRequestLate`, `TestAuthFailureWindow` (the harness's nginx answers no 401s) |
| rate abuse | ❌ (c) `TestRateBucket` |
| user-agent rotation (opt-in, off in the harness) | ❌ (c) `TestUserAgentBucket`, `TestUARotationBansACyclingSource`; under the interpreter by `tools/yaegi-smoke` |
| SEO crawler policy per router | ❌ (c) `TestCrawler*` (14 tests in `scanguard_test.go`) |
| tarpit | ❌ (c) `TestTarpitDelaysRejectedRequests`, `TestTarpitAbortsWhenTheClientDisconnects` |
| escalation ladder and decay | ❌ (c) `TestEscalationLadderAndDecay`, `TestEscalationClimbsAcrossABanExpiry` |
| subnet escalation (opt-in): a /24 of banned sources bans the range; unblock lifts it | ✅ `rules.spec.ts › range escalation: three banned sources in one /24 ban the range, and unblock lifts it` |
| forwarded-header spoofing is attributed to the real peer | ❌ (c) `examples/scanner-sim.sh` "Spoofing"; `TestResolveWalksForwardedForRightToLeft` |
| allowlisted user agents and paths | ❌ (c) `TestExemptRules`, `TestAllowlistedPathIsNotAWayAroundABan` |
| bans survive a Traefik restart (the same keys, still refused) | ❌ (c) `examples/restart-check.sh` (CI integration "bans survive a restart"); `TestFileStoreRoundTrip` |
| console rule edits survive a Traefik restart | ❌ (c) `examples/rules-check.sh` "Edits survive a Traefik restart"; `TestRuleEditPersistsAcrossRestart` |
| WebSocket upgrade and SSE flush through the middleware | ❌ (c) `examples/streaming-check.sh` |
| webhook and chat notifications (ban, unban by console and by expiry; no per-reject flood; dead endpoint survivable) | ❌ (c) `examples/notify-check.sh` (webhook sink in the harness); `TestWebhookDelivery`, `TestChatPayloadsPerProvider`, `TestExpiredBansAreReportedToNotifiers` |
| AbuseIPDB report / check | ❌ (a) needs an AbuseIPDB account; `TestAbuseIPDBReport`, `TestAbuseIPDBCheckIsAsyncAndCached` against a fake |
| `SCANGUARD_DISABLE` kill switch | ❌ (c) `TestDisabledAndKillSwitch` |
| console in prefix mode (`admin.pathPrefix` on a detection router) and `serveOnDetectionRoutes` | ❌ (c) `TestPrefixModeStillServesTheConsole`, `TestAdminPrefixNeedsAPathBoundary`, `TestServeOnDetectionRoutesReopensTheConsoleDeliberately` |
| Redis backend: a console ban, a detection and a rule edit (and lifting / reverting them) reach the other replica | ✅ `replicas.spec.ts › a ban from one console blocks on the other replica, and so does lifting it`, `› a detection on one replica bans the source on the other`, `› a rule edit on one console reaches the other replica, and so does reverting it` |
| plugin-catalog `testData` accepted | ❌ (c) `TestManifestTestDataShape` |
| plugin loads under Yaegi (Go 1.22 stdlib) | ❌ (c) `tools/yaegi-smoke` (CI `yaegi` job), and every e2e run (the harness interprets the working tree) |

## Done twice (7)

Each action twice in a row on one page, by mouse and keyboard only
(`repeat.spec.ts`).

| Item | Test |
|---|---|
| a wrong token, then the right one | ✅ `repeat.spec.ts › a wrong token, then the right one` |
| two bans unblocked one after the other | ✅ `repeat.spec.ts › two bans unblocked one after the other` |
| the same address banned twice: one row, the second ban | ✅ `repeat.spec.ts › the same address banned twice: one row, with the second ban` |
| the rule editor saved twice in a row | ✅ `repeat.spec.ts › the rule editor › saved twice in a row` |
| saved, reverted, and saved again | ✅ `repeat.spec.ts › the rule editor › saved, reverted, and saved again` |
| a refused save (422), corrected and saved | ✅ `repeat.spec.ts › the rule editor › a refused save, corrected and saved` |
| two form bans in a row, the second with only an address: its duration | ❌ (d) `repeat.spec.ts › two bans in a row: the second, with only an address typed, is not permanent` (fixme: should the duration go back to 1h after a ban?) |
