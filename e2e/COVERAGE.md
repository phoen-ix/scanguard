# e2e coverage

Every user-facing feature of scanguard and the test that exercises it. The
console suite is `e2e/tests/` (`npx playwright test --list`; run it with
`scripts/e2e.sh`). The plugin's request-path behaviour has no page: it is
exercised against a live Traefik by the `examples/*.sh` checks (CI `integration`
job, fleet `traefik-integration`) and by `go test`, cited as (c).

Inventory, 2026-10-31, from the repo root:

```bash
# admin routes (serveAdmin) - 10 cases, 11 paths
grep -oE 'case "/[^"]*"(, "[^"]*")*:' admin.go
# console: panels, forms, inputs, buttons, filter chips, tiles, rule-editor groups, toasts - 43 items
grep -oE '<h2[^>]*>[A-Za-z ]+|<(form|button|input)[^>]*id="[a-z-]+"|data-kind="[a-z]*"|tile\(tiles, "[^"]+"|\{ title: "[^"]+"|toast\("[^"]+' admin_ui.go
# request-path features: the README "What it does" table and the Configuration block
```

Roles: **guest** (no credential), **wrong token**, **operator** (`X-Scanguard-Token`
or `Authorization: Bearer`), **read-only operator** (`admin.readOnly`), **SSO user**
(`admin.trustForwardedUser`, identity from an auth proxy). The read-only, SSO and
"orphan" (no detector shares its `instanceName`) consoles come from
`e2e/fixtures/consoles.yml`, added to the running harness for the length of the run;
two Traefik replicas sharing a Redis come from the overlay `examples/docker-compose.e2e.yml`.

**Totals: 159 items — ✅ 139, ❌ 20** ((a) 2, (c) 18).

Test names are `file › [describe ›] title`.

## Admin routes × callers (54)

| Route | guest | wrong token | operator (token / Bearer) |
|---|---|---|---|
| `/` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › / is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/index.html` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › /index.html is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/app.css` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › /app.css is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/app.js` — served to everyone with CSP, `no-store`, `nosniff`, `no-referrer`; HEAD 200; POST 405 | ✅ `sweep.spec.ts › admin routes › /app.js is served to every caller, with the console's security headers` | ✅ same test | ✅ same test |
| `/api/state` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/state as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/state as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/state as the token`, `sweep.spec.ts › admin routes › GET /api/state as a Bearer token` |
| `/api/events` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/events as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/events as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/events as the token`, `sweep.spec.ts › admin routes › GET /api/events as a Bearer token` |
| `/api/sources` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/sources as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/sources as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/sources as the token`, `sweep.spec.ts › admin routes › GET /api/sources as a Bearer token` |
| `/api/bans` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/bans as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/bans as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/bans as the token`, `sweep.spec.ts › admin routes › GET /api/bans as a Bearer token` |
| `/api/rules` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/rules as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/rules as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/rules as the token`, `sweep.spec.ts › admin routes › GET /api/rules as a Bearer token` |
| `/api/rules/compiled` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/rules/compiled as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/rules/compiled as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/rules/compiled as the token`, `sweep.spec.ts › admin routes › GET /api/rules/compiled as a Bearer token` |
| `/api/health` (guest/wrong token: 401 + `WWW-Authenticate`) | ✅ `sweep.spec.ts › admin routes › GET /api/health as guest` | ✅ `sweep.spec.ts › admin routes › GET /api/health as a wrong token` | ✅ `sweep.spec.ts › admin routes › GET /api/health as the token`, `sweep.spec.ts › admin routes › GET /api/health as a Bearer token` |

| Item | Test |
|---|---|
| unknown `/api/*` endpoint: 404 for the operator, 401 for anyone else | ✅ `sweep.spec.ts › admin routes › an unknown endpoint is a 404 for the operator and a 401 for anyone else` |
| 405 for a method an endpoint does not take (6 endpoints) | ✅ `sweep.spec.ts › admin routes › POST /api/state is refused with 405`, `… POST /api/events …`, `… POST /api/sources …`, `… POST /api/rules/compiled …`, `… PATCH /api/bans …`, `… PATCH /api/rules …` |
| 403 for a mutation without `X-Scanguard-Action` (CSRF guard; 4 mutations) | ✅ `sweep.spec.ts › admin routes › POST /api/bans without the anti-CSRF header is refused with 403`, `… DELETE /api/bans …`, `… PUT /api/rules …`, `… DELETE /api/rules …` |
| 400s: unknown event kind, malformed ban JSON, unknown rule field, `clientIP`/`store`/`admin`/`notify` not editable | ✅ `sweep.spec.ts › admin routes › malformed requests are refused with the reason` |
| 403 for every mutation on a read-only console | ✅ `readonly.spec.ts › the API refuses every change, whoever asks` |
| failed logins counted in `stats.authFailures` | ✅ `gate.spec.ts › a wrong token is refused, counted, and not remembered` |

(4 asset rows × 3 caller columns = 12, 7 API rows × 4 callers = 28, 14 further items: 54.)

## Console pages × roles (8)

| Console | guest | its operator |
|---|---|---|
| main `/` (operator) | ✅ `sweep.spec.ts › main console (/) › as a guest: the gate, nothing else` | ✅ `sweep.spec.ts › main console (/) › as its operator: every panel` |
| `/ro/` (read-only operator) | ✅ `sweep.spec.ts › read-only console (/ro/) › as a guest: …` | ✅ `… › as its operator: every panel` |
| `/sso/` (SSO user) | ✅ `sweep.spec.ts › SSO console (/sso/) › as a guest: …` | ✅ `… › as its operator: every panel` |
| `/orphan/` (operator, no detector) | ✅ `sweep.spec.ts › orphan console (/orphan/) › as a guest: …` | ✅ `… › as its operator: every panel` |

## Console features (43, from the extraction command)

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
| 12 | Rules that fired | ✅ `panels.spec.ts › rules that fired names the detector and the pattern` |
| 13 | Live activity — events stream in | ✅ `activity.spec.ts › a detection and the rejects after it stream in without a reload` |
| 14–17 | filter chips `all`, `ban`, `reject`, `unban` (with `aria-pressed`) | ✅ `activity.spec.ts › the kind filter shows one kind at a time` |
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
| 38 | editor group Payload probes | ✅ same |
| 39 | editor group Allowlist | ✅ `rules.spec.ts › an allowlist edit exempts the range at once, and the ban form refuses it`; `› a rejected edit (Never-ban CIDRs: 10.0.0.0/33) …` |
| 40 | editor group Enforcement (ladder, reject body, reject status) | ✅ `rules.spec.ts › every kind of field in every group round-trips: …`; `› a rejected edit (Reject status: 99) …` |
| 41 | toast "Rules applied" | ✅ `rules.spec.ts › saving applies on the next request, is marked, and survives a reload` |
| 42 | toast "Reverted to the file configuration" | ✅ `rules.spec.ts › Revert asks first, then hands control back to the file` |
| 43 | toast "Banned …" (and "Unblocked …", "No ban found for …") | ✅ `bans.spec.ts › a manual ban from the form is listed, enforced, and lifted by unblock`, `› unblocking a ban that is already gone says so` |

## Cross-cutting flows and states (24)

| Item | Test |
|---|---|
| login: right token unlocks | ✅ `gate.spec.ts › the right token unlocks, a reload keeps the session, Lock forgets it` |
| session survives a reload | ✅ same |
| logout (Lock), and a reload after it | ✅ same |
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

## Request-path features (30)

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
| SEO crawler policy per router | ❌ (c) `TestCrawlerPolicy*` (11 tests in `scanguard_test.go`) |
| tarpit | ❌ (c) `TestTarpitDelaysRejectedRequests`, `TestTarpitAbortsWhenTheClientDisconnects` |
| escalation ladder and decay | ❌ (c) `TestEscalationLadderAndDecay`, `TestEscalationClimbsAcrossABanExpiry` |
| forwarded-header spoofing is attributed to the real peer | ❌ (c) `examples/scanner-sim.sh` "Spoofing"; `TestResolveWalksForwardedForRightToLeft` |
| allowlisted user agents and paths | ❌ (c) `TestExemptRules`, `TestAllowlistedPathIsNotAWayAroundABan` |
| bans survive a Traefik restart | ❌ (c) `ci.yml` integration "bans survive a restart"; `TestFileStoreRoundTrip` |
| console rule edits survive a Traefik restart | ❌ (c) `examples/rules-check.sh` "Edits survive a Traefik restart"; `TestRuleEditPersistsAcrossRestart` |
| WebSocket upgrade and SSE flush through the middleware | ❌ (c) `examples/streaming-check.sh` |
| webhook and chat notifications (ban, unban; no per-reject flood; dead endpoint survivable) | ❌ (c) `examples/notify-check.sh` (webhook sink in the harness); `TestWebhookDelivery`, `TestChatPayloadsPerProvider` |
| AbuseIPDB report / check | ❌ (a) needs an AbuseIPDB account; `TestAbuseIPDBReport`, `TestAbuseIPDBCheckIsAsyncAndCached` against a fake |
| `SCANGUARD_DISABLE` kill switch | ❌ (c) `TestDisabledAndKillSwitch` |
| console in prefix mode (`admin.pathPrefix` on a detection router) and `serveOnDetectionRoutes` | ❌ (c) `TestPrefixModeStillServesTheConsole`, `TestAdminPrefixNeedsAPathBoundary`, `TestServeOnDetectionRoutesReopensTheConsoleDeliberately` |
| Redis backend: a console ban, a detection and a rule edit (and lifting / reverting them) reach the other replica | ✅ `replicas.spec.ts › a ban from one console blocks on the other replica, and so does lifting it`, `› a detection on one replica bans the source on the other`, `› a rule edit on one console reaches the other replica, and so does reverting it` |
| plugin-catalog `testData` accepted | ❌ (c) `TestManifestTestDataShape` |
| plugin loads under Yaegi (Go 1.22 stdlib) | ❌ (c) `tools/yaegi-smoke` (CI `yaegi` job), and every e2e run (the harness interprets the working tree) |
