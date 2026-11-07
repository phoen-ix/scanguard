# The console's HTTP API

Everything the console does, it does through these endpoints, so a script can
too. In `uiMode` they sit at the root of the console's router; on a detector
with its own `admin` block they sit under `admin.pathPrefix` (default
`/__scanguard`). `examples/*.sh` and `e2e/tests/` are worked examples.

## Authentication

Every `/api/*` request needs the token, in either form:

```
X-Scanguard-Token: <admin.token>
Authorization: Bearer <admin.token>
```

With `admin.trustForwardedUser: true` an `X-Forwarded-User` header from the auth
proxy in front of the console is accepted instead, and becomes the `actor` on
what it changes. A wrong or missing credential is a 401 with a JSON `error`;
failures are counted (`stats.authFailures`) and logged, throttled to one line a
minute. The three static assets (`/`, `/app.css`, `/app.js`) need no token; they
contain nothing but the page.

**Mutations** (POST, PUT, DELETE) additionally need

```
X-Scanguard-Action: 1
```

with any value: a custom header that no cross-origin form or image request can
set, which is what makes cross-site request forgery structurally impossible.
Without it a mutation is a 403. With `admin.readOnly: true` every mutation is a
403, whatever headers it carries.

## Endpoints

| | |
| --- | --- |
| `GET /api/health` | `{ok, instance, backend}`. The console's login gate uses it to validate a token |
| `GET /api/state` | the dashboard payload: `instance`, `backend`, `dryRun`, `readOnly`, `uptime`, `stats` (requests, rejected, detections, bansIssued, bansManual, unbans, expired, exempt, authFailures), `trackedSources`, `evictedSources`, `bans` (newest 500) and `bansTotal`, `events` (newest 100 of every kind), `lastSeq`, the tallies `topPaths`, `topSources`, `topDetectors`, `topRules`, `topHosts`, `topExempt`, and `config` (a redacted summary; no secrets) |
| `GET /api/events?since=N&limit=M&kind=K` | events with `seq > N`, oldest first, at most `M` (default 200, max 1000). `kind` is `ban`, `unban` or `reject`; bans and unbans come from their own ring, so they survive any volume of rejects. Returns `{events, lastSeq}` |
| `GET /api/sources?limit=N` | the tracked-source table, most recently seen first, at most `N` (default 50, max 500): `{sources: [{key, lastSeen, offences, badPaths}], total, truncated}`. Fetched on demand because it walks the whole table under the request path's lock |
| `GET /api/bans` | every active ban: `{bans: [...]}` with `key`, `reason`, `detector`, `rule`, `created`, `expires` (zero time when permanent), `offences`, `manual`, `actor`, `lastPath`, `lastUA`, `country`, `hits` |
| `POST /api/bans` | body `{"key": "203.0.113.5" or "198.51.100.0/24", "duration": "1h" (default; "0" means permanent), "reason": "..."}`. Refused with 400 when the key is narrower than the configured ban-key width or wider than /8 (IPv4) or /16 (IPv6), and with 409 when it overlaps the allowlist or a trusted proxy. Returns `{ban}` |
| `DELETE /api/bans?key=...` | lifts a ban and clears the source's escalation ladder. Returns `{unbanned: bool, key}` |
| `GET /api/rules` | the rule editor's payload: `effective` and `fromFile` (the editable sections `dryRun`, `detectors`, `allowlist`, `enforcement`), `overridden` (the sections the console owns), `builtIn` counts, `updated`, `actor` |
| `PUT /api/rules` | the same editable shape back. Validated by the same parser as the file; a bad regex or duration is a 422 with the reason and nothing changes. Sections identical to the file are not taken over. Unknown fields (anything outside the four editable sections) are a 400 |
| `DELETE /api/rules` | discards the console's edits; the file configuration is back in force |
| `GET /api/rules/compiled` | what the detectors actually run: `signatures`, `exclude`, `userAgents`, `crawlers`, `honeypots`, `payload`, `allowPaths`, `allowUA`, `allowCIDRs`, `trusted`, defaults folded in and duplicates removed |

Every response is JSON with `Cache-Control: no-store` and a strict
`Content-Security-Policy`. Errors are `{"error": "..."}` with the status above;
an unknown path under the prefix is a 404 JSON body.

## Examples

```bash
C=https://scanguard.example.com; T=$SCANGUARD_TOKEN
curl -s -H "X-Scanguard-Token: $T" $C/api/rules/compiled | jq '.signatures | length'
curl -s -H "X-Scanguard-Token: $T" "$C/api/events?kind=ban&limit=20" | jq '.events[] | [.time,.key,.detector,.path]'
curl -s -X POST -H "X-Scanguard-Token: $T" -H 'X-Scanguard-Action: 1' \
  -d '{"key":"203.0.113.5","duration":"24h","reason":"credential stuffing"}' $C/api/bans
curl -s -X DELETE -H "X-Scanguard-Token: $T" -H 'X-Scanguard-Action: 1' "$C/api/bans?key=203.0.113.5"
```
