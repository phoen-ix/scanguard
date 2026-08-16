<div align="center">

<img src=".assets/icon.png" width="88" alt="">

# scanguard

**A Traefik middleware plugin that detects HTTP vulnerability scanning, bans the source, and ships its own web console.**

One artifact. No sidecar, no database, no agent. MIT.

</div>

---

Every public host gets the same background noise: `/wp-login.php`, `/.env`,
`/phpmyadmin`, `/.git/config`, endless 404s from someone else's wordlist.
scanguard watches for it, blocks the source before your backend is touched, and
gives you a page where you can see who is banned and let them back in.

```yaml
# The whole installation.
experimental:
  plugins:
    scanguard:
      moduleName: github.com/phoen-ix/scanguard
      version: v0.1.0
```

## What it does

| | |
|---|---|
| **Signature probes** | 48 curated paths that only a scanner asks for. Blocked before the request reaches your backend. |
| **Distinct-404 floods** | A leaky bucket over *distinct* failing paths — so a scanner walking a wordlist is caught, and a real user hammering one broken link never is. |
| **Honeypots** | Paths you invent that no legitimate client could know. One hit, instant ban, effectively zero false positives. |
| **Scanner user-agents** | nikto, sqlmap, nuclei, masscan, zgrab and friends. Generic clients like `curl` and `python-requests` are deliberately *not* in the defaults. |
| **Brute force** | Repeated 401/403 from your real login endpoints. |
| **Rate abuse** | Token bucket per source, independent of status code. |
| **Injection payloads** | SQLi, traversal, template injection and XSS probes in the query string and optionally the body. Checked in both raw and decoded form. |

Every detector is individually switchable, and every threshold is configurable.

Bans escalate (`1h → 24h → 7d → permanent`), decay when a source behaves, survive
a Traefik restart, and can be pushed to a webhook, Discord/Slack/ntfy/Gotify, or
AbuseIPDB.

## The console

<div align="center"><em>Your own router, on your own host or port — not a tab in the Traefik dashboard.</em></div>

Active bans with the rule that caught them, one-click unblock, manual ban by IP or
CIDR, a live activity feed, most-probed paths, top sources, and a **full rule
editor**. It is one self-contained page: no build step, no npm, no CDN.

### Editing rules from the browser

Every detector, threshold, allowlist and enforcement setting can be changed in the
console and takes effect on the **next request** — no Traefik restart, no reload,
no file to edit.

Traefik's configuration is one-way: it is decoded once when the middleware is
built, and nothing can write back to it. Writing to the file provider instead
would be worse — every write trips fsnotify, rebuilds the whole router tree and
re-runs `New()` for every plugin middleware on every router. So scanguard keeps
its own override store, saved beside the ban list and restored at startup.

- **Only what you change is taken over.** Edit a honeypot and the console owns
  `detectors`; `enforcement` keeps tracking your YAML. The editor marks changed
  fields and lists exactly which sections it manages.
- **Edits are validated by the same parser as the file.** A broken regex comes
  back as a 422 with the reason and the running rules are untouched — it cannot
  half-apply and leave you undefended.
- **Reverting restores the file configuration**, section by section.
- **A Traefik reload re-layers your edits** onto the new file config rather than
  discarding them.
- **`clientIP`, `store`, `admin` and `notify` are not editable.** They hold
  secrets, or must agree with Traefik's *static* configuration that nothing at
  runtime can change — see the comment at the top of `overrides.go`.

With the Redis backend, a rule change on one replica reaches the others on their
next refresh, exactly like a ban.

**Traefik plugins cannot extend the Traefik dashboard.** The dashboard is a
compiled-in single-page app with no extension point;
[traefik#8684](https://github.com/traefik/traefik/issues/8684) has been open since
January 2022, and the dashboard's own CSP blocks embedding a plugin page in an
iframe. So scanguard serves its console on a router you define. Put it on a
private entrypoint and chain your own auth in front of it.

## Honest comparison

**If your actual problem is "my server is getting hammered and I want it to
stop", deploy [CrowdSec](https://www.crowdsec.net/) instead.** CrowdSec plus
`crowdsec-bouncer-traefik-plugin` plus the community web UI covers most of what
this does, with community-sourced threat intelligence, a real decisions database,
and proper multi-node support. It is free, self-hostable, and more battle-tested
than anything one person writes in a month.

scanguard exists for the case CrowdSec does not serve: **one lightweight artifact
you drop into Traefik, with a console built in.** No agent container, no access
log plumbing, no hub. If that is what you want, this is for you.

| | scanguard | CrowdSec + bouncer | tomMoulard/fail2ban |
|---|---|---|---|
| Artifacts to deploy | 1 | 3+ | 1 |
| Built-in web console | ✅ | separate UI | ❌ ([#238](https://github.com/tomMoulard/fail2ban/issues/238)) |
| Survives restart | ✅ | ✅ | ❌ |
| Multiple Traefik replicas | Redis backend | ✅ | ❌ |
| Community threat intel | ❌ | ✅ | ❌ |
| Bounded memory | ✅ | ✅ | ❌ (no eviction) |
| Trusted-proxy validation | ✅ | ✅ | ❌ (spoofable) |

## Install

### Local plugin (recommended to start)

```yaml
# traefik static configuration
experimental:
  localPlugins:
    scanguard:
      moduleName: github.com/phoen-ix/scanguard
```

```yaml
# docker-compose.yml
volumes:
  - ./scanguard:/plugins-local/src/github.com/phoen-ix/scanguard:ro
  - scanguard-state:/var/lib/scanguard
```

Local plugins need no network access at startup. That matters more than it
sounds: a remote plugin is fetched from `plugins.traefik.io` on **every** Traefik
start, and one transient failure disables *every* declared plugin with a
misleading error ([traefik#13005](https://github.com/traefik/traefik/issues/13005)).
For something whose job is security, prefer a local plugin or a baked image.

### Attach it

Three options, and they compose:

```yaml
# 1. EntryPoint-wide — every router, automatically. Static config, needs a restart to change.
entryPoints:
  websecure:
    http:
      middlewares:
        - scanguard@file

# 2. Per-router — gradual rollout, per-route tuning. Easy to forget a router.
labels:
  - "traefik.http.routers.myapp.middlewares=scanguard@file"

# 3. Catch-all — the ONLY way to see probes aimed at hostnames you do not serve.
#    Traefik answers those 404 from the router itself; no middleware ever runs.
http:
  routers:
    catchall:
      rule: HostRegexp(`^.+$`)
      priority: 1
      service: your-dummy-service
      middlewares: [scanguard]
```

### Turn on the console

```yaml
http:
  routers:
    scanguard-console:
      rule: PathPrefix(`/`)
      entryPoints: [admin]          # bind this entrypoint to 127.0.0.1 in production
      service: your-dummy-service   # never reached; the middleware terminates
      middlewares: [scanguard-ui, your-basic-auth]

  middlewares:
    scanguard-ui:
      plugin:
        scanguard:
          instanceName: default     # must match your detector instance
          uiMode: true
          admin:
            enabled: true
            token: "a-long-random-secret"
```

A `uiMode` instance is a *view* onto the shared runtime, not a second
configuration of it — it contributes only the admin surface and cannot overwrite
your detectors.

## ⚠️ Client IP, or how to take your own site down

If Traefik sits behind Cloudflare, a load balancer, or a Kubernetes Service,
`RemoteAddr` is **the proxy**, not the client. Ban it and every legitimate user is
locked out at once. Both halves of the configuration are required:

```yaml
# 1. Traefik must be told to keep the headers. Without this it DELETES every
#    X-Forwarded-* header before any middleware runs, and scanguard silently
#    bans nobody at all.
entryPoints:
  websecure:
    forwardedHeaders:
      trustedIPs: ["173.245.48.0/20", "..."]   # cloudflare.com/ips-v4

# 2. scanguard must be told which peers may be believed.
clientIP:
  trustedProxies: ["173.245.48.0/20", "..."]   # the same list
  header: Cf-Connecting-Ip
```

`trustedProxies` has **no default**, on purpose. A configurable client-IP header
without a trusted-proxy check is not a hardening gap, it is a remote "ban anybody
you name" primitive — an attacker sets the header per request to evade their own
ban and to poison your list with third parties. scanguard refuses to start if you
set `clientIP.header` without `clientIP.trustedProxies`, never bans an address
inside `trustedProxies`, and refuses to attribute a request it cannot identify.

If your load balancer speaks PROXY protocol, use it instead — it actually
rewrites `RemoteAddr` and the whole problem disappears.

**Roll out with `dryRun: true` first.** It runs every detector, logs and displays
everything it *would* have banned, and blocks nothing.

## ⚠️ WebSockets, SSE and gRPC

Seeing response codes means wrapping `http.ResponseWriter`. A wrapper that drops
`http.Flusher` and `http.Hijacker` silently breaks streaming on every route it
touches — [traefik#10269](https://github.com/traefik/traefik/issues/10269) — and
it surfaces weeks later as "the chat stopped working", never as an error.

scanguard forwards `Flush`, `Hijack`, `ReadFrom` and `Push`, skips wrapping
protocol-upgrade requests entirely, and does not wrap at all when no
response-status detector is enabled. `examples/streaming-check.sh` is the release
gate, and it passes against Traefik v3.7.10. **Re-run it after every Traefik
upgrade** — and if you ever see a `flusher-unavailable` warning in the log, set
`observeResponse: false` on that route.

## Blocking at the firewall

scanguard cannot touch nftables itself: `os/exec` does not exist under the Yaegi
interpreter, and Traefik has no privileges to do it with. Instead it emits a ban
event and **you supply the helper** — a small privileged container that consumes
these webhooks and applies nftables rules. No such helper ships here; what ships
is the payload contract below, verified end to end by `examples/notify-check.sh`
against a real receiver:

```yaml
notify:
  webhooks:
    - url: http://scanguard-nft:8080/ban
      events: [ban, unban]
```

```json
{ "source": "scanguard", "instance": "default",
  "event": { "kind": "ban", "key": "203.0.113.5/32", "client": "203.0.113.5",
             "detector": "signature", "rule": "/wp-login\\.php", "banFor": "1h",
             "method": "GET", "path": "/wp-login.php", "time": "2026-08-16T10:00:00Z" } }
```

Only `ban` and `unban` are delivered — per-request rejections are not, so a
blocked scanner hammering your site cannot turn your webhook endpoint into a
firehose. Delivery is bounded and fire-and-forget: a dead endpoint costs nothing
but a log line, and cannot stall a request or take Traefik down with it.

## Configuration

<details>
<summary><b>Full reference</b></summary>

```yaml
enabled: true
instanceName: default        # keys the shared state; instances sharing a name share bans
dryRun: false                # detect and log, never block
observeResponse: true        # wrap ResponseWriter; needed by badPaths and bruteForce

store:
  backend: memory            # memory | file | redis
  path: /var/lib/scanguard/state.json
  snapshotInterval: 30s
  failOpen: true
  maxEntries: 50000          # hard cap on tracked sources; LRU-evicted
  redis:
    address: redis:6379
    password: ""
    db: 0
    keyPrefix: "scanguard:"
    timeout: 2s

clientIP:
  trustedProxies: []         # NO DEFAULT — see the warning above
  header: ""                 # e.g. Cf-Connecting-Ip; only honoured from a trusted peer
  ipv4Prefix: 32             # ban-key width
  ipv6Prefix: 64             # /128 bans are useless; a host owns a whole /64

allowlist:
  cidrs: []                  # office egress, uptime monitors
  userAgents: []             # verified crawlers
  paths: []                  # e.g. ^/health$

detectors:
  signatures:  { enabled: true,  useDefaults: true, patterns: [], exclude: [] }
  honeypots:   { enabled: true,  paths: [] }
  userAgent:   { enabled: true,  useDefaults: true, patterns: [], banEmptyUA: false }
  badPaths:    { enabled: true,  capacity: 10, leak: 10s, statuses: [400,401,403,404,405,501] }
  bruteForce:  { enabled: false, capacity: 5, window: 60s, statuses: [401,403], paths: [] }
  rateAbuse:   { enabled: false, rps: 50, burst: 100 }
  payload:     { enabled: false, useDefaults: true, scanQuery: true, scanBody: false, maxBodyBytes: 8192 }

enforcement:
  rejectStatus: 403          # 404 hides the middleware's existence
  rejectBody: ""
  escalation: ["1h", "24h", "168h", "0"]   # "0" means permanent
  decay: 24h                 # behave this long and drop a rung
  tarpit: { enabled: false, delay: 3s, maxConcurrent: 50 }

notify:
  timeout: 5s
  webhooks: [{ url: "", method: POST, headers: {}, events: [ban, unban] }]
  chat: { kind: "", url: "", events: [] }   # discord | slack | ntfy | gotify
  abuseipdb: { enabled: false, apiKey: "", report: true, check: false, minConfidence: 75, cacheTTL: 24h }

geo: { enabled: false, provider: ip-api, cacheTTL: 168h }   # console display only

admin:
  enabled: false             # off by default; no default token
  pathPrefix: /__scanguard
  token: ""                  # 16+ characters, compared in constant time
  trustForwardedUser: false  # honour X-Forwarded-User from Authelia/Authentik/oauth2-proxy
  readOnly: false
  eventLogSize: 500
```

Locked out of the console? `SCANGUARD_DISABLE=1` in Traefik's environment turns
scanguard into a pass-through at startup, no config edit required.

</details>

<details>
<summary><b>Running WordPress?</b></summary>

The default signatures include the `wp-*` paths, so your own admin traffic would
ban you. Either allowlist yourself, or exclude them:

```yaml
detectors:
  signatures:
    exclude: ['^/wp-admin/', '^/wp-login\.php$', '^/wp-includes/', '^/wp-content/']
```

</details>

## Development

```bash
go test ./...                                  # unit tests, ~0.5s
(cd tools/yaegi-smoke && go run .)             # run the plugin under the real interpreter
cd examples && docker compose up -d
./scanner-sim.sh                               # 20 end-to-end checks against live Traefik
./streaming-check.sh                           # the WebSocket + SSE release gate
./rules-check.sh                               # the rule editor, including restart survival
./notify-check.sh                              # webhooks and chat, delivered for real
```

**`tools/yaegi-smoke` is the most important thing in this repository.** Traefik
does not compile plugins, it interprets them with
[Yaegi](https://github.com/traefik/yaegi), which is pinned at v0.16.1 and exposes
only the **Go 1.22** standard library. Two whole classes of bug are invisible to
`go build` and `go test`:

- Using a newer stdlib API (`slices.Sort`, `sync.OnceFunc`, `atomic.Pointer`,
  `min`/`max`, `os/exec`). Compiles locally, fails at plugin load.
- `//go:embed`, which does not work under Yaegi and **fails silently** — the
  variable is empty, the tests pass, and the page is blank only inside Traefik.
  That is why the console is a string constant, and why the smoke test asserts
  the page is non-empty.

Two more interpreter traps this project hit, both invisible to `go test` and both
now asserted by the smoke test:

- **Encoding a response as `map[string]interface{}` with structs as values
  produced `{"effective":{}}`** under Yaegi — the nested structs lost every field,
  with no encoding error. The console read that empty object, wrote it back, and
  wiped the ruleset. Every admin response now has a named struct type; see the
  note on `RulesResponse`.
- **mapstructure merges into a pre-populated slice instead of replacing it.**
  A default of `[400,401,403,404,405,501]` plus a configured `[404]` yields
  `[404,401,403,404,405,501]`. List defaults therefore live in
  `defaultBadPathStatuses` and friends, applied after decoding, never in
  `CreateConfig`.

`go.mod` declares `go 1.22` so your local toolchain refuses the newer APIs for
you. Keep the module dependency-free: anything using cgo, assembly, `//go:embed`
or heavy reflection fails at plugin import.

## Performance

Measured on Traefik v3.7.10 with the example configuration, `wrk -t4 -c50` inside
the compose network:

| | req/s | avg latency |
|---|---|---|
| Baseline route, no middleware | 8790 | 5.7 ms |
| Through scanguard | 2760 | 18.9 ms |

So roughly a third of the raw proxy throughput — which is the price of an
interpreted plugin, and still five to ten times a "hundreds of requests per
second" workload. Traefik's memory was 75 MB with several thousand tracked
sources.

Where the time goes, from `go test -bench .`:

| | cost | note |
|---|---|---|
| Already-banned request | **881 ns**, 4 allocs | resolve, one map lookup, write a status |
| Client-IP resolution | 208 ns, 0 allocs | with four trusted-proxy CIDRs |
| Signature match (48 patterns) | 3.2 µs | short subject, so cheap |
| User-agent match (22 patterns) | 25 µs | **the dominant cost** |
| Clean request, end to end | 52 µs, 3 allocs | almost entirely the two matches |

An alternation with no literal prefix must attempt a match at every position, so
cost scales with subject length — which is why matching a 90-character
user-agent costs 8× more than matching a path despite having half the patterns.
A literal pre-filter measures 3.2× faster interpreted, and is deliberately not
implemented; see the note in `matcher.go` for why a wrong pre-filter fails
silently in exactly the direction you cannot afford.

If you need the throughput back: `detectors.userAgent.enabled: false` removes
most of the cost, at the price of catching self-identifying scanners only via
their request paths.

## Limitations

- **No Traefik dashboard tab.** Not now, not later. See above.
- **Single Traefik instance by default.** State is process-global, so N replicas
  means N independent ban lists, thresholds effectively multiplied by N, and an
  Unblock that applies to one replica. It degrades *silently*. Use the Redis
  backend for HA — bans are shared and propagate to other replicas within one
  janitor cycle (~30s, measured), the way CrowdSec's stream mode works. Per-source
  counters stay local by design: shipping a counter increment to Redis on every
  request would put a network round trip on the hot path to share state nobody
  needs. A Redis outage therefore degrades to per-replica enforcement rather than
  to an outage of its own.
- **Plugins load only at startup.** Installing or upgrading scanguard needs a
  Traefik restart. The console cannot do it.
- **Response-status detectors act one request late.** The decision for request N
  can only be enforced from N+1. That is inherent to observing responses.
- **Yaegi plugins have broken on Traefik patch releases.** Pin your Traefik
  version and re-run the harness after upgrades.
- **Interpreted code is unprofilable** — every frame shows as
  `yaegi/interp.call.func9` in pprof. The hot path is kept to a map lookup and one
  pre-compiled alternation regexp for that reason.

## Licence

MIT. Default rulesets were written for this project; the design owes a debt to
[tomMoulard/fail2ban](https://github.com/tomMoulard/fail2ban) (MIT),
[CrowdSec](https://github.com/crowdsecurity/crowdsec) (MIT) — whose distinct-path
bucket model is the single best idea here — and
[maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)
(Apache-2.0), which proved most of these mechanisms work under Yaegi at all.
