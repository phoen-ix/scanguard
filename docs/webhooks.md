# Webhooks and blocking at the firewall

scanguard cannot touch nftables itself: `os/exec` does not exist under the Yaegi
interpreter, and Traefik has no privileges to do it with.

Instead it emits ban and unban events and **you supply the helper**: a small
privileged container that consumes these webhooks and applies nftables rules. No
such helper ships here. What ships is the payload contract below, verified end to
end by `examples/notify-check.sh` against a real receiver.

```yaml
notify:
  webhooks:
    - url: http://scanguard-nft:8080/ban
      events: [ban, unban]
```

## Payload

```json
{ "source": "scanguard", "instance": "default",
  "event": { "seq": 1041, "time": "2026-08-16T10:00:00Z", "kind": "ban",
             "key": "203.0.113.5/32", "client": "203.0.113.5",
             "detector": "signature", "rule": "/wp-login\\.php", "banFor": "1h",
             "expires": "2026-08-16T11:00:00Z",
             "method": "GET", "host": "example.com", "path": "/wp-login.php",
             "ua": "Mozilla/5.0 zgrab/0.x" } }
```

```json
{ "source": "scanguard", "instance": "default",
  "event": { "seq": 1102, "time": "2026-08-16T11:00:00Z", "kind": "unban",
             "key": "203.0.113.5/32", "detector": "signature", "actor": "expiry" } }
```

| field | when | meaning |
| --- | --- | --- |
| `seq` | always | monotonically increasing per instance, shared with the console's event feed |
| `time` | always | RFC 3339, UTC |
| `kind` | always | `ban` or `unban`; nothing else is delivered |
| `key` | always | the banned prefix: `203.0.113.5/32`, a `/64` for IPv6, a CIDR for a range ban or a manual range |
| `client` | automatic bans of a single source | the address that was seen; absent on range bans and manual bans |
| `detector` | ban; unban by expiry | one of `signature`, `honeypot`, `user-agent`, `crawler`, `bad-paths`, `brute-force`, `rate-abuse`, `payload`, `ua-rotation`, `reputation`, `subnet`, `manual` |
| `rule` | ban | the pattern or threshold that fired; the operator's reason on a manual ban |
| `banFor` | ban | `1h`, `1d`, `7d`, `1h30m` when a rung is not a whole unit, or `permanent` |
| `expires` | ban, unless permanent | RFC 3339, UTC: when the ban runs out. Schedule the rule's removal from this rather than parsing `banFor`; absent on a permanent ban |
| `method`, `host`, `path`, `ua` | automatic bans | the request that tripped the detector; `path` and `ua` are truncated to 512 and 256 bytes |
| `country` | ban, with `geo.enabled` | ISO country code from the display-only lookup, when the cache already had it |
| `actor` | unban; manual ban | `expiry` when the janitor swept the ban, `token` for a console token, otherwise the `X-Forwarded-User` identity |
| `dryRun` | `true` on dry-run events | **a would-ban, not a ban.** A helper must ignore events with `dryRun: true`, or a dry run blocks at the firewall what it was promised never to block. Absent when false |

Field names are stable; new fields may be added. Decode leniently.

## Range bans

A range ban from `enforcement.subnet` arrives with a CIDR `key`
(`"198.51.100.0/24"`), detector `subnet` and **no `client`**. So the AbuseIPDB
reporter skips it, and a range is never reported there.

## Delivery

- **Only `ban` and `unban` are delivered**, and every unban is: a ban lifted
  from the console and a ban that expired both produce one (`actor` says which),
  so a helper that keys its firewall rules on `key` can keep them in step with
  the ban list. Per-request rejections are not delivered, so a blocked scanner
  hammering your site cannot turn your webhook endpoint into a firehose.
- **Validated at startup.** `events` may name only `ban` and `unban`; anything
  else is refused with the reason rather than accepted and never fired.
- **Queued, bounded, fire-and-forget.** Events wait in a queue of 1024 and
  eight workers deliver them, so a janitor tick that expires hundreds of bans
  at once delivers every unban. If the queue is full — a sustained ban flood
  against an endpoint that answers slowly — events are dropped rather than
  held: the count is `stats.notifyDropped` in `/api/state`, and the log says
  so at most once a minute. A dead endpoint costs nothing but a log line, and
  cannot stall a request or take Traefik down with it. A helper that must never
  miss an event should reconcile against `GET /api/bans` now and then.
- **Once per instance, not once per replica.** With `store.backend: redis`,
  every replica's janitor notices the same expiry; one of them claims it in
  Redis and delivers the unban, the others only record it in their own
  console. A manual unban is delivered by the replica that performed it. If
  Redis is unreachable at that moment, every replica delivers: duplicates beat
  silence for a helper waiting on the unban.
- **Dry runs are labelled everywhere.** The webhook payload carries
  `dryRun: true`, the console shows "(dry)", and a chat message says
  "would have banned (dry run)".
