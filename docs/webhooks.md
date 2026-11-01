# Webhooks and blocking at the firewall

scanguard cannot touch nftables itself: `os/exec` does not exist under the Yaegi
interpreter, and Traefik has no privileges to do it with.

Instead it emits a ban event and **you supply the helper**: a small privileged
container that consumes these webhooks and applies nftables rules. No such helper
ships here. What ships is the payload contract below, verified end to end by
`examples/notify-check.sh` against a real receiver.

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

## Range bans

A range ban from `enforcement.subnet` arrives with a CIDR `key`
(`"198.51.100.0/24"`), detector `subnet` and **no `client`**. So the AbuseIPDB
reporter skips it, and a range is never reported there.

## Delivery

- **Only `ban` and `unban` are delivered.** Per-request rejections are not, so a
  blocked scanner hammering your site cannot turn your webhook endpoint into a
  firehose.
- **Bounded and fire-and-forget.** A dead endpoint costs nothing but a log line,
  and cannot stall a request or take Traefik down with it.
