# Crawlers, per router

`detectors.userAgent.crawlers` is the one setting read from the middleware
definition that handled the request rather than from the instance.

It exists because a single instance often protects both placeholder hosts, which
have nothing to crawl, and a real site, which wants crawling. Splitting them into
two `instanceName`s to express that would split the ban list and the console too.

```yaml
http:
  middlewares:
    # Placeholder hosts: refuse crawlers.
    scanguard-parked:
      plugin:
        scanguard: &sg
          instanceName: prod
          detectors:
            userAgent: { enabled: true, useDefaults: true, crawlers: block }

    # Real content: same instance, same ban list, opposite answer.
    scanguard-content:
      plugin:
        scanguard:
          <<: *sg
          detectors:
            userAgent: { enabled: true, useDefaults: true, crawlers: ignore }
```

## The four values

**Prefer `block` to `ban` when the instance also protects a site you want
crawled.** The difference is where the decision is recorded:

| value | effect |
| --- | --- |
| `ignore` (default) | the crawler list is unused |
| `ban` | writes a ban record — the crawler is then refused on **every** router this instance protects, and escalates |
| `block` | refuses the crawler on **this router only**, with `rejectStatus`. No ban record, no offence, no escalation |
| `exempt` | adds the list to the User-Agent allowlist, so a matching crawler skips every detector **and** an existing ban |

## Why `block` exists

The ban list is keyed by source, shared by the whole instance, and consulted
*before* any crawler policy.

- So one `ban` on a placeholder host refuses that crawler on your content site as
  well, and setting `ignore` there does **not** undo it.
- `block` writes nothing shared, so each router genuinely decides for itself.

## The cost of `exempt`

`exempt` is the only value that forgives an existing ban, because the allowlist is
checked before the ban list.

- A User-Agent is trivially forged, so `exempt` hands anyone who copies the string
  a free pass past every detector.
- `ban` and `block` carry no such risk: the worst a forged UA achieves is getting
  its own author refused.

## Practical notes

- **Siblings sharing an `instanceName` should be identical apart from this one
  key.** They publish to one settings object, and any other difference means
  whichever Traefik builds last wins.
- **State the policy on every definition that shares an instance.** One that
  states none inherits the instance-wide value, and which sibling supplies that is
  decided by build order.
- **Own detector name:** a crawler refused by policy is reported as `crawler`, not
  `user-agent`, so the console and the event log tell the two apart.
