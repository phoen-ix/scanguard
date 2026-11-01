# Performance

Measured on Traefik v3.7.10 with the example configuration, `wrk -t4 -c50` inside
the compose network:

| | req/s | avg latency |
|---|---|---|
| Baseline route, no middleware | 8790 | 5.7 ms |
| Through scanguard | 2760 | 18.9 ms |

So roughly a third of the raw proxy throughput. That is the price of an
interpreted plugin, and still five to ten times a "hundreds of requests per
second" workload. Traefik's memory was 75 MB with several thousand tracked
sources.

## Where the time goes

From `go test -bench .` (compiled, Ryzen 7 3700X, 87 signatures and 41
user-agent patterns):

| | cost | note |
|---|---|---|
| Already-banned request | **770 ns**, 5 allocs | resolve, one map lookup, write a status |
| Client-IP resolution | 184 ns, 0 allocs | with four trusted-proxy CIDRs |
| Signature match | 7.1 µs | short subject, so cheap |
| User-agent match | 35 µs | **the dominant cost** |
| Clean request, end to end | 63 µs, 4 allocs | almost entirely the two matches |

An alternation with no literal prefix must attempt a match at every position, so
cost scales with subject length. That is why matching a 90-character user-agent
costs 5× more than matching a path despite having fewer than half the patterns.

A literal pre-filter measures 3.2× faster interpreted, and is deliberately not
implemented; see the note in `matcher.go` for why a wrong pre-filter fails
silently in exactly the direction you cannot afford.

## Getting the throughput back

`detectors.userAgent.enabled: false` removes most of the cost, at the price of
catching self-identifying scanners only via their request paths.
