#!/usr/bin/env bash
# The streaming release gate.
#
# scanguard wraps http.ResponseWriter so it can see what the backend answered,
# which is what makes 404-flood and brute-force detection possible. A wrapper that
# forgets to forward http.Flusher and http.Hijacker silently breaks WebSockets,
# Server-Sent Events and gRPC streaming on every route it touches — that is
# traefik#10269, open since 2023, and it surfaces weeks later as "the chat stopped
# working", never as an error at deploy time.
#
# So this must pass against the exact Traefik patch version you deploy, and it
# must be re-run after every Traefik upgrade.
set -uo pipefail

BASE="${BASE:-http://localhost:8800}"
HOST="${HOST:-localhost:8800}"

pass=0
fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }

printf '\n\033[1mWebSocket upgrade through the middleware\033[0m\n'
# A raw handshake, so the check needs no extra tooling. A 101 means the upgrade
# survived; anything else means the ResponseWriter wrapper ate the hijack.
response=$(printf 'GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' "$HOST" \
  | timeout 6 curl -s --http1.1 --max-time 5 \
      -o /dev/null -w '%{http_code}' \
      -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
      -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
      -H 'Sec-WebSocket-Version: 13' \
      "$BASE/ws" 2>/dev/null)

if [[ "$response" == "101" ]]; then
  ok "the handshake returned 101 Switching Protocols"
else
  bad "the handshake returned $response — http.Hijacker did not survive the wrapper"
fi

printf '\n\033[1mServer-Sent Events flush through the middleware\033[0m\n'
# The backend emits a tick every 400ms for four seconds. If Flush is forwarded,
# the first bytes arrive almost immediately; if the wrapper swallowed it, nothing
# appears until the stream ends.
start=$(date +%s%N)
first_byte=$(curl -s --no-buffer --max-time 6 \
  -w '%{time_starttransfer}' -o /tmp/scanguard-sse.$$ "$BASE/sse" 2>/dev/null)
end=$(date +%s%N)
total_ms=$(( (end - start) / 1000000 ))
ticks=$(grep -c '^data: tick' /tmp/scanguard-sse.$$ 2>/dev/null || echo 0)
rm -f /tmp/scanguard-sse.$$

ttfb_ms=$(awk -v t="$first_byte" 'BEGIN { printf "%d", t * 1000 }')
printf '  time to first byte: %sms, total: %sms, ticks received: %s\n' "$ttfb_ms" "$total_ms" "$ticks"

if [[ "$ticks" -lt 5 ]]; then
  bad "only $ticks ticks arrived — the SSE backend may not be reachable"
elif [[ "$ttfb_ms" -lt 1500 && "$total_ms" -gt 2000 ]]; then
  ok "events streamed incrementally (first byte well before the stream ended)"
else
  bad "the whole stream arrived at once — http.Flusher did not survive the wrapper"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
