#!/usr/bin/env bash
# Drives scanguard the way a real scanner would and checks that it reacts.
#
# Each scenario poses as its own source address via X-Real-Ip. That works because
# the harness trusts the Docker bridge on both sides: forwardedHeaders.trustedIPs
# in traefik.yml lets the header through, and clientIP.trustedProxies in
# dynamic/scanguard.yml lets scanguard believe it. Traffic WITHOUT that header is
# attributed to the bridge itself, which is a trusted proxy and therefore exempt —
# so running this script cannot lock you out of your own harness.
set -uo pipefail

BASE="${BASE:-http://localhost:8800}"
CONSOLE="${CONSOLE:-http://localhost:9900}"
TOKEN="${TOKEN:-dev-token-change-me-0123456789}"

pass=0
fail=0

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }

# hit <source-ip> <path> [extra curl args...]  -> prints the status code
hit() {
  local src="$1" path="$2"; shift 2
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "X-Real-Ip: $src" "$@" "$BASE$path"
}

expect() { # expect <description> <expected> <actual>
  if [[ "$3" == "$2" ]]; then ok "$1 ($3)"; else bad "$1 — expected $2, got $3"; fi
}

# What matters is whether scanguard blocked the request, not what the backend
# would otherwise have answered. A 404 from the site is still "not blocked", and
# asserting on 200 instead would make these checks depend on the backend's routing.
blocked() { # blocked <description> <status>
  if [[ "$2" == "403" ]]; then ok "$1 (blocked)"; else bad "$1 — expected a block, got $2"; fi
}
served() { # served <description> <status>
  if [[ "$2" != "403" ]]; then ok "$1 (passed through, $2)"; else bad "$1 — scanguard blocked it"; fi
}

console() { curl -s --max-time 10 -H "X-Scanguard-Token: $TOKEN" "$CONSOLE$1"; }

say "Baseline"
served "a clean request from a fresh source" "$(hit 198.51.100.1 /)"
served "local traffic with no forwarded header is exempt" \
  "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/wp-login.php")"

say "Signature probes"
blocked "/wp-login.php" "$(hit 198.51.100.10 /wp-login.php)"
blocked "/.env" "$(hit 198.51.100.11 /.env)"
blocked "phpMyAdmin" "$(hit 198.51.100.12 /phpmyadmin/index.php)"
blocked "the PHPUnit RCE path" \
  "$(hit 198.51.100.13 /vendor/phpunit/phpunit/src/util/php/eval-stdin.php)"
blocked "a probing source stays banned on an innocent path" "$(hit 198.51.100.10 /)"

say "Honeypot"
blocked "a trap path bans on the first hit" "$(hit 198.51.100.20 /admin.php)"

say "Scanner user-agent"
blocked "sqlmap user-agent" "$(hit 198.51.100.21 / -A 'sqlmap/1.7#stable')"
served "a normal browser user-agent" \
  "$(hit 198.51.100.22 / -A 'Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0')"

say "Injection payload in the query string"
blocked "percent-encoded UNION SELECT" \
  "$(hit 198.51.100.23 '/search?q=1%20UNION%20SELECT%20password%20FROM%20users')"
served "an ordinary search query" "$(hit 198.51.100.24 '/search?q=hello+world')"

say "Distinct 404 flood (capacity 6 in the example configuration)"
src=198.51.100.30
for i in $(seq 1 6); do hit "$src" "/does-not-exist-$i" >/dev/null; done
blocked "the source is banned after 6 distinct 404s" "$(hit "$src" /)"

say "One broken link hammered by a real user must NOT ban"
src=198.51.100.31
for _ in $(seq 1 25); do hit "$src" /a-single-broken-link >/dev/null; done
served "repeating one failing path is tolerated" "$(hit "$src" /a-single-broken-link)"

say "Spoofing"
# 198.51.100.40 probes while claiming to be someone else in X-Forwarded-For.
hit 198.51.100.40 /wp-login.php -H 'X-Forwarded-For: 203.0.113.99' >/dev/null
served "the claimed third party is unaffected" "$(hit 203.0.113.99 /)"
blocked "the real source" "$(hit 198.51.100.40 /)"

say "Console"
count=$(console /api/bans | grep -o '"key"' | wc -l | tr -d ' ')
if [[ "$count" -gt 0 ]]; then ok "console reports $count active ban(s)"; else bad "console reports no bans"; fi
expect "console refuses an unauthenticated request" 401 \
  "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$CONSOLE/api/health")"
expect "console serves the dashboard with a token" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "X-Scanguard-Token: $TOKEN" "$CONSOLE/")"

say "Unblock takes effect immediately"
if curl -s -X DELETE --max-time 10 \
     -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" \
     "$CONSOLE/api/bans?key=198.51.100.10%2F32" | grep -q '"unbanned":true'; then
  served "the unbanned source on its very next request" "$(hit 198.51.100.10 /)"
else
  bad "unban request did not report success"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
