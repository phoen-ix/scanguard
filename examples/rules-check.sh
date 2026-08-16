#!/usr/bin/env bash
# Exercises the rule editor against a live Traefik.
#
# The interesting property is that none of this needs a Traefik restart: the
# console owns its own store, edits are re-validated through the same parser that
# reads the file configuration, and the effective settings are swapped atomically.
set -uo pipefail

BASE="${BASE:-http://localhost:8800}"
CONSOLE="${CONSOLE:-http://localhost:9900}"
TOKEN="${TOKEN:-dev-token-change-me-0123456789}"

pass=0
fail=0
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }

expect() { if [[ "$3" == "$2" ]]; then ok "$1 ($3)"; else bad "$1 — expected $2, got $3"; fi; }

hit() { # hit <source> <path>
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "X-Real-Ip: $1" "$BASE$2"
}
get_rules() { curl -s --max-time 10 -H "X-Scanguard-Token: $TOKEN" "$CONSOLE/api/rules"; }
put_rules() {
  curl -s --max-time 10 -X PUT -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" \
    -H 'Content-Type: application/json' --data-binary @- "$CONSOLE/api/rules"
}
jqp() { python3 -c "import json,sys;d=json.load(sys.stdin);$1"; }

# Start from a known state.
curl -s -X DELETE --max-time 10 -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" \
  "$CONSOLE/api/rules" >/dev/null

say "Baseline"
expect "no sections are console-managed yet" "[]" \
  "$(get_rules | jqp 'print(json.dumps(d["overridden"]))')"
expect "the effective rules equal the file rules" "True" \
  "$(get_rules | jqp 'print(json.dumps(d["effective"],sort_keys=True)==json.dumps(d["fromFile"],sort_keys=True))')"
# Traefik's mapstructure merges into pre-populated slices, so a default leaking
# into a configured list is a real and silent failure mode.
expect "a configured list is not merged with defaults" "6" \
  "$(get_rules | jqp 'print(len(d["effective"]["detectors"]["badPaths"]["statuses"]))')"

say "Add a honeypot from the console"
expect "the path is ordinary right now" 404 "$(hit 198.51.100.60 /rules-check-trap)"
get_rules | jqp '
e = d["effective"]
e["detectors"]["honeypots"]["paths"].append("/rules-check-trap")
print(json.dumps(e))' | put_rules >/dev/null
expect "it blocks immediately, with no restart" 403 "$(hit 198.51.100.61 /rules-check-trap)"
expect "only the edited section is console-managed" '["detectors"]' \
  "$(get_rules | jqp 'print(json.dumps(d["overridden"]))')"

say "Invalid edits are refused without disturbing what runs"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
  -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" -H 'Content-Type: application/json' \
  -d '{"detectors":{"signatures":{"enabled":true,"patterns":["([unclosed"]}}}' "$CONSOLE/api/rules")
expect "a broken regular expression is rejected" 422 "$code"
expect "the previous rules still run" 403 "$(hit 198.51.100.62 /rules-check-trap)"
expect "signature detection is untouched" 403 "$(hit 198.51.100.63 /wp-login.php)"

say "Protected settings are out of reach"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
  -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" -H 'Content-Type: application/json' \
  -d '{"clientIP":{"trustedProxies":["0.0.0.0/0"]}}' "$CONSOLE/api/rules")
expect "a submission naming clientIP is rejected outright" 400 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
  -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" -H 'Content-Type: application/json' \
  -d '{"admin":{"token":"attacker-controlled-token"}}' "$CONSOLE/api/rules")
expect "a submission naming admin is rejected outright" 400 "$code"

say "Mutations still need authentication"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
  -H 'Content-Type: application/json' -d '{}' "$CONSOLE/api/rules")
expect "no token is refused" 401 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
  -H "X-Scanguard-Token: $TOKEN" -H 'Content-Type: application/json' -d '{}' "$CONSOLE/api/rules")
expect "no anti-CSRF header is refused" 403 "$code"

say "Edits survive a Traefik restart"
if docker compose restart traefik >/dev/null 2>&1; then
  # Give the old container time to actually go away first. Polling immediately can
  # succeed against a Traefik that is still shutting down, which would make this
  # check pass while measuring nothing.
  sleep 3
  for _ in $(seq 1 30); do
    curl -sf --max-time 3 -H "X-Scanguard-Token: $TOKEN" "$CONSOLE/api/health" >/dev/null 2>&1 && break
    sleep 1
  done
  expect "the console rules were restored" '["detectors"]' \
    "$(get_rules | jqp 'print(json.dumps(d["overridden"]))')"
  expect "the honeypot added from the console still blocks" 403 "$(hit 198.51.100.64 /rules-check-trap)"
else
  bad "could not restart traefik (run this from examples/)"
fi

say "Revert hands control back to the file"
curl -s -X DELETE --max-time 10 -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" \
  "$CONSOLE/api/rules" >/dev/null
expect "nothing is console-managed any more" "[]" \
  "$(get_rules | jqp 'print(json.dumps(d["overridden"]))')"
expect "the console honeypot is gone" 404 "$(hit 198.51.100.65 /rules-check-trap)"
expect "the honeypot from the file is still in force" 403 "$(hit 198.51.100.66 /admin.php)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
