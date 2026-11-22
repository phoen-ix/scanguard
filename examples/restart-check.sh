#!/usr/bin/env bash
# Bans survive a Traefik restart: the same keys are listed afterwards, and a
# banned source is still refused. Run from examples/ after scanner-sim.sh, under
# the compose project that serves :9900 (COMPOSE_PROJECT_NAME).
set -euo pipefail

BASE="${BASE:-http://localhost:8800}"
CONSOLE="${CONSOLE:-http://localhost:9900}"
TOKEN="${TOKEN:-dev-token-change-me-0123456789}"

keys() {
  curl -sf --max-time 10 -H "X-Scanguard-Token: $TOKEN" "$CONSOLE/api/bans" |
    python3 -c 'import json,sys; print("\n".join(sorted(b["key"] for b in json.load(sys.stdin)["bans"])))'
}

before=$(keys)
probe=$(grep -m1 '/32$' <<<"$before" || true)
[[ -n "$probe" ]] || { echo "FAIL no single-address ban to carry over"; exit 1; }
docker compose restart traefik >/dev/null
# `restart` returns once the new container has started; wait until it serves.
curl -sf -o /dev/null --max-time 3 --retry 60 --retry-delay 1 --retry-all-errors \
  -H "X-Scanguard-Token: $TOKEN" "$CONSOLE/api/health"
after=$(keys)
if [[ "$after" != "$before" ]]; then
  echo "FAIL the ban list changed across the restart:"; diff <(echo "$before") <(echo "$after") || true; exit 1
fi
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "X-Real-Ip: ${probe%/32}" "$BASE/")
[[ "$code" == 403 ]] || { echo "FAIL $probe was listed but served ($code) after the restart"; exit 1; }
echo "PASS $(wc -l <<<"$after") bans survived the restart; $probe is still refused"
