#!/usr/bin/env bash
# Run the console e2e suite (e2e/tests/, e2e/playwright.config.ts): start the
# examples/ harness plus its e2e overlay (examples/docker-compose.e2e.yml: two
# Traefik replicas sharing a Redis) under its own compose project, run the
# suite against it, and tear everything down again.
#
#   scripts/e2e.sh [playwright args...]     e.g. scripts/e2e.sh tests/bans.spec.ts
#
# The harness's host ports are fixed (8800 site, 8899 webhook sink, 9900
# console, 18081 Traefik dashboard; the examples/ scripts use them; the
# replicas add 8801/9901 and 8802/9902), so this cannot run next to another
# harness. They are bound to 127.0.0.1 only.
# COMPOSE_PROJECT_NAME defaults to scanguard_e2e. ARTIFACTS: Playwright's
# results and traces (default: a temp dir). Node + `npm ci` in e2e/ are the
# caller's.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS="${ARTIFACTS:-$(mktemp -d)}"
mkdir -p "$ARTIFACTS"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-scanguard_e2e}"

case "$COMPOSE_PROJECT_NAME" in
  phytotron | phytotron-dev | vib | fileheron | keyb-dev)
    echo "e2e: refusing the live project name '$COMPOSE_PROJECT_NAME'" >&2
    exit 1 ;;
esac

export SG_WEB=127.0.0.1:8800 SG_HOOKS=127.0.0.1:8899 SG_CONSOLE=127.0.0.1:9900 SG_DASHBOARD=127.0.0.1:18081
export COMPOSE_FILE=docker-compose.yml:docker-compose.e2e.yml
TOKEN=dev-token-change-me-0123456789 # examples/dynamic/scanguard.yml

cd "$ROOT/examples"
teardown() {
  rc=$?
  [ "$rc" = 0 ] || docker compose logs --tail=300 >"$ARTIFACTS/stack.log" 2>&1 || true
  rm -f dynamic/zz-e2e-consoles.yml # the suite's extra consoles, should it have died mid-run
  docker compose down -v --remove-orphans --rmi local || true
  exit "$rc"
}
trap teardown EXIT

docker compose up -d --wait
for console in 9900:$TOKEN 9901:e2e-redis-token-0123456789 9902:e2e-redis-token-0123456789; do
  for _ in $(seq 60); do
    curl -sf -o /dev/null -H "X-Scanguard-Token: ${console#*:}" "http://localhost:${console%%:*}/api/health" && break
    sleep 1
  done
done
docker compose logs traefik 2>&1 | grep 'scanguard initialised' >/dev/null # not -q: under pipefail an early exit fails the pipe

cd "$ROOT/e2e"
npx playwright test --output "$ARTIFACTS/e2e-results" "$@"
