#!/usr/bin/env bash
# Regenerate the console screenshots: start the examples/ harness under its own
# compose project, run the docs tour (e2e/docs/) against the console - once on
# the empty harness, once after examples/scanner-sim.sh has produced bans -
# and tear everything down again.
#
#   scripts/docs-screenshots.sh [outdir]      # default: docs/screenshots
#
# The harness's host ports are fixed (8800 site, 8899 webhook sink, 9900
# console, 18081 Traefik dashboard; the examples/ scripts use them), so this
# cannot run next to another harness. They are bound to 127.0.0.1 only.
# COMPOSE_PROJECT_NAME defaults to scanguard_docs. ARTIFACTS: Playwright's
# test results (default: a temp dir). Node + `npm ci` in e2e/ are the caller's.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mkdir -p "${1:-$ROOT/docs/screenshots}" && cd "${1:-$ROOT/docs/screenshots}" && pwd)"
ARTIFACTS="${ARTIFACTS:-$(mktemp -d)}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-scanguard_docs}"

case "$COMPOSE_PROJECT_NAME" in
  phytotron | phytotron-dev | vib | fileheron | keyb-dev)
    echo "docs-screenshots: refusing the live project name '$COMPOSE_PROJECT_NAME'" >&2
    exit 1 ;;
esac

export SG_WEB=127.0.0.1:8800 SG_HOOKS=127.0.0.1:8899 SG_CONSOLE=127.0.0.1:9900 SG_DASHBOARD=127.0.0.1:18081
TOKEN=dev-token-change-me-0123456789 # examples/dynamic/scanguard.yml

cd "$ROOT/examples"
teardown() {
  rc=$?
  [ "$rc" = 0 ] || docker compose logs --tail=200 >"$ARTIFACTS/stack.log" 2>&1 || true
  docker compose down -v --remove-orphans --rmi local || true
  exit "$rc"
}
trap teardown EXIT

docker compose up -d --wait
for _ in $(seq 60); do
  curl -sf -o /dev/null -H "X-Scanguard-Token: $TOKEN" http://localhost:9900/api/health && break
  sleep 1
done
docker compose logs traefik 2>&1 | grep -q 'scanguard initialised'

tour() { # tour <results subdir> <playwright args...>
  (cd "$ROOT/e2e" && DOCS_SCREENSHOT_DIR="$OUT" \
    npx playwright test -c playwright.docs.config.ts --output "$ARTIFACTS/$1" "${@:2}")
}
tour empty --grep @empty
./scanner-sim.sh
tour bans --grep-invert @empty
echo "docs-screenshots: $(find "$OUT" -name '*.png' | wc -l) PNGs in $OUT"
