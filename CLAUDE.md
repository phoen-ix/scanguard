# scanguard

Traefik middleware plugin (Go, one package at the repo root) that bans HTTP
scanners and serves its own console. Traefik does not compile it: it
**interprets** it with Yaegi v0.16.1, which exposes only the Go 1.22 stdlib.
docs/development.md explains the interpreter traps in full.

## Commands

```bash
go vet ./... && go test -race -count=1 ./...   # unit tests (CI: Go 1.22)
gofmt -l .                                     # must print nothing
# Yaegi smoke test: the plugin must sit at its import path in a GOPATH tree
gp=$(mktemp -d); mkdir -p "$gp/src/github.com/phoen-ix"; ln -s "$PWD" "$gp/src/github.com/phoen-ix/scanguard"
(cd tools/yaegi-smoke && SMOKE_GOPATH="$gp" go run .)
# e2e: the examples/ harness (Traefik + nginx + webhook sink), fixed ports
# (rules-check.sh restarts Traefik itself, under the project that serves :9900)
cd examples && export COMPOSE_PROJECT_NAME=scanguard_e2e && docker compose up -d
./scanner-sim.sh && ./streaming-check.sh && ./rules-check.sh && ./notify-check.sh
docker compose down -v --remove-orphans
# console e2e suite (starts and removes its own harness, project scanguard_e2e)
scripts/e2e.sh [playwright args]               # e2e/COVERAGE.md maps features to tests
# docs screenshots (starts and removes its own harness, project scanguard_docs)
(cd e2e && npm ci && npx playwright install chromium)
scripts/docs-screenshots.sh [outdir]           # default docs/screenshots
```

In the fleet: `fleet check scanguard` (unit, vet, gofmt, no-deps, yaegi-smoke),
`--with e2e` adds the harness checks (project `fleet-scanguard`) and the console
suite (`scanguard_e2e`), `--with docs` the tour.
Anything that starts Docker goes through `~/repos/.fleet/scripts/slot heavy scanguard -- …`.

## Invariants

- **`go.mod` stays `go 1.22`, CI stays on Go 1.22** (Yaegi's stdlib level).
  Never bump. Beyond that, Yaegi has no generic stdlib APIs and no `min`/`max`
  builtins: `slices.Sort` or `atomic.Pointer` compile under 1.22 and fail at
  plugin load; only yaegi-smoke catches them. No `os/exec`, cgo or assembly.
- **Zero dependencies** (`go.mod` has no `require`; CI and fleet check it).
- **No `//go:embed`** — empty under Yaegi, silently. The console is three string
  constants in `admin_ui.go`: no backticks in its CSS/JS, ES5-style JS (string
  concatenation, no template literals), text via `textContent` only, no inline
  script (the CSP forbids it), no build step.
- **Every admin JSON response is a named struct type**, never
  `map[string]interface{}` holding structs: Yaegi encodes those as `{}`
  (see `RulesResponse` in `admin.go`).
- **No list defaults in `CreateConfig`**: Traefik's mapstructure merges into a
  pre-filled slice. List defaults (`defaultBadPathStatuses`,
  `defaultEscalation`) are applied after decoding.
- **Default rules** (`rules_default.go`) are RE2, lower case (matching is
  case-insensitive), one pattern per entry; a default must be something no
  legitimate client of a site without that software would request.
- `clientIP`, `store`, `admin`, `notify` are not editable from the console
  (`overrides.go`); edits go through the same `Config.parse` as the file.
- `.traefik.yml` `testData` is executed by the plugin catalog: it must stay a
  config `New()` accepts.
- **Harness ports are fixed**: 8800 site, 8899 webhook sink, 9900 console,
  18081 Traefik dashboard (`SG_WEB`/`SG_HOOKS`/`SG_CONSOLE`/`SG_DASHBOARD`
  move them, but the examples/ scripts and CI assume these). One harness at a
  time; fleet runs them `exclusive`. Compose project names are always explicit
  (`scanguard_e2e`, `scanguard_docs`, fleet's `fleet-scanguard`); never
  `phytotron*`, `vib`, `fileheron`, `keyb-dev`.
- The harness token `dev-token-change-me-0123456789` is public test data; the
  tour authenticates with it (`X-Scanguard-Token`).
- Traefik is pinned to a patch version in `examples/docker-compose.yml` and in
  `ci.yml` (matrix, the `sed`, and the render-check steps' `if:`), and in the
  e2e overlay `examples/docker-compose.e2e.yml`. Bump them together and re-run
  `streaming-check.sh`.
- The harness keeps `enforcement.subnet` and `detectors.uaRotation` off (the
  defaults). scanner-sim bans ten sources in 198.51.100.0/24 and `uniqueIp()`
  hands out consecutive addresses, so tests' sources share /24s: with range
  escalation on they would ban each other. The one e2e test that needs it
  (`rules.spec.ts`, range escalation) enables it from the editor for itself, on
  198.51.100.0/24, which scanner-sim only uses in its own harness.
- Console e2e suite (`e2e/tests/`): one worker, because every test shares the
  harness's runtime; tests own their data through `uniqueIp()` sources, and
  rule-editor tests revert to the file config after each test. The read-only,
  SSO and orphan consoles come from `e2e/fixtures/consoles.yml`, which
  global-setup copies into `examples/dynamic/zz-e2e-consoles.yml` (gitignored)
  for the run. `scripts/e2e.sh` adds the overlay `examples/docker-compose.e2e.yml`:
  Redis plus two Traefik replicas on 8801/9901 and 8802/9902.
- Docs tour (`e2e/docs/`): screenshot names are stable once committed;
  `tour.spec.ts` pins every server timestamp to 2026-06-15 10:00 Vienna so two
  runs give identical PNGs. Optimise with oxipng before committing.

## Pointers

- `admin.go` — threat model of the console (top comment); `overrides.go` — why
  the rule editor keeps its own store; `matcher.go` — why there is no literal
  pre-filter.
- Screenshots and their gallery: `docs/screenshots/README.md`.
