# Development: the Yaegi traps

**`tools/yaegi-smoke` is the most important thing in this repository.** Traefik
does not compile plugins, it interprets them with
[Yaegi](https://github.com/traefik/yaegi) — v0.16.3 in the pinned Traefik v3.7.19,
which the smoke test follows, and v0.16.1 in v3.6 — which exposes only the
**Go 1.22** standard library.

How to run it, and the other checks: [README → Development](../README.md#development).

## Invisible to `go build` and `go test`

Two whole classes of bug:

- **A stdlib API the interpreter does not expose:** generic ones such as
  `slices.Sort` and `atomic.Pointer`, the `min`/`max` builtins, `os/exec`.
  Compiles locally, fails at plugin load.
- **`//go:embed`**, which does not work under Yaegi and **fails silently**.
  - The variable is empty, the tests pass, and the page is blank only inside
    Traefik.
  - That is why the console is a string constant, and why the smoke test asserts
    the page is non-empty.

## Five more traps this project hit

All invisible to `go test`; four are asserted by the smoke test, the fifth by a
source check:

- **`map[string]interface{}` with structs as values encoded as
  `{"effective":{}}`** under Yaegi: the nested structs lost every field, with no
  encoding error.
  - The console read that empty object, wrote it back, and wiped the ruleset.
  - Every admin response now has a named struct type; see the note on
    `RulesResponse`. The smoke test decodes `/api/state`, `/api/events`,
    `/api/bans`, `/api/sources` and `/api/rules/compiled` and checks the fields
    are populated.
- **A struct passed through an `interface{}` parameter arrives empty.**
  `json.Marshal` of it returns `{}` with a nil error, so every configuration
  hashed the same and no dynamic-configuration change ever reached the running
  middleware (see `configFingerprint`). Fingerprint helpers take concrete types.
  - Asserted by rotating the admin token on a rebuild.
- **Parallel assignment can silently skip a target.** `best, bestBits = b,
  w.Bits()` ran without setting `best` under Yaegi v0.16.1, so a range ban
  matched nothing (`matchWideLocked`). One assignment per statement in that
  code, and in `setKeyWidths`.
  - Asserted by a manual range ban, and by switching range escalation off on a
    reload with a range ban in place.
- **A tagless switch case with several expressions tests only the first.**
  `switch { case a, b, c: }` behaves as `case a:` under Yaegi v0.16.1, so a
  Redis replica decoded a published revert (`"null"`) as an empty rule set,
  refused it, and kept enforcing the reverted rules. Tagged switches
  (`switch x { case 1, 2: }`) are fine.
  - `TestNoMultiExpressionCasesInTaglessSwitches` parses the plugin's source
    and refuses the construct; the e2e replicas test covers the revert.
- **mapstructure merges into a pre-populated slice instead of replacing it.**
  - A default of `[400,401,403,404,405,501]` plus a configured `[404]` yields
    `[404,401,403,404,405,501]`.
  - List defaults therefore live in `defaultBadPathStatuses` and friends, applied
    after decoding, never in `CreateConfig`. Asserted for `badPaths.statuses`
    and for `enforcement.escalation`.

The smoke test also reads a snapshot back into a fresh runtime, exercises a
read-only console, both crawler policies on sibling definitions, the rule
editor's write path, and refuses three invalid configurations.

## Go version and dependencies

- `go.mod` declares `go 1.22`, Yaegi's stdlib level, so CI's Go 1.22 toolchain
  (and `go vet` locally) refuses anything newer.
- The generic APIs above are older than that; only the smoke test catches them.
- Keep the module dependency-free: anything using cgo, assembly, `//go:embed` or
  heavy reflection fails at plugin import.
