# Development: the Yaegi traps

**`tools/yaegi-smoke` is the most important thing in this repository.** Traefik
does not compile plugins, it interprets them with
[Yaegi](https://github.com/traefik/yaegi), which is pinned at v0.16.1 and exposes
only the **Go 1.22** standard library.

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

## Two more traps this project hit

Both invisible to `go test`, both now asserted by the smoke test:

- **`map[string]interface{}` with structs as values encoded as
  `{"effective":{}}`** under Yaegi: the nested structs lost every field, with no
  encoding error.
  - The console read that empty object, wrote it back, and wiped the ruleset.
  - Every admin response now has a named struct type; see the note on
    `RulesResponse`.
- **mapstructure merges into a pre-populated slice instead of replacing it.**
  - A default of `[400,401,403,404,405,501]` plus a configured `[404]` yields
    `[404,401,403,404,405,501]`.
  - List defaults therefore live in `defaultBadPathStatuses` and friends, applied
    after decoding, never in `CreateConfig`.

## Go version and dependencies

- `go.mod` declares `go 1.22`, Yaegi's stdlib level, so CI's Go 1.22 toolchain
  (and `go vet` locally) refuses anything newer.
- The generic APIs above are older than that; only the smoke test catches them.
- Keep the module dependency-free: anything using cgo, assembly, `//go:embed` or
  heavy reflection fails at plugin import.
