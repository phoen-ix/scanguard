# E2E coverage, part c: use cases (`tests/usecases/`)

[COVERAGE.md](COVERAGE.md) maps every FEATURE to a test. This part maps every
HAND-OVER: a chain in which one party gives something to another - a ban, an
unblock, a rule set, a token - and the next one uses it. The parties are
whoever runs scanguard (its config file, its Traefik), the console's
operators, the clients it judges, and the webhook consumer it tells.

**Why it exists.** The feature specs plant the token where the gate keeps it
(`unlock()`), set preconditions up through the API and often read the outcome
through it too, so what one party produced was rarely what the next one met: a
rule edit "on replica A" was a PUT, the unblock behind the unban webhook was a
curl, a rotated token was a stale one planted in sessionStorage. Read from all
specs and the harness checks in the 2026-11 audit: of 16 hand-overs, 4 were
followed to the end, 11 partly, 1 not at all; no operator signed in at the gate.

**The rules** (pinned by `hygiene_test.go ›
TestAUseCaseReachesTheServerOnlyAsAPersonOrAClient`):

- Every operator acts in their own browser and signs in at the console's gate
  (`browserOf(browser, THE_OPERATOR)`): the token typed, or Unlock behind the
  auth proxy.
- What is handed over is the SAME thing that is used: the row on the
  operator's screen, the token the runner wrote into the config.
- The outcome is read on the affected party's side: the operator's screen, the
  status a client is answered (`clientAt(ip).gets(path)`, each client at an
  address of its own), what the webhook consumer was sent (`delivered(key)`).
- A use-case spec imports only `./lib` and `@playwright/test` and calls no
  API. Background facts (the file rules back in force, a second console) come
  from `given` in `tests/usecases/lib.ts`, the one file that does; what the
  runner does (rewrite the config, restart Traefik) is `theRunner` there.

**A failing chain is a product finding.** None of the 12 failed (2026-11-28):
the bugs the audit had found on these paths (Lock during a poll, a rule change
first seen by a ban, the sticky ban duration, sibling consoles sharing one
admin block) were fixed before, in phase 2. The last column stays for the next
chain that does.

- **Run:** `scripts/e2e.sh tests/usecases`.
- **Items:** 12 hand-overs, ✅ 12, in 12 tests, plus the 4 the feature specs
  already followed to the end (below).

## Bans - `bans.spec.ts`

| # | Hand-over | Before | Followed to | Test | Found |
|---|---|---|---|---|---|
| U2 | A signature bans a scanner; the operator unblocks it | partial: the single-source ban was never lifted in the UI | the operator sees the row, unblocks; the scanner is served; probing again bans it at the first rung (unblock forgives the offence) | `U2 a scanner a signature banned is unblocked by the operator and served; probing again starts at the first rung` | - |
| U3 | The operator bans an address from the form, then unblocks it | partial: the token was planted | the visitor is refused, its refusals count up on the operator's row; unblocked, it is served | `U3 an address the operator bans from the form is refused until they unblock it` | - |
| U8 | An operator behind the auth proxy unblocks a scanner | partial: the unban was a curl, its actor unchecked | the consumer is sent the ban, then the unban with the same key and the operator's identity; the operator's feed names them too | `U8 an unblock behind the auth proxy reaches the webhook consumer with the key and who lifted it` | - |

## Rules - `rules.spec.ts`

| # | Hand-over | Before | Followed to | Test | Found |
|---|---|---|---|---|---|
| U1 | The operator saves a trap path | partial: the token was planted | the next scanner on it is refused and listed; reverted, a new scanner is served | `U1 a trap the operator saves refuses the next scanner; reverted, it is an ordinary path again` | - |
| U7 | One operator saves while another has the editor open | none: the other save was a PUT | the other's clean editor reloads by itself; dirty, it is warned and keeps the edit; reloaded, it shows the save | `U7 a save by one operator reloads the other's clean editor, and warns it once it holds unsaved edits` | - |
| U9 | The operator turns on dry run | partial: the lift was API only | the scanner is served and its would-ban listed; lifted, the next probe is listed again; dry run off, the would-ban is gone and enforces nothing | `U9 a dry run lists the would-ban, the operator lifts it, and turning it off enforces nothing hypothetical` | - |
| U10 | The operator allowlists a range | partial: the token was planted | a scanner in it is served and counted as exempt; the ban form refuses it; reverted, the range is judged again and the form bans it | `U10 a range the operator allowlists is exempt and cannot be banned from the form; reverted, both work again` | - |

## Replicas - `replicas.spec.ts`

Two Traefik replicas sharing one Redis, an operator at each console. Each step
waits for the other operator's screen (a replica re-reads Redis every 30 s),
then asks as the client: what a replica's console shows is what it enforces.

| # | Hand-over | Before | Followed to | Test | Found |
|---|---|---|---|---|---|
| U4 | A ban from A's console; the unblock from B's | partial: the token was planted | B's operator sees the row and B refuses; B's unblock serves on B, and once A's row is gone A serves | `U4 a ban from replica A's console is refused on B; lifted from B's console, A serves the address again` | - |
| U5 | A rule saved on A; reverted on B | partial: the edit and the revert were API calls | B's editor says "edited here" and B refuses the trap; B's revert reaches A's editor, and A serves the path | `U5 a rule saved on replica A is in B's editor and enforced by B; reverted from B, A runs the file again` | - |

## The runner - `runner.spec.ts`

| # | Hand-over | Before | Followed to | Test | Found |
|---|---|---|---|---|---|
| U6 | The runner rotates a console's token in the config | partial: a stale token was planted; a real rotation only in yaegi-smoke | the open session is sent back to the gate with the reason; the old token is refused, the new one gets in | `U6 a token rotated in the config sends the open session back to the gate; the new one gets in, the old one never again` | - |
| U11 | The runner restarts Traefik after a console edit | partial: API only (`rules-check.sh`) | the operator's editor still says "edited here" with the edit; a scanner on it is refused; it still reverts | `U11 a rule the operator saved is still in their editor and still enforced after the runner restarts Traefik` | - |
| U12 | The runner restarts Traefik with bans in force | partial: CI compared the count; `restart-check.sh` the keys, by API | the operator's rows are the same; both clients are still refused; an unblock after the restart serves | `U12 the bans the operator sees survive the runner's Traefik restart: the same rows, still refused, still liftable` | - |

## Followed to the end before

| Hand-over | Test |
|---|---|
| A detection on replica A bans the source on B | `replicas.spec.ts › a detection on one replica bans the source on the other` |
| A token from the config typed at the gate, kept across a reload, ended by Lock | `gate.spec.ts › the right token unlocks, a reload keeps the session, Lock forgets it`; behind basicAuth `auth.spec.ts` |
| An SSO identity is the actor on the unban and in the rule-editor meta | `sso.spec.ts › the forwarded identity is who the audit trail names` |
| A ban reaches the webhook consumer with the same key | `examples/notify-check.sh` "Payload contract" |
