# bp — Next Steps

> Last updated: 2026-06-16. Status: awaiting founder GO.

---

## Immediate Next: Phase 1 TDD Implementation

### Step 1 — Project scaffold (TDD precondition)

- Choose implementation language (Go is the natural fit for a POSIX CLI binary: single static binary,
  fast startup, good stdlib for HTTP + SQLite). Confirm with founder before scaffolding.
- Init project at repo root (e.g. `go mod init github.com/…/bp`) or a separate `cli/` directory.
- Wire up the test runner before writing any production code (TDD: RED first).

### Step 2 — RED: `--pos` parser unit tests

The `--pos` parser is the load-bearing core. Write failing tests first:

- Parse `header:NAME` → `{selector: "header", name: "NAME"}`
- Parse `cookie:NAME`, `body:FIELD`, `query:NAME`, `path:INDEX`, `offset:START-END`
- Parse multi-`--pos` (slice of selectors)
- Reject unknown selectors (exit 64)
- Parse `--type sniper|battering-ram|pitchfork|cluster-bomb`

**Burp not required for these tests.**

### Step 3 — RED: offset resolver unit tests

The resolver takes a selector + the raw HTTP bytes of the base request and returns
`PayloadPosition{start:Int, end:Int, name:String}`.

Key test cases from `docs/SPEC.md §5`:
- `header:X-Forwarded-For` → byte range of its value in the raw request
- `cookie:role` → byte range inside the Cookie header value
- `body:username` → byte range in a form-urlencoded or JSON body
- `query:q` → byte range in the URL query string
- `offset:42-52` → passthrough (start=42, end=52, name from `--pos` name)
- multi-position selector produces a slice of `PayloadPosition`

**Burp not required.**

### Step 4 — RED: `CreateAttackRequest` builder tests

Verify the JSON emitted by `bp fuzz` matches the Kotlin contract exactly (`docs/SPEC.md §8`):
- `attackType` as String (not enum)
- `positions[].start` and `.end` as Int (required, no defaults)
- `payloads` as `Map<String, List<String>>`; all values are flattened server-side (document caveat)
- For `cluster-bomb`: client expands the N-D product before calling `/intruder/attack/create` (or
  calls it once per row — TBD; see ADR-0003)

### Step 5 — GREEN: implement parser + resolver + builder

Implement each piece to make its RED tests pass. No other code yet.

### Step 6 — Contract tests (Kotlin JSON models)

Write contract tests that freeze the JSON shapes from `docs/SPEC.md §6` and §8:
- `ApiResponse<T>` envelope unwrapping
- `AttackResultEntry` field names, types, nullability
- `HistoryEntryResponse.id` as Long (not Int)
- Enum-as-String: `attackType`, `status`, `severity`, `confidence`

**Burp not required.**

### Step 7 — Scaffold remaining commands (priority order)

Once the fuzz core is green:

1. `bp health` / `bp version` — simplest; good integration smoke test
2. `bp send` (repeater) — fuzz-adjacent, critical
3. `bp fuzz status|results|pause|resume|stop` — completes the fuzz lifecycle
4. `bp proxy` / `bp req` / `bp history` — read-heavy, no side effects
5. `bp session` commands
6. `bp scope` / `bp sitemap` / `bp target`
7. `bp collab` / `bp scan` (Pro-gated; must degrade gracefully)
8. `bp encode|decode|hash` / `bp diff` / `bp endpoints`
9. `bp config` / `bp ext` (stubs; document as stubs)
10. `bp log` / `bp tag` / `bp show` (C4 Run Ledger)

### Step 8 — Integration tests (live `:8089`)

Run against a real Burp instance. Skip cleanly if Burp absent (`BURP_REST_URL` unreachable).
Use the BDD scenarios in `docs/bdd-clean/` as the acceptance gate.

---

## Deferred (do not block Phase 1)

- C3 bug-bounty-mini adapter (I6/G006 floor) — optional, separate adapter
- Sequencer / Comparer / Logger / Dashboard — not in `configureRouting()`, cannot be implemented
  until new `*Routes.kt` are added to the extension
