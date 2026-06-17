# bp — Current State

> Last updated: 2026-06-16

---

## Where We Are

**Phase 0 is complete. No implementation code exists yet. Awaiting founder GO for Phase 1.**

---

## What Is Done

### Spec (SDD)

- `docs/SPEC.md` — canonical API spec reconstructed from `RestServer.kt` + `routes/*.kt`.
  13 groups, 69 endpoints, verdict COMPLETE (0 missed). Includes: `--pos` grammar, C4 Ledger
  design, DDD aggregates, TDD test architecture, acceptance criteria, Community vs Pro matrix.
- `docs/CLI.md` — canonical CLI grammar. Command map (one verb per REST group), `--pos`
  selectors, global flags, naming decisions, error/exit-code conventions.
- `docs/OUTPUT.md` — output contract. 4 formats (json/table/raw/quiet), `-w` template grammar
  (11 core tokens), field catalog per command family, agent (AX) schema contract, exit codes.

### BDD Scenarios

`docs/bdd-clean/` contains 15 Gherkin feature files covering all 13 API groups:

| File | Coverage |
|---|---|
| `00-common.feature` | Connection refused, envelope, Pro-required, `--id` invalid — transversal |
| `00-output.feature` | All 4 formats, `-w` template, `--fields`, exit codes — transversal |
| `01-health.feature` | `/health`, `/version`, `/docs` |
| `02-proxy.feature` | `/proxy/history`, intercept, websocket |
| `03-repeater.feature` | `/repeater/send`, batch, tab |
| `04-fuzz-core.feature` | `bp fuzz` create+start (async), `--pos` selectors, attack types |
| `05-fuzz-results.feature` | status/pause/resume/stop/results/summary |
| `06-collaborator.feature` | generate, poll, Pro-gate |
| `07-scanner.feature` | crawl/audit/all, issues, pause/resume/stop, Pro-gate |
| `08-securityscan.feature` | auth-bypass, idor, headers, cors, endpoints |
| `09-target.feature` | scope set/add/remove/check, sitemap |
| `10-decoder-utils.feature` | encode, decode, hash, smart-decode, diff, extract-endpoints |
| `11-session.feature` | set, get, clear, send, batch, cookie-jar |
| `12-config.feature` | project/user config stubs, extensions |
| `13-history.feature` | history list/get/sitemap/replay/clear (DB-conditional) |
| `14-ledger.feature` | Run Ledger (C4): log, tag, show, `--no-ledger` |

### Totality Verification

All 69 endpoints from `configureRouting()` are enumerated. No invented routes. Verdict: COMPLETE.

### ADRs

6 locked decisions recorded in `docs/adr/` (see `INDEX.md`). All status: accepted 2026-06-16.

---

## What Is NOT Done

- No `bp` CLI source code exists.
- No Go (or other language) project scaffold.
- No unit tests for `--pos` parser or offset resolver.
- No contract tests against the Kotlin JSON models.
- No integration test harness against `:8089`.
- C3 (bug-bounty-mini adapter) — DEFERRED, not started, not blocked.

---

## Known Caveats to Encode at Implementation

- Server only implements sniper Intruder; `battering-ram`/`pitchfork`/`cluster-bomb` = client-side expansion.
- `/history` group 404s entirely if extension DB init failed — `bp` must probe + degrade.
- `collaborator`/`scanner start` = Pro-only; others degrade gracefully.
- `DELETE /history` is destructive, immediate, non-transactional — must require `--confirm`.
- `POST /target/scope` is a full replace (not additive) — document prominently.
- `%{anomalous}` token is only meaningful in `quick-fuzz`; render as empty for `attack/results`.
- `requestId` = Int; `attackId`/`scanId` = String (8-char UUID); history `id` = Long — type mismatch is load-bearing.
