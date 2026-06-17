# bp — Project Brain

> Phase 0 complete. Spec done. No implementation code yet.
> Next: TDD implementation of the `bp` CLI client per `docs/CLI.md`.

---

## Mission

`bp` (alias `burpctl`) is a standalone POSIX CLI that drives Burp Suite via its local REST
extension at `:8089`. It delivers flexible fuzzing (the `--pos` grammar), full observability
of every operation (C4 Run Ledger), and a stable agent-readable output contract. Target: a
distributable, user-facing product — not an internal script.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Developer / Agent                                          │
│                                                             │
│   bp <command> [flags]          burpctl <command> [flags]   │
│         │                                                   │
│         ▼                                                   │
│  bp CLI client (Go / language TBD)                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  --pos parser → offset resolver → CreateAttackReq   │   │
│  │  C4 Run Ledger  (~/.bp/  SQLite)                     │   │
│  │  Output model  (json│table│raw│quiet │ -w template)  │   │
│  └──────────────────────────────────────────────────────┘   │
│         │                                                   │
│         │  HTTP  http://127.0.0.1:8089                      │
│         ▼                                                   │
│  Burp Suite REST Extension  (RestServer.kt / Ktor)          │
│  13 groups · 69 endpoints  ←── source of truth             │
│         │                                                   │
│         ▼                                                   │
│  Burp Suite Pro / Community                                 │
└─────────────────────────────────────────────────────────────┘
```

**Key constraint:** The REST extension listens on `:8089`. `spec.md` (port 9876 / Python / MCP)
is DEPRECATED and must not be used as a reference. See ADR-0001.

---

## The 3 Contracts

| Doc | Role | Status |
|---|---|---|
| [`docs/SPEC.md`](docs/SPEC.md) | API source-of-truth: 13 groups / 69 endpoints, `--pos` grammar, C4 Ledger, DDD aggregates, TDD test architecture, acceptance criteria | DRAFT · awaiting GO |
| [`docs/CLI.md`](docs/CLI.md) | CLI grammar: command map, flags, naming decisions, error conventions | DRAFT · awaiting GO |
| [`docs/OUTPUT.md`](docs/OUTPUT.md) | Output contract: 4 formats, `-w` grammar, agent schema, exit codes, field catalog | DRAFT · awaiting GO |

All three are grounded on `RestServer.kt` + `routes/*.kt`. No invented endpoints.

---

## Current Status

| Phase | State | Evidence |
|---|---|---|
| Phase 0 — SDD spec | DONE | `docs/SPEC.md`, `docs/CLI.md`, `docs/OUTPUT.md` |
| Phase 0 — BDD scenarios | DONE | `docs/bdd-clean/` (15 feature files) |
| Phase 0 — Totality verification | DONE | 69 endpoints enumerated, 0 missed, verdict COMPLETE |
| Phase 1 — TDD implementation | NOT STARTED | awaiting founder GO |

**No implementation source files exist yet.** The `src/` tree contains the Burp extension
(Kotlin). The `bp` CLI client is a separate artifact to be built.

---

## Locked Decisions (2026-06-16)

See `docs/adr/INDEX.md` for full records. Summary:

| ADR | Decision |
|---|---|
| [ADR-0001](docs/adr/0001-rest-source-of-truth.md) | API source = `RestServer.kt` at `:8089`; `spec.md` (port 9876) is DEPRECATED |
| [ADR-0002](docs/adr/0002-cli-name-bp.md) | CLI name = `bp`, alias `burpctl` |
| [ADR-0003](docs/adr/0003-pos-fuzzing-grammar.md) | `--pos` grammar: semantic selectors + byte-offset + multi-pos + 4 attack types (client-side expansion) |
| [ADR-0004](docs/adr/0004-fuzz-async-lifecycle.md) | `bp fuzz` ONE verb with `--async`; no separate `create`/`start` subcommands |
| [ADR-0005](docs/adr/0005-run-ledger-observability.md) | C4 Run Ledger ON BY DEFAULT; SQLite `~/.bp/`; `--no-ledger` opt-out |
| [ADR-0006](docs/adr/0006-methodology-sdd-tdd-ddd.md) | Methodology: SDD + TDD + DDD + spec-as-contract; trunk-based; atomic commits |

---

## How to Catch Up in Under 3 Minutes

1. Read `docs/brain/STATE.md` — where we are right now (1 min).
2. Read `docs/brain/NEXT.md` — the exact next implementation step (1 min).
3. Skim `docs/CLI.md` §Command map and §`--pos` grammar — the two load-bearing surfaces (1 min).
4. Check `docs/adr/INDEX.md` for the 6 locked decisions before writing any code.

---

## Key Constraints for Implementors

- Target URL: `http://127.0.0.1:8089` (env: `BURP_REST_URL`). Never 9876.
- The REST server only accepts **byte-offsets** for fuzz positions (`start:Int, end:Int, name:String`).
  The `--pos` parser must resolve semantic selectors to byte-ranges by parsing the base captured request.
- `battering-ram`, `pitchfork`, `cluster-bomb` are client-side expansions (server only implements sniper).
- `collaborator` and `scanner` start endpoints require Burp Suite Professional; degrade gracefully elsewhere.
- The `/history` group returns 404 entirely if the extension's SQLite DB failed to init; `bp` must probe and handle.
- C4 Run Ledger is on by default. Every `:8089` call gets one ledger entry. `--no-ledger` opts out.
- C3 (bug-bounty-mini adapter) is DEFERRED and optional — do not block Phase 1 on it.
