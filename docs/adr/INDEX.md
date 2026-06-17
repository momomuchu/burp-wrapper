# ADR Index — bp project

All decisions locked 2026-06-16 by founder. Status: accepted.

| ADR | Title | Criticality |
|---|---|---|
| [ADR-0001](0001-rest-source-of-truth.md) | REST API source of truth = `RestServer.kt` at `:8089` | [CRITICAL] |
| [ADR-0002](0002-cli-name-bp.md) | CLI name = `bp`, alias `burpctl` | [HIGH] |
| [ADR-0003](0003-pos-fuzzing-grammar.md) | `--pos` flexible-fuzzing grammar with client-side expansion | [CRITICAL] |
| [ADR-0004](0004-fuzz-async-lifecycle.md) | `bp fuzz` single verb with `--async`; no split create/start | [HIGH] |
| [ADR-0005](0005-run-ledger-observability.md) | C4 Run Ledger on by default; SQLite `~/.bp/`; `--no-ledger` opt-out | [HIGH] |
| [ADR-0006](0006-methodology-sdd-tdd-ddd.md) | Methodology: SDD + TDD + DDD + spec-as-contract; trunk; atomic commits | [HIGH] |
