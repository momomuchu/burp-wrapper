---
project: bp
version: "1.0"
date: 2026-06-16
authority: founder-decision
---

# bp — Project Disciplines

Authoritative methodology, quality, and process policy for the `bp` CLI project.
All agents and contributors must follow these disciplines. Deviations require a new ADR.

---

## Methodology axes

| Axis | Policy |
|---|---|
| **Design** | SDD (Spec-Driven Development). Spec is validated before any implementation file is created. `docs/SPEC.md`, `docs/CLI.md`, `docs/OUTPUT.md` are the contracts. |
| **Testing** | TDD (Test-Driven Development). RED test before GREEN implementation, always. Unit and contract tests must not require a running Burp instance. |
| **Architecture** | DDD (Domain-Driven Design). Use the aggregates and ubiquitous language defined in `docs/SPEC.md §11`. No invented jargon. |
| **Spec role** | spec-as-contract. The spec wins over the code. Code diverging from spec = update the code (not the spec, unless the spec is wrong — record a new ADR either way). |

---

## Branching policy

- **Trunk-based development.** All work lands on `main`.
- Feature branches are short-lived: max 1–2 days before merge.
- Merge strategy: fast-forward or squash. No long-lived feature branches.
- No WIP commits on `main`.

---

## Commit policy

- **Atomic commits.** Each commit must: compile, pass all tests, and represent exactly one logical change.
- Commit message format: `<type>(<scope>): <short description>` (conventional commits).
- Types: `feat`, `fix`, `test`, `refactor`, `docs`, `chore`.
- Scope examples: `pos-parser`, `offset-resolver`, `fuzz-lifecycle`, `ledger`, `output`.

---

## Testing policy

| Level | What | Burp required |
|---|---|---|
| Unit | `--pos` parser, offset resolver, `CreateAttackRequest` builder, output renderer | No |
| Contract | JSON shapes vs Kotlin models (`docs/SPEC.md §8`), envelope unwrapping, id-types | No |
| Integration | Live smoke against `:8089`; skip cleanly if `BURP_REST_URL` unreachable | Yes |
| Acceptance | BDD scenarios in `docs/bdd-clean/` | Yes |

- RED test must be committed before GREEN implementation.
- Contract tests freeze the Kotlin JSON field names, types, and nullability. Any server-side change
  that breaks a contract test is a breaking change — do not silently update the test.
- Integration tests must be skippable without Burp: `if [ -z "$(curl -s $BURP_REST_URL/health)" ]; then skip; fi`.

---

## Quality policy

- **No phantom endpoints.** `bp` only calls routes confirmed in `routes/*.kt`. New routes require
  a Kotlin extension update first, then a `docs/SPEC.md` update, then CLI implementation.
- **No invented field names.** All CLI output fields map to Kotlin camelCase identifiers from
  `docs/SPEC.md §6/§8` (or are explicitly documented as `cli:` computed fields in `docs/OUTPUT.md §2`).
- **Graceful degradation is mandatory.** `collaborator` and `scanner start` → Pro-only (exit 69).
  `/history` group absent → 404 probe + exit 69 with clear message. Stubs are documented as stubs.
- **Ledger on by default.** Every `:8089` call gets one LedgerEntry in `~/.bp/`. `--no-ledger`
  opts out. Ledger write failure never fails the operation.
- **No implementation until GO.** Phase 1 starts only after explicit founder GO signal. Spec
  artifacts (docs, ADRs, disciplines) are the only deliverables in Phase 0.

---

## Spec-as-contract enforcement

Before any `Write`/`Edit` call on an implementation file, verify:

1. A corresponding spec entry exists in `docs/SPEC.md` or `docs/CLI.md` or `docs/OUTPUT.md`.
2. If a material decision is being made (architecture, library, data model, API contract),
   an ADR exists in `docs/adr/` with status `accepted`.
3. A RED test exists for the behaviour being implemented.

If any of the three checks fail: write the missing artifact first, then implement.

---

## API source-of-truth rules (ADR-0001)

- Target: `http://127.0.0.1:8089` (env: `BURP_REST_URL`). **Never port 9876.**
- `spec.md` (root) is DEPRECATED. Never consult it.
- New endpoint claims must be verified against `RestServer.kt` + `routes/*.kt` before appearing
  in any spec or implementation.

---

## Community vs Pro support (ADR-0006)

- `bp` ships for Community and Pro users.
- Pro-only surfaces (collaborator, scanner start): detect 503/500, exit 69, clear stderr message.
- All other groups: available on Community.
- Stubs (config endpoints, proxy intercept/forward/drop, scanner pause/resume): documented as
  stubs in `--help` output; `bp` surfaces the caveat rather than pretending they work.

---

## Deferred items (do not implement in Phase 1)

- C3 — bug-bounty-mini adapter (I6/G006 floor): optional, separate adapter, no Phase 1 dependency.
- Sequencer / Comparer / Logger / Dashboard: not in `configureRouting()`. Requires Kotlin extension
  work before CLI can expose them.

---

## Path routing table

```routing
# bp project path routing table (path-class.sh S1 format)
# path-regex<TAB>types<TAB>class<TAB>state<TAB>authority<TAB>inject
#
# Rule: CLI command modules under bp/src/bp/commands/ are agent-owned CLI
# wrappers, not security policy code. The filename may contain words like
# "securityscan" that would otherwise hit the global sensitive-catchall.
# Explicitly classify them as agent_solo so the guard does not block writes.
bp/src/bp/commands/	py	cli-command	building	agent_solo	corpus-code-quality-maintainability
bp/src/bp/	py	cli-core	building	agent_solo	corpus-code-quality-maintainability
```
