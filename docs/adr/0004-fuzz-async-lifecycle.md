# ADR-0004 — `bp fuzz` single verb with `--async`; no split create/start

**Status:** accepted — 2026-06-16
**Criticality:** [HIGH][BLOCKS:high]

---

## Decision

The fuzz lifecycle is exposed as **one verb**: `bp fuzz <id> [--pos …] [--payloads …] [--type T] [--async]`.

- Without `--async` (default): `bp fuzz` calls `POST /intruder/attack/create`, then immediately
  calls `POST /intruder/attack/{id}/start`, then polls status and streams results — **synchronous
  from the user's perspective**.
- With `--async`: same create+start sequence, then returns immediately with the `attackId`. The
  user polls manually with `bp fuzz status <attackId>` and retrieves results with
  `bp fuzz results <attackId>`.

Subcommands for lifecycle management:

```
bp fuzz status  <attackId>
bp fuzz results <attackId> [--anomalous-only] [--limit N] [--index N]
bp fuzz summary <attackId>
bp fuzz pause   <attackId>
bp fuzz resume  <attackId>
bp fuzz stop    <attackId>
```

There are **no** `bp fuzz create` or `bp fuzz start` subcommands.

---

## Rationale

Founder decision 2026-06-16. `docs/CLI.md §Command map` defines `bp fuzz` as the single Intruder
verb. Splitting create/start would expose an internal implementation detail (the two-call sequence
required by the REST API) as a user-facing concept, increasing friction and error surface
(e.g. creating an attack and forgetting to start it).

The `--async` flag preserves power-user access to the lifecycle for scripts that need to launch
multiple attacks concurrently and poll them independently, without forcing all users through a
two-step dance.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| `bp fuzz create` + `bp fuzz start` as separate commands | Leaks the API's internal two-step sequence. A user who calls `create` but not `start` gets a silent no-op. No user-facing benefit over a single `bp fuzz` with `--async`. |
| Always async (no blocking mode) | Most single-target fuzz sessions want to wait for results. Forcing `--async` + manual polling on every run adds friction for the 80% case. |
| Always synchronous (no `--async`) | Prevents scripted parallel attacks. A hunter launching 3 simultaneous cluster-bomb attacks needs async access. |
| Separate `bp intruder` namespace | `bp fuzz` is clearer and shorter. `intruder` is an implementation detail; `fuzz` is the user's intent. `docs/CLI.md §Naming decisions` explicitly rejects `bp intruder`. |

---

## Consequences

- `bp fuzz` internally does a create+start sequence. The `attackId` returned by create is stored in
  the Run Ledger entry so the user can always retrieve it for follow-up commands.
- Race condition documented in `docs/SPEC.md §6.4`: `/start` spawns a new thread on each call.
  `bp` must not call `/start` twice on the same `attackId` (the sync path is safe; async path
  should guard against double-start).
- `bp fuzz quick <id> --param NAME --payloads @file` maps to `POST /intruder/quick-fuzz` and is
  a fully synchronous convenience shorthand (no `--async` needed).
