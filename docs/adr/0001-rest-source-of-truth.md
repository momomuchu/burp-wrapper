# ADR-0001 — REST API source of truth = `RestServer.kt` at `:8089`

**Status:** accepted — 2026-06-16
**Criticality:** [CRITICAL][BLOCKS:critical]

---

## Decision

The sole authoritative source for the `bp` CLI's API surface is `RestServer.kt` and `routes/*.kt`
in the Burp extension (`configureRouting()`). The canonical port is **8089**. All 13 groups and
69 endpoints are enumerated from that source; nothing is inferred from other documents.

`spec.md` (the legacy document describing port 9876, Python wrappers, and MCP/SSE transport) is
**DEPRECATED**: archived, not deleted, never consulted for new implementation work.

---

## Rationale

Founder decision 2026-06-16. Three documents in the repo contradicted each other on fundamental
facts (port, transport, which endpoints exist). Root-cause analysis (`docs/SPEC.md §2`) found:

- `spec.md` describes the pre-rewrite architecture (port 9876, Python, MCP/PortSwigger SSE).
  The reality is a Kotlin/Ktor REST server with no SSE and no MCP. Any client built from `spec.md`
  targets the wrong port and fails immediately.
- `README.md` lists phantom endpoints (`/sequencer/*`, `/comparer/*`, `/logger/*`, `/search`)
  that have no handler in `configureRouting()`, and omits three real groups (`/session/*`,
  `/scan/*`, `/utils/*`).
- Only `RestServer.kt` reflects the actual routing table.

A complete enumeration verified 69 handlers from source equals 69 enumerated — verdict COMPLETE,
0 missed.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Use `README.md` as primary reference | Lists 4 phantom endpoints; omits 3 real groups. Would produce a broken client. |
| Use the embedded OpenAPI at `/docs` | Declares version 0.2.0, omits entire groups (session, scan, utils, history), inconsistent with `/health` version 0.1.0. Non-authoritative by its own incompleteness. |
| Keep `spec.md` as co-equal source | Describes a different (deprecated) system. Co-equal status would introduce ambiguity on every API call (port, transport, endpoint names). |

---

## Consequences

- `bp` always connects to `http://127.0.0.1:8089` (or `$BURP_REST_URL`). Port 9876 must never appear in client code.
- `spec.md` is kept in the repo for historical reference only; it carries a DEPRECATED header.
- Any future API additions must originate in `RestServer.kt` before being reflected in `docs/SPEC.md`.
