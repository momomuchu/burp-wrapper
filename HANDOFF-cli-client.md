# HANDOFF — burp-wrapper → CLI client re-architecture

> For a NEW dedicated Claude Code session, run from `~/burp-wrapper`.
> Author: handoff written 2026-06-16 from bug-bounty-mini session. Owner: founder (momomuchu).

## Mission (one line)

Re-architect `burp-wrapper` so an AI agent / operator can drive **real Burp Suite** as a simple
**CLI client via command** (like `bb-fetch`), with **first-class flexible fuzzing** (arbitrary
injection positions INCLUDING headers, multi-position, all attack types) — not the crippled
one-param shortcut.

## Phase 0 — ENUMERATE + SPEC + ANALYSE FIRST (founder's explicit ask)

Before writing any client code, produce a complete spec/analysis document:
1. **Enumerate every REST endpoint** the Burp extension exposes on `http://127.0.0.1:8089`. Read
   `src/main/kotlin/com/burprest/routes/*.kt` (13 route groups) + `models/*.kt`. Group surface today:
   - `RepeaterRoutes` — `/repeater/send`, `/send/batch`, `/tab/create`
   - `IntruderRoutes` — `/intruder/attack/create`, `/attack/{id}/start|status|results|pause|resume|stop`, `/quick-fuzz`
   - `ProxyRoutes` — `/proxy/history`, `/history/{id}`, `/websocket/history`, `/intercept/*`
   - `ScannerRoutes` / `SecurityScanRoutes` — crawl + audit (Pro)
   - `CollaboratorRoutes` — `/collaborator/generate` (OOB / blind)
   - `DecoderRoutes`, `TargetRoutes`, `SessionRoutes`, `ConfigRoutes`, `HistoryRoutes`,
     `UtilsRoutes`, `HealthRoutes`
2. For each: method, path, request model, response model, what Burp tool it drives, and **how a
   hunter actually uses it** (the "how to use it" analysis the founder wants).
3. Map the data shapes that matter most for fuzzing:
   - `CreateAttackRequest{ requestId|request, attackType(sniper|battering-ram|pitchfork|cluster-bomb),
     positions:[{start,end,name}], payloads:Map<name,[..]>, options{followRedirects,maxRetries,throttleMs} }`
   - `SendRequest{ requestId|request, modifications{headers, body, method, path} }`
   - `AttackResultEntry{ index, payload, statusCode, length, durationMs, contentType, bodyPreview, anomalous }`

## The PROBLEM being solved

- **Integration is clunky via raw REST.** Agents should call ONE command, not hand-craft JSON POSTs.
  A thin CLI (`burp ...`) that wraps `:8089` simplifies everything and mirrors the `bb-fetch` pattern.
- **The fuzzing was too narrow.** `/intruder/quick-fuzz` takes only `{requestId, param, payloads[]}`
  — ONE query param, NO header targeting, no multi-position, no open injection point. **THE WHOLE
  POINT** of moving to Burp is professional fuzzing: the CLI MUST expose `/intruder/attack/create`'s
  full `positions[]` (mark ANY byte-range — header value, body field, path segment, cookie) + all
  attack types + multiple payload sets. The capability already exists in the REST layer; the CLI is
  what makes it usable.

## Target CLI shape (proposal to refine in Phase 0)

A single `burp` command (language TBD — favour something the harness can call cheaply; Python or a
thin sh that curls `:8089`, token-efficient concise output). Sketch:
```
burp health
burp proxy history [--host H --limit N]          # capture base requests -> requestId
burp repeater send  --id <reqId> [--set-header "N: V"]... [--set-body @file] [--method M] [--path P]
burp fuzz --id <reqId> --pos 'header:Authorization' --pos 'body:id' \
          --payloads sqli.txt --type cluster-bomb [--throttle-ms 500]   # FULL positions incl headers
burp fuzz results <attackId> [--anomalous-only]
burp collaborator new                            # OOB payload for blind SSRF/RCE/XXE
burp scan crawl-and-audit --url <U>
```
Design `--pos` so a hunter can target headers, cookies, body fields, path, query — arbitrary
positions — and combine several (multi-position attacks). This is the load-bearing requirement.

## Integration target — bug-bounty-mini (context)

- Repo: `~/bug-bounty-mini` (harness on trunk `main`). Its I6 floor = `bb-fetch` is the SOLE egress
  for target HTTP (scope-gated, anti-injection envelope, requests.jsonl log). A Burp CLI is a NEW
  egress path → decide the floor story: either the `burp` CLI becomes a *sanctioned* egress that
  still records scope + a log line, OR it is gated behind the same scope check. Do NOT silently add
  an unlogged egress channel (that was Red-team finding G006 for the passive-enum tools).
- Real workflow: founder starts programs on **Intigriti** (and other platforms); the CLI is for
  live hunting — capture in Burp proxy, fuzz with Intruder, blind-test with Collaborator.

## Constraints / prereqs

- Needs **Burp Suite Pro** + this extension JAR loaded (`./gradlew shadowJar` → load in Burp →
  REST auto-starts on `:8089`). The CLI is a thin client; Burp is the engine.
- Keep responses CONCISE (token budget for AI agents) — summarise Intruder results, don't dump.

## First moves for the new session

1. Boot Burp Pro + load the JAR; `curl http://127.0.0.1:8089/health` (or via the new CLI once built).
2. Phase 0 enumeration/spec doc (above) — commit it.
3. Design the `burp` CLI surface (esp. the `--pos` flexible-fuzzing grammar). Get founder sign-off.
4. Implement + test each command against the live `:8089`.
5. Wire the integration story into bug-bounty-mini with the floor decision explicit.
