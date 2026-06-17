# Domain: 04-fuzz-core
# Ground truth: SPEC.md §5 (--pos grammar) + §6.4 (intruder endpoints)
# API base: http://127.0.0.1:8089
# All endpoints: POST /intruder/attack/create  POST /intruder/attack/{id}/start
#                GET  /intruder/attack/{id}/status  GET /intruder/attack/{id}/results
#                POST /intruder/attack/{id}/pause   POST /intruder/attack/{id}/resume
#                POST /intruder/attack/{id}/stop    POST /intruder/quick-fuzz
# Key invariants:
#   - attackId = 8-char UUID prefix (String)
#   - requestId = Int (history index, 0-based)
#   - Server only executes sniper; battering-ram/pitchfork/cluster-bomb are client-side in bp
#   - payloads Map<String,List<String>> — ALL values flattened (keys irrelevant at server)
#   - positions[0].name only consumed in sniper
#   - PayloadPosition { start:Int, end:Int, name:String } — ALL required, no defaults
#   - throttleMs active; followRedirects/maxRetries accepted but NOT wired
#   - attack status enum: created | running | paused | stopped | completed | error
#   - Community: intruder runs (delegates to RepeaterService, not Burp Pro Intruder)
#   - quick-fuzz: baseline = first result with error==null; anomalous if statusCode diff
#     OR |Δlength| > max(length*0.2, 20) OR contentType diff

Feature: bp fuzz — core fuzzing lifecycle with --pos grammar and 4 attack types
  As a security researcher (human DX) or an AI agent (AX),
  I want to drive Burp's Intruder engine via `bp fuzz` using semantic position selectors,
  multiple attack types, payload sets, throttle control, and a full attack lifecycle,
  so that I can automate targeted payload injection and triage anomalous responses
  with machine-readable output at every stage.

  Background:
    Given Burp Suite is running and listening on http://127.0.0.1:8089
    And the extension REST API is healthy (GET /health returns status "ok")
    And proxy history contains at least one captured request at index 3
      with URL "https://api.target.com/login" method POST
      and raw body "username=admin&password=secret"

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 1 · quick-fuzz (POST /intruder/quick-fuzz) — synchronous, 1 param
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: quick-fuzz a single param from history entry — table output
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads admin,root,"' OR '1'='1","admin'--" \
        --throttle-ms 100 \
        --format table
      """
    Then the exit code is 0
    And stdout contains a table with headers:
      | index | payload       | status | length | time | contentType      | anomalous |
    And at least one row has anomalous "true"
    And a baseline row is printed first (the first request with no error)

  @happy @fuzz @community
  Scenario: quick-fuzz in JSON agent mode — compact line-per-record
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin","root","' OR 1=1--" \
        --format json
      """
    Then the exit code is 0
    And each stdout line is a valid compact JSON object
    And each JSON object contains exactly the fields:
      | index | payload | statusCode | length | durationMs | error | contentType | bodyPreview | anomalous |
    And the JSON objects appear one per line with no pretty-printing

  @happy @fuzz @community
  Scenario: quick-fuzz with -w template — one line per result, status + payload only
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin","root","' OR '1'='1" \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And stdout contains exactly one line per payload, each matching the pattern:
      """
      <HTTP_STATUS_CODE> <payload_string>
      """
    Examples:
      | expected_lines |
      | 200 admin      |
      | 200 root       |
      | 200 ' OR '1'='1 |

  @happy @fuzz @community
  Scenario: quick-fuzz --quiet prints only the anomalous count
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin","' OR 1=1--" \
        --quiet
      """
    Then the exit code is 0
    And stdout is a single integer (the count of anomalous results)

  @happy @fuzz @community
  Scenario: quick-fuzz with --fields selector — only requested fields rendered
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin","root" \
        --fields index,status,anomalous \
        --format table
      """
    Then the exit code is 0
    And the table contains only the columns: index, status, anomalous
    And no other columns appear in stdout

  @happy @fuzz @community @ledger
  Scenario: quick-fuzz is recorded in the Run Ledger by default
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin","root" \
        --tag sqli-login-test
      """
    Then the exit code is 0
    And running "bp log --tag sqli-login-test --format json" shows an entry with:
      | field     | value                       |
      | tag       | sqli-login-test             |
      | burp_op   | POST /intruder/quick-fuzz   |
      | status    | ok                          |

  @happy @fuzz @community @ledger
  Scenario: quick-fuzz with --no-ledger is NOT recorded in the Run Ledger
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin" \
        --no-ledger
      """
    Then the exit code is 0
    And running "bp log --format json" shows no new entry for this run

  @error @fuzz @community
  Scenario: quick-fuzz with blank param is rejected 400
    When I run:
      """
      bp fuzz quick --id 3 --param "" \
        --payloads "admin","root"
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr explains that param must not be blank

  @error @fuzz @community
  Scenario: quick-fuzz with empty payloads list is rejected 400
    When I run:
      """
      bp fuzz quick --id 3 --param username --payloads ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr explains that payloads must be non-empty

  @error @fuzz @community
  Scenario: quick-fuzz with neither --id nor inline request is rejected 400
    When I run:
      """
      bp fuzz quick --param username --payloads "admin"
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr explains that exactly one of --id or --request is required

  @error @fuzz @community
  Scenario: quick-fuzz when Burp is down returns a clear error
    Given Burp Suite is NOT running on port 8089
    When I run:
      """
      bp fuzz quick --id 3 --param username --payloads "admin"
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "SERVICE_UNAVAILABLE"
    And no crash traceback is shown to the user

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 2 · SNIPER — 1 position, 1 payload set, tour à tour
  # Endpoints: create → start → status → results
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: sniper attack on header:Authorization — full async lifecycle
    Given a file "/tmp/tokens.txt" with content:
      """
      Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
      Bearer invalid-token
      Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.fake
      """
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'header:Authorization' \
        --type sniper \
        --payloads Authorization=/tmp/tokens.txt \
        --throttle-ms 200 \
        --format json
      """
    Then the exit code is 0
    And stdout is a JSON object with field "attackId" matching pattern "[a-f0-9]{8}"
    And the attack status is "created"

    When I run:
      """
      bp fuzz start --attack-id <attackId> --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "running"

    When I poll:
      """
      bp fuzz status --attack-id <attackId> --format json
      """
    Then eventually stdout JSON contains "isComplete": true
    And stdout JSON contains "progress": 100

    When I run:
      """
      bp fuzz results --attack-id <attackId> --format json
      """
    Then the exit code is 0
    And stdout contains 3 JSON result objects (one per payload)
    And each result has fields: index, payload, statusCode, length, durationMs, error, contentType, anomalous

  @happy @fuzz @community
  Scenario: sniper on cookie:session — results with -w template
    Given a file "/tmp/sessions.txt" with 5 session token strings
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'cookie:session' \
        --type sniper \
        --payloads session=/tmp/sessions.txt \
        --throttle-ms 50
      """
    And I start and wait for the attack to complete
    When I run:
      """
      bp fuzz results --attack-id <attackId> \
        -w '%{index} %{status} %{payload} %{anomalous}'
      """
    Then the exit code is 0
    And stdout contains exactly 5 lines, each matching:
      """
      <integer> <http_status> <session_token> <true|false>
      """

  @happy @fuzz @community
  Scenario: sniper on body:username — offset auto-resolved from captured request
    # bp must parse the raw request bytes and compute start/end offsets for "username"
    # The raw POST body is "username=admin&password=secret"
    # "admin" sits at bytes 9-14 → PayloadPosition{start:9,end:14,name:"username"}
    Given request at history index 3 has raw body "username=admin&password=secret"
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/usernames.txt \
        --throttle-ms 0 \
        --format json
      """
    Then the exit code is 0
    And the resolved PayloadPosition sent to POST /intruder/attack/create matches:
      | name     | start | end |
      | username | 9     | 14  |

  @happy @fuzz @community
  Scenario: sniper on query:id — offset resolved from URL query string
    Given request at history index 7 has URL "https://api.target.com/orders?id=1001&format=json"
    When I run:
      """
      bp fuzz create --id 7 \
        --pos 'query:id' \
        --type sniper \
        --payloads id=/tmp/ids.txt \
        --format json
      """
    Then the exit code is 0
    And the resolved PayloadPosition name is "id"
    And start/end offsets correspond to "1001" in the raw request bytes

  @happy @fuzz @community
  Scenario: sniper on path:1 — second path segment replaced
    Given request at history index 5 has URL "https://api.target.com/users/42/profile"
    When I run:
      """
      bp fuzz create --id 5 \
        --pos 'path:1' \
        --type sniper \
        --payloads path=/tmp/user_ids.txt \
        --format json
      """
    Then the exit code is 0
    And the resolved PayloadPosition covers the bytes of "42" in the raw path "/users/42/profile"

  @happy @fuzz @community
  Scenario: sniper on offset:42-52 — raw byte-range used directly, no resolution needed
    Given request at history index 3 exists
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'offset:42-52' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt \
        --format json
      """
    Then the exit code is 0
    And the PayloadPosition sent is exactly: start=42, end=52, name="offset:42-52"
    And no byte-resolution parsing is performed (offsets are passed through directly)

  @happy @fuzz @community
  Scenario: sniper results paginated — offset and limit
    Given an attack "a1b2c3d4" exists with 50 results
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 \
        --offset 20 --limit 10 \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 10 JSON result objects
    And the first object has "index": 20

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 3 · LIFECYCLE — pause / resume / stop
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: pause a running attack and then resume it
    Given an attack "a1b2c3d4" is in status "running"
    When I run:
      """
      bp fuzz pause --attack-id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "paused"

    When I run:
      """
      bp fuzz resume --attack-id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "running"

  @happy @fuzz @community
  Scenario: stop a running attack
    Given an attack "a1b2c3d4" is in status "running"
    When I run:
      """
      bp fuzz stop --attack-id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "stopped"
    And isComplete is true (stopped is a terminal state)

  @happy @fuzz @community
  Scenario: poll status until complete — progress goes from 0 to 100
    Given an attack "a1b2c3d4" was just started
    When I run "bp fuzz status --attack-id a1b2c3d4 --format json" repeatedly
    Then each response JSON contains "progress" between 0 and 100
    And eventually "isComplete": true appears
    And "status" transitions through: running → completed

  @error @fuzz @community
  Scenario: start an attack twice — second start creates a new thread (race risk)
    # SPEC §6.4 caveat: /start spawns a new Thread each call → race if already running
    Given an attack "a1b2c3d4" is in status "running"
    When I run:
      """
      bp fuzz start --attack-id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And bp warns: "attack already running — starting a second thread may cause a race condition"

  @error @fuzz @community
  Scenario: status of unknown attackId returns error
    When I run:
      """
      bp fuzz status --attack-id 00000000 --format json
      """
    Then the exit code is non-zero
    And stderr contains "not found" or an appropriate error message
    And no crash traceback is shown

  @error @fuzz @community
  Scenario: create does not validate request at create-time — error deferred to start
    # SPEC §6.4: create does NOT validate request/requestId; validation happens at /start
    When I run:
      """
      bp fuzz create --id 9999 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/usernames.txt \
        --format json
      """
    Then the exit code is 0
    And stdout JSON contains "attackId"
    And no error is reported yet (validation is deferred)

    When I run:
      """
      bp fuzz start --attack-id <attackId> --format json
      """
    Then the exit code is non-zero
    And stderr contains an error about invalid requestId 9999

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 4 · BATTERING-RAM — same payload in all positions simultaneously
  # Client-side: bp expands the attack (server only executes sniper)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: battering-ram — same payload injected into username AND password simultaneously
    # bp sends one payload to all positions at the same time
    # Positions: body:username AND body:password
    # Each payload (e.g. "admin") replaces BOTH simultaneously → total = len(payloads) requests
    Given a file "/tmp/creds.txt" with lines: admin, root, administrator, test
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type battering-ram \
        --payloads shared=/tmp/creds.txt \
        --throttle-ms 150 \
        --format json
      """
    Then the exit code is 0
    And bp expands client-side into 4 sniper-style requests (one per payload)
    And each request has the SAME payload in both body:username and body:password positions

    When the attack completes
    Then "bp fuzz results --attack-id <attackId> --format json" returns 4 result objects

  @happy @fuzz @community
  Scenario: battering-ram -w template — show payload and both resolved positions
    Given a file "/tmp/creds.txt" with lines: admin, root
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type battering-ram \
        --payloads shared=/tmp/creds.txt
      """
    And the attack completes
    When I run:
      """
      bp fuzz results --attack-id <attackId> \
        -w '%{payload} %{status} %{anomalous}'
      """
    Then stdout has exactly 2 lines:
      """
      admin <status> <true|false>
      root <status> <true|false>
      """

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 5 · PITCHFORK — N payload sets in lockstep (min of lengths)
  # Client-side expansion; pairs set[i] ↔ position[i]
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: pitchfork — username list paired with password list in lockstep
    # username.txt: admin, user1, operator  (3 entries)
    # password.txt: pass1, pass2            (2 entries)
    # lock-step → min(3,2) = 2 requests total
    # Request 1: username=admin,    password=pass1
    # Request 2: username=user1,    password=pass2
    Given a file "/tmp/username.txt" with lines: admin, user1, operator
    And a file "/tmp/password.txt" with lines: pass1, pass2
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type pitchfork \
        --payloads username=/tmp/username.txt \
        --payloads password=/tmp/password.txt \
        --throttle-ms 100 \
        --format json
      """
    Then the exit code is 0
    And bp computes lock-step count: min(3, 2) = 2
    And the attack is expanded client-side into 2 requests

    When the attack completes
    Then "bp fuzz results --attack-id <attackId> --format json" returns exactly 2 result objects
    And result at index 0 has payload pair: username="admin", password="pass1"
    And result at index 1 has payload pair: username="user1", password="pass2"

  @happy @fuzz @community
  Scenario: pitchfork — three positions, three payload sets, lockstep min enforced
    # 3 positions: header:X-User-ID, cookie:role, query:action
    # users.txt: alice, bob, carol        (3 entries)
    # roles.txt: admin, viewer            (2 entries)
    # actions.txt: read, write, delete    (3 entries)
    # lock-step → min(3,2,3) = 2 requests
    Given files "/tmp/users.txt" (alice,bob,carol), "/tmp/roles.txt" (admin,viewer), "/tmp/actions.txt" (read,write,delete)
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'header:X-User-ID' \
        --pos 'cookie:role' \
        --pos 'query:action' \
        --type pitchfork \
        --payloads X-User-ID=/tmp/users.txt \
        --payloads role=/tmp/roles.txt \
        --payloads action=/tmp/actions.txt \
        --throttle-ms 0 \
        --format json
      """
    Then the exit code is 0
    And bp client-side expansion yields exactly 2 requests (min of 3,2,3)
    And result at index 0 has: X-User-ID=alice, role=admin, action=read
    And result at index 1 has: X-User-ID=bob,   role=viewer, action=write

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 6 · CLUSTER-BOMB — Cartesian product (N-dimensional matrix)
  # Client-side expansion; every combination of all sets
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: cluster-bomb 2D matrix — header:X-Forwarded-For × cookie:role
    # ips.txt: 127.0.0.1, 10.0.0.1      (a=2)
    # roles.txt: admin, user, guest      (b=3)
    # Total: 2 × 3 = 6 requests
    Given a file "/tmp/ips.txt" with lines: 127.0.0.1, 10.0.0.1
    And a file "/tmp/roles.txt" with lines: admin, user, guest
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 200 \
        --format json
      """
    Then the exit code is 0
    And bp client-side expansion yields 2 × 3 = 6 request combinations
    And the attack is created with "attackType": "cluster-bomb"

    When the attack completes
    Then "bp fuzz results --attack-id <attackId> --format json" returns exactly 6 result objects
    And the combination matrix covers every pair:
      | X-Forwarded-For | role  |
      | 127.0.0.1       | admin |
      | 127.0.0.1       | user  |
      | 127.0.0.1       | guest |
      | 10.0.0.1        | admin |
      | 10.0.0.1        | user  |
      | 10.0.0.1        | guest |

  @happy @fuzz @community
  Scenario: cluster-bomb 3D matrix — 2 headers + 1 cookie = a × b × c requests
    # Canonical SPEC §5 example: X-Forwarded-For × X-Real-IP × role
    # ips.txt (shared): 127.0.0.1, 10.0.0.1     (a=2, b=2)
    # roles.txt:        admin, user              (c=2)
    # Total: 2 × 2 × 2 = 8 requests
    Given a file "/tmp/ips.txt" with lines: 127.0.0.1, 10.0.0.1
    And a file "/tmp/roles.txt" with lines: admin, user
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'header:X-Real-IP' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads X-Real-IP=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 500 \
        --format json
      """
    Then the exit code is 0
    And bp client-side expansion yields 2 × 2 × 2 = 8 request combinations
    And all 8 combinations of (X-Forwarded-For, X-Real-IP, role) are scheduled

    When the attack completes
    Then "bp fuzz results --attack-id <attackId> --format json" returns exactly 8 result objects

  @happy @fuzz @community
  Scenario: cluster-bomb 3D — anomalous-only filter reduces output
    Given the 3D cluster-bomb attack "cb3d1234" has completed with 8 results
    And only 2 results have anomalous=true
    When I run:
      """
      bp fuzz results --attack-id cb3d1234 \
        --anomalous-only \
        --format table
      """
    Then the exit code is 0
    And the table contains exactly 2 rows

  @happy @fuzz @community
  Scenario: cluster-bomb 3D — agent-mode JSON with --fields for pipeline
    Given the 3D cluster-bomb attack "cb3d1234" has completed
    When I run:
      """
      bp fuzz results --attack-id cb3d1234 \
        --fields index,status,anomalous,payload \
        --format json
      """
    Then the exit code is 0
    And each stdout line is a compact JSON object with ONLY: index, status, anomalous, payload
    And the output is pipeable (one JSON object per line, no trailing commas)

  @happy @fuzz @community
  Scenario: cluster-bomb 3D — -w template for human-readable triage
    Given the 3D cluster-bomb attack "cb3d1234" has completed with 8 results
    When I run:
      """
      bp fuzz results --attack-id cb3d1234 \
        -w '%{index} %{status} %{length} %{anomalous} %{payload}'
      """
    Then stdout contains exactly 8 lines
    And each line shows: result_index HTTP_status response_length anomalous_flag payload_value

  @happy @fuzz @community
  Scenario: cluster-bomb full SPEC example with --throttle-ms 500 and --anomalous-only
    # Exact example from SPEC.md §5 "Fuzz matriciel"
    Given a file "/tmp/ips.txt" and "/tmp/roles.txt" populated
    When I run:
      """
      bp fuzz --id 42 \
        --pos 'header:X-Forwarded-For' \
        --pos 'header:X-Real-IP' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads X-Real-IP=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 500 \
        --anomalous-only \
        --format table
      """
    Then the exit code is 0
    And bp waits 500ms between each of the a×b×c requests
    And only rows with anomalous=true are displayed

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 7 · MULTI-POSITION SELECTORS — comprehensive --pos coverage
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: --pos selector types are resolved to correct byte offsets
    Given request at history index <history_id> has the given structure
    When I run:
      """
      bp fuzz create --id <history_id> \
        --pos '<selector>' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt \
        --format json
      """
    Then the exit code is 0
    And the PayloadPosition name is "<expected_name>"
    And the PayloadPosition start and end offsets correspond to "<target_value>" in the raw request

    Examples:
      | history_id | selector              | expected_name   | target_value |
      | 3          | header:Authorization  | Authorization   | admin        |
      | 3          | cookie:session        | session         | sess123      |
      | 3          | body:username         | username        | admin        |
      | 7          | query:id              | id              | 1001         |
      | 5          | path:1                | path:1          | 42           |
      | 3          | offset:9-14           | offset:9-14     | admin        |

  @happy @fuzz @community
  Scenario: multiple --pos flags resolve multiple positions for sniper (tour à tour)
    # sniper with 2 positions: it fuzzes position[0] then position[1] sequentially
    Given request at history index 3 has body "username=admin&password=secret"
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type sniper \
        --payloads set1=/tmp/wordlist.txt \
        --format json
      """
    Then the exit code is 0
    And 2 PayloadPositions are sent to POST /intruder/attack/create
    And bp sends payloads through position 0 (username) first, then position 1 (password)
    And SPEC caveat is respected: only positions[0].name is consumed by the server in sniper mode

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 8 · THROTTLE & OPTIONS
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --throttle-ms 0 runs at maximum speed without delay
    Given a file "/tmp/payloads.txt" with 10 entries
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --throttle-ms 0 \
        --format json
      """
    Then the exit code is 0
    And the CreateAttackRequest sent contains "throttleMs": 0

  @happy @fuzz @community
  Scenario: --throttle-ms 1000 sends AttackOptions with throttleMs=1000
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --throttle-ms 1000 \
        --format json
      """
    Then the exit code is 0
    And the AttackOptions in the request body contains "throttleMs": 1000

  @happy @fuzz @community
  Scenario: --follow-redirects flag is accepted but noted as not wired server-side
    # SPEC §6.4 caveat: followRedirects accepted but NOT wired
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --follow-redirects \
        --format json
      """
    Then the exit code is 0
    And bp emits a warning: "followRedirects is accepted by the server but not currently wired"
    And the AttackOptions contains "followRedirects": true

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 9 · PAYLOAD FILE LOADING (--payloads name=file)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: payload file with 100 entries produces 100 results in sniper
    Given a file "/tmp/big_list.txt" with 100 unique string entries
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/big_list.txt \
        --throttle-ms 0 \
        --format json
      """
    And I start the attack and wait for completion
    Then "bp fuzz results --attack-id <attackId> --limit 0 --format json" returns exactly 100 result objects

  @error @fuzz @community
  Scenario: payload file does not exist — clear error before attack is created
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/nonexistent_file.txt
      """
    Then the exit code is non-zero
    And stderr contains "file not found: /tmp/nonexistent_file.txt"
    And no request is sent to POST /intruder/attack/create

  @happy @fuzz @community
  Scenario: inline payloads via --payloads name=val1,val2,val3
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads 'username=admin,root,administrator' \
        --format json
      """
    Then the exit code is 0
    And the CreateAttackRequest payloads map has key "username" with list ["admin","root","administrator"]

  @happy @fuzz @community
  Scenario: SPEC caveat — server flattens all payload map values regardless of key names
    # All Map<String,List<String>> values are flattened; keys have no functional role at server
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads 'set1=admin,root' \
        --payloads 'set2=administrator' \
        --format json
      """
    Then the exit code is 0
    And the payloads sent to the server have key "set1" with ["admin","root"] and "set2" with ["administrator"]
    And bp warns: "server flattens all payload sets — key names (set1,set2) have no functional role in sniper"

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 10 · ATTACK TYPES — server behaviour caveat (all map to sniper)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: all attack types are accepted by the server but bp handles expansion
    # SPEC §5 caveat: server only implements sniper; bp expands others client-side
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type <attack_type> \
        --payloads username=/tmp/payloads.txt \
        --format json
      """
    Then the exit code is 0
    And the CreateAttackRequest contains "attackType": "<attack_type>"
    And <client_side_note>

    Examples:
      | attack_type   | client_side_note                                                    |
      | sniper        | bp delegates directly to the server                                 |
      | battering-ram | bp expands client-side (same payload to all positions per request)  |
      | pitchfork     | bp expands client-side (lock-step pairing across sets)              |
      | cluster-bomb  | bp expands client-side (full Cartesian product)                     |

  @happy @fuzz @community
  Scenario: bp warns that only sniper is server-side; others are client-side expansions
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type cluster-bomb \
        --payloads username=/tmp/usernames.txt \
        --payloads password=/tmp/passwords.txt \
        --format json
      """
    Then the exit code is 0
    And stderr or stdout contains:
      """
      Note: cluster-bomb is expanded client-side by bp (server implements sniper only)
      """

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 11 · COMMUNITY vs PRO — intruder runs on Community
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: fuzz attack runs successfully on Community edition
    # SPEC §6.4 + §7: intruder delegates to RepeaterService, NOT Burp Pro Intruder
    # Therefore it runs on Community without throttling by Burp
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin","root" \
        --format json
      """
    Then the exit code is 0
    And the attack succeeds without a 503 or "Pro required" error

  @community @fuzz
  Scenario: fuzz on Community — bp does NOT warn about Pro requirement for intruder
    Given Burp Suite Community Edition is running
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --format json
      """
    Then the exit code is 0
    And stderr does NOT contain "Pro required" or "SERVICE_UNAVAILABLE"

  @community @fuzz
  Scenario: bp degrades gracefully on Community for Pro-only adjacent features
    # Collaborator and scanner (start) are Pro-only — intruder is NOT Pro-only
    # bp help/docs must clearly distinguish intruder (Community OK) from collaborator (Pro)
    When I run:
      """
      bp fuzz --help
      """
    Then stdout notes that `bp fuzz` is available on Community edition
    And stdout distinguishes from `bp collab` which requires Pro

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 12 · OUTPUT FORMAT COVERAGE (all four modes)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --format table in a TTY — aligned columns with header row
    Given stdout is a TTY
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --format table
      """
    Then the exit code is 0
    And stdout first line contains aligned column headers including "index", "payload", "status"
    And subsequent rows are padded to align under headers

  @happy @fuzz @community
  Scenario: --format json when piped — default for agent/AI use
    Given stdout is a pipe (not a TTY)
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4
      """
    Then the exit code is 0
    And each stdout line is a compact single-line JSON object (no pretty-printing)
    And the JSON schema is stable: every object has the same keys in the same order

  @happy @fuzz @community
  Scenario: --format raw — Burp raw bytes for repeater-level inspection
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --format raw --limit 1
      """
    Then the exit code is 0
    And stdout contains the raw HTTP response bytes for result index 0

  @happy @fuzz @community
  Scenario: --format quiet — single most essential value
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --quiet --limit 1
      """
    Then the exit code is 0
    And stdout is a single line with only the HTTP status code of result 0

  @happy @fuzz @community
  Scenario: -w template with all supported tokens
    Given attack "a1b2c3d4" has completed with results
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 \
        -w '%{index} %{status} %{length} %{time} %{payload} %{anomalous} %{contentType} %{location} %{requestId}'
      """
    Then the exit code is 0
    And each line contains 9 space-separated fields in the declared order

  @happy @fuzz @community
  Scenario: -w '%{status} %{payload}' — founder's headline example
    # Exact example from the output model spec
    Given attack "a1b2c3d4" has completed
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 \
        -w '%{status} %{payload}'
      """
    Then stdout contains one line per result, each containing:
      """
      <HTTP_STATUS_CODE> <payload_value>
      """
    And no other fields or headers appear

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 13 · RUN LEDGER — tagging and recording
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @ledger @community
  Scenario: fuzz attack is tagged and retrievable from Run Ledger
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --tag sqli-enumeration-phase1
      """
    And I start and complete the attack
    Then "bp log --tag sqli-enumeration-phase1 --format json" returns an entry with:
      | field     | value                          |
      | tag       | sqli-enumeration-phase1        |
      | burp_op   | POST /intruder/attack/create   |
      | status    | ok                             |
      | target    | https://api.target.com/login   |

  @happy @fuzz @ledger @community
  Scenario: fuzz results step is also recorded in the ledger
    Given attack "a1b2c3d4" is tagged "sqli-enum"
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --tag sqli-enum-results --format json
      """
    Then "bp log --tag sqli-enum-results" shows an entry with:
      | burp_op | GET /intruder/attack/a1b2c3d4/results |

  @happy @fuzz @ledger @community
  Scenario: ledger entry can be annotated post-run with bp tag
    Given an attack was run and recorded with ledger id "7"
    When I run:
      """
      bp tag 7 confirmed-sqli-bypass
      """
    Then "bp show 7 --format json" returns entry with tag "confirmed-sqli-bypass"

  @happy @fuzz @ledger @community
  Scenario: --no-ledger suppresses recording for a quick-fuzz probe
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "probe-only" \
        --no-ledger
      """
    Then the exit code is 0
    And "bp log --format json" does NOT contain a new entry matching this run's timestamp

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 14 · EDGE CASES & RESULT ANALYSIS
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: anomalous detection — status code difference triggers anomalous=true
    # SPEC §6.4 quick-fuzz: anomalous if statusCode≠baseline
    Given baseline response for history id 3 returns HTTP 200
    When quick-fuzz sends payload "' OR 1=1--" and receives HTTP 302
    Then the result has anomalous=true
    And the -w output shows: "302 ' OR 1=1--"

  @happy @fuzz @community
  Scenario: anomalous detection — response length delta > max(length*0.2, 20) triggers anomalous
    # SPEC §6.4: anomalous if |Δlength| > max(length*0.2, 20)
    Given baseline response length is 500 bytes
    When a payload causes response length 560 bytes (delta=60 > max(100,20)=100... false)
    # 60 < 100: NOT anomalous by length alone
    Then that result has anomalous=false for length criterion alone

    Given baseline response length is 100 bytes
    When a payload causes response length 130 bytes (delta=30 > max(20,20)=20)
    Then that result has anomalous=true (delta 30 > 20)

  @happy @fuzz @community
  Scenario: anomalous detection — content-type change triggers anomalous
    # SPEC §6.4: anomalous if contentType≠baseline
    Given baseline response has Content-Type "application/json"
    When a payload causes Content-Type "text/html"
    Then the result has anomalous=true
    And the -w output shows: "200 <payload>"
    And "--fields contentType,anomalous --format json" shows {"contentType":"text/html","anomalous":true}

  @happy @fuzz @community
  Scenario: results with --offset and --limit=0 returns ALL results
    Given attack "a1b2c3d4" has 200 results
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --offset 0 --limit 0 --format json
      """
    Then the exit code is 0
    And stdout contains exactly 200 JSON result objects
    And no pagination truncation occurs (limit=0 means "all" per SPEC §6.4)

  @happy @fuzz @community
  Scenario: empty results for a just-created (not-started) attack
    Given attack "a1b2c3d4" has status "created" and has not been started
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is an empty JSON array "[]" or zero result lines

  @error @fuzz @community
  Scenario: missing --pos raises a clear usage error before any API call
    When I run:
      """
      bp fuzz create --id 3 \
        --type sniper \
        --payloads username=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "at least one --pos is required"
    And no HTTP request is sent to :8089

  @error @fuzz @community
  Scenario: cluster-bomb with mismatched --payloads count vs --pos count raises error
    # cluster-bomb requires one payload set per position
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type cluster-bomb \
        --payloads username=/tmp/usernames.txt
      """
    Then the exit code is non-zero
    And stderr contains "cluster-bomb requires one payload set per position (got 1 sets for 2 positions)"

  @error @fuzz @community
  Scenario: pitchfork with fewer payload sets than positions raises a warning
    # pitchfork can proceed (uses min), but warn about the short set
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --pos 'query:action' \
        --type pitchfork \
        --payloads username=/tmp/u.txt \
        --payloads password=/tmp/p.txt
      """
    Then the exit code is non-zero
    And stderr contains "pitchfork requires one payload set per position (got 2 sets for 3 positions)"

  @error @fuzz @community
  Scenario: invalid --pos selector raises a descriptive parse error
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'unknown:foo' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "unknown position selector type: 'unknown'"
    And stderr lists valid selector types: header, cookie, body, query, path, offset

  @error @fuzz @community
  Scenario: offset selector with invalid range format raises error
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'offset:not-a-range' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "invalid offset format: 'not-a-range' — expected 'offset:START-END' with integer start and end"

  @error @fuzz @community
  Scenario: --pos header:NonExistent raises error if header not found in captured request
    Given request at history index 3 does NOT have header "X-Missing-Header"
    When I run:
      """
      bp fuzz create --id 3 \
        --pos 'header:X-Missing-Header' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "header 'X-Missing-Header' not found in request at index 3"

  @error @fuzz @community
  Scenario: results on a stopped attack still returns partial results collected before stop
    Given attack "a1b2c3d4" ran 15 out of 50 payloads then was stopped
    When I run:
      """
      bp fuzz results --attack-id a1b2c3d4 --limit 0 --format json
      """
    Then the exit code is 0
    And stdout contains exactly 15 JSON result objects (results collected before stop)

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 15 · AGENT MODE (AX) — machine-readable end-to-end
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: agent drives full cluster-bomb lifecycle via JSON mode — no TTY assumed
    # An AI agent pipes each command; stable JSON schema required throughout
    Given stdout is a pipe (non-TTY agent environment)
    When the agent runs:
      """
      bp fuzz create --id 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 200 \
        --format json
      """
    Then stdout is a single compact JSON line like:
      """
      {"success":true,"data":{"attackId":"a1b2c3d4","status":"created"},"error":null}
      """
    When the agent extracts "attackId" and runs:
      """
      bp fuzz start --attack-id a1b2c3d4 --format json
      """
    Then stdout is a single compact JSON line containing "status":"running"
    When the agent polls:
      """
      bp fuzz status --attack-id a1b2c3d4 --format json
      """
    Until stdout contains "isComplete":true
    When the agent runs:
      """
      bp fuzz results --attack-id a1b2c3d4 --format json
      """
    Then each stdout line is a compact JSON object with stable schema:
      """
      {"index":<int>,"payload":"<str>","statusCode":<int>,"length":<int>,"durationMs":<int>,"error":null,"contentType":"<str>","bodyPreview":"<str>","anomalous":<bool>}
      """
    And the agent can filter anomalous results by parsing "anomalous":true

  @happy @fuzz @community
  Scenario: agent uses --fields to get minimal JSON for downstream processing
    Given attack "a1b2c3d4" has completed
    When the agent runs:
      """
      bp fuzz results --attack-id a1b2c3d4 \
        --fields index,status,anomalous \
        --format json
      """
    Then each stdout line is:
      """
      {"index":<int>,"status":<int>,"anomalous":<bool>}
      """
    And no other fields appear (schema is exactly as declared in --fields)

  @happy @fuzz @community
  Scenario: agent quick-fuzz with --format json and --no-ledger for ephemeral probes
    Given stdout is a pipe
    When the agent runs:
      """
      bp fuzz quick --id 3 \
        --param username \
        --payloads "admin","' OR 1=1--","<script>alert(1)</script>" \
        --format json \
        --no-ledger
      """
    Then each stdout line is a compact JSON object
    And the agent can identify injection candidates by filtering "anomalous":true
    And the run is NOT recorded in the Run Ledger
