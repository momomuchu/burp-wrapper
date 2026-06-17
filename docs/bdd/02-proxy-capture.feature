Feature: Proxy Capture — history inspection, WebSocket history, and intercept control
  As a security researcher or AI agent driving Burp via bp,
  I want to list, filter, and inspect captured proxy traffic,
  browse WebSocket messages, and toggle intercept on/off,
  so that I can triage captured requests and control what Burp intercepts
  without leaving the terminal.

  Background:
    Given Burp Suite is running and the bp extension is loaded at http://127.0.0.1:8089
    And the proxy listener is active on 127.0.0.1:8080

  # ─────────────────────────────────────────────────────────────
  # §6.2  GET /proxy/history  — list + filter + pagination
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: List proxy history with default pagination returns first 50 entries
    Given the proxy has captured at least 3 HTTP requests
    When I run:
      """
      bp proxy history
      """
    Then the exit code is 0
    And the output is a table with columns: id, method, host, path, status, length
    And the table contains at most 50 rows
    And each row has a non-empty "host" value

  @happy @community
  Scenario: List proxy history in JSON mode for AI agent consumption
    Given the proxy has captured requests to "api.example.com"
    When I run:
      """
      bp proxy history --format json
      """
    Then the exit code is 0
    And stdout is compact JSON (one object per line) with the envelope:
      """
      {"success":true,"data":{"items":[...],"total":<Int>,"limit":<Int>,"offset":<Int>}}
      """
    And each item in "data.items" contains the fields: id, method, host, path, statusCode, length
    And no pretty-printing whitespace is present (compact, AX-stable schema)

  @happy @community
  Scenario: Filter proxy history by host
    Given the proxy has captured requests to "api.example.com" and "login.evil.com"
    When I run:
      """
      bp proxy history --host api.example.com --format json
      """
    Then the exit code is 0
    And every item in "data.items" has host equal to "api.example.com"
    And no item has host equal to "login.evil.com"
    And "data.total" reflects the filtered count, not the total history size

  @happy @community
  Scenario: Paginate proxy history with limit and offset
    Given the proxy has captured at least 10 requests to "shop.target.com"
    When I run:
      """
      bp proxy history --host shop.target.com --limit 3 --offset 0 --format json
      """
    Then the exit code is 0
    And "data.items" contains exactly 3 entries
    And "data.limit" is 3
    And "data.offset" is 0
    When I run:
      """
      bp proxy history --host shop.target.com --limit 3 --offset 3 --format json
      """
    Then the exit code is 0
    And "data.items" contains the next 3 entries (none duplicated from the previous page)
    And "data.offset" is 3

  @happy @community
  Scenario: Quiet flag prints only the total count
    Given the proxy has captured requests
    When I run:
      """
      bp proxy history --host api.example.com --quiet
      """
    Then the exit code is 0
    And stdout is a single integer representing the total number of captured entries for that host

  @happy @community
  Scenario: Write-out template selects specific fields per entry
    Given the proxy has captured at least 2 requests
    When I run:
      """
      bp proxy history --limit 2 -w "%{status} %{requestId}"
      """
    Then the exit code is 0
    And stdout contains exactly 2 lines
    And each line matches the pattern "<HTTP-status-code> <integer-id>"
    # e.g.:
    # 200 0
    # 302 1

  @happy @community @ledger
  Scenario: Proxy history list operation is recorded in the Run Ledger by default
    Given no prior ledger entry for this operation
    When I run:
      """
      bp proxy history --host api.example.com --tag recon-phase1
      """
    Then the exit code is 0
    And a ledger entry is created with:
      | field      | value                           |
      | tag        | recon-phase1                    |
      | burp_op    | GET /proxy/history              |
      | target     | api.example.com                 |
      | status     | ok                              |

  @happy @community @ledger
  Scenario: --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp proxy history --limit 5 --no-ledger
      """
    Then the exit code is 0
    And no new ledger entry is created for this invocation

  @error @community
  Scenario: History list when proxy has captured zero requests returns empty result
    Given the proxy history is empty
    When I run:
      """
      bp proxy history --format json
      """
    Then the exit code is 0
    And "data.items" is an empty array []
    And "data.total" is 0

  @error @community
  Scenario: History list filtered by unknown host returns empty result
    Given the proxy has captured requests but none to "nevervisited.internal"
    When I run:
      """
      bp proxy history --host nevervisited.internal --format json
      """
    Then the exit code is 0
    And "data.items" is an empty array []
    And "data.total" is 0

  @error @community
  Scenario: History list when Burp is down shows a clear connection error
    Given Burp Suite is NOT running
    When I run:
      """
      bp proxy history
      """
    Then the exit code is non-zero (1 or 2)
    And stderr contains a message like "cannot connect to Burp at http://127.0.0.1:8089"
    And stdout is empty

  # ─────────────────────────────────────────────────────────────
  # §6.2  GET /proxy/history  — --fields flag
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: --fields flag restricts and orders output columns
    Given the proxy has captured requests
    When I run:
      """
      bp proxy history --fields id,method,statusCode --format table
      """
    Then the exit code is 0
    And the table has exactly 3 columns: id, method, statusCode
    And columns like "host", "path", "length" are absent

  # ─────────────────────────────────────────────────────────────
  # §6.2  GET /proxy/history/{id}  — get single request by id
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Get a single proxy history entry by its absolute index
    Given the proxy has captured at least 1 request and its id is known as 0
    When I run:
      """
      bp proxy history get 0 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON envelope:
      """
      {"success":true,"data":{"id":0,"method":"GET","host":"api.example.com","path":"/v1/users","statusCode":200,"length":<Int>,"listenerInterface":null,"clientIp":null,"timestamp":null}}
      """
    And the response always includes all declared fields (encodeDefaults=true), even if null

  @happy @community
  Scenario: Get a single entry and render as table
    Given proxy history entry with id 2 exists
    When I run:
      """
      bp proxy history get 2 --format table
      """
    Then the exit code is 0
    And the table contains one row with id=2
    And columns id, method, host, path, statusCode, length are visible

  @happy @community
  Scenario: Use write-out template to extract just the status code of an entry
    Given proxy history entry with id 5 exists and returned HTTP 403
    When I run:
      """
      bp proxy history get 5 -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      403
      """

  @happy @community
  Scenario: Agent-mode extraction of host from a single entry
    Given proxy history entry with id 1 exists for host "auth.corp.internal"
    When I run:
      """
      bp proxy history get 1 --format json --fields id,host,path
      """
    Then the exit code is 0
    And the JSON payload contains:
      """
      {"id":1,"host":"auth.corp.internal","path":"/oauth/token"}
      """

  @error @community
  Scenario: Get proxy history entry with non-integer id returns INVALID_PARAM error
    # The server parses id via toIntOrNull; non-integer → INVALID_PARAM (not 404)
    When I run:
      """
      bp proxy history get abc --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_PARAM","message":"<any>"}}
      """

  @error @community
  Scenario: Get proxy history entry with out-of-bounds id triggers a server 500
    # The spec notes: out-of-bounds id → 500 Ktor (unmapped)
    Given the proxy history has 3 entries (ids 0, 1, 2)
    When I run:
      """
      bp proxy history get 9999 --format json
      """
    Then the exit code is non-zero
    And bp surfaces the error to the user with a message indicating the entry was not found or an internal server error occurred
    And stdout or stderr contains "INTERNAL_ERROR" or "not found" or a non-zero HTTP status code hint

  @error @community
  Scenario: Offset-relative id instability warning is surfaced by bp
    # Per spec: id = start+idx (offset-relative → unstable between offsets)
    # bp should warn users to use absolute ids via /{id}, not relative page ids
    Given the proxy has captured 20 requests
    When I run:
      """
      bp proxy history --limit 5 --offset 10 --format json
      """
    Then the exit code is 0
    And bp emits a warning on stderr:
      """
      Warning: item ids in paginated results are offset-relative and unstable. Use 'bp proxy history get <id>' with the absolute index for stable access.
      """

  # ─────────────────────────────────────────────────────────────
  # §6.2  GET /proxy/history  — Scenario Outline: various filter combos
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Proxy history pagination boundary combinations
    Given the proxy has captured <total> requests to "<host>"
    When I run:
      """
      bp proxy history --host <host> --limit <limit> --offset <offset> --format json
      """
    Then the exit code is 0
    And "data.items" contains exactly <expected_count> entries
    And "data.total" is <total>

    Examples:
      | host              | total | limit | offset | expected_count |
      | api.example.com   | 10    | 5     | 0      | 5              |
      | api.example.com   | 10    | 5     | 5      | 5              |
      | api.example.com   | 10    | 5     | 8      | 2              |
      | api.example.com   | 10    | 5     | 10     | 0              |
      | api.example.com   | 10    | 100   | 0      | 10             |
      | shop.target.com   | 3     | 1     | 2      | 1              |

  # ─────────────────────────────────────────────────────────────
  # §6.2  GET /proxy/websocket/history  — WebSocket message history
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: List WebSocket history shows direction and payload
    Given the proxy has captured WebSocket messages on "wss://realtime.app.com/socket"
    When I run:
      """
      bp proxy websocket history --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON envelope:
      """
      {"success":true,"data":{"items":[...],"total":<Int>}}
      """
    And each item contains the fields: direction, payload, timestamp
    And "direction" is one of CLIENT_TO_SERVER or SERVER_TO_CLIENT (Montoya enum .name)
    And "timestamp" is the Instant.now() at query time (not capture time — per spec flag)

  @happy @community
  Scenario: WebSocket history in table format for human review
    Given the proxy has captured at least 2 WebSocket messages
    When I run:
      """
      bp proxy websocket history --format table
      """
    Then the exit code is 0
    And the table contains columns: direction, payload, timestamp
    And at least one row has direction CLIENT_TO_SERVER and a non-empty payload

  @happy @community
  Scenario: WebSocket history agent-mode with write-out template
    Given the proxy has captured WebSocket messages
    When I run:
      """
      bp proxy websocket history -w "%{direction} %{payload}"
      """
    Then the exit code is 0
    And each line of stdout matches the pattern "<DIRECTION> <payload-text>"
    # e.g.:
    # CLIENT_TO_SERVER {"action":"subscribe","channel":"orders"}
    # SERVER_TO_CLIENT {"event":"order_update","orderId":1042}

  @error @community
  Scenario: WebSocket history when no WebSocket traffic was captured returns empty list
    Given the proxy has captured only HTTP traffic (no WebSocket connections)
    When I run:
      """
      bp proxy websocket history --format json
      """
    Then the exit code is 0
    And "data.items" is an empty array []
    And "data.total" is 0

  @error @community
  Scenario: WebSocket history when Burp is down shows connection error
    Given Burp Suite is NOT running
    When I run:
      """
      bp proxy websocket history
      """
    Then the exit code is non-zero
    And stderr contains "cannot connect to Burp at http://127.0.0.1:8089"

  # ─────────────────────────────────────────────────────────────
  # §6.2  GET /proxy/intercept  — STUB always {enabled:false}
  # ─────────────────────────────────────────────────────────────

  @community
  Scenario: GET intercept status always returns enabled=false (stub — unreliable)
    # Per spec: GET /proxy/intercept is a STUB — always returns {enabled:false}
    # bp must surface this caveat rather than silently report false status
    Given intercept has been enabled via POST /proxy/intercept/enable
    When I run:
      """
      bp proxy intercept status --format json
      """
    Then the exit code is 0
    And stdout contains:
      """
      {"enabled":false}
      """
    And bp emits a warning on stderr:
      """
      Warning: GET /proxy/intercept is a stub and always returns {enabled:false}. This does not reflect actual intercept state.
      """

  @community
  Scenario: GET intercept status in table format still surfaces the stub warning
    When I run:
      """
      bp proxy intercept status --format table
      """
    Then the exit code is 0
    And the table shows enabled = false
    And stderr contains the stub caveat warning

  # ─────────────────────────────────────────────────────────────
  # §6.2  POST /proxy/intercept/enable  — activate intercept
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Enable intercept before manual navigation
    When I run:
      """
      bp proxy intercept enable --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"enabled":true},"error":null}
      """

  @happy @community
  Scenario: Enable intercept with quiet flag prints minimal output
    When I run:
      """
      bp proxy intercept enable --quiet
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      enabled
      """

  @happy @community @ledger
  Scenario: Enable intercept is tagged and recorded in the Run Ledger
    When I run:
      """
      bp proxy intercept enable --tag pre-manual-browse --format json
      """
    Then the exit code is 0
    And a ledger entry is created with:
      | field      | value                              |
      | tag        | pre-manual-browse                  |
      | burp_op    | POST /proxy/intercept/enable       |
      | status     | ok                                 |

  @error @community
  Scenario: Enable intercept when Burp is down returns connection error
    Given Burp Suite is NOT running
    When I run:
      """
      bp proxy intercept enable
      """
    Then the exit code is non-zero
    And stderr contains "cannot connect to Burp at http://127.0.0.1:8089"

  # ─────────────────────────────────────────────────────────────
  # §6.2  POST /proxy/intercept/disable  — deactivate intercept
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Disable intercept after manual inspection
    Given intercept is currently enabled
    When I run:
      """
      bp proxy intercept disable --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"enabled":false},"error":null}
      """

  @happy @community
  Scenario: Disable intercept with quiet flag prints minimal output
    Given intercept is currently enabled
    When I run:
      """
      bp proxy intercept disable --quiet
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      disabled
      """

  @happy @community @ledger
  Scenario: Disable intercept is recorded in the Run Ledger with --no-ledger suppressed
    When I run:
      """
      bp proxy intercept disable --no-ledger
      """
    Then the exit code is 0
    And no new ledger entry is created

  @error @community
  Scenario: Disable intercept when Burp is down returns connection error
    Given Burp Suite is NOT running
    When I run:
      """
      bp proxy intercept disable
      """
    Then the exit code is non-zero
    And stderr contains "cannot connect to Burp at http://127.0.0.1:8089"

  # ─────────────────────────────────────────────────────────────
  # §6.2  POST /proxy/intercept/forward  — STUB no-op
  # ─────────────────────────────────────────────────────────────

  @community
  Scenario: Forward intercepted request is a stub no-op that returns {forwarded:true}
    # Per spec: POST /proxy/intercept/forward is a stub — {forwarded:true} no-op
    # bp must surface the caveat rather than imply real forwarding happened
    When I run:
      """
      bp proxy intercept forward --format json
      """
    Then the exit code is 0
    And stdout body (from Burp) is:
      """
      {"forwarded":true}
      """
    And bp emits a warning on stderr:
      """
      Warning: POST /proxy/intercept/forward is a stub. No request was actually forwarded by this call.
      """

  @community
  Scenario: Forward with quiet flag still emits stub caveat on stderr
    When I run:
      """
      bp proxy intercept forward --quiet
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      forwarded
      """
    And stderr contains the stub caveat for forward

  # ─────────────────────────────────────────────────────────────
  # §6.2  POST /proxy/intercept/drop  — STUB no-op
  # ─────────────────────────────────────────────────────────────

  @community
  Scenario: Drop intercepted request is a stub no-op that returns {dropped:true}
    # Per spec: POST /proxy/intercept/drop is a stub — {dropped:true} no-op
    When I run:
      """
      bp proxy intercept drop --format json
      """
    Then the exit code is 0
    And stdout body (from Burp) is:
      """
      {"dropped":true}
      """
    And bp emits a warning on stderr:
      """
      Warning: POST /proxy/intercept/drop is a stub. No request was actually dropped by this call.
      """

  @community
  Scenario: Drop with quiet flag still emits stub caveat on stderr
    When I run:
      """
      bp proxy intercept drop --quiet
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      dropped
      """
    And stderr contains the stub caveat for drop

  # ─────────────────────────────────────────────────────────────
  # Full enable→browse→disable workflow (DX scenario)
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Intercept lifecycle — enable, capture, disable in sequence
    When I run:
      """
      bp proxy intercept enable --quiet
      """
    Then stdout is "enabled" and exit code is 0
    # (user browses manually to trigger capture)
    When I run:
      """
      bp proxy history --limit 1 --format json
      """
    Then exit code is 0 and "data.total" is at least 1
    When I run:
      """
      bp proxy intercept disable --quiet
      """
    Then stdout is "disabled" and exit code is 0

  # ─────────────────────────────────────────────────────────────
  # AX (AI-agent) scenario — full proxy inspection pipeline
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: AI agent inspects proxy history for a target host in JSON mode
    # AX pattern: agent calls bp with --format json, parses compact JSON,
    # picks an interesting entry, then fetches its full record.
    Given the proxy has captured requests to "api.bugbounty-target.com"
    When I (as an AI agent) run:
      """
      bp proxy history --host api.bugbounty-target.com --limit 50 --format json
      """
    Then the exit code is 0
    And stdout is compact single-line JSON (no newlines within the envelope)
    And the schema is stable: {"success":Boolean,"data":{"items":[...],"total":Int,"limit":Int,"offset":Int},"error":null}
    # Agent selects entry id=7 from the list
    When I run:
      """
      bp proxy history get 7 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line with all declared fields present (encodeDefaults=true)
    And "data.listenerInterface" is null
    And "data.clientIp" is null
    And "data.timestamp" is null
    # (these are always null per spec — agent must handle nulls)

  @happy @community
  Scenario: AI agent filters history and extracts status codes with write-out
    # AX pattern: agent uses -w for lightweight structured extraction without JSON parsing overhead
    Given the proxy has captured 5 requests to "api.bugbounty-target.com"
    When I (as an AI agent) run:
      """
      bp proxy history --host api.bugbounty-target.com --limit 5 -w "%{status} %{requestId}"
      """
    Then the exit code is 0
    And stdout contains exactly 5 lines
    And each line is "<HTTP-status-integer> <integer-id>"
    # e.g.:
    # 200 0
    # 401 1
    # 200 2
    # 403 3
    # 302 4

  # ─────────────────────────────────────────────────────────────
  # Scenario Outline: intercept toggle truth table
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Intercept toggle commands produce correct JSON response
    When I run:
      """
      bp proxy intercept <action> --format json
      """
    Then the exit code is 0
    And stdout contains:
      """
      {"success":true,"data":{"enabled":<enabled_value>},"error":null}
      """

    Examples:
      | action  | enabled_value |
      | enable  | true          |
      | disable | false         |

  # ─────────────────────────────────────────────────────────────
  # Edge: known null fields in proxy history (spec flags)
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Proxy history entries always have null listenerInterface clientIp and HTTP timestamp
    # Per spec: listenerInterface, clientIp, timestamp (HTTP) always null
    # encodeDefaults=true means these null fields ARE present in the JSON output
    Given proxy history entry with id 0 exists
    When I run:
      """
      bp proxy history get 0 --format json
      """
    Then the exit code is 0
    And "data.listenerInterface" is explicitly present and null (not absent)
    And "data.clientIp" is explicitly present and null (not absent)
    And "data.timestamp" is explicitly present and null (not absent)

  @happy @community
  Scenario: WebSocket history timestamp reflects query time not capture time
    # Per spec: WS timestamp = Instant.now() at call time (not when traffic was captured)
    # bp must document this in --help and not mislead users
    Given the proxy has captured WebSocket messages at 10:00:00
    When I run at 10:05:00:
      """
      bp proxy websocket history --format json
      """
    Then each item's "timestamp" reflects approximately 10:05:00 (query time)
    And bp emits a note on stderr:
      """
      Note: WebSocket history timestamps reflect query time, not capture time.
      """

  # ─────────────────────────────────────────────────────────────
  # forward/drop absent from /docs — bp must not rely on /docs discovery
  # ─────────────────────────────────────────────────────────────

  @community
  Scenario: bp help for proxy intercept forward and drop is available even though these endpoints are absent from /docs
    # Per spec: forward/drop absent from /docs (OpenAPI embedded)
    # bp must NOT rely on /docs for discovery — spec from source (RestServer.kt) is authority
    When I run:
      """
      bp proxy intercept --help
      """
    Then the exit code is 0
    And stdout lists "forward" as a subcommand
    And stdout lists "drop" as a subcommand
    And stdout notes that forward and drop are stubs

  # ─────────────────────────────────────────────────────────────
  # --fields and --format combinations: Scenario Outline
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: bp proxy history supports multiple output format modes
    Given the proxy has captured at least 1 request
    When I run:
      """
      bp proxy history --limit 1 --format <format>
      """
    Then the exit code is 0
    And the output matches the expected shape for <format>

    Examples:
      | format | expected shape                                                  |
      | json   | compact single-line JSON envelope with success:true             |
      | table  | aligned human-readable table with column headers                |
      | raw    | raw Burp bytes or structured text (format-specific fallback)    |
      | quiet  | single most essential value (total count or first id)           |

  # ─────────────────────────────────────────────────────────────
  # Run Ledger interaction scenarios
  # ─────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Multiple proxy history operations accumulate in the Run Ledger and are queryable
    When I run:
      """
      bp proxy history --host api.example.com --tag recon-1 --format json
      """
    And I run:
      """
      bp proxy history get 0 --tag inspect-entry-0 --format json
      """
    And I run:
      """
      bp proxy intercept enable --tag enable-intercept-session1
      """
    Then I run:
      """
      bp log --format json
      """
    And the ledger output contains 3 entries with tags: recon-1, inspect-entry-0, enable-intercept-session1
    And each ledger entry has fields: id, tag, timestamp, target, command, burp_op, status

  @happy @community @ledger
  Scenario: bp tag annotates a prior ledger entry after the fact
    Given a ledger entry with id "42" exists from a previous proxy history call
    When I run:
      """
      bp tag 42 interesting-403-cluster
      """
    Then the exit code is 0
    And the ledger entry 42 now has tag "interesting-403-cluster"

  # ─────────────────────────────────────────────────────────────
  # Error matrix: various bad inputs to proxy history
  # ─────────────────────────────────────────────────────────────

  @error @community
  Scenario Outline: bp proxy history handles invalid query parameters gracefully
    When I run:
      """
      bp proxy history <args> --format json
      """
    Then the exit code is <exit_code>
    And the output or error contains <expected_message_fragment>

    Examples:
      | args                     | exit_code | expected_message_fragment                      |
      | --limit -1               | non-zero  | "invalid value for --limit"                    |
      | --offset -5              | non-zero  | "invalid value for --offset"                   |
      | --limit abc              | non-zero  | "invalid value for --limit"                    |
      | --limit 0                | 0         | "data.items"                                   |

  @error @community
  Scenario: bp proxy history get with empty id argument shows usage error
    When I run:
      """
      bp proxy history get
      """
    Then the exit code is non-zero
    And stderr contains "missing required argument: <id>"
