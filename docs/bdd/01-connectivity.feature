Feature: 01-connectivity — health, version, docs, Burp reachability, and edition detection
  As a human operator or AI agent driving bp against a local Burp Suite extension on :8089
  I want bp to confirm the server is alive, report its version, expose the embedded OpenAPI,
  detect Community vs Pro at runtime, and fail cleanly when Burp is not running —
  so that every downstream operation starts from a known, trusted baseline.

  Background:
    Given the bp binary is installed and on PATH
    And the default Burp REST URL is "http://127.0.0.1:8089" (BURP_REST_URL env)

  # ---------------------------------------------------------------------------
  # §6.1 /health — GET /health
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: health check returns status ok and uptime in table format (human TTY)
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health
      """
    Then the exit code is 0
    And stdout contains a table with columns: status  version  uptime  burpVersion
    And the "status" cell equals "ok"
    And the "version" cell equals "0.1.0"
    And the "burpVersion" cell equals "null"
    And stderr is empty

  @happy @community
  Scenario: health check in JSON agent mode returns a stable single-line ApiResponse envelope
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line matching:
      """
      {"success":true,"data":{"status":"ok","version":"0.1.0","uptime":<positive-long>,"burpVersion":null},"error":null}
      """
    And the JSON field "success" is true
    And the JSON field "data.status" equals "ok"
    And the JSON field "data.version" equals "0.1.0"
    And the JSON field "data.burpVersion" is null
    And the JSON field "data.uptime" is a positive integer
    And stderr is empty

  @happy @community
  Scenario: health check --quiet prints only the essential value
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --quiet
      """
    Then the exit code is 0
    And stdout is exactly "ok"
    And stderr is empty

  @happy @community
  Scenario: health check with --write-out template for scripting
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly "ok"
    And stderr is empty

  @happy @community
  Scenario: health check with --fields to select a subset of output columns
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --fields status,version
      """
    Then the exit code is 0
    And stdout contains a table with columns: status  version
    And stdout does NOT contain "uptime"
    And stdout does NOT contain "burpVersion"

  @happy @community
  Scenario: health check tagged in the Run Ledger for traceability
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --tag session-start --format json
      """
    Then the exit code is 0
    And a Run Ledger entry exists with tag "session-start"
    And the ledger entry has field "burp_op" equal to "GET /health"
    And the ledger entry has field "status" equal to "ok"

  @happy @community
  Scenario: health check with --no-ledger does not create a Run Ledger entry
    Given Burp Suite is running with the REST extension active on port 8089
    And the Run Ledger currently has N entries
    When I run:
      """
      bp health --no-ledger
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  @happy @community
  Scenario: health check raw format returns the unmodified ApiResponse JSON bytes
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --format raw
      """
    Then the exit code is 0
    And stdout begins with '{"success":true'
    And stdout contains '"status":"ok"'

  # ---------------------------------------------------------------------------
  # §6.1 /version — GET /version
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: version endpoint returns the deployed extension version
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version
      """
    Then the exit code is 0
    And stdout contains "0.1.0"
    And stderr is empty

  @happy @community
  Scenario: version endpoint in JSON mode returns stable schema
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line matching:
      """
      {"success":true,"data":{"status":"ok","version":"0.1.0","uptime":<positive-long>,"burpVersion":null},"error":null}
      """
    And the JSON field "data.version" equals "0.1.0"
    And the JSON field "data.burpVersion" is null

  @happy @community
  Scenario: version --quiet prints only the version string
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version --quiet
      """
    Then the exit code is 0
    And stdout is exactly "0.1.0"

  @happy @community
  Scenario: version --write-out template extracts just the version token
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version -w "%{payload}"
      """
    Then the exit code is 0
    And stdout is exactly "0.1.0"

  # ---------------------------------------------------------------------------
  # §6.1 /docs — GET /docs
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: docs endpoint returns the embedded OpenAPI JSON (raw, not enveloped)
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs --format raw
      """
    Then the exit code is 0
    And stdout is valid JSON
    And the JSON root object contains key "openapi" or "swagger"
    And the JSON field "info.version" equals "0.2.0"
    And stdout does NOT begin with '{"success"'

  @happy @community
  Scenario: bp warns the user that the embedded OpenAPI is known-incomplete
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs
      """
    Then the exit code is 0
    And stderr contains a warning matching "OpenAPI.*incomplete" or "docs.*0.2.0.*outdated"
    And stderr contains a note that /session, /scan, /scanner (start) are absent from /docs

  @happy @community
  Scenario: docs in JSON mode still surfaces the raw bytes inside the data field
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs --format json
      """
    Then the exit code is 0
    And stdout is valid JSON
    And the JSON field "success" is true
    And the raw OpenAPI bytes are accessible (bp normalises the non-enveloped /docs response)

  # ---------------------------------------------------------------------------
  # Error paths — Burp not running
  # ---------------------------------------------------------------------------

  @error
  Scenario: bp health exits non-zero with a clear message when Burp is not running
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp health
      """
    Then the exit code is non-zero (1 or 2)
    And stderr contains "connection refused" or "Burp is not running" or "unreachable"
    And stderr contains "http://127.0.0.1:8089"
    And stdout is empty

  @error
  Scenario: bp health --format json emits a machine-readable error envelope when Burp is down
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp health --format json
      """
    Then the exit code is non-zero
    And stdout is exactly one JSON line matching:
      """
      {"success":false,"data":null,"error":{"code":"CONNECTION_REFUSED","message":"<non-empty string>"}}
      """
    And the JSON field "success" is false
    And the JSON field "error.code" equals "CONNECTION_REFUSED"

  @error
  Scenario: bp version exits non-zero with structured error when Burp is not running
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp version --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "CONNECTION_REFUSED"

  @error
  Scenario: bp docs exits non-zero with helpful error when Burp is not running
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp docs
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "Burp is not running"
    And stdout is empty

  @error
  Scenario: bp health respects a custom BURP_REST_URL and fails gracefully on wrong port
    Given Burp Suite is running on port 8089
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:9999"
    When I run:
      """
      bp health
      """
    Then the exit code is non-zero
    And stderr contains "http://127.0.0.1:9999"
    And stderr does NOT contain "8089"

  @error
  Scenario: bp health fails gracefully on wrong host
    Given no service is listening on host "192.0.2.1" port 8089 (TEST-NET-1, unreachable)
    And environment variable BURP_REST_URL is set to "http://192.0.2.1:8089"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And the error message contains "192.0.2.1"

  @error
  Scenario: bp health with legacy port 9876 (old spec.md) produces an actionable error
    Given Burp Suite is running on port 8089 only
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:9876"
    When I run:
      """
      bp health
      """
    Then the exit code is non-zero
    And stderr contains "9876"
    And stderr contains a hint suggesting "http://127.0.0.1:8089"

  # ---------------------------------------------------------------------------
  # Community vs Pro detection — §7
  # ---------------------------------------------------------------------------

  @community
  Scenario: bp detects Community edition and reports it on health check
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And bp infers edition as "community" from the runtime probe
    And the JSON field "data.burpVersion" is null

  @pro
  Scenario: bp detects Pro edition and reports it on health check
    Given Burp Suite Professional is running on port 8089
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And bp infers edition as "pro" from the runtime probe

  @community
  Scenario: bp edition probe degrades gracefully — collaborator unavailable in Community
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp edition
      """
    Then the exit code is 0
    And stdout contains "community" (case-insensitive)
    And stdout contains a warning that "collaborator" requires Pro
    And stdout contains a warning that "scanner crawl/audit" requires Pro

  @pro
  Scenario: bp edition probe shows all groups available in Pro
    Given Burp Suite Professional is running on port 8089
    When I run:
      """
      bp edition --format json
      """
    Then the exit code is 0
    And the JSON output includes a field "edition" equal to "pro"
    And the JSON output includes a field "availableGroups" containing "collaborator"
    And the JSON output includes a field "availableGroups" containing "scanner"

  @community
  Scenario: bp edition probe in JSON mode emits stable schema for AI agents
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp edition --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON contains field "edition" with value "community"
    And the JSON contains field "proGroups" listing ["collaborator","scanner"]
    And the JSON contains field "communityGroups" listing at minimum ["health","proxy","repeater","intruder","target","decoder","config","session","utils"]
    And the JSON contains field "conditionalGroups" listing ["history"]

  @community
  Scenario: bp edition probe detects Pro by calling GET /collaborator/generate and checking for 503
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp edition
      """
    Then bp internally calls GET /collaborator/generate (or equivalent Pro probe)
    And bp receives HTTP 503 with body containing "SERVICE_UNAVAILABLE"
    And bp concludes edition is "community"
    And the exit code is 0

  @pro
  Scenario: bp edition probe confirms Pro when /collaborator/generate returns HTTP 200
    Given Burp Suite Professional is running on port 8089
    When I run:
      """
      bp edition
      """
    Then bp internally calls GET /collaborator/generate
    And bp receives HTTP 200
    And bp concludes edition is "pro"
    And the exit code is 0

  @community
  Scenario: bp warns and exits non-zero when a Pro-only command is run on Community
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is non-zero (e.g., exit 3 = PRO_REQUIRED)
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "SERVICE_UNAVAILABLE"
    And stderr contains "requires Burp Suite Professional"

  @community
  Scenario: bp warns and exits non-zero when scanner crawl is attempted on Community
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp scanner crawl --url https://example.com --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "error.code" equals "INTERNAL_ERROR" or "SERVICE_UNAVAILABLE"
    And stderr contains "requires Burp Suite Professional"

  @community
  Scenario: scanner issue-definitions succeeds in Community (graceful degradation)
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then the exit code is 0
    And stdout JSON field "success" is true
    And stdout JSON field "data" is an array (possibly empty)

  # ---------------------------------------------------------------------------
  # --format variations — output model contract
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario Outline: health check output format contract for all supported --format values
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --format <format>
      """
    Then the exit code is 0
    And stdout matches the expected shape for format "<format>"

    Examples:
      | format | expected shape                                               |
      | json   | single compact JSON line; {"success":true,...}               |
      | table  | aligned columns: STATUS VERSION UPTIME BURPVERSION           |
      | raw    | raw bytes from HTTP body; begins with {"success":true        |
      | quiet  | single word: ok                                              |

  @happy @community
  Scenario: bp health in a non-TTY pipe context defaults to json format without --format flag
    Given Burp Suite is running with the REST extension active on port 8089
    When stdout is a pipe (not a TTY) and I run:
      """
      bp health | cat
      """
    Then the output is valid compact JSON (not a table)
    And the JSON field "success" is true

  @happy @community
  Scenario: bp health in a TTY context defaults to table format without --format flag
    Given Burp Suite is running with the REST extension active on port 8089
    And stdout is a real TTY
    When I run:
      """
      bp health
      """
    Then stdout is an aligned table with header row containing "STATUS"

  @happy @community
  Scenario: --write-out template %{status} for health returns HTTP status class
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health -w "%{status}"
      """
    Then stdout is exactly "200"

  @happy @community
  Scenario: --write-out template %{length} for health returns response byte count
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health -w "%{length}"
      """
    Then stdout is a positive integer string
    And the exit code is 0

  @happy @community
  Scenario: --write-out template %{time} for health returns elapsed milliseconds
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health -w "%{time}"
      """
    Then stdout is a non-negative integer string
    And the exit code is 0

  @happy @community
  Scenario: --write-out with multiple tokens on health
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health -w "%{status} %{time}ms %{length}b"
      """
    Then stdout matches the pattern "<3-digit-int> <int>ms <int>b"
    And the exit code is 0

  @happy @community
  Scenario Outline: health --fields selects and orders output columns
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --fields <fields> --format table
      """
    Then stdout contains only the columns <columns> in that order
    And stdout does NOT contain any other column headers

    Examples:
      | fields          | columns         |
      | status          | STATUS          |
      | version,status  | VERSION STATUS  |
      | uptime,version  | UPTIME VERSION  |

  # ---------------------------------------------------------------------------
  # Run Ledger — §9 — connectivity operations
  # ---------------------------------------------------------------------------

  @ledger @happy @community
  Scenario: bp health records a ledger entry with correct burp_op and target
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --tag health-check-001
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field     | value                   |
      | tag       | health-check-001        |
      | burp_op   | GET /health             |
      | target    | http://127.0.0.1:8089   |
      | status    | ok                      |
      | command   | bp health --tag health-check-001 |

  @ledger @happy @community
  Scenario: bp version records a ledger entry with burp_op GET /version
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version --tag pre-flight
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value          |
      | tag     | pre-flight     |
      | burp_op | GET /version   |
      | status  | ok             |

  @ledger @error
  Scenario: a failed health call (Burp down) is still recorded in the ledger with status=error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp health --tag failed-probe
      """
    Then the exit code is non-zero
    And running "bp log --format json" shows a ledger entry where:
      | field  | value        |
      | tag    | failed-probe |
      | status | error        |

  @ledger @happy @community
  Scenario: --no-ledger suppresses Run Ledger recording on version call
    Given Burp Suite is running with the REST extension active on port 8089
    And the Run Ledger currently has N entries
    When I run:
      """
      bp version --no-ledger
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  # ---------------------------------------------------------------------------
  # Agent mode (AX) — stable JSON for AI callers
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: AX agent polls health to gate a fuzzing session — full JSON flow
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp health --format json --no-ledger
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (no trailing newline issues)
    And the JSON schema is stable: fields success(bool), data.status(str), data.version(str), data.uptime(int), data.burpVersion(null), error(null)
    And the agent can parse data.status == "ok" to proceed with fuzzing

  @happy @community
  Scenario: AX agent checks edition before calling collaborator
    Given Burp Suite Community Edition is running on port 8089
    When an AI agent runs:
      """
      bp edition --format json --no-ledger
      """
    Then the exit code is 0
    And stdout JSON field "edition" equals "community"
    And the agent knows to skip collaborator and scanner crawl/audit calls

  @happy @community
  Scenario: AX agent uses bp health -w "%{status}" as the minimal liveness probe
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp health -w "%{status}" --no-ledger
      """
    Then the exit code is 0
    And stdout is exactly "200"
    And the agent confirms Burp is reachable with a single integer comparison

  @error
  Scenario: AX agent receives machine-parseable error when Burp is down
    Given Burp Suite is NOT running
    When an AI agent runs:
      """
      bp health --format json --no-ledger
      """
    Then the exit code is non-zero
    And stdout is a single compact JSON line
    And the JSON field "success" equals false
    And the JSON field "error.code" equals "CONNECTION_REFUSED"
    And the agent can branch on success==false to abort the session

  # ---------------------------------------------------------------------------
  # Edge cases and known caveats — §2 docMismatches, §6.1 flags
  # ---------------------------------------------------------------------------

  @community
  Scenario: burpVersion is always null in health response (known flag — never populated)
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "data.burpVersion" is null
    And bp does NOT attempt to interpret burpVersion for edition detection (uses separate probe)

  @community
  Scenario: /docs declares version 0.2.0 while /health reports 0.1.0 — bp surfaces the discrepancy
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs --format json
      """
    Then the exit code is 0
    And the JSON field "info.version" in the OpenAPI payload equals "0.2.0"
    And stderr contains a warning about version mismatch between /docs (0.2.0) and /health (0.1.0)

  @community
  Scenario: /docs omits /session, /scan, /scanner-start endpoints — bp warns user not to rely on docs for discovery
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs
      """
    Then the exit code is 0
    And stderr contains a warning that /docs is known-incomplete
    And stderr mentions that /session, /scan, /scanner groups are absent from the embedded OpenAPI

  @community
  Scenario: bp health works correctly when BURP_REST_URL has a trailing slash
    Given Burp Suite is running on port 8089
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:8089/"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

  @community
  Scenario: bp health works when BURP_REST_URL uses localhost instead of 127.0.0.1
    Given Burp Suite is running on port 8089
    And environment variable BURP_REST_URL is set to "http://localhost:8089"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

  @error
  Scenario: bp health returns a non-zero exit code when the server returns HTTP 500
    Given Burp Suite extension returns HTTP 500 with body {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected Throwable"}}
    When I run:
      """
      bp health --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "INTERNAL_ERROR"

  @community
  Scenario Outline: bp health is resilient to high uptime values (large Long)
    Given Burp Suite is running and has been up for <uptime_ms> milliseconds
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "data.uptime" equals <uptime_ms>
    And bp renders the uptime without integer overflow or truncation

    Examples:
      | uptime_ms       |
      | 1               |
      | 86400000        |
      | 2592000000      |
      | 9007199254740991|

  # ---------------------------------------------------------------------------
  # Scenario Outline: connectivity check across multiple Burp-rest URL forms
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario Outline: bp health succeeds for valid BURP_REST_URL configurations
    Given Burp Suite is running and reachable at "<host>:<port>"
    And environment variable BURP_REST_URL is set to "<url>"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

    Examples:
      | url                          | host        | port |
      | http://127.0.0.1:8089        | 127.0.0.1   | 8089 |
      | http://localhost:8089        | localhost   | 8089 |
      | http://127.0.0.1:8089/       | 127.0.0.1   | 8089 |

  @error
  Scenario Outline: bp health fails cleanly for unreachable BURP_REST_URL configurations
    Given no service is listening at "<url>"
    And environment variable BURP_REST_URL is set to "<url>"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stderr contains the URL "<url>"

    Examples:
      | url                          |
      | http://127.0.0.1:9876        |
      | http://127.0.0.1:9999        |
      | http://192.0.2.1:8089        |
      | http://127.0.0.1:0           |
