Feature: Errors and Edge Cases
  As a security engineer or AI agent driving bp against Burp Suite,
  I need bp to fail fast, clearly, and predictably on every failure mode —
  Burp unreachable, invalid identifiers, absent history group, malformed
  --pos selectors, empty result sets, Pro-only commands on Community,
  lenient/invalid JSON, very large truncated responses, and out-of-range
  offsets — so that pipelines never hang silently and humans never mistake
  a broken probe for a clean result.

  Background:
    Given the bp CLI is installed and on PATH
    And the default Burp REST URL is "http://127.0.0.1:8089"

  # ─────────────────────────────────────────────
  # §1  BURP NOT RUNNING
  # ─────────────────────────────────────────────

  @error @community
  Scenario: Health check when Burp is not running returns a clear connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health
    Then bp exits with a non-zero exit code
    And stderr contains "connection refused" or "could not connect" and the target URL "http://127.0.0.1:8089"
    And stdout is empty

  @error @community
  Scenario: Health check with --format json when Burp is down emits a machine-readable error envelope
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health --format json
    Then bp exits with a non-zero exit code
    And stdout is a single compact JSON line matching:
      """
      {"success":false,"data":null,"error":{"code":"CONNECTION_REFUSED","message":"<non-empty>"}}
      """
    And the JSON contains the field "error.code" equal to "CONNECTION_REFUSED"

  @error @community
  Scenario: Any subcommand when Burp is not running emits the same connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp proxy history --format json
    Then bp exits with a non-zero exit code
    And stdout contains "CONNECTION_REFUSED" or stderr contains "connection refused"
    And bp does not hang — it fails within 5 seconds

  @error @community
  Scenario: bp fuzz aborts immediately when Burp is unreachable
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp fuzz --id 7 \
        --pos 'body:username' \
        --payloads username=wordlist.txt \
        --format json
      """
    Then bp exits with a non-zero exit code
    And no fuzz results are printed
    And stderr contains a connection error message

  @error @community
  Scenario: --quiet flag still exits non-zero and prints nothing on connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health --quiet
    Then bp exits with a non-zero exit code
    And stdout is empty

  # ─────────────────────────────────────────────
  # §2  INVALID / MISSING requestId
  # ─────────────────────────────────────────────

  @error @community
  Scenario: Repeater send with a non-existent requestId returns INVALID_REQUEST
    Given Burp Suite is running on port 8089
    And the proxy history contains fewer than 9999 entries
    When I run:
      """
      bp repeater send --id 9999 --format json
      """
    Then bp exits with a non-zero exit code
    And stdout contains:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"<non-empty>"}}
      """

  @error @community
  Scenario: Repeater send with a negative requestId is rejected
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp repeater send --id -1 --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: Repeater send with a string requestId (non-integer) is rejected client-side before the HTTP call
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp repeater send --id "abc" --format json
      """
    Then bp exits with a non-zero exit code
    And stderr or stdout contains an error indicating requestId must be an integer

  @error @community
  Scenario: Repeater send with neither --id nor --request body is rejected with INVALID_REQUEST
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp repeater send --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_REQUEST"
    And the error message explains that exactly one of requestId or request body is required

  @error @community
  Scenario: Intruder quick-fuzz with a missing requestId and no inline request is rejected
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp fuzz quick --param q \
        --payloads "' OR '1'='1" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: Proxy history lookup for a non-integer path id returns INVALID_PARAM
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp proxy history get --id "not-a-number" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_PARAM"

  @error @community
  Scenario: Proxy history lookup with a floating-point id is rejected
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp proxy history get --id 3.14 --format json
      """
    Then bp exits with a non-zero exit code
    And stdout or stderr contains an error about the id not being an integer

  @error @community
  Scenario Outline: requestId edge values are all rejected or return meaningful errors
    Given Burp Suite is running on port 8089
    When I run: bp repeater send --id <value> --format json
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "success" equal to false

    Examples:
      | value        |
      | 0            |
      | 2147483648   |
      | -2147483649  |
      | 1.5          |
      | ""           |

  # ─────────────────────────────────────────────
  # §3  HISTORY GROUP ABSENT WHEN DB INIT FAILED
  # ─────────────────────────────────────────────

  @error @community
  Scenario: GET /history returns 404 when the SQLite DB failed to initialise
    Given Burp Suite is running on port 8089
    And the SQLite database at "~/.burp-rest/burpdata" failed to initialise (historyDao is null)
    When I run:
      """
      bp history list --format json
      """
    Then bp exits with a non-zero exit code
    And the output or stderr explains that the history group is unavailable (404 or DB_UNAVAILABLE)
    And the message is NOT a generic "connection refused" — it identifies the group as absent

  @error @community
  Scenario: GET /history/{id} returns 404 when DB is absent
    Given Burp Suite is running on port 8089
    And the history group is NOT registered (DB init failed)
    When I run:
      """
      bp history get --id 1 --format json
      """
    Then bp exits with a non-zero exit code
    And stdout contains JSON indicating the route is absent or the DB is unavailable

  @error @community
  Scenario: POST /history/{id}/replay returns 404 when DB is absent
    Given Burp Suite is running on port 8089
    And the history group is NOT registered (DB init failed)
    When I run:
      """
      bp history replay --id 1 --format json
      """
    Then bp exits with a non-zero exit code
    And bp reports a clear error rather than silently succeeding

  @error @community
  Scenario: DELETE /history returns 404 when DB is absent (not a silent no-op)
    Given Burp Suite is running on port 8089
    And the history group is NOT registered (DB init failed)
    When I run:
      """
      bp history delete --format json
      """
    Then bp exits with a non-zero exit code
    And bp does NOT print a success message

  @error @community
  Scenario: bp probes /history availability at session start and warns the user when the group is absent
    Given Burp Suite is running on port 8089
    And the history group is NOT registered (DB init failed)
    When I run:
      """
      bp health --format json
      """
    Then bp exits with exit code 0 (health itself is fine)
    And the JSON output or a warning line indicates that the history/DB group is degraded

  @error @community
  Scenario: /scan/endpoints returns SERVICE_UNAVAILABLE when DB is absent
    Given Burp Suite is running on port 8089
    And the SQLite database failed to initialise
    When I run:
      """
      bp scan endpoints --host "api.target.local" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "error.code" equal to "SERVICE_UNAVAILABLE"

  # ─────────────────────────────────────────────
  # §4  MALFORMED --pos SELECTOR
  # ─────────────────────────────────────────────

  @error @community @fuzz
  Scenario: Unknown --pos selector prefix is rejected client-side
    Given Burp Suite is running on port 8089
    And proxy history entry 3 exists
    When I run:
      """
      bp fuzz --id 3 \
        --pos 'jsonpath:$.user.id' \
        --type sniper \
        --payloads "set1=admin,root" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains an error like "unknown selector prefix: jsonpath"
    And stderr lists valid prefixes: header, cookie, body, query, path, offset

  @error @community @fuzz
  Scenario: --pos with offset selector missing the dash separator is rejected
    Given Burp Suite is running on port 8089
    And proxy history entry 5 exists
    When I run:
      """
      bp fuzz --id 5 \
        --pos 'offset:42' \
        --type sniper \
        --payloads "set1=FUZZ" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "malformed offset selector" or "expected offset:START-END"

  @error @community @fuzz
  Scenario: --pos with offset:START-END where START > END is rejected
    Given Burp Suite is running on port 8089
    And proxy history entry 5 exists
    When I run:
      """
      bp fuzz --id 5 \
        --pos 'offset:100-50' \
        --type sniper \
        --payloads "set1=FUZZ" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "invalid offset range" or "start must be less than end"

  @error @community @fuzz
  Scenario: --pos offset with non-integer bounds is rejected client-side
    Given Burp Suite is running on port 8089
    And proxy history entry 5 exists
    When I run:
      """
      bp fuzz --id 5 \
        --pos 'offset:abc-def' \
        --type sniper \
        --payloads "set1=FUZZ" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "offset values must be integers"

  @error @community @fuzz
  Scenario: --pos header selector with a blank header name is rejected
    Given Burp Suite is running on port 8089
    And proxy history entry 2 exists
    When I run:
      """
      bp fuzz --id 2 \
        --pos 'header:' \
        --type sniper \
        --payloads "set1=value1" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "header name must not be blank"

  @error @community @fuzz
  Scenario: --pos header selector targeting a header NOT present in the captured request fails to resolve
    Given Burp Suite is running on port 8089
    And proxy history entry 12 exists with request headers: Host, User-Agent, Authorization
    When I run:
      """
      bp fuzz --id 12 \
        --pos 'header:X-Nonexistent-Header' \
        --type sniper \
        --payloads "set1=FUZZ" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "header not found in captured request: X-Nonexistent-Header"

  @error @community @fuzz
  Scenario: --pos body:FIELD on a request with no body is rejected
    Given Burp Suite is running on port 8089
    And proxy history entry 8 exists with a GET request and no body
    When I run:
      """
      bp fuzz --id 8 \
        --pos 'body:username' \
        --type sniper \
        --payloads "set1=admin" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "cannot resolve body selector: request has no body"

  @error @community @fuzz
  Scenario: --pos path:INDEX with an out-of-range segment index is rejected
    Given Burp Suite is running on port 8089
    And proxy history entry 4 exists with path "/api/v1/users"  (3 segments)
    When I run:
      """
      bp fuzz --id 4 \
        --pos 'path:99' \
        --type sniper \
        --payloads "set1=FUZZ" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "path segment index 99 out of range"

  @error @community @fuzz
  Scenario: cluster-bomb attack with fewer payload sets than positions is rejected client-side
    Given Burp Suite is running on port 8089
    And proxy history entry 3 exists
    When I run:
      """
      bp fuzz --id 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'header:X-Real-IP' \
        --type cluster-bomb \
        --payloads "X-Forwarded-For=ips.txt" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "cluster-bomb requires one payload set per position"
    And stderr shows that 2 positions but only 1 payload set were provided

  @error @community @fuzz
  Scenario: Fuzz with empty payloads list is rejected (intruder refuses blank payloads)
    Given Burp Suite is running on port 8089
    And proxy history entry 3 exists
    When I run:
      """
      bp fuzz quick --id 3 \
        --param "q" \
        --payloads "" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_REQUEST"
    And the message contains "payloads" and is non-blank

  # ─────────────────────────────────────────────
  # §5  EMPTY RESULT SET
  # ─────────────────────────────────────────────

  @happy @community
  Scenario: Proxy history for a host with no traffic returns total=0 and empty list in table mode
    Given Burp Suite is running on port 8089
    And no requests to "nevervisited.internal" exist in the proxy history
    When I run:
      """
      bp proxy history --host nevervisited.internal
      """
    Then bp exits with exit code 0
    And stdout contains "0 results" or a table with zero rows
    And stdout does NOT contain an error

  @happy @community
  Scenario: Proxy history empty result set in --format json emits stable schema with empty array
    Given Burp Suite is running on port 8089
    And no requests to "nevervisited.internal" exist in the proxy history
    When I run:
      """
      bp proxy history --host nevervisited.internal --format json
      """
    Then bp exits with exit code 0
    And stdout is a compact JSON object containing:
      """
      {"success":true,"data":{"entries":[],"total":0,"limit":<N>,"offset":0},"error":null}
      """
    And the "total" field is 0

  @happy @community @fuzz
  Scenario: Intruder quick-fuzz against a host with all identical responses returns anomalous=false for all and exits 0
    Given Burp Suite is running on port 8089
    And proxy history entry 6 is a GET to "https://app.example.com/api/healthz"
    When I run:
      """
      bp fuzz quick --id 6 \
        --param "probe" \
        --payloads "a,b,c" \
        --format json
      """
    Then bp exits with exit code 0
    And every result line has "anomalous":false
    And no result is omitted even though there are no anomalies

  @happy @community @fuzz
  Scenario: Fuzz with --anomalous-only and no anomalous responses prints nothing but exits 0
    Given Burp Suite is running on port 8089
    And proxy history entry 6 produces identical responses to all payloads
    When I run:
      """
      bp fuzz quick --id 6 \
        --param "probe" \
        --payloads "a,b,c" \
        --anomalous-only \
        --format json
      """
    Then bp exits with exit code 0
    And stdout is empty (no result lines because no anomalies)
    And stderr optionally prints "0 anomalous results"

  @happy @community
  Scenario: History sitemap for unknown host returns empty sitemap with total=0
    Given Burp Suite is running on port 8089
    And the sitemap contains no entry for "phantom.local"
    When I run:
      """
      bp history sitemap --host phantom.local --format json
      """
    Then bp exits with exit code 0
    And stdout matches compact JSON:
      """
      {"success":true,"data":{"entries":[],"total":0},"error":null}
      """

  @happy @community
  Scenario: Scanner issue-definitions on Community returns empty list but exits 0 (graceful degradation)
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then bp exits with exit code 0
    And stdout contains JSON with "data" being an empty array or empty list
    And bp does NOT treat an empty list as an error

  @happy @community
  Scenario: Target sitemap filtered by prefix with no matches returns an empty list exit 0
    Given Burp Suite is running on port 8089
    And the target sitemap contains no URLs under "https://notscoped.example.com"
    When I run:
      """
      bp target sitemap --url "https://notscoped.example.com" --format json
      """
    Then bp exits with exit code 0
    And stdout contains JSON with an empty entries array

  # ─────────────────────────────────────────────
  # §6  PRO-ONLY COMMAND ON COMMUNITY
  # ─────────────────────────────────────────────

  @error @community @pro
  Scenario: collaborator generate on Community edition returns SERVICE_UNAVAILABLE 503
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp collaborator generate --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches compact JSON:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"<non-empty>"}}
      """
    And the error message mentions "Collaborator" or "Professional"

  @error @community @pro
  Scenario: collaborator generate/batch on Community returns 503 with count parameter
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp collaborator generate --count 5 --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "SERVICE_UNAVAILABLE"

  @error @community @pro
  Scenario: collaborator poll on Community returns SERVICE_UNAVAILABLE
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp collaborator poll --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "SERVICE_UNAVAILABLE"

  @error @community @pro
  Scenario: collaborator poll for a specific id on Community returns SERVICE_UNAVAILABLE
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp collaborator poll --id "a1b2c3d4" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "SERVICE_UNAVAILABLE"

  @error @community @pro
  Scenario: scanner crawl on Community returns INTERNAL_ERROR 500 with explicit Professional message
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp scanner crawl --url "https://app.example.com" --format json
      """
    Then bp exits with a non-zero exit code
    And the HTTP response was 500
    And stdout matches JSON with "error.code" equal to "INTERNAL_ERROR"
    And the error message contains "requires Burp Suite Professional"

  @error @community @pro
  Scenario: scanner audit on Community returns INTERNAL_ERROR 500
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp scanner audit --url "https://app.example.com" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INTERNAL_ERROR"
    And the error message mentions "Professional"

  @error @community @pro
  Scenario: scanner crawl-and-audit on Community returns INTERNAL_ERROR 500
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp scanner crawl-and-audit --url "https://shop.target.local" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INTERNAL_ERROR"
    And the error message contains "requires Burp Suite Professional"

  @error @community @pro
  Scenario: bp detects Community edition at startup and warns before any Pro-only command is dispatched
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp collaborator generate --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains a pre-flight warning such as "collaborator requires Burp Suite Professional"
    And the warning appears before any HTTP call is made to /collaborator/generate

  @happy @pro
  Scenario: bp scanner issue-definitions works even in Community edition (the one Community-safe scanner endpoint)
    Given Burp Suite is running in Community edition on port 8089
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And "data" is a list (possibly empty) without error

  # ─────────────────────────────────────────────
  # §7  LENIENT / INVALID JSON INPUT
  # ─────────────────────────────────────────────

  @happy @community
  Scenario: Server accepts JSON with trailing comma due to isLenient=true (unknown-keys are silently dropped)
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      {"requestId":1,"unknownField":"ignored",}
      """
    Then the server responds with HTTP 200
    And the response JSON has "success" equal to true
    And the "unknownField" key is NOT reflected back in any response field

  @happy @community
  Scenario: bp CLI forwards extra --option flags and the server silently drops unknown keys
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run:
      """
      bp repeater send --id 1 \
        --extra-key "future-flag-value" \
        --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And no error about "extra-key" is returned

  @error @community
  Scenario: Sending completely invalid JSON (not even an object) to /repeater/send returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      not-json-at-all
      """
    Then the server responds with HTTP 400
    And the response JSON matches:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"<non-empty>"}}
      """

  @error @community
  Scenario: Sending an array at the top level instead of an object returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      ["requestId",1]
      """
    Then the server responds with HTTP 400
    And the response JSON has "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: Sending a number where an object is expected returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/intruder/attack/create" with body:
      """
      42
      """
    Then the server responds with HTTP 400
    And the response JSON has "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: Intruder quick-fuzz with param set to blank string returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run:
      """
      bp fuzz quick --id 1 \
        --param "" \
        --payloads "a,b" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_REQUEST"
    And the message contains "param" and indicates it must not be blank

  @error @community
  Scenario: Collaborator batch generate with count as a non-integer string triggers INVALID_REQUEST
    Given Burp Suite is running in Professional edition on port 8089
    When I send a raw POST to "/collaborator/generate/batch" with body:
      """
      {"count":"five"}
      """
    Then the server responds with HTTP 400
    And the response JSON has "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: Sending a JSON body with a requestId typed as String triggers INVALID_REQUEST
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      {"requestId":"seven"}
      """
    Then the server responds with HTTP 400
    And the response JSON has "error.code" equal to "INVALID_REQUEST"
    And the message references the type mismatch (requestId must be Int)

  @happy @community
  Scenario: isLenient=true allows unquoted keys in the JSON body and the server processes the request
    Given Burp Suite is running on port 8089
    And proxy history entry 2 exists
    When I send a raw POST to "/repeater/send" with body:
      """
      {requestId:2}
      """
    Then the server responds with HTTP 200
    And the response JSON has "success" equal to true

  # ─────────────────────────────────────────────
  # §8  VERY LARGE RESULT TRUNCATION
  # ─────────────────────────────────────────────

  @happy @community
  Scenario: History entry with a response body exceeding 1 MB is stored truncated at 1 MB
    Given Burp Suite is running on port 8089
    And the proxy captured a response with a body larger than 1 048 576 bytes for entry id 100
    When I run:
      """
      bp history get --id 100 --format json
      """
    Then bp exits with exit code 0
    And the "data.responseBody" field in the JSON is at most 1 048 576 bytes long
    And the JSON contains a field or annotation indicating truncation (e.g. "truncated":true or a note in metadata)

  @happy @community
  Scenario: History entry with a body under 1 MB is returned in full without truncation flag
    Given Burp Suite is running on port 8089
    And the proxy captured a response with a 512-byte body for entry id 101
    When I run:
      """
      bp history get --id 101 --format json
      """
    Then bp exits with exit code 0
    And the "data.responseBody" field length equals 512 bytes

  @happy @community
  Scenario: Fuzz results with many records are paginated cleanly via --offset and --limit
    Given Burp Suite is running on port 8089
    And intruder attack "a1b2c3d4" completed with 500 result entries
    When I run:
      """
      bp intruder results --attack-id a1b2c3d4 --offset 0 --limit 50 --format json
      """
    Then bp exits with exit code 0
    And stdout contains exactly 50 result records
    And each record has fields: index, payload, status, length, time, contentType, anomalous

  @happy @community
  Scenario: Large table output is not truncated in table mode — all rows appear
    Given Burp Suite is running on port 8089
    And intruder attack "a1b2c3d4" completed with 200 result entries
    When I run:
      """
      bp intruder results --attack-id a1b2c3d4 --offset 0 --limit 0
      """
    Then bp exits with exit code 0
    And stdout contains exactly 200 rows of results in aligned table format
    And no "truncated" message is emitted (limit=0 means all results)

  @happy @community @fuzz
  Scenario: --write-out template with large result set prints one line per record without truncation
    Given Burp Suite is running on port 8089
    And intruder attack "a1b2c3d4" completed with 150 result entries
    When I run:
      """
      bp intruder results --attack-id a1b2c3d4 \
        -w "%{status} %{payload}" \
        --limit 0
      """
    Then bp exits with exit code 0
    And stdout contains exactly 150 lines
    And each line matches the pattern "<HTTP_STATUS_CODE> <payload_value>"

  # ─────────────────────────────────────────────
  # §9  OFFSET OUT OF RANGE
  # ─────────────────────────────────────────────

  @error @community
  Scenario: Proxy history with offset beyond total entry count returns empty list not an error
    Given Burp Suite is running on port 8089
    And proxy history contains 10 entries
    When I run:
      """
      bp proxy history --offset 9999 --limit 50 --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "data.entries" equal to []
    And "data.total" reflects the actual total (10), not 0

  @error @community
  Scenario: Proxy history with negative offset is rejected client-side before the HTTP call
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp proxy history --offset -1 --limit 50 --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "offset must be >= 0"

  @error @community
  Scenario: History list (DB group) with page=-1 is handled gracefully — server does not crash
    Given Burp Suite is running on port 8089
    And the history DB is initialised
    When I run:
      """
      bp history list --page -1 --page-size 50 --format json
      """
    Then bp exits with exit code 0 or a non-zero exit code
    And if non-zero, stdout contains JSON with "error.code" non-null
    And if zero, stdout contains JSON with "data.entries" as a list (possibly empty)
    And Burp does NOT crash

  @error @community
  Scenario: Intruder attack results with offset beyond result count returns empty array not an error
    Given Burp Suite is running on port 8089
    And intruder attack "b9c3d1e2" completed with 20 result entries
    When I run:
      """
      bp intruder results --attack-id b9c3d1e2 --offset 9999 --limit 50 --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "data" as an empty array

  @error @community
  Scenario: History list with pageSize=0 is handled — either returns all entries or rejects cleanly
    Given Burp Suite is running on port 8089
    And the history DB is initialised with 5 entries
    When I run:
      """
      bp history list --page 0 --page-size 0 --format json
      """
    Then bp exits with exit code 0 or a non-zero exit code
    And no unhandled exception is leaked in the response body

  @error @community
  Scenario: Proxy history --offset beyond total combined with --format json still returns valid ApiResponse envelope
    Given Burp Suite is running on port 8089
    And proxy history contains 3 entries
    When I run:
      """
      bp proxy history --offset 1000 --limit 10 --format json
      """
    Then bp exits with exit code 0
    And stdout is a valid compact JSON object with "success" true
    And "data.entries" is an empty array
    And the JSON schema is stable (same keys present regardless of result count)

  # ─────────────────────────────────────────────
  # §10  OUTPUT MODEL CONSISTENCY — AGENT MODE (AX)
  # ─────────────────────────────────────────────

  @error @community
  Scenario: AI agent calling bp health in json mode receives stable schema even on connection failure
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health --format json
    Then stdout is a single compact JSON line (no pretty-print, no newlines within the object)
    And the JSON matches the ApiResponse envelope:
      """
      {"success":false,"data":null,"error":{"code":"<non-empty>","message":"<non-empty>"}}
      """
    And there is NO trailing comma or unquoted key in the output (isLenient=true only applies server-side)

  @error @community @fuzz
  Scenario: AI agent uses --fields to select only anomalous results — error on invalid field name
    Given Burp Suite is running on port 8089
    And intruder attack "c2d4e6f8" completed with results
    When I run:
      """
      bp intruder results --attack-id c2d4e6f8 \
        --fields "index,payload,anomalous,INVALID_FIELD" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains "unknown field: INVALID_FIELD"
    And stderr lists the valid fields: index, payload, status, length, time, contentType, anomalous, location, requestId

  @happy @community @fuzz
  Scenario: AI agent uses --write-out template for machine-parseable one-liner output per fuzz result
    Given Burp Suite is running on port 8089
    And proxy history entry 7 is a POST to "https://api.target.local/login" with body "username=admin&password=admin"
    And intruder attack "d3e5f7a9" is completed with 3 results: 200/401/403
    When I run:
      """
      bp intruder results --attack-id d3e5f7a9 \
        -w "%{status} %{payload}" \
        --no-ledger
      """
    Then bp exits with exit code 0
    And stdout contains exactly 3 lines
    And the lines are:
      """
      200 <payload_that_got_200>
      401 <payload_that_got_401>
      403 <payload_that_got_403>
      """

  @happy @community @ledger
  Scenario: --no-ledger flag prevents the operation from being recorded in the Run Ledger
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run:
      """
      bp repeater send --id 1 --no-ledger --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And running "bp log" afterwards does NOT show an entry for this operation

  @happy @community @ledger
  Scenario: --tag flag records the operation in the Run Ledger with the given label
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run:
      """
      bp repeater send --id 1 --tag "auth-bypass-probe-1" --format json
      """
    Then bp exits with exit code 0
    And running "bp log --format json" afterwards shows an entry with "tag" equal to "auth-bypass-probe-1"
    And that ledger entry includes the exact bp command, timestamp, and target URL

  @happy @community
  Scenario: --quiet flag on a successful health check prints only the most essential value
    Given Burp Suite is running on port 8089
    When I run: bp health --quiet
    Then bp exits with exit code 0
    And stdout is a single line containing only "ok" (the status value)
    And no other fields or labels are printed

  @happy @community @fuzz
  Scenario: --quiet flag on a fuzz result prints only one value per record (the status code)
    Given Burp Suite is running on port 8089
    And intruder attack "e4f6a8b0" completed with 3 results at status codes 200, 401, 500
    When I run:
      """
      bp intruder results --attack-id e4f6a8b0 --quiet
      """
    Then bp exits with exit code 0
    And stdout contains exactly 3 lines: "200", "401", "500"
    And no payload, length, or other field appears on any line

  # ─────────────────────────────────────────────
  # §11  ADDITIONAL CROSS-CUTTING EDGE CASES
  # ─────────────────────────────────────────────

  @error @community
  Scenario: Batch repeater send aborts on the first failed item and returns no partial results
    Given Burp Suite is running on port 8089
    And proxy history entries 1 and 2 exist but entry 9999 does not
    When I run:
      """
      bp repeater send-batch \
        --ids "1,9999,2" \
        --format json
      """
    Then bp exits with a non-zero exit code
    And the error indicates that item 2 (requestId 9999) failed
    And no result for item 3 (requestId 2) is returned (abort-total behaviour)

  @error @community
  Scenario: Batch session send aborts on the first failed request and returns no partial results
    Given Burp Suite is running on port 8089
    And a session with cookie "sessionid=abc123" is active
    When I run:
      """
      bp session send-batch \
        --requests '[{"method":"GET","url":"https://app.example.com/api/me"},{"method":"GET","url":"not-a-url"}]' \
        --format json
      """
    Then bp exits with a non-zero exit code
    And the JSON error identifies which request in the batch failed
    And no result for the first (valid) request is returned alongside the error

  @error @community
  Scenario: scope check without --url returns INVALID_PARAM wrapped in HTTP 200
    Given Burp Suite is running on port 8089
    When I send a raw GET to "/target/scope/check" with no url query parameter
    Then the server responds with HTTP 200
    And the response JSON has "error.code" equal to "INVALID_PARAM"
    And "success" is false

  @error @community
  Scenario: bp scope check without --url exits non-zero despite the server returning HTTP 200
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp target scope check --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_PARAM"

  @error @community
  Scenario: Intruder attack start for a non-existent attackId returns an appropriate error
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp intruder start --attack-id "00000000" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "success" equal to false

  @error @community
  Scenario: Intruder attack status poll for a non-existent attackId returns an error
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp intruder status --attack-id "ffffffff" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "success" equal to false

  @error @community
  Scenario: DELETE /history without confirmation flag is blocked by bp as a safety gate
    Given Burp Suite is running on port 8089
    And the history DB contains 42 entries
    When I run:
      """
      bp history delete --format json
      """
    Then bp exits with a non-zero exit code
    And stderr contains a warning: "destructive operation requires --confirm flag"
    And no delete is performed

  @error @community
  Scenario: DELETE /history with --confirm executes and wipes all entries irreversibly
    Given Burp Suite is running on port 8089
    And the history DB contains 42 entries
    When I run:
      """
      bp history delete --confirm --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And running "bp history list --format json" immediately after shows "data.total" equal to 0

  @error @community
  Scenario: POST /target/scope with an empty includes list is accepted by the server but bp warns (full replace clears scope)
    Given Burp Suite is running on port 8089
    And the current scope contains 3 URLs
    When I run:
      """
      bp target scope set --includes "" --format json
      """
    Then bp exits with exit code 0 or a non-zero exit code after a warning
    And if exit 0: stderr contains "WARNING: this will clear all in-scope URLs"
    And if exit non-zero: stderr explains that an empty includes list would wipe all scope entries

  @error @community
  Scenario: Repeater tab create with neither --request nor --id silently uses https://example.com as fallback
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp repeater tab create --name "EmptyTab" --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And stderr or the JSON data indicates the fallback URL "https://example.com" was used

  @error @community
  Scenario: Proxy intercept forward is a stub and bp warns the user it is a no-op
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp proxy intercept forward --format json
      """
    Then bp exits with exit code 0
    And stdout contains JSON with "data.forwarded" equal to true
    And stderr contains "WARNING: /proxy/intercept/forward is a stub — no request was actually forwarded"

  @error @community
  Scenario: Scanner pause is a stub and bp warns the user the scan continues running
    Given Burp Suite is running in Professional edition on port 8089
    And scanner scan "f0a1b2c3" is running
    When I run:
      """
      bp scanner pause --scan-id f0a1b2c3 --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And stderr contains "WARNING: /scanner/{id}/pause is a stub — the scan continues running in Burp"

  @error @community
  Scenario: Config PUT does not persist changes — bp informs the user this is a stub echo
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp config project set --config '{"proxy.listener.port":"8080"}' --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "success" equal to true
    And stderr contains "WARNING: /config/project (PUT) is a stub — no change was written to Burp"

  @error @community
  Scenario: /docs endpoint returns raw JSON (not wrapped in ApiResponse) and bp handles the non-standard envelope
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp docs --format json
      """
    Then bp exits with exit code 0
    And stdout is valid JSON but does NOT have a top-level "success" key (raw OpenAPI schema)
    And bp does not attempt to parse it as ApiResponse

  @error @community
  Scenario: /extensions endpoint always returns total=1 and bp surfaces this caveat
    Given Burp Suite is running on port 8089
    When I run:
      """
      bp config extensions --format json
      """
    Then bp exits with exit code 0
    And stdout matches JSON with "data.total" equal to 1
    And a note in the output or metadata indicates "total is always 1 (Montoya API limitation)"

  @error @community @fuzz
  Scenario Outline: Various invalid attackType values are accepted by the server but documented as executing sniper
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run:
      """
      bp intruder attack create --id 1 \
        --type <attack_type> \
        --pos 'body:username' \
        --payloads "set1=admin" \
        --format json
      """
    Then bp exits with exit code 0
    And the response contains "attackId" (the attack was created)
    And stderr or the JSON metadata notes: "only sniper is implemented server-side; <attack_type> will execute as sniper"

    Examples:
      | attack_type   |
      | battering-ram |
      | pitchfork     |
      | cluster-bomb  |

  @error @community
  Scenario: history search with a SQL wildcard in the --search parameter is passed through unescaped (known behaviour)
    Given Burp Suite is running on port 8089
    And the history DB is initialised
    When I run:
      """
      bp history list --search "%" --format json
      """
    Then bp exits with exit code 0
    And all history entries are returned (% matches everything in SQL LIKE)
    And stderr contains a note: "WARNING: search uses SQL LIKE — % and _ are wildcards"

  @error @community
  Scenario: history id typed as non-Long string returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    And the history DB is initialised
    When I run:
      """
      bp history get --id "notanumber" --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: history id typed as floating-point returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    And the history DB is initialised
    When I run:
      """
      bp history get --id 1.5 --format json
      """
    Then bp exits with a non-zero exit code
    And stdout matches JSON with "error.code" equal to "INVALID_REQUEST"
