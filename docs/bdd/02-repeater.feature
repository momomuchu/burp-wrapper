# Feature: Repeater — 3 /repeater endpoints (§6.3)
#
# Ground truth: SPEC.md §6.3 · 3 endpoints · Community (C) · fuzz-critique.
# Real Kotlin types:
#   SendRequest        { request:HttpRequestData?=null, requestId:Int?=null,
#                        modifications:RequestModifications?=null }
#                        — EXACTLY ONE of request / requestId must be set.
#   BatchSendRequest   { requests:List<SendRequest> }
#   CreateTabRequest   { name:String?=null, request:HttpRequestData?=null,
#                        requestId:Int?=null }
#   HttpRequestData    { method:String, url:String,
#                        headers:List<{name,value}>?, body:String? }
#   RequestModifications { headers:Map<String,String>?,  // full replace
#                          body:String?,                 // replaces entire body
#                          method:String?,               // replaces verb
#                          path:String? }               // replaces path (not URL)
#
# Behaviour:
#   /send          — drives http().sendRequest() (not UI); records row (source='repeater')
#                    + upserts sitemap when DB available (silent skip if DB absent).
#                    Returns req + resp + timing.
#   /send/batch    — strictly sequential; failure on item N → total abort, zero partials.
#   /tab/create    — opens Repeater UI tab; NO traffic; NO DB; if both request and
#                    requestId are null → silent fallback to https://example.com.
#
# Error codes (§8 StatusPages):
#   INVALID_REQUEST    400  (neither/both request+requestId; out-of-bounds; malformed JSON)
#   SERVICE_UNAVAILABLE 503
#   INTERNAL_ERROR     500
#
# DB: optional — recording silently skipped on init failure (not an error to the caller).
#
# Output contract (canonical CLI flags):
#   --format json|table|raw|quiet  (default: table if TTY, json otherwise)
#   --fields f1,f2,...             (column filter)
#   -w / --write-out 'TPL'         tokens: %{status} %{length} %{time} %{payload}
#                                          %{location} %{anomalous} %{contentType}
#                                          %{index} %{requestId} %{host} %{method}
#   --quiet                        suppress stdout, exit-code only
#   --tag NAME                     annotate C4 ledger entry
#   --no-ledger                    skip C4 run-ledger recording
#
# Tags:
#   @happy      nominal success path
#   @error      error / rejection path
#   @community  runs without Burp Pro licence (all repeater endpoints are C)
#   @fuzz       fuzzing / craft oriented scenario
#   @ledger     exercises C4 run-ledger behaviour

Feature: Repeater — send, batch-send, and tab-create via /repeater (§6.3)

  As a bug-bounty hunter using `bp`
  I want to send crafted or replayed HTTP requests through Burp's HTTP engine,
  batch them for multi-step workflows, and push them to the Repeater UI tab,
  so that I can inspect responses, iterate on modifications, and maintain a
  traceable ledger of every request sent.

  Background:
    Given the Burp extension is running and reachable at http://127.0.0.1:8089
    And GET /health returns {"success":true,"data":{"status":"ok","version":"0.1.0"}}

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — inline request (HttpRequestData path)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Send an inline GET request and receive response with status, length and timing
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --header "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9" \
        --format json
      """
    Then the exit code is 0
    And stdout is a single JSON line
    And the JSON contains field "statusCode" with an integer value
    And the JSON contains field "responseLength" with an integer value
    And the JSON contains field "durationMs" with an integer value
    And the JSON contains field "requestBody" (may be null)
    And the JSON contains field "responseBody" (may be null)

  @happy @community
  Scenario: Send an inline POST request with JSON body and Authorization header
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://target.example.com/api/login \
        --header "Content-Type: application/json" \
        --header "Authorization: Bearer token123" \
        --body '{"username":"admin","password":"s3cr3t"}' \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"
    And the JSON line contains "durationMs"

  @happy @community
  Scenario: Send with default table output shows status, length, time columns
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users
      """
    Then the exit code is 0
    And the output table contains columns "status", "length", "time"

  @happy @community
  Scenario: Send with -w write-out template prints status and response length on one line
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/profile \
        -w '%{status} %{length}'
      """
    Then the exit code is 0
    And stdout matches the pattern "<integer> <integer>"

  @happy @community
  Scenario: Send with -w '%{status} %{time}' prints status code and duration in ms
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        -w '%{status} %{time}'
      """
    Then the exit code is 0
    And stdout matches the pattern "<integer> <integer>"

  @happy @community
  Scenario: Send with -w '%{method} %{host}' prints verb and host from the request
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://target.example.com/api/submit \
        -w '%{method} %{host}'
      """
    Then the exit code is 0
    And stdout is exactly "POST target.example.com"

  @happy @community
  Scenario: Send with --quiet produces no stdout and exits 0 on success
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Send with --fields limits table output to requested columns only
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --fields status,length
      """
    Then the exit code is 0
    And the output table contains only columns "status", "length"
    And the output table does not contain column "time"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — requestId path (replay from proxy history)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Replay proxy history entry by requestId and receive response
    Given the proxy history contains an entry at index 42
    When I run:
      """
      bp repeater send \
        --request-id 42 \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"
    And the JSON line contains "durationMs"

  @happy @community
  Scenario: Replay requestId 0 (first proxy history entry) succeeds
    Given the proxy history contains at least one entry
    When I run:
      """
      bp repeater send \
        --request-id 0 \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"

  @happy @community
  Scenario: Replay with -w '%{status} %{payload}' prints status and empty payload token
    Given the proxy history contains an entry at index 7
    When I run:
      """
      bp repeater send \
        --request-id 7 \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And stdout starts with an integer status code

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — RequestModifications applied on top of base request
  # RequestModifications: headers(Map replace), body(String), method, path
  # Only non-null fields are applied; all 4 are independent.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @fuzz
  Scenario: Send with body modification replaces the entire request body
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://target.example.com/api/data \
        --body '{"original":"value"}' \
        --modify-body '{"injected":"payload","role":"admin"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"modifications\":{\"body\":\"{\\\"injected\\\":\\\"payload\\\""

  @happy @community @fuzz
  Scenario: Send with method modification overrides the HTTP verb
    Given the proxy history contains a GET request at index 10
    When I run:
      """
      bp repeater send \
        --request-id 10 \
        --modify-method POST \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"modifications\":{\"method\":\"POST\"}"

  @happy @community @fuzz
  Scenario: Send with path modification replaces only the path segment (not full URL)
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users/1 \
        --modify-path '/api/users/2?debug=true' \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"path\":\"/api/users/2?debug=true\""
    And the POST /repeater/send body sent to :8089 does not contain "\"url\":\"/api/users/2\""

  @happy @community @fuzz
  Scenario: Send with header modification performs full replace of named header
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --header "X-Role: user" \
        --modify-header "X-Role: admin" \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"headers\":{\"X-Role\":\"admin\"}"

  @happy @community @fuzz
  Scenario: Send with all four modifications applied simultaneously (all non-null fields active)
    Given the proxy history contains an entry at index 3
    When I run:
      """
      bp repeater send \
        --request-id 3 \
        --modify-method PUT \
        --modify-path '/api/v2/resource' \
        --modify-header "Authorization: Bearer newtoken" \
        --modify-body '{"key":"value"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"method\":\"PUT\""
    And the POST /repeater/send body sent to :8089 contains "\"path\":\"/api/v2/resource\""
    And the POST /repeater/send body sent to :8089 contains "\"Authorization\":\"Bearer newtoken\""
    And the POST /repeater/send body sent to :8089 contains "\"body\":\"{\\\"key\\\":\\\"value\\\"}\""

  @happy @community @fuzz
  Scenario: Null modifications are not serialised — only non-null fields are applied
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/ping \
        --modify-body 'FUZZ' \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"body\":\"FUZZ\""
    And the POST /repeater/send body sent to :8089 does not contain "\"method\":"
    And the POST /repeater/send body sent to :8089 does not contain "\"path\":"
    And the POST /repeater/send body sent to :8089 does not contain "\"headers\":"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — DB recording behaviour
  # Row inserted with source='repeater' + sitemap upsert when DB available.
  # Silent skip (no error) when DB absent or init failed.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Send records history row with source repeater when DB is available
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --format json
      """
    Then the exit code is 0
    And GET /history on :8089 with filter source=repeater shows a new entry for "target.example.com"

  @happy @community
  Scenario: Send silently skips DB recording when DB is absent — no error returned
    Given the SQLite DB at ~/.burp-rest/burpdata is absent or failed to initialise
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"
    And stderr does not contain "SERVICE_UNAVAILABLE"
    And stderr does not contain "INTERNAL_ERROR"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — C4 ledger
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Send with --tag records a named C4 ledger entry
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --tag recon-users-endpoint
      """
    Then the exit code is 0
    And running "bp log --last 1" shows an entry with tag "recon-users-endpoint"
    And the ledger entry records burp_op "POST /repeater/send"
    And the ledger entry records target "target.example.com"

  @happy @community @ledger
  Scenario: Send with --no-ledger does not create a ledger entry
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --no-ledger
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  @happy @community @ledger
  Scenario: Replay by requestId with --tag records the requestId and target in ledger
    Given the proxy history contains an entry at index 42
    When I run:
      """
      bp repeater send \
        --request-id 42 \
        --tag replay-42
      """
    Then the exit code is 0
    And running "bp log --tag replay-42" returns 1 entry
    And the ledger entry records burp_op "POST /repeater/send"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — error paths
  # ═══════════════════════════════════════════════════════════════════════════

  @error @community
  Scenario: Send with neither --url/--method nor --request-id returns INVALID_REQUEST 400
    When I run:
      """
      bp repeater send
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "400"

  @error @community
  Scenario: Send with both --url and --request-id returns INVALID_REQUEST 400 (exactlyOne violated)
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --request-id 42
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Send with out-of-bounds requestId returns INVALID_REQUEST 400
    Given the proxy history contains 10 entries (indices 0–9)
    When I run:
      """
      bp repeater send \
        --request-id 9999 \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Send with non-integer requestId returns INVALID_REQUEST 400
    When I run:
      """
      bp repeater send \
        --request-id abc \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Send returns SERVICE_UNAVAILABLE 503 when Burp HTTP engine is unavailable
    Given the REST API at :8089/repeater/send will respond with HTTP 503 and body:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"HTTP engine not ready"}}
      """
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE"

  @error @community
  Scenario: Send returns INTERNAL_ERROR 500 on unexpected server-side Throwable
    Given the REST API at :8089/repeater/send will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected exception"}}
      """
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  @error @community
  Scenario: Send with malformed JSON body (structurally invalid) returns INVALID_REQUEST
    Given the REST API at :8089/repeater/send will respond with HTTP 400 and body:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"Unexpected JSON token"}}
      """
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — fuzz scenarios (body/path mutation)
  # Note: positional fuzz → Intruder; repeater fuzz = full payload in body/path
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @fuzz
  Scenario: Fuzz body with SQL injection payload via --modify-body
    Given the proxy history contains a POST request at index 5
    When I run:
      """
      bp repeater send \
        --request-id 5 \
        --modify-body "' OR '1'='1" \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"

  @happy @community @fuzz
  Scenario: Fuzz path with traversal payload via --modify-path
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/files/report.pdf \
        --modify-path '/api/files/../../../../etc/passwd' \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"
    And the JSON line contains "responseLength"

  @happy @community @fuzz
  Scenario: Fuzz with XSS payload in body and check response does not sanitise output
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://target.example.com/api/comment \
        --header "Content-Type: application/json" \
        --body '{"comment":"<script>alert(1)</script>"}' \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"

  @happy @community @fuzz
  Scenario: Fuzz Authorization header value to probe token reuse
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/admin \
        --header "Authorization: Bearer AAAA" \
        --modify-header "Authorization: Bearer BBBB" \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains "\"Authorization\":\"Bearer BBBB\""

  @fuzz @community
  Scenario Outline: Fuzz inline request with different HTTP methods and paths
    When I run:
      """
      bp repeater send \
        --method <method> \
        --url https://target.example.com<path> \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"
    And the JSON line contains "durationMs"

    Examples:
      | method  | path                        |
      | GET     | /api/users                  |
      | POST    | /api/users                  |
      | PUT     | /api/users/42               |
      | DELETE  | /api/users/42               |
      | PATCH   | /api/users/42/email         |
      | OPTIONS | /api/users                  |
      | HEAD    | /api/health                 |

  @fuzz @community
  Scenario Outline: Fuzz requestId replay across a range of history indices
    Given the proxy history contains at least <id_plus_one> entries
    When I run:
      """
      bp repeater send \
        --request-id <id> \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "statusCode"

    Examples:
      | id | id_plus_one |
      | 0  | 1           |
      | 1  | 2           |
      | 5  | 6           |
      | 10 | 11          |
      | 99 | 100         |

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send/batch — BatchSendRequest { requests:List<SendRequest> }
  # Strictly sequential. Failure on item N → total abort, zero partials returned.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Batch send two inline requests and receive results for both in order
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=GET,url=https://target.example.com/api/orders \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 2 JSON lines
    And the first JSON line corresponds to /api/users
    And the second JSON line corresponds to /api/orders

  @happy @community
  Scenario: Batch send three requests sequentially and all succeed
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/health \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=GET,url=https://target.example.com/api/orders \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 3 JSON lines
    And each JSON line contains "statusCode" and "durationMs"

  @happy @community
  Scenario: Batch send mixes inline requests and requestId replays
    Given the proxy history contains entries at indices 0 and 1
    When I run:
      """
      bp repeater send-batch \
        --request request-id=0 \
        --request method=POST,url=https://target.example.com/api/login,body='{"u":"a","p":"b"}' \
        --request request-id=1 \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 3 JSON lines

  @happy @community
  Scenario: Batch send with table output shows one row per request with status and length
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=GET,url=https://target.example.com/api/orders
      """
    Then the exit code is 0
    And the output table contains columns "index", "status", "length", "time"
    And the output table contains exactly 2 data rows

  @happy @community
  Scenario: Batch send with -w write-out prints one line per request result
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=GET,url=https://target.example.com/api/orders \
        -w '%{status} %{length}'
      """
    Then the exit code is 0
    And stdout contains exactly 2 lines each matching "<integer> <integer>"

  @happy @community
  Scenario: Batch send with --quiet produces no stdout on success
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Batch send with --fields narrows table output to requested columns
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=GET,url=https://target.example.com/api/orders \
        --fields index,status
      """
    Then the exit code is 0
    And the output table contains only columns "index", "status"
    And the output table does not contain column "length"

  @happy @community
  Scenario: Batch send with modifications on individual items applies them per request
    When I run:
      """
      bp repeater send-batch \
        --request method=POST,url=https://target.example.com/api/data,modify-body='{"a":1}' \
        --request method=POST,url=https://target.example.com/api/data,modify-body='{"b":2}' \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 2 JSON lines
    And the first batch item body sent to :8089 contains "\"body\":\"{\\\"a\\\":1}\""
    And the second batch item body sent to :8089 contains "\"body\":\"{\\\"b\\\":2}\""

  @happy @community @ledger
  Scenario: Batch send with --tag records a single C4 ledger entry for the entire batch
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=GET,url=https://target.example.com/api/orders \
        --tag batch-recon-phase1
      """
    Then the exit code is 0
    And running "bp log --tag batch-recon-phase1" returns 1 entry
    And the ledger entry records burp_op "POST /repeater/send/batch"

  @happy @community @ledger
  Scenario: Batch send with --no-ledger does not create any ledger entry
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --no-ledger \
        --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  # ─── batch abort-on-first-failure semantics ─────────────────────────────

  @error @community
  Scenario: Batch aborts on item 1 failure — item 2 is never sent (total abort, zero partials)
    Given the proxy history contains 0 entries (empty)
    When I run:
      """
      bp repeater send-batch \
        --request request-id=9999 \
        --request method=GET,url=https://target.example.com/api/orders \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stdout contains 0 JSON lines (no partial results)
    And the second request is never sent to :8089

  @error @community
  Scenario: Batch aborts on item 2 failure — item 1 result is NOT returned (zero partials)
    Given item 1 is a valid request that would succeed
    And item 2 uses an out-of-bounds requestId 9999
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request request-id=9999 \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stdout contains 0 JSON lines (no partial results for item 1)

  @error @community
  Scenario: Batch aborts on item 2 server error — zero partials returned
    Given item 1 is valid and item 2 triggers a 503 from the server
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/ok \
        --request method=GET,url=https://target.example.com/api/broken \
        --format json
      """
    Then the exit code is non-zero
    And stdout contains 0 JSON lines

  @error @community
  Scenario: Batch aborts on item 3 of 5 — items 4 and 5 are never sent
    Given items 1 and 2 are valid requests
    And item 3 has neither request nor requestId (violates exactlyOne)
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/one \
        --request method=GET,url=https://target.example.com/api/two \
        --request-invalid-item \
        --request method=GET,url=https://target.example.com/api/four \
        --request method=GET,url=https://target.example.com/api/five \
        --format json
      """
    Then the exit code is non-zero
    And items 4 and 5 are never sent to :8089

  @error @community
  Scenario: Batch send with empty requests list returns INVALID_REQUEST 400
    When I run:
      """
      bp repeater send-batch \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Batch send where one item has both request and requestId returns INVALID_REQUEST
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users,request-id=42 \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Batch send returns SERVICE_UNAVAILABLE 503 when HTTP engine is down
    Given the REST API at :8089/repeater/send/batch will respond with HTTP 503 and body:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"engine down"}}
      """
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE"

  @fuzz @community
  Scenario Outline: Batch fuzz with varying payload counts per batch
    When I run a batch of <count> inline GET requests to https://target.example.com/api/users with distinct body payloads
    Then the exit code is 0
    And stdout contains exactly <count> JSON lines
    And each JSON line contains "statusCode"

    Examples:
      | count |
      | 1     |
      | 2     |
      | 5     |
      | 10    |

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/tab/create — CreateTabRequest
  # Opens Repeater UI tab. NO traffic. NO DB writes.
  # Silent fallback to https://example.com when both request and requestId are null.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Tab create with inline request and name opens a named Repeater UI tab
    When I run:
      """
      bp repeater tab create \
        --name "Auth Probe" \
        --method GET \
        --url https://target.example.com/api/admin \
        --header "Authorization: Bearer token123" \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains field "tabId" or "name" confirming tab creation
    And no HTTP request is sent to target.example.com during this operation

  @happy @community
  Scenario: Tab create with requestId pushes history entry into Repeater UI tab
    Given the proxy history contains an entry at index 7
    When I run:
      """
      bp repeater tab create \
        --name "Replay #7" \
        --request-id 7 \
        --format json
      """
    Then the exit code is 0
    And the JSON line indicates the tab was created
    And no HTTP request is sent to target.example.com during this operation

  @happy @community
  Scenario: Tab create with no request and no requestId silently opens tab with https://example.com
    When I run:
      """
      bp repeater tab create \
        --name "Empty Tab" \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/tab/create body sent to :8089 contains neither "request" nor "requestId" fields
    And the response indicates success (silent fallback to https://example.com is server-side)

  @happy @community
  Scenario: Tab create with no name omits the name field (null default — encodeDefaults sends null)
    When I run:
      """
      bp repeater tab create \
        --method GET \
        --url https://target.example.com/api/users \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/tab/create body sent to :8089 contains "\"name\":null"

  @happy @community
  Scenario: Tab create does NOT record any row in DB (no DB interaction)
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the history entry count is N before this operation
    When I run:
      """
      bp repeater tab create \
        --name "TestTab" \
        --method GET \
        --url https://target.example.com/api/users
      """
    Then the exit code is 0
    And GET /history on :8089 still returns N entries (no new row inserted)

  @happy @community
  Scenario: Tab create succeeds even when DB is absent (no DB dependency)
    Given the SQLite DB at ~/.burp-rest/burpdata is absent or failed to initialise
    When I run:
      """
      bp repeater tab create \
        --name "NoDB Tab" \
        --method GET \
        --url https://target.example.com/api/users \
        --format json
      """
    Then the exit code is 0
    And the JSON line indicates success
    And stderr does not contain "SERVICE_UNAVAILABLE"

  @happy @community
  Scenario: Tab create with table output shows tab name and url columns
    When I run:
      """
      bp repeater tab create \
        --name "Scan Target" \
        --method GET \
        --url https://target.example.com/api/admin
      """
    Then the exit code is 0
    And the output table contains columns "name", "url"

  @happy @community
  Scenario: Tab create with --quiet produces no stdout on success
    When I run:
      """
      bp repeater tab create \
        --name "Silent Tab" \
        --method GET \
        --url https://target.example.com/api/users \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community @ledger
  Scenario: Tab create with --tag records a C4 ledger entry for the operation
    When I run:
      """
      bp repeater tab create \
        --name "Recon Tab" \
        --method GET \
        --url https://target.example.com/api/users \
        --tag tab-recon-phase1
      """
    Then the exit code is 0
    And running "bp log --tag tab-recon-phase1" returns 1 entry
    And the ledger entry records burp_op "POST /repeater/tab/create"

  @happy @community @ledger
  Scenario: Tab create with --no-ledger does not create a ledger entry
    When I run:
      """
      bp repeater tab create \
        --name "No Ledger Tab" \
        --method GET \
        --url https://target.example.com/api/users \
        --no-ledger
      """
    Then the exit code is 0
    And no new ledger entry is created

  @error @community
  Scenario: Tab create with both --url/--method and --request-id returns INVALID_REQUEST
    # exactlyOne constraint also applies to CreateTabRequest when both are provided
    # (the extension ignores unknown combos but bp CLI should guard against it)
    When I run:
      """
      bp repeater tab create \
        --method GET \
        --url https://target.example.com/api/users \
        --request-id 7
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Tab create returns INTERNAL_ERROR 500 on unexpected server-side Throwable
    Given the REST API at :8089/repeater/tab/create will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"Repeater UI unavailable"}}
      """
    When I run:
      """
      bp repeater tab create \
        --name "Fail Tab" \
        --method GET \
        --url https://target.example.com/api/users
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  @fuzz @community
  Scenario Outline: Tab create fuzz with different named tabs for various target endpoints
    When I run:
      """
      bp repeater tab create \
        --name "<tab_name>" \
        --method <method> \
        --url https://target.example.com<path> \
        --format json
      """
    Then the exit code is 0
    And the JSON line indicates tab was created

    Examples:
      | tab_name            | method | path                        |
      | Auth Bypass         | GET    | /api/admin/users            |
      | IDOR Check          | GET    | /api/orders/42              |
      | Header Injection    | POST   | /api/comment                |
      | CORS Probe          | OPTIONS| /api/data                   |
      | Path Traversal      | GET    | /api/files/../../etc/passwd |
      | SQLi Test           | POST   | /api/search                 |

  # ═══════════════════════════════════════════════════════════════════════════
  # Agent-mode scenarios (--format json for AX / pipeline integration)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Agent mode — send returns compact NDJSON suitable for jq piping
    When I run:
      """
      bp repeater send \
        --method GET \
        --url https://target.example.com/api/users \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (no pretty-print, no trailing newline issues)
    And the JSON is parseable by "jq .statusCode"

  @happy @community
  Scenario: Agent mode — batch returns one compact NDJSON line per request (stable schema)
    When I run:
      """
      bp repeater send-batch \
        --request method=GET,url=https://target.example.com/api/users \
        --request method=POST,url=https://target.example.com/api/login,body='{"u":"a","p":"b"}' \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 2 JSON lines
    And each line is parseable independently by "jq .statusCode"

  @happy @community
  Scenario: Agent mode — tab create returns compact JSON with tab identity fields
    When I run:
      """
      bp repeater tab create \
        --name "CI Probe" \
        --method GET \
        --url https://target.example.com/api/admin \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON does not contain newlines or indentation

  @happy @community
  Scenario: Agent mode — send error response is also valid NDJSON on stderr or exit-code signal
    Given the REST API at :8089/repeater/send will respond with HTTP 400 and body:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"neither request nor requestId"}}
      """
    When I run:
      """
      bp repeater send \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stdout is empty (error is not mixed into NDJSON stream)

  # ═══════════════════════════════════════════════════════════════════════════
  # Community-edition confirmation — all 3 repeater endpoints are C (no Pro gate)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: All three repeater endpoints work under Burp Suite Community edition
    Given Burp Suite Community edition is running at :8089
    When I run each of the following commands:
      | bp repeater send --method GET --url https://target.example.com/api/health --format json        |
      | bp repeater send-batch --request method=GET,url=https://target.example.com/api/health --format json |
      | bp repeater tab create --name "CE Tab" --method GET --url https://target.example.com/api/health --format json |
    Then all three commands exit with code 0
    And none of the outputs contains "SERVICE_UNAVAILABLE"
    And none of the outputs contains "requires Burp Suite Professional"

  # ═══════════════════════════════════════════════════════════════════════════
  # End-to-end / combined scenarios
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Full recon loop — send, inspect, push to tab, all tagged
    Given the proxy history contains an entry at index 3
    When I run the send step:
      """
      bp repeater send \
        --request-id 3 \
        --modify-header "X-Role: admin" \
        --tag loop-step1 \
        --format json
      """
    And I capture the statusCode from the JSON output
    And I run the tab-create step:
      """
      bp repeater tab create \
        --name "Admin Probe" \
        --request-id 3 \
        --tag loop-step2
      """
    Then both commands exit with code 0
    And running "bp log --last 2" shows entries tagged loop-step1 and loop-step2
    And the ledger entries record burp_ops "POST /repeater/send" and "POST /repeater/tab/create"

  @happy @community
  Scenario: Multi-step authentication workflow via batch — login then fetch protected resource
    When I run:
      """
      bp repeater send-batch \
        --request method=POST,url=https://target.example.com/api/login,body='{"username":"alice","password":"pass"}',header="Content-Type: application/json" \
        --request method=GET,url=https://target.example.com/api/dashboard,header="Cookie: session=from-login-step" \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 2 JSON lines
    And the first JSON line has a statusCode (login response)
    And the second JSON line has a statusCode (dashboard response)

  @happy @community @fuzz
  Scenario: Send with body modification then immediately push failing variant to Repeater tab
    When I run the fuzz step:
      """
      bp repeater send \
        --method POST \
        --url https://target.example.com/api/data \
        --body '{"role":"user"}' \
        --modify-body '{"role":"admin"}' \
        --format json
      """
    And the JSON output statusCode is 403
    And I run the tab-push step:
      """
      bp repeater tab create \
        --name "403 Privesc Candidate" \
        --method POST \
        --url https://target.example.com/api/data \
        --format json
      """
    Then both commands exit with code 0
    And the tab-push step produces no HTTP traffic to target.example.com
