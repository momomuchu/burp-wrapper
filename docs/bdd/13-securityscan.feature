# Feature: Security Scan — Custom /scan probes (§6.7)
#
# Ground truth: SPEC.md §6.7 · 5 endpoints · Community (C) · all synchronous/blocking.
# Real Kotlin types: AuthBypassRequest · IdorRequest · HeadersBypassRequest ·
#   CorsRequest · EndpointsScanRequest.
# /scan/endpoints requires SQLite DB (~/.burp-rest/burpdata); all others: session-optional.
# SPA HTML catch-all filter: body starts "<!…" AND length >50000 → synthetic status 302 / length 0.
# Error envelope: ApiResponse<T> { success, data, error:{code,message} }
# Error codes: INVALID_REQUEST 400 · SERVICE_UNAVAILABLE 503 · INTERNAL_ERROR 500.
# Probes no-auth are NOT recorded in proxy history.
# The /scan group is entirely absent from /docs (OpenAPI).
#
# Output contract (canonical CLI flags):
#   --format json|table|raw|quiet   (default: table if TTY, json otherwise)
#   --fields f1,f2,...              (column filter)
#   -w / --write-out 'TPL'          tokens: %{status} %{payload} %{length} %{time}
#                                           %{anomalous} %{contentType} %{index}
#                                           %{requestId} %{host} %{method} %{location}
#   --quiet                         suppress output, exit-code only
#   --tag NAME                      annotate ledger entry
#   --no-ledger                     skip C4 run-ledger recording
#
# Tags legend:
#   @happy      — nominal success path
#   @error      — error / rejection path
#   @community  — runs without Burp Pro licence
#   @pro        — requires Burp Pro (none in this group; kept for cross-ref)
#   @fuzz       — fuzzing / enumeration oriented scenario
#   @ledger     — exercises C4 run-ledger behaviour

Feature: Security Scan — 5 custom /scan probes (§6.7)

  As a bug-bounty hunter using `bp`
  I want to run the 5 custom security-scan probes via POST /scan/*
  So that I can detect auth-bypass, IDOR, header-bypass, CORS misconfigs,
  and mass endpoint vulnerabilities through Burp's HTTP engine with full ledger traceability.

  Background:
    Given the Burp extension is running and reachable at http://127.0.0.1:8089
    And the extension reports {"success":true,"data":{"status":"ok","version":"0.1.0"}} on GET /health

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/auth-bypass
  # Request type: AuthBypassRequest { endpoints:List<String> (required),
  #               baseUrl:String (required), method:String="GET" }
  # Behaviour: triple-probe per endpoint — withAuth / withoutAuth / cookieOnly
  # A session must be active for the "withAuth" and "cookieOnly" probes to carry
  # credentials; "withoutAuth" probe always runs bare.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Auth-bypass scan returns triple-probe results for a single endpoint
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --method GET
      """
    Then the exit code is 0
    And the output table contains columns "endpoint", "probe", "status", "length", "vulnerable"
    And the output contains a row with probe "withAuth"
    And the output contains a row with probe "withoutAuth"
    And the output contains a row with probe "cookieOnly"

  @happy @community
  Scenario: Auth-bypass scan in agent-mode returns compact NDJSON per probe result
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --format json
      """
    Then the exit code is 0
    And each output line is valid JSON
    And each JSON line contains fields "endpoint", "probe", "statusCode", "length", "vulnerable"
    And the JSON lines include one object where "probe" equals "withAuth"
    And the JSON lines include one object where "probe" equals "withoutAuth"
    And the JSON lines include one object where "probe" equals "cookieOnly"

  @happy @community
  Scenario: Auth-bypass scan across multiple endpoints emits three probes per endpoint
    Given an active session has been set with cookie "session=abc123; role=user"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users,/api/admin/config,/api/admin/logs \
        --method GET
      """
    Then the exit code is 0
    And the output contains exactly 9 probe rows (3 endpoints × 3 probes)

  @happy @community
  Scenario: Auth-bypass detects unauthenticated access when withoutAuth probe returns 200
    Given an active session has been set with cookie "session=abc123"
    And the target endpoint /api/admin/users responds 200 to all three probes
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON line where "probe" is "withoutAuth" has "vulnerable" equal to true

  @happy @community
  Scenario: Auth-bypass with --write-out formats per-probe summary lines
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/orders \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And the output contains exactly 3 lines matching the pattern "<status_code> <probe_name>"

  @happy @community
  Scenario: Auth-bypass with --fields narrows table to requested columns only
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --fields endpoint,probe,vulnerable
      """
    Then the exit code is 0
    And the output table contains only columns "endpoint", "probe", "vulnerable"
    And the output table does not contain column "length"

  @happy @community @ledger
  Scenario: Auth-bypass run is recorded in the C4 ledger with tag
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --tag recon-day1
      """
    Then the exit code is 0
    And running "bp log --last 1" shows a ledger entry with tag "recon-day1"
    And the ledger entry records burp_op "POST /scan/auth-bypass"

  @happy @community @ledger
  Scenario: Auth-bypass with --no-ledger does not create a ledger entry
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --no-ledger
      """
    Then the exit code is 0
    And running "bp log --last 1" does not show a new ledger entry for this operation

  @happy @community
  Scenario: Auth-bypass with --quiet suppresses all output and exits 0 on success
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Auth-bypass uses POST method when --method POST is supplied
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/create \
        --method POST
      """
    Then the exit code is 0
    And the POST /scan/auth-bypass request body sent to :8089 contains "\"method\":\"POST\""

  @error @community
  Scenario: Auth-bypass with empty endpoints list returns INVALID_REQUEST 400
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "endpoints"

  @error @community
  Scenario: Auth-bypass with missing --base-url returns INVALID_REQUEST 400
    When I run:
      """
      bp scan auth-bypass \
        --endpoints /api/admin/users
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "baseUrl"

  @error @community
  Scenario: Auth-bypass with malformed JSON body (simulated) returns INVALID_REQUEST 400
    # bp sends a well-formed body; this scenario verifies CLI surfaces the server error
    Given the REST API at :8089/scan/auth-bypass will respond with:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"JSON parse error"}}
      """
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Auth-bypass returns INTERNAL_ERROR 500 when Burp HTTP engine fails
    Given the REST API at :8089/scan/auth-bypass will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"HTTP engine unavailable"}}
      """
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  @fuzz @community
  Scenario Outline: Auth-bypass fuzz over a set of sensitive endpoint paths
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints <endpoint> \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output includes probe rows for "withAuth", "withoutAuth", "cookieOnly"

    Examples:
      | endpoint              |
      | /api/admin/users      |
      | /api/admin/config     |
      | /api/admin/export     |
      | /api/v2/internal/keys |
      | /management/actuator  |
      | /debug/pprof          |
      | /metrics              |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/idor
  # Request type: IdorRequest { endpoint:String (required), param:String (required),
  #   ownValues:List<String> (required), targetValues:List<String> (required),
  #   method:String="GET", body:String?, extraHeaders:Map<String,String>? }
  # Detection: cross-account access flagged when response is 2xx AND
  #   |Δlength| > 5% of own-value response length (>5% delta).
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: IDOR scan detects cross-account access with >5% body-length delta
    Given an active session has been set with cookie "session=victim-abc"
    And the target endpoint https://target.example.com/orders/124 returns HTTP 200
    And the body length for own value "123" is 1000 bytes
    And the body length for target value "124" is 1100 bytes (delta 10%)
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 124,125 \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output for target value "124" has "vulnerable" equal to true
    And the JSON output for target value "124" has "deltaPercent" greater than 5.0

  @happy @community
  Scenario: IDOR scan returns table output by default with required columns
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 124,125
      """
    Then the exit code is 0
    And the output table contains columns "param", "ownValue", "targetValue", "statusCode", "deltaPercent", "vulnerable"

  @happy @community
  Scenario: IDOR scan with delta below 5% does not flag as vulnerable
    Given an active session has been set with cookie "session=victim-abc"
    And the body length for own value "123" is 1000 bytes
    And the body length for target value "999" is 1030 bytes (delta 3%)
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 999 \
        --format json
      """
    Then the exit code is 0
    And the JSON output for target value "999" has "vulnerable" equal to false

  @happy @community
  Scenario: IDOR scan does not flag when target returns non-2xx status (403 = access denied)
    Given an active session has been set with cookie "session=victim-abc"
    And the target endpoint for value "999" returns HTTP 403
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 999 \
        --format json
      """
    Then the exit code is 0
    And the JSON output for target value "999" has "vulnerable" equal to false
    And the JSON output for target value "999" has "statusCode" equal to 403

  @happy @community
  Scenario: IDOR scan with extra headers passes them in the probe request
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/api/invoices/{id} \
        --param id \
        --own-values 100 \
        --target-values 101 \
        --extra-header "X-Tenant-ID: tenant-A" \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/idor request body sent to :8089 contains "\"X-Tenant-ID\":\"tenant-A\""

  @happy @community
  Scenario: IDOR scan with body payload for POST endpoints
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/api/transfer \
        --param account_id \
        --own-values acc-owner \
        --target-values acc-victim \
        --method POST \
        --body '{"amount":1,"currency":"USD"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/idor request body sent to :8089 contains "\"method\":\"POST\""
    And the POST /scan/idor request body sent to :8089 contains "\"body\":\"{\\\"amount\\\":1"

  @happy @community
  Scenario: IDOR scan with -w write-out template prints per-target summary
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 124,125 \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And the output contains 2 lines each matching "<status_code> <target_value>"

  @happy @community @ledger
  Scenario: IDOR scan entry is tagged and retrievable from the C4 ledger
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 124 \
        --tag idor-orders-phase2
      """
    Then the exit code is 0
    And running "bp log --tag idor-orders-phase2" returns at least one entry
    And the ledger entry records burp_op "POST /scan/idor"
    And the ledger entry records target "target.example.com"

  @error @community
  Scenario: IDOR scan with missing required param field returns INVALID_REQUEST
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --own-values 123 \
        --target-values 124
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "param"

  @error @community
  Scenario: IDOR scan with empty ownValues list returns INVALID_REQUEST
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values "" \
        --target-values 124
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: IDOR scan with empty targetValues list returns INVALID_REQUEST
    When I run:
      """
      bp scan idor \
        --endpoint https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @fuzz @community
  Scenario Outline: IDOR fuzz across multiple parameter names and endpoint patterns
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp scan idor \
        --endpoint <endpoint> \
        --param <param> \
        --own-values <own> \
        --target-values <targets> \
        --method <method> \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains "vulnerable" field for each target value

    Examples:
      | endpoint                                       | param      | own     | targets      | method |
      | https://t.example.com/api/users/{id}/profile   | id         | 1001    | 1002,1003    | GET    |
      | https://t.example.com/api/orders/{order_id}    | order_id   | ORD-001 | ORD-002      | GET    |
      | https://t.example.com/api/messages/{msg_id}    | msg_id     | 5000    | 5001,5002    | GET    |
      | https://t.example.com/api/invoices/{invoice}   | invoice    | INV-100 | INV-101      | GET    |
      | https://t.example.com/api/documents/{doc_id}   | doc_id     | doc-A   | doc-B,doc-C  | GET    |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/headers
  # Request type: HeadersBypassRequest { url:String (required), method:String="GET",
  #   body:String? }
  # Behaviour: sends 16 fixed IP-spoof / URL-override headers to attempt 403 bypass.
  # The 16 headers are hardcoded in the extension (not configurable by the caller).
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Headers-bypass scan returns exactly 16 probe results for a 403 endpoint
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 16 objects
    And each JSON object contains fields "header", "headerValue", "statusCode", "length", "bypassed"

  @happy @community
  Scenario: Headers-bypass scan table output lists header name, value, status, and bypass verdict
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin
      """
    Then the exit code is 0
    And the output table contains columns "header", "headerValue", "statusCode", "bypassed"
    And the output table contains exactly 16 rows (one per injected header)

  @happy @community
  Scenario: Headers-bypass scan marks bypassed=true when header probe returns 200 instead of 403
    Given the endpoint https://target.example.com/admin returns 403 by default
    And the endpoint returns 200 when header "X-Forwarded-For: 127.0.0.1" is present
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        --format json
      """
    Then the exit code is 0
    And at least one JSON object has "bypassed" equal to true
    And that JSON object has "statusCode" equal to 200

  @happy @community
  Scenario: Headers-bypass scan with --fields shows only header and bypassed columns
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        --fields header,bypassed
      """
    Then the exit code is 0
    And the output table contains only columns "header", "bypassed"

  @happy @community
  Scenario: Headers-bypass scan with -w write-out prints per-header one-liner
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And the output contains exactly 16 lines each matching "<status_code> <header_value>"

  @happy @community
  Scenario: Headers-bypass scan with POST method and body is forwarded correctly
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin/action \
        --method POST \
        --body '{"action":"reset"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/headers request body sent to :8089 contains "\"method\":\"POST\""
    And the POST /scan/headers request body sent to :8089 contains "\"body\":\"{\\\"action\\\":\\\"reset\\\"}\""

  @happy @community @ledger
  Scenario: Headers-bypass ledger entry records the target URL and operation
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        --tag header-bypass-admin
      """
    Then the exit code is 0
    And running "bp log --tag header-bypass-admin" returns 1 entry
    And the ledger entry records burp_op "POST /scan/headers"
    And the ledger entry records target "https://target.example.com/admin"

  @happy @community
  Scenario: Headers-bypass with --quiet produces no output and exits 0
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @error @community
  Scenario: Headers-bypass with missing --url returns INVALID_REQUEST
    When I run:
      """
      bp scan headers
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "url"

  @error @community
  Scenario: Headers-bypass returns INTERNAL_ERROR 500 when Burp HTTP engine is unavailable
    Given the REST API at :8089/scan/headers will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"engine error"}}
      """
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  @fuzz @community
  Scenario Outline: Headers-bypass fuzz across common 403-protected paths
    When I run:
      """
      bp scan headers \
        --url https://target.example.com<path> \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 16 probe result objects

    Examples:
      | path                    |
      | /admin                  |
      | /admin/dashboard        |
      | /internal/status        |
      | /.well-known/security   |
      | /api/v1/internal        |
      | /actuator/env           |
      | /server-info            |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/cors
  # Request type: CorsRequest { url:String (required), method:String="GET" }
  # Behaviour: tests 8 fixed crafted origins for credentialed CORS exploitability.
  # Detection: CORS is exploitable when Access-Control-Allow-Origin reflects the
  #   tested origin AND Access-Control-Allow-Credentials: true is present.
  # The 8 origins are hardcoded in the extension.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: CORS scan returns exactly 8 origin probe results in JSON mode
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 8 objects
    And each JSON object contains fields "origin", "reflected", "credentialed", "exploitable"

  @happy @community
  Scenario: CORS scan table output shows all 8 origins with exploitability verdict
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data
      """
    Then the exit code is 0
    And the output table contains columns "origin", "reflected", "credentialed", "exploitable"
    And the output table contains exactly 8 rows

  @happy @community
  Scenario: CORS scan detects exploitable CORS when origin is reflected and credentials allowed
    Given the endpoint https://api.target.example.com/data responds with:
      """
      Access-Control-Allow-Origin: https://evil.example.com
      Access-Control-Allow-Credentials: true
      """
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And the JSON object where "origin" contains "evil.example.com" has "exploitable" equal to true
    And that JSON object has "reflected" equal to true
    And that JSON object has "credentialed" equal to true

  @happy @community
  Scenario: CORS scan marks exploitable=false when origin is not reflected
    Given the endpoint https://api.target.example.com/data responds with a static ACAO header
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And all JSON objects where "reflected" is false have "exploitable" equal to false

  @happy @community
  Scenario: CORS scan marks exploitable=false when credentials not allowed even if origin reflected
    Given the endpoint reflects the origin but does NOT send Access-Control-Allow-Credentials
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And the JSON object where "reflected" is true has "credentialed" equal to false
    And that JSON object has "exploitable" equal to false

  @happy @community
  Scenario: CORS scan with POST method sends correct method in request body
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/submit \
        --method POST \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/cors request body sent to :8089 contains "\"method\":\"POST\""

  @happy @community
  Scenario: CORS scan with -w write-out template prints per-origin one-liner
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And the output contains exactly 8 lines each matching "<status_code> <origin>"

  @happy @community
  Scenario: CORS scan with --fields limits output to origin and exploitable
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --fields origin,exploitable
      """
    Then the exit code is 0
    And the output table contains only columns "origin", "exploitable"

  @happy @community @ledger
  Scenario: CORS scan ledger entry captures command and target host
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --tag cors-api-data
      """
    Then the exit code is 0
    And running "bp log --tag cors-api-data" returns 1 entry
    And the ledger entry records burp_op "POST /scan/cors"
    And the ledger entry records target "api.target.example.com"

  @happy @community
  Scenario: CORS scan with --no-ledger skips recording but returns results
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data \
        --no-ledger \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 8 probe objects
    And no new ledger entry is created

  @error @community
  Scenario: CORS scan with missing --url returns INVALID_REQUEST
    When I run:
      """
      bp scan cors
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "url"

  @error @community
  Scenario: CORS scan returns INTERNAL_ERROR 500 on HTTP engine failure
    Given the REST API at :8089/scan/cors will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"probe failed"}}
      """
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com/data
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  @fuzz @community
  Scenario Outline: CORS fuzz across API endpoints that may have misconfigured CORS
    When I run:
      """
      bp scan cors \
        --url https://api.target.example.com<path> \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 8 origin probe objects

    Examples:
      | path                        |
      | /v1/user/profile            |
      | /v2/payments/history        |
      | /internal/token/refresh     |
      | /api/graphql                |
      | /api/data/export            |
      | /v1/admin/users             |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/endpoints
  # Request type: EndpointsScanRequest { host:String (required),
  #   tests:List<String>=["auth-bypass","method-switch"], limit:Int=100 }
  # Behaviour: mass scan of proxy history for the given host (requires SQLite DB).
  #   Precondition: DB must be initialised (~/.burp-rest/burpdata).
  #   Returns SERVICE_UNAVAILABLE 503 if DB absent.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Endpoints scan runs auth-bypass and method-switch tests over proxy history
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 10 requests for host "target.example.com"
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --tests auth-bypass,method-switch \
        --limit 100 \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains one result object per tested endpoint
    And each JSON object contains fields "endpoint", "test", "result", "statusCode", "vulnerable"

  @happy @community
  Scenario: Endpoints scan table output shows scanned endpoint, test type, and verdict
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 5 requests for host "target.example.com"
    When I run:
      """
      bp scan endpoints \
        --host target.example.com
      """
    Then the exit code is 0
    And the output table contains columns "endpoint", "test", "statusCode", "vulnerable"

  @happy @community
  Scenario: Endpoints scan respects --limit and does not exceed the specified cap
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 200 requests for host "target.example.com"
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --limit 10 \
        --format json
      """
    Then the exit code is 0
    And the number of distinct endpoints tested does not exceed 10

  @happy @community
  Scenario: Endpoints scan with default limit of 100 is used when --limit is omitted
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"limit\":100"

  @happy @community
  Scenario: Endpoints scan with default tests list is used when --tests is omitted
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"tests\":[\"auth-bypass\",\"method-switch\"]"

  @happy @community
  Scenario: Endpoints scan with only auth-bypass test requested
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --tests auth-bypass \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"tests\":[\"auth-bypass\"]"
    And no JSON result object has "test" equal to "method-switch"

  @happy @community
  Scenario: Endpoints scan with -w write-out template prints per-result line
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        -w '%{status} %{host}'
      """
    Then the exit code is 0
    And each output line matches "<status_code> target.example.com"

  @happy @community @ledger
  Scenario: Endpoints scan ledger entry records host and test list
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --tests auth-bypass,method-switch \
        --tag mass-scan-target
      """
    Then the exit code is 0
    And running "bp log --tag mass-scan-target" returns 1 entry
    And the ledger entry records burp_op "POST /scan/endpoints"
    And the ledger entry records target "target.example.com"

  @happy @community
  Scenario: Endpoints scan with --quiet produces no stdout and exits 0
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @error @community
  Scenario: Endpoints scan returns SERVICE_UNAVAILABLE 503 when DB is not initialised
    Given the SQLite DB at ~/.burp-rest/burpdata is absent or failed to initialise
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE"
    And stderr contains a message indicating the database is required

  @error @community
  Scenario: Endpoints scan with missing --host returns INVALID_REQUEST
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "host"

  @error @community
  Scenario: Endpoints scan with empty host string returns INVALID_REQUEST
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Endpoints scan with limit zero is passed as-is; extension uses it literally
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --limit 0 \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"limit\":0"
    And the JSON output is an empty array or contains 0 results

  @error @community
  Scenario: Endpoints scan returns INTERNAL_ERROR 500 on unexpected server failure
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the REST API at :8089/scan/endpoints will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected failure"}}
      """
    When I run:
      """
      bp scan endpoints \
        --host target.example.com
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  @fuzz @community
  Scenario Outline: Endpoints scan fuzz across multiple hosts present in proxy history
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains requests for host "<host>"
    When I run:
      """
      bp scan endpoints \
        --host <host> \
        --tests <tests> \
        --limit <limit> \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains endpoint result objects for host "<host>"

    Examples:
      | host                      | tests                        | limit |
      | api.target.example.com    | auth-bypass                  | 50    |
      | admin.target.example.com  | method-switch                | 25    |
      | staging.target.example.com| auth-bypass,method-switch    | 100   |
      | internal.target.example.com| auth-bypass                 | 10    |
      | dev.target.example.com    | method-switch                | 5     |

  # ─────────────────────────────────────────────────────────────────────────────
  # SPA HTML catch-all filter — cross-cutting behaviour (§6.7 flag)
  # When a probe response body starts with "<!" AND length > 50000 bytes,
  # the extension synthesises: statusCode=302, length=0 (filters out SPA shells).
  # This applies to all 5 /scan/* endpoints.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Auth-bypass probe hitting SPA HTML catch-all returns synthetic 302 / length 0
    Given the endpoint https://target.example.com/api/admin responds with:
      | body_starts_with | <!DOCTYPE html>  |
      | body_length      | 51000            |
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin \
        --format json
      """
    Then the exit code is 0
    And the JSON probe results for "/api/admin" have "statusCode" equal to 302
    And the JSON probe results for "/api/admin" have "length" equal to 0

  @happy @community
  Scenario: Headers-bypass probe hitting SPA HTML catch-all returns synthetic 302 / length 0
    Given the endpoint https://target.example.com/admin responds with HTML body >50000 bytes starting "<!DOCTYPE"
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin \
        --format json
      """
    Then the exit code is 0
    And all 16 JSON probe objects have "statusCode" equal to 302
    And all 16 JSON probe objects have "length" equal to 0

  @happy @community
  Scenario: SPA filter does not trigger when HTML body is under 50000 bytes
    Given the endpoint https://target.example.com/api/data responds with:
      | body_starts_with | <!DOCTYPE html> |
      | body_length      | 49000           |
    When I run:
      """
      bp scan cors \
        --url https://target.example.com/api/data \
        --format json
      """
    Then the exit code is 0
    And the JSON output does not universally show statusCode 302

  # ─────────────────────────────────────────────────────────────────────────────
  # Proxy history recording — cross-cutting behaviour (§6.7 flag)
  # No-auth probes (withoutAuth / cookieOnly in auth-bypass; bare IDOR probes;
  # all headers/cors probes) are NOT recorded in the Burp proxy history.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Auth-bypass no-auth probes do not appear in GET /proxy/history
    Given an active session has been set with cookie "session=abc123"
    And the proxy history has N entries before the scan
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin/users
      """
    Then the exit code is 0
    And GET /proxy/history at :8089 returns N entries (unchanged — probes not recorded)

  @happy @community
  Scenario: Headers-bypass probes do not appear in GET /proxy/history
    Given the proxy history has M entries before the scan
    When I run:
      """
      bp scan headers \
        --url https://target.example.com/admin
      """
    Then the exit code is 0
    And GET /proxy/history at :8089 returns M entries (unchanged)

  # ─────────────────────────────────────────────────────────────────────────────
  # /docs absence — cross-cutting flag (§6.7 flag)
  # The entire /scan group is absent from the embedded OpenAPI at GET /docs.
  # bp must NOT rely on /docs for /scan endpoint discovery.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: GET /docs does not list any /scan endpoint
    When I run:
      """
      bp docs --format json
      """
    Then the exit code is 0
    And the JSON output does not contain any path starting with "/scan"

  # ─────────────────────────────────────────────────────────────────────────────
  # Combined / end-to-end scenarios
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Full recon pipeline — auth-bypass then IDOR then CORS on same target
    Given an active session has been set with cookie "session=abc123"
    And the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run auth-bypass scan:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/orders \
        --tag pipeline-step1 \
        --format json
      """
    And I run IDOR scan:
      """
      bp scan idor \
        --endpoint https://target.example.com/api/orders/{id} \
        --param id \
        --own-values 100 \
        --target-values 101,102 \
        --tag pipeline-step2 \
        --format json
      """
    And I run CORS scan:
      """
      bp scan cors \
        --url https://target.example.com/api/orders \
        --tag pipeline-step3 \
        --format json
      """
    Then all three commands exit with code 0
    And running "bp log --last 3" shows 3 ledger entries tagged pipeline-step1, pipeline-step2, pipeline-step3
    And all ledger entries record target "target.example.com"

  @happy @community
  Scenario: Auth-bypass and headers-bypass run sequentially on same endpoint without session clash
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin \
        --format json
      """
    And I run:
      """
      bp scan headers \
        --url https://target.example.com/api/admin \
        --format json
      """
    Then both commands exit with code 0
    And the auth-bypass JSON output contains 3 probe objects
    And the headers JSON output contains 16 probe objects

  @happy @community
  Scenario: Endpoints mass scan combined with CORS check for discovered endpoints
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 5 requests for host "target.example.com"
    When I run:
      """
      bp scan endpoints \
        --host target.example.com \
        --tests auth-bypass \
        --limit 5 \
        --format json
      """
    Then the exit code is 0
    And for each vulnerable endpoint in the output I can subsequently run:
      """
      bp scan cors \
        --url https://target.example.com<endpoint_path> \
        --format json
      """
    And each such cors scan exits with code 0

  @happy @community
  Scenario: All five /scan probes work without Burp Pro licence (Community edition)
    Given Burp Suite Community edition is running at :8089
    When I run each of the following commands:
      | bp scan auth-bypass --base-url https://t.example.com --endpoints /api/test --format json   |
      | bp scan idor --endpoint https://t.example.com/r/{id} --param id --own-values 1 --target-values 2 --format json |
      | bp scan headers --url https://t.example.com/admin --format json                             |
      | bp scan cors --url https://t.example.com/api/data --format json                             |
    Then all four commands exit with code 0
    And none of the outputs contains "SERVICE_UNAVAILABLE" or "requires Burp Suite Professional"

  @error @community
  Scenario: All /scan endpoints return INVALID_REQUEST when JSON body is structurally malformed
    # Verifies the extension returns INVALID_REQUEST (400) for malformed JSON input,
    # consistent with §8 StatusPages mapping of SerializationException → 400.
    Given the REST API at :8089/scan/auth-bypass will respond with HTTP 400 and body:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"Unexpected JSON token"}}
      """
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://target.example.com \
        --endpoints /api/admin
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "400"
