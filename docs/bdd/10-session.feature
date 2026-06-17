Feature: Session management — set/get/clear auth state, authenticated send, batch send, and cookie-jar lifecycle
  # Domain: /session — 7 endpoints (Community, §6.11)
  # Session is a singleton shared across all /send calls.
  # Cookies + headers are a full replace on /session/set.
  # Cookie-jar (auto-captured Set-Cookie) is distinct from session cookies.
  # /session/send appears in Burp proxy history; batch is strictly sequential (abort-on-first-failure).
  # extraHeaders on /send override (not merge) session headers.
  # Cookie-jar is in-memory only; survives /session/clear but is wiped on extension reload.
  # Endpoints absent from /docs — bp must discover them independently.

  Background:
    Given Burp Suite is running and the extension is listening on http://127.0.0.1:8089
    And the bp CLI is installed and targets http://127.0.0.1:8089 by default

  # ─────────────────────────────────────────────────────────────────────────────
  # SESSION SET  (POST /session/set)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Set session with cookies and headers — human table output
    Given no session is currently active
    When I run:
      """
      bp session set \
        --cookie "session_token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
        --cookie "csrf_token=abc123" \
        --header "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig" \
        --header "X-Tenant-Id: acme-corp" \
        --name "acme-admin-auth" \
        --format table
      """
    Then the exit code is 0
    And the output contains a table with columns: key  value  type
    And the table contains a row with key "session_token" and type "cookie"
    And the table contains a row with key "Authorization" and type "header"
    And the session name "acme-admin-auth" is shown
    And the Run Ledger records an entry with burp_op "POST /session/set" and tag "acme-admin-auth"

  @happy @community
  Scenario: Set session — agent mode (--format json, stable schema)
    Given no session is currently active
    When I run:
      """
      bp session set \
        --cookie "PHPSESSID=r2t5uvjq495r4q7ib3vtdjq120" \
        --cookie "role=admin" \
        --header "X-Api-Key: sk-prod-aBcDeFgHiJkLmNoPqRsTuVwX" \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"cookies":{"PHPSESSID":"r2t5uvjq495r4q7ib3vtdjq120","role":"admin"},"headers":{"X-Api-Key":"sk-prod-aBcDeFgHiJkLmNoPqRsTuVwX"},"name":null},"error":null}
      """
    And no extra whitespace or line breaks appear before or after the JSON object

  @happy @community
  Scenario: Set session — quiet mode prints nothing on success
    When I run:
      """
      bp session set \
        --cookie "token=s3cr3t-jwt-val" \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Set session with cookies only (no headers — headers field defaults to null)
    When I run:
      """
      bp session set \
        --cookie "auth=v2:user42:hmac" \
        --format json
      """
    Then the exit code is 0
    And the JSON response has "success" equal to true
    And the JSON field "data.headers" is null
    And the JSON field "data.cookies" equals {"auth":"v2:user42:hmac"}

  @happy @community
  Scenario: Set session is a full replace — existing cookies are wiped
    Given a session is active with cookies {"old_token":"dead","legacy":"yes"} and headers {"X-Old":"removed"}
    When I run:
      """
      bp session set \
        --cookie "new_token=fresh" \
        --format json
      """
    Then the exit code is 0
    And the JSON field "data.cookies" equals {"new_token":"fresh"}
    And the JSON field "data.headers" is null
    # old_token and legacy no longer appear — full replace, not merge

  @happy @community
  Scenario: Set session with --write-out template for scripting
    When I run:
      """
      bp session set \
        --cookie "sid=abc" \
        -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      200
      """

  @error @community
  Scenario: Set session with no cookies — INVALID_REQUEST 400
    When I run:
      """
      bp session set \
        --header "Authorization: Bearer tok" \
        --format json
      """
    Then the exit code is non-zero
    And stderr or the JSON error code is "INVALID_REQUEST"
    And the message references the missing required "cookies" field

  @error @community
  Scenario: Burp down — session set fails with connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp session set --cookie "token=x" --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "unable to reach Burp at http://127.0.0.1:8089"

  # ─────────────────────────────────────────────────────────────────────────────
  # SESSION GET  (GET /session/get)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Get active session — human table output
    Given a session is active with:
      | type   | key              | value                              |
      | cookie | session_token    | eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig |
      | header | Authorization    | Bearer eyJhbGciOiJSUzI1NiJ9.p.s   |
    When I run:
      """
      bp session get --format table
      """
    Then the exit code is 0
    And the output table shows "session_token" under cookies
    And the output table shows "Authorization" under headers

  @happy @community
  Scenario: Get active session — agent mode returns stable JSON envelope
    Given a session is active with cookies {"token":"abc"} and headers {"X-Role":"auditor"}
    When I run:
      """
      bp session get --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches the ApiResponse envelope: {"success":true,"data":{...},"error":null}
    And "data.cookies.token" equals "abc"
    And "data.headers.X-Role" equals "auditor"

  @happy @community
  Scenario: Get session — select specific output fields with --fields
    Given a session is active with cookies {"sid":"val"} and headers {"X-Custom":"hdr"}
    When I run:
      """
      bp session get --fields cookies --format json
      """
    Then the exit code is 0
    And the JSON "data" contains only the "cookies" field
    And the JSON "data" does NOT contain "headers" or "name"

  @happy @community
  Scenario: Get session when no session is set — returns empty/null data
    Given no session has been set since Burp started
    When I run:
      """
      bp session get --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.cookies" is null or {}
    And the JSON field "data.headers" is null or {}

  @happy @community
  Scenario: Get session — quiet mode prints session name only
    Given a session is active with name "prod-admin"
    When I run:
      """
      bp session get --quiet
      """
    Then stdout is exactly "prod-admin"

  # ─────────────────────────────────────────────────────────────────────────────
  # SESSION CLEAR  (DELETE /session/clear)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Clear session — cookies and headers removed, cookie-jar unaffected
    Given a session is active with cookies {"token":"abc"} and headers {"Authorization":"Bearer x"}
    And the cookie-jar contains {"api.example.com": {"__Secure-sid": "jar-value"}}
    When I run:
      """
      bp session clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And a subsequent "bp session get --format json" shows empty cookies and headers
    And a subsequent "bp session cookie-jar --format json" still shows {"api.example.com":{"__Secure-sid":"jar-value"}}
    And the Run Ledger records an entry with burp_op "DELETE /session/clear"

  @happy @community
  Scenario: Clear session — table output confirms reset
    Given a session is active with cookies {"tok":"old"}
    When I run:
      """
      bp session clear --format table
      """
    Then the exit code is 0
    And the output confirms "session cleared" or shows empty cookies/headers

  @happy @community
  Scenario: Clear session when already empty — idempotent, no error
    Given no session has been set
    When I run:
      """
      bp session clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

  @happy @community
  Scenario: Clear session — quiet mode produces no output
    Given a session is active with cookies {"x":"y"}
    When I run:
      """
      bp session clear --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @ledger
  Scenario: Clear session with --no-ledger skips Run Ledger recording
    Given a session is active with cookies {"tok":"v"}
    When I run:
      """
      bp session clear --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is created for this operation

  # ─────────────────────────────────────────────────────────────────────────────
  # SESSION SEND  (POST /session/send)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Authenticated GET request — session cookies injected automatically
    Given a session is active with cookies {"session_token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/users/profile" \
        --method GET \
        --format table
      """
    Then the exit code is 0
    And the output shows the HTTP response status (e.g. 200)
    And the request appears in the Burp proxy history with the session cookie injected
    And the Run Ledger records an entry with burp_op "POST /session/send" and target "api.example.com"

  @happy @community
  Scenario: Authenticated POST with body — agent mode output
    Given a session is active with cookies {"auth_token":"v2-tok"} and headers {"X-Csrf-Token":"csrf99"}
    When I run:
      """
      bp session send \
        --url "https://internal.corp.io/api/orders" \
        --method POST \
        --body '{"product_id":42,"qty":1}' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data.statusCode" is an integer (e.g. 201)
    And the JSON field "data.body" contains the response body (possibly truncated to 1 MB)

  @happy @community
  Scenario: Authenticated send with extraHeaders overriding session headers
    Given a session is active with headers {"X-Role":"user"}
    When I run:
      """
      bp session send \
        --url "https://app.target.io/admin" \
        --method GET \
        --extra-header "X-Role: admin" \
        --format json
      """
    Then the exit code is 0
    # extraHeaders override (not merge) session headers per §6.11
    And the outbound request carries "X-Role: admin" (not "X-Role: user")
    And the JSON field "data.statusCode" is present

  @happy @community
  Scenario: Send — write-out template for status and length
    Given a session is active with cookies {"tok":"abc"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/health" \
        --method GET \
        -w "%{status} %{length}"
      """
    Then the exit code is 0
    And stdout matches the pattern "<integer> <integer>" on a single line
    # e.g. "200 143"

  @happy @community
  Scenario: Send — quiet mode prints HTTP status code only
    Given a session is active with cookies {"tok":"abc"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v2/ping" \
        --method GET \
        --quiet
      """
    Then the exit code is 0
    And stdout is a single integer representing the HTTP status code

  @happy @community
  Scenario: Send — tag the operation in the Run Ledger
    Given a session is active with cookies {"tok":"secret"}
    When I run:
      """
      bp session send \
        --url "https://shop.example.com/api/cart" \
        --method GET \
        --tag "recon-cart-endpoint" \
        --format json
      """
    Then the exit code is 0
    And the Run Ledger entry has name/tag "recon-cart-endpoint"

  @error @community
  Scenario: Send — missing url field returns INVALID_REQUEST
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send --method GET --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INVALID_REQUEST"
    And the message references the missing required "url" field

  @error @community
  Scenario: Send — Burp down returns connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp session send --url "https://api.example.com/data" --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "unable to reach Burp at http://127.0.0.1:8089"

  @error @community
  Scenario: Send — target unreachable returns SERVICE_UNAVAILABLE or error in data
    Given a session is active with cookies {"tok":"y"}
    And "https://unreachable.internal.invalid/api" is not accessible
    When I run:
      """
      bp session send \
        --url "https://unreachable.internal.invalid/api" \
        --method GET \
        --format json
      """
    Then the exit code is non-zero OR the JSON field "success" is false
    And the error code is "SERVICE_UNAVAILABLE" or "INTERNAL_ERROR"

  @happy @community
  Scenario: Send with no active session — request is sent without auth cookies
    Given no session has been set (session is empty)
    When I run:
      """
      bp session send \
        --url "https://api.example.com/public/status" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the request appears in Burp history without any session cookie header injected
    And the JSON field "data.statusCode" is present

  # ─────────────────────────────────────────────────────────────────────────────
  # SESSION SEND BATCH  (POST /session/send/batch)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Batch authenticated send — multi-step workflow with session
    Given a session is active with cookies {"auth":"Bearer-v2-tok"} and headers {"X-Csrf":"csrf42"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://app.corp.io/api/profile"}' \
        --request '{"method":"POST","url":"https://app.corp.io/api/cart","body":"{\"item\":99}"}' \
        --request '{"method":"GET","url":"https://app.corp.io/api/orders"}' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data" is an array of 3 response objects
    And each element has a "statusCode" field
    And all 3 requests appear in the Burp proxy history (sequential, in order)
    And the Run Ledger records a single batch entry with burp_op "POST /session/send/batch"

  @happy @community
  Scenario: Batch send — agent mode with --format json for parsing in automation
    Given a session is active with cookies {"sid":"sess-prod-8823"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://api.example.com/v1/users/1"}' \
        --request '{"method":"GET","url":"https://api.example.com/v1/users/2"}' \
        --format json
      """
    Then the exit code is 0
    And stdout is exactly one compact JSON line (no pretty-print, no extra newlines)
    And the JSON schema is: {"success":true,"data":[<responseObj>,<responseObj>],"error":null}

  @happy @community
  Scenario: Batch send — write-out template per response item
    Given a session is active with cookies {"tok":"abc"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://api.example.com/a"}' \
        --request '{"method":"GET","url":"https://api.example.com/b"}' \
        -w "%{index} %{status}"
      """
    Then the exit code is 0
    And stdout contains 2 lines matching:
      """
      0 <integer>
      1 <integer>
      """

  @error @community
  Scenario: Batch send — first request fails, batch aborts (no partial success)
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://INVALID-HOST-404.invalid/"}' \
        --request '{"method":"GET","url":"https://api.example.com/safe"}' \
        --format json
      """
    Then the exit code is non-zero OR the JSON field "success" is false
    # Per §6.11: failure on item N → abort total, no partial
    And the second request is NOT executed (abort-on-first-failure semantics)
    And the error message identifies which request in the batch failed

  @error @community
  Scenario: Batch send — empty requests list returns INVALID_REQUEST
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send batch --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INVALID_REQUEST"

  @happy @community
  Scenario: Batch IDOR probe — two different resource IDs in sequence
    Given a session is active with cookies {"user_token":"victim-sess"} and headers {"X-User-Id":"victim-42"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://api.shop.io/orders/1001","extraHeaders":{"X-User-Id":"victim-42"}}' \
        --request '{"method":"GET","url":"https://api.shop.io/orders/1002","extraHeaders":{"X-User-Id":"victim-42"}}' \
        --format json
      """
    Then the exit code is 0
    And the output contains two response objects, each with "statusCode" and "body"

  # ─────────────────────────────────────────────────────────────────────────────
  # COOKIE-JAR GET  (GET /session/cookie-jar)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Get cookie-jar after authenticated sends have populated it
    Given a session is active with cookies {"auth":"token"}
    And I previously ran "bp session send --url https://api.example.com/login --method POST --body '{}'"
    And the server returned Set-Cookie headers for api.example.com
    When I run:
      """
      bp session cookie-jar --format table
      """
    Then the exit code is 0
    And the output shows a table grouped by domain
    And "api.example.com" appears as a domain row with its captured cookies

  @happy @community
  Scenario: Get cookie-jar — agent mode compact JSON
    Given the cookie-jar contains auto-captured cookies for "shop.internal.io" domain
    When I run:
      """
      bp session cookie-jar --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data" is a map keyed by domain, e.g.:
      """
      {"shop.internal.io":{"__Host-session":"abc123","csrfToken":"xyz"}}
      """

  @happy @community
  Scenario: Get cookie-jar when empty — returns empty map
    Given no authenticated requests have been sent (cookie-jar is empty)
    When I run:
      """
      bp session cookie-jar --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data" is {} (empty map)

  @happy @community
  Scenario: Cookie-jar survives session clear (in-memory, not DB)
    Given the cookie-jar contains {"api.example.com": {"tok": "captured"}}
    When I run "bp session clear --format json"
    Then the exit code is 0
    And a subsequent "bp session cookie-jar --format json" still shows {"api.example.com":{"tok":"captured"}}
    # Per §6.11: clear resets cookies/headers but NOT the cookie-jar

  @happy @community
  Scenario: Cookie-jar — select fields with --fields domain,cookies
    Given the cookie-jar contains cookies for multiple domains
    When I run:
      """
      bp session cookie-jar --fields domain,cookies --format json
      """
    Then the exit code is 0
    And each row in the JSON output contains only "domain" and "cookies" fields

  # ─────────────────────────────────────────────────────────────────────────────
  # COOKIE-JAR CLEAR  (DELETE /session/cookie-jar)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Clear cookie-jar — jar wiped, session unchanged
    Given the cookie-jar contains {"api.example.com":{"sess":"abc"}}
    And a session is active with cookies {"auth_token":"still-here"}
    When I run:
      """
      bp session cookie-jar clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And a subsequent "bp session cookie-jar --format json" shows data: {}
    And a subsequent "bp session get --format json" still shows {"auth_token":"still-here"} in cookies
    And the Run Ledger records an entry with burp_op "DELETE /session/cookie-jar"

  @happy @community
  Scenario: Clear cookie-jar when already empty — idempotent
    Given the cookie-jar is empty
    When I run:
      """
      bp session cookie-jar clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

  @happy @community
  Scenario: Clear cookie-jar — quiet mode produces no output
    Given the cookie-jar contains {"x.io":{"k":"v"}}
    When I run:
      """
      bp session cookie-jar clear --quiet
      """
    Then the exit code is 0
    And stdout is empty

  # ─────────────────────────────────────────────────────────────────────────────
  # AUTH STATE MAINTENANCE ACROSS FUZZING
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @fuzz
  Scenario: Auth state maintained across fuzz run — session injected into every intruder request
    Given a session is active with cookies {"auth_token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"} and headers {"X-Csrf-Token":"f3e4d5c6"}
    And proxy history entry 7 is a POST to "https://api.shop.io/api/search?q=shoes"
    When I run:
      """
      bp fuzz \
        --id 7 \
        --pos 'query:q' \
        --type sniper \
        --payloads "' OR '1'='1" --payloads "admin'--" --payloads "<script>alert(1)</script>" \
        --format json
      """
    Then the exit code is 0
    And each fuzz request in the Burp history carries the "auth_token" cookie and "X-Csrf-Token" header
    And the JSON output is an array of result objects each with fields: index, payload, status, length, time, contentType, anomalous, location, requestId

  @happy @community @fuzz
  Scenario: Auth state maintained across repeater batch fuzz via session send
    Given a session is active with cookies {"sess":"active-jwt"} and headers {"Authorization":"Bearer active-jwt"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"POST","url":"https://api.corp.io/transfer","body":"{\"amount\":1,\"to\":\"attacker\"}"}' \
        --request '{"method":"POST","url":"https://api.corp.io/transfer","body":"{\"amount\":100,\"to\":\"attacker\"}"}' \
        --request '{"method":"POST","url":"https://api.corp.io/transfer","body":"{\"amount\":9999,\"to\":\"attacker\"}"}' \
        --format json
      """
    Then the exit code is 0
    And the JSON data array has 3 entries
    And each request in Burp history shows the session "Authorization" header injected

  @happy @community @fuzz
  Scenario: Session refresh pattern — update session mid-workflow and continue fuzzing
    Given a session is active with cookies {"old_token":"expired-abc"}
    And I run "bp session send --url https://auth.example.com/refresh --method POST --body '{\"refresh\":\"rtoken99\"}' --format json"
    And the response includes Set-Cookie "new_token=fresh-xyz"
    When I run:
      """
      bp session set \
        --cookie "new_token=fresh-xyz" \
        --name "refreshed-session" \
        --format json
      """
    Then the exit code is 0
    And a subsequent fuzz run uses "new_token=fresh-xyz" (not the expired cookie)

  @happy @community @fuzz
  Scenario: extraHeaders on send/batch override session headers — useful for role-switching in fuzz
    Given a session is active with cookies {"auth":"user-tok"} and headers {"X-Role":"user"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://admin.internal.io/api/users","extraHeaders":{"X-Role":"admin"}}' \
        --request '{"method":"GET","url":"https://admin.internal.io/api/users","extraHeaders":{"X-Role":"superadmin"}}' \
        --format json
      """
    Then the exit code is 0
    And request 1 in Burp history carries "X-Role: admin" (overrides session "X-Role: user")
    And request 2 in Burp history carries "X-Role: superadmin"
    # Confirms override (not merge) semantics of extraHeaders per §6.11

  @happy @community @fuzz
  Scenario: Cookie-jar auto-capture during fuzz enables chained multi-step attacks
    Given no session is active
    When I run:
      """
      bp session send \
        --url "https://webapp.target.io/login" \
        --method POST \
        --body '{"username":"test@corp.io","password":"Passw0rd!"}' \
        --format json
      """
    Then the exit code is 0
    And the server returns Set-Cookie for "webapp.target.io"
    When I run "bp session cookie-jar --format json"
    Then the cookie-jar JSON shows cookies for "webapp.target.io" domain
    When I run:
      """
      bp session send \
        --url "https://webapp.target.io/api/admin/users" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the request to /api/admin/users includes the auto-captured cookie from the login response

  # ─────────────────────────────────────────────────────────────────────────────
  # RUN LEDGER INTEGRATION
  # ─────────────────────────────────────────────────────────────────────────────

  @ledger @community
  Scenario: Session send is recorded in Run Ledger with full metadata
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/resource" \
        --method GET \
        --tag "manual-recon-v1" \
        --format json
      """
    Then the Run Ledger entry has:
      | field       | value                                    |
      | burp_op     | POST /session/send                       |
      | target      | api.example.com                          |
      | tag         | manual-recon-v1                          |
      | status      | ok                                       |
      | command     | bp session send --url ... --tag ...      |

  @ledger @community
  Scenario: --no-ledger flag suppresses Run Ledger recording for session send
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/resource" \
        --method GET \
        --no-ledger \
        --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is created for this invocation

  # ─────────────────────────────────────────────────────────────────────────────
  # OUTPUT FORMAT MATRIX
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Session get — output format matrix
    Given a session is active with cookies {"tok":"val"} and headers {"X-H":"hval"} and name "test-session"
    When I run "bp session get --format <format>"
    Then the exit code is 0
    And the output matches <expected_pattern>

    Examples:
      | format | expected_pattern                                                                |
      | json   | single compact JSON line with {"success":true,"data":{...},"error":null}        |
      | table  | aligned human-readable table with columns for key, value, type                  |
      | quiet  | prints only the session name "test-session" on a single line                    |

  @happy @community
  Scenario Outline: Session send — output format matrix
    Given a session is active with cookies {"tok":"abc"}
    When I run "bp session send --url https://api.example.com/ping --method GET --format <format>"
    Then the exit code is 0
    And the output matches <expected_pattern>

    Examples:
      | format | expected_pattern                                                                |
      | json   | single compact JSON line with success, data.statusCode, data.body, error fields |
      | table  | human-readable table showing status code, body excerpt, response time           |
      | quiet  | prints only the integer HTTP status code on a single line                       |

  @happy @community
  Scenario Outline: Cookie-jar — output format matrix
    Given the cookie-jar has cookies for domain "api.example.com"
    When I run "bp session cookie-jar --format <format>"
    Then the exit code is 0
    And the output matches <expected_pattern>

    Examples:
      | format | expected_pattern                                                                |
      | json   | single compact JSON: {"success":true,"data":{"api.example.com":{...}},"error":null} |
      | table  | aligned table grouped by domain showing cookie name and value columns           |
      | quiet  | prints only the number of domains in the jar (e.g. "1")                        |

  # ─────────────────────────────────────────────────────────────────────────────
  # EDGE CASES AND SPEC CONTRACT VERIFICATIONS
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Session endpoint group is absent from /docs — bp does not rely on /docs for discovery
    When I run:
      """
      bp health --format json
      """
    Then the /docs endpoint returns OpenAPI spec version 0.2.0 that omits /session/* routes
    But "bp session get --format json" still succeeds (bp uses hardcoded spec, not runtime /docs)

  @happy @community
  Scenario: Session state persists to SQLite when DB is available
    Given the SQLite DB at ~/.burp-rest/burpdata is initialized
    When I run:
      """
      bp session set \
        --cookie "persist_tok=db-persisted" \
        --name "persisted-session" \
        --format json
      """
    Then the exit code is 0
    And the session is retrievable via "bp session get" after a Burp extension soft reload
    # SessionDao writes to burpdata DB per §6.11

  @happy @community
  Scenario: Cookie-jar is in-memory only — wiped on extension reload, not persisted to DB
    Given the cookie-jar contains {"api.example.com":{"sess":"abc"}}
    When the Burp extension is reloaded
    Then "bp session cookie-jar --format json" shows data: {}
    # Per §6.11: cookie-jar in-memory, no DB backing

  @happy @community
  Scenario: ApiResponse envelope — all session endpoints return encodeDefaults fields
    Given a session is active with cookies {"tok":"abc"}
    When I run "bp session get --format json"
    Then the JSON object always has "success", "data", and "error" fields present
    And "error" is null (not absent) on success
    And "data" is null (not absent) on error
    # Per §8: encodeDefaults=true — all declared fields always present even if null

  @happy @community
  Scenario: Session set — ignoreUnknownKeys allows bp to send extra metadata fields
    When I run:
      """
      bp session set \
        --cookie "tok=x" \
        --format json
      """
    Then if bp sends additional client-side fields in the JSON body
    And the server silently drops unknown fields (ignoreUnknownKeys=true per §8)
    And the exit code is 0 (no deserialization error from extra keys)

  @error @community
  Scenario: Session send/batch — malformed JSON body in request returns INVALID_REQUEST
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send batch \
        --request '{not valid json}' \
        --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INVALID_REQUEST"
    # SerializationException → 400 INVALID_REQUEST per §8 StatusPages mapping

  @error @community
  Scenario: Session send — internal Burp HTTP engine error returns INTERNAL_ERROR 500
    Given a session is active with cookies {"tok":"abc"}
    And the Burp HTTP engine throws an unexpected exception for this target
    When I run:
      """
      bp session send \
        --url "https://error-trigger.example.com/api" \
        --method GET \
        --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INTERNAL_ERROR"
    And the HTTP status is 500

  @happy @community
  Scenario: Session send — request appears in Burp proxy history (side-effect verification)
    Given a session is active with cookies {"auth":"token"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/items" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And a subsequent "bp proxy history --host api.example.com --format json" shows this request
    # Per §6.11: /session/send goes through Burp HTTP engine and appears in proxy history

  @happy @community
  Scenario: Batch send — all responses in strict sequential order matching request order
    Given a session is active with cookies {"tok":"seq"}
    When I run:
      """
      bp session send batch \
        --request '{"method":"GET","url":"https://api.example.com/step/1"}' \
        --request '{"method":"GET","url":"https://api.example.com/step/2"}' \
        --request '{"method":"GET","url":"https://api.example.com/step/3"}' \
        --format json
      """
    Then the exit code is 0
    And the JSON data array index 0 corresponds to /step/1
    And the JSON data array index 1 corresponds to /step/2
    And the JSON data array index 2 corresponds to /step/3
    # Per §6.11: strictly sequential; order is guaranteed
