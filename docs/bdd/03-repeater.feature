Feature: Repeater — send, batch, tab/create, chaining
  As a security hunter or AI agent driving bp,
  I want to replay and mutate captured HTTP requests through the Burp engine
  so that I can test modifications live, chain request IDs, and open Repeater tabs,
  all with full observability via the Run Ledger.

  Background:
    Given Burp Suite is running at http://127.0.0.1:8089
    And the bp CLI is on PATH
    And proxy history entry 42 exists (POST /api/login, host: auth.example.com)
    And proxy history entry 7 exists (GET /api/users/me, host: api.example.com)

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.3 /repeater/send — happy paths
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Replay a captured request by requestId with no modifications
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"requestId":42,"method":"POST","url":"https://auth.example.com/api/login","statusCode":200,"responseLength":843,"durationMs":<any-int>,"responseBody":"<any>","requestBody":"<any>","responseHeaders":[<any>]}}
      """
    And the response body contains the "statusCode" field (never absent — encodeDefaults=true)

  @happy @community
  Scenario: Send an inline-crafted request without a requestId
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://api.example.com/api/login \
        --header "Content-Type: application/json" \
        --header "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig" \
        --body '{"username":"admin","password":"hunter2"}' \
        --format json
      """
    Then exit code is 0
    And stdout is a single compact JSON line where:
      | field        | expectation              |
      | success      | true                     |
      | data.method  | POST                     |
      | data.url     | https://api.example.com/api/login |
      | data.statusCode | an integer >= 100     |

  @happy @community
  Scenario: Override a header on a replayed request using --set-header
    When I run:
      """
      bp repeater send --id 42 \
        --set-header "Authorization: Bearer newtoken_abc123" \
        --set-header "X-Forwarded-For: 127.0.0.1" \
        --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And the outgoing request sent to Burp has header "Authorization" value "Bearer newtoken_abc123"
    And the outgoing request sent to Burp has header "X-Forwarded-For" value "127.0.0.1"

  @happy @community
  Scenario: Override the body of a replayed request using --set-body
    When I run:
      """
      bp repeater send --id 42 \
        --set-body '{"username":"root","password":"toor"}' \
        --format json
      """
    Then exit code is 0
    And the REST call to POST /repeater/send contains:
      """
      {"requestId":42,"modifications":{"body":"{\"username\":\"root\",\"password\":\"toor\"}"}}
      """
    And stdout contains '"success":true'

  @happy @community
  Scenario: Override the HTTP method on a replayed request using --method
    When I run:
      """
      bp repeater send --id 7 \
        --method DELETE \
        --format json
      """
    Then exit code is 0
    And the REST call to POST /repeater/send contains '"method":"DELETE"' inside modifications
    And stdout contains '"success":true'

  @happy @community
  Scenario: Override the path on a replayed request using --path
    When I run:
      """
      bp repeater send --id 7 \
        --path "/api/users/999" \
        --format json
      """
    Then exit code is 0
    And the REST call to POST /repeater/send contains '"path":"/api/users/999"' inside modifications
    And stdout contains '"success":true'

  @happy @community
  Scenario: Combine all four modification types in one send
    When I run:
      """
      bp repeater send --id 42 \
        --method PUT \
        --path "/api/v2/login" \
        --set-header "X-Debug: 1" \
        --set-body '{"user":"test","pass":"x"}' \
        --format json
      """
    Then exit code is 0
    And the REST call body to POST /repeater/send is:
      """
      {
        "requestId": 42,
        "modifications": {
          "method":  "PUT",
          "path":    "/api/v2/login",
          "headers": {"X-Debug": "1"},
          "body":    "{\"user\":\"test\",\"pass\":\"x\"}"
        }
      }
      """
    And stdout contains '"success":true'

  @happy @community
  Scenario: Human-readable table output for a replayed request
    When I run:
      """
      bp repeater send --id 42 --format table
      """
    Then exit code is 0
    And stdout contains a table with headers including "STATUS" and "LENGTH" and "TIME_MS"
    And stdout contains a row with a numeric status code and a non-negative integer length

  @happy @community
  Scenario: Quiet mode returns only the HTTP status code
    When I run:
      """
      bp repeater send --id 42 --quiet
      """
    Then exit code is 0
    And stdout is exactly one line containing a 3-digit HTTP status code
    And no other fields are printed

  @happy @community
  Scenario: Write-out template prints status and response length
    When I run:
      """
      bp repeater send --id 42 -w "%{status} %{length}"
      """
    Then exit code is 0
    And stdout is exactly one line of the form "<3-digit-int> <non-negative-int>"
    # e.g. "200 843"

  @happy @community
  Scenario: Write-out template with all supported tokens
    When I run:
      """
      bp repeater send --id 7 \
        -w "%{status} %{length} %{time} %{requestId} %{contentType}"
      """
    Then exit code is 0
    And stdout matches the pattern:
      """
      <int:status> <int:length> <int:time_ms> <int:requestId> <string:contentType>
      """
    # e.g. "200 1024 312 7 application/json"

  @happy @community @ledger
  Scenario: Operation is recorded in the Run Ledger by default
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then exit code is 0
    And the most recent entry in the Run Ledger contains:
      | field      | value                  |
      | burp_op    | POST /repeater/send    |
      | target     | auth.example.com       |
      | status     | ok                     |
      | command    | bp repeater send --id 42 --format json |

  @happy @community @ledger
  Scenario: Tag an operation in the Run Ledger with --tag
    When I run:
      """
      bp repeater send --id 42 \
        --set-header "Authorization: Bearer admintoken" \
        --tag "auth-test-admin" \
        --format json
      """
    Then exit code is 0
    And the most recent Run Ledger entry has tag "auth-test-admin"
    And the Run Ledger entry status is "ok"

  @happy @community @ledger
  Scenario: Suppress Run Ledger recording with --no-ledger
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp repeater send --id 7 --no-ledger --format json
      """
    Then exit code is 0
    And the Run Ledger still has exactly N entries (unchanged)

  @happy @community
  Scenario: --fields flag selects and orders output columns (table mode)
    When I run:
      """
      bp repeater send --id 42 --format table --fields status,length,time
      """
    Then exit code is 0
    And stdout contains only the columns "STATUS", "LENGTH", "TIME" in that order
    And stdout does not contain a "METHOD" column

  @happy @community
  Scenario: --fields flag filters JSON output to named keys only
    When I run:
      """
      bp repeater send --id 42 --format json --fields status,length
      """
    Then exit code is 0
    And stdout is a compact JSON object containing only the keys "status" and "length"

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.3 /repeater/send — AX (AI agent) mode scenarios
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Agent mode — piped output is compact JSON by default (no TTY)
    Given stdout is not a TTY (piped to another process)
    When I run:
      """
      bp repeater send --id 42
      """
    Then stdout is a single compact JSON line (no newlines within the object)
    And the JSON schema is stable: fields "success", "data" always present
    And "data" contains "statusCode", "responseLength", "durationMs" (never absent)

  @happy @community
  Scenario: Agent chaining — extract requestId from send response and replay it
    Given I capture the output of:
      """
      bp repeater send --id 42 --format json
      """
    When I parse the JSON and extract "data.requestId" as NEW_ID
    And I run:
      """
      bp repeater send --id $NEW_ID \
        --set-header "X-Custom-Token: abc999" \
        --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    # This validates the requestId-chaining pattern: /repeater/send returns the
    # persisted requestId which can be passed back as requestId in the next call.

  @happy @community
  Scenario: Agent write-out for anomaly detection pipeline
    When I run:
      """
      bp repeater send --id 42 \
        --set-body '{"username":"'"'"' OR 1=1--","password":"x"}' \
        -w "%{status} %{length} %{requestId}"
      """
    Then exit code is 0
    And stdout is exactly one line: "<int> <int> <int>"
    # Downstream agent can parse this deterministically for status-diff analysis.

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.3 /repeater/send/batch — happy paths
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Batch send two requests sequentially
    When I run:
      """
      bp repeater batch \
        --id 42 \
        --id 7 \
        --format json
      """
    Then exit code is 0
    And stdout is a single compact JSON line where:
      | field           | expectation                    |
      | success         | true                           |
      | data.results    | array with exactly 2 elements  |
      | data.results[0] | has statusCode for request 42  |
      | data.results[1] | has statusCode for request 7   |

  @happy @community
  Scenario: Batch send with per-request modifications (inline JSON file)
    Given a file "/tmp/batch_repeater.json" with content:
      """
      {
        "requests": [
          {
            "requestId": 42,
            "modifications": {
              "headers": {"Authorization": "Bearer token_user_a"},
              "body": "{\"username\":\"alice\"}"
            }
          },
          {
            "requestId": 42,
            "modifications": {
              "headers": {"Authorization": "Bearer token_user_b"},
              "body": "{\"username\":\"bob\"}"
            }
          }
        ]
      }
      """
    When I run:
      """
      bp repeater batch --from-file /tmp/batch_repeater.json --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And stdout contains a "results" array with 2 elements
    And execution was strictly sequential (item 0 completed before item 1 started)

  @happy @community
  Scenario: Batch send table output shows one row per request
    When I run:
      """
      bp repeater batch --id 42 --id 7 --format table
      """
    Then exit code is 0
    And stdout contains a table with 2 data rows
    And each row has columns "INDEX", "STATUS", "LENGTH", "TIME_MS"

  @happy @community @ledger
  Scenario: Batch send records all operations in the Run Ledger
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp repeater batch --id 42 --id 7 --tag "login-flow" --format json
      """
    Then exit code is 0
    And the Run Ledger has N+2 new entries (one per request in the batch)
    And each entry has tag "login-flow" and burp_op "POST /repeater/send/batch"

  @happy @community
  Scenario: Batch with inline request and requestId mixed
    When I run:
      """
      bp repeater batch \
        --id 42 \
        --method GET --url https://api.example.com/api/whoami \
          --header "Authorization: Bearer tok123" \
        --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And the results array contains 2 elements

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.3 /repeater/tab/create — happy paths
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Create a Repeater tab from a captured request by requestId
    When I run:
      """
      bp repeater tab create --id 42 --name "Login replay" --format json
      """
    Then exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"name":"Login replay","created":true}}
      """
    And no HTTP traffic was sent (tab/create opens UI only — no request fired)
    And nothing is written to the Run Ledger history table (DB not touched by tab/create)

  @happy @community
  Scenario: Create a Repeater tab from an inline request
    When I run:
      """
      bp repeater tab create \
        --name "Custom XSS probe" \
        --method GET \
        --url "https://xss.example.com/search?q=<script>alert(1)</script>" \
        --header "Accept: text/html" \
        --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And the Burp Repeater UI now shows a tab named "Custom XSS probe"

  @happy @community
  Scenario: Create a Repeater tab without a name (auto-named by Burp)
    When I run:
      """
      bp repeater tab create --id 7 --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    # name:null is valid — the extension passes null to createNewlyCreatedTab

  @happy @community
  Scenario: Create a Repeater tab with no request and no requestId (silent fallback)
    When I run:
      """
      bp repeater tab create --name "Blank tab" --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    # Per spec: if request AND requestId are both null → fallback silently to
    # https://example.com — no error, no warning surfaced to the caller.

  @happy @community
  Scenario: Tab create quiet mode confirms success with minimal output
    When I run:
      """
      bp repeater tab create --id 42 --name "Quick tab" --quiet
      """
    Then exit code is 0
    And stdout is exactly "created" or "ok" (the single most essential value)

  # ─────────────────────────────────────────────────────────────────────────────
  # Scenario Outline — modifications matrix
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Send with a single modification type independently
    When I run:
      """
      bp repeater send --id 42 <flag> <value> --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And the REST request body sent to POST /repeater/send includes <mod_field> set to <mod_value>

    Examples:
      | flag         | value                          | mod_field | mod_value                      |
      | --method     | PATCH                          | method    | PATCH                          |
      | --path       | /api/v2/login                  | path      | /api/v2/login                  |
      | --set-body   | {"x":1}                        | body      | {"x":1}                        |
      | --set-header | X-Debug: true                  | headers   | {"X-Debug":"true"}             |

  @happy @community
  Scenario Outline: Write-out single token renders expected field
    When I run:
      """
      bp repeater send --id 42 -w "<token>"
      """
    Then exit code is 0
    And stdout is exactly one line matching the pattern for <expected_pattern>

    Examples:
      | token        | expected_pattern              |
      | %{status}    | 3-digit integer               |
      | %{length}    | non-negative integer          |
      | %{time}      | non-negative integer (ms)     |
      | %{requestId} | non-negative integer          |
      | %{contentType} | string (may be empty)       |
      | %{payload}   | string (empty for non-fuzz)   |

  # ─────────────────────────────────────────────────────────────────────────────
  # Error paths — /repeater/send
  # ─────────────────────────────────────────────────────────────────────────────

  @error @community
  Scenario: Send fails with INVALID_REQUEST when neither --id nor --url is given
    When I run:
      """
      bp repeater send --set-body '{"test":1}' --format json
      """
    Then exit code is non-zero
    And stderr or stdout contains:
      """
      {"success":false,"error":{"code":"INVALID_REQUEST","message":"<any>"}}
      """
    # Spec: exactly one of request / requestId required; neither → 400 INVALID_REQUEST

  @error @community
  Scenario: Send fails with INVALID_REQUEST when both --id and --url are given
    When I run:
      """
      bp repeater send --id 42 --url https://api.example.com/test --format json
      """
    Then exit code is non-zero
    And stdout or stderr contains '"code":"INVALID_REQUEST"'
    # Spec: exactly one of request / requestId; both → 400 INVALID_REQUEST

  @error @community
  Scenario: Send with a requestId that is out of bounds returns an error
    When I run:
      """
      bp repeater send --id 99999 --format json
      """
    Then exit code is non-zero
    And stdout or stderr contains one of:
      | {"success":false,"error":{"code":"INVALID_REQUEST","message":"<any>"}} |
      | {"success":false,"error":{"code":"INTERNAL_ERROR","message":"<any>"}} |
    # Spec note: out-of-bounds requestId → INVALID_REQUEST 400 or unhandled 500

  @error @community
  Scenario: Send with a non-integer requestId is rejected before hitting the server
    When I run:
      """
      bp repeater send --id "not-an-int" --format json
      """
    Then exit code is non-zero
    And stderr contains a validation error about "--id must be an integer"
    # bp must validate requestId type (Int) client-side before sending

  @error @community
  Scenario: Send with malformed JSON body is rejected by the server
    When I run:
      """
      bp repeater send \
        --url https://api.example.com/test \
        --method POST \
        --body '{bad json' \
        --format json
      """
    Then exit code is non-zero
    And stdout or stderr contains '"code":"INVALID_REQUEST"'
    # isLenient=true may let some malformed JSON through; strict malform → 400

  @error @community
  Scenario: Send returns SERVICE_UNAVAILABLE when Burp HTTP engine is unavailable
    Given the Burp HTTP engine (Montoya) is not available (simulated)
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then exit code is non-zero
    And stdout or stderr contains '"code":"SERVICE_UNAVAILABLE"'
    # Spec: IllegalStateException → 503 SERVICE_UNAVAILABLE

  @error @community
  Scenario: Burp extension is down — connection refused gives a clear CLI error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then exit code is non-zero
    And stderr contains "connection refused" or "could not reach Burp at http://127.0.0.1:8089"
    And no partial output is written to stdout

  # ─────────────────────────────────────────────────────────────────────────────
  # Error paths — /repeater/send/batch
  # ─────────────────────────────────────────────────────────────────────────────

  @error @community
  Scenario: Batch send aborts entirely when item N fails (no partial results)
    Given proxy history entry 42 exists (valid)
    And proxy history entry 99999 does NOT exist (out of bounds)
    When I run:
      """
      bp repeater batch --id 42 --id 99999 --id 7 --format json
      """
    Then exit code is non-zero
    And stdout or stderr contains '"success":false'
    And no result is emitted for request 7 (processing aborted at item index 1)
    # Spec: /send/batch is strictly sequential; failure on item N → abort total, no partial

  @error @community
  Scenario: Batch send with an empty request list is rejected
    When I run:
      """
      bp repeater batch --format json
      """
    Then exit code is non-zero
    And stderr contains a usage error: "at least one --id or request must be provided"

  @error @community
  Scenario: Batch from-file with invalid JSON file is rejected
    Given a file "/tmp/bad_batch.json" with content:
      """
      { "requests": [BROKEN
      """
    When I run:
      """
      bp repeater batch --from-file /tmp/bad_batch.json --format json
      """
    Then exit code is non-zero
    And stderr contains "failed to parse batch file" or '"code":"INVALID_REQUEST"'

  # ─────────────────────────────────────────────────────────────────────────────
  # Error paths — /repeater/tab/create
  # ─────────────────────────────────────────────────────────────────────────────

  @error @community
  Scenario: Tab create with a requestId that does not exist still succeeds silently
    When I run:
      """
      bp repeater tab create --id 99999 --name "Ghost tab" --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    # Spec: /tab/create performs no validation of requestId before calling the UI;
    # it may create a broken tab or use the fallback URL silently.

  @error @community
  Scenario: Tab create with Burp down returns a clear connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp repeater tab create --id 42 --name "Offline tab" --format json
      """
    Then exit code is non-zero
    And stderr contains "connection refused" or "could not reach Burp"

  # ─────────────────────────────────────────────────────────────────────────────
  # Chaining — requestId extraction and reuse
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Chain send → modify → compare statuses (manual IDOR probe)
    Given I capture the response of:
      """
      bp repeater send --id 7 --format json
      """
    And the response status (data.statusCode) for user A is stored as STATUS_A
    When I run:
      """
      bp repeater send --id 7 \
        --set-header "Authorization: Bearer token_user_b" \
        --format json
      """
    Then exit code is 0
    And I compare data.statusCode against STATUS_A
    # A status 200 with matching responseLength signals a likely IDOR

  @happy @community
  Scenario: Chain send to get requestId then open it in Repeater tab
    Given I run:
      """
      bp repeater send \
        --method GET \
        --url https://api.example.com/api/users/me \
        --header "Authorization: Bearer tok_analyst" \
        --format json
      """
    And I extract "data.requestId" as TAB_ID
    When I run:
      """
      bp repeater tab create --id $TAB_ID --name "Live users/me probe" --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And the Repeater UI shows the exact request sent in the previous step

  @happy @community @ledger
  Scenario: Chain send → tag → query Run Ledger by tag
    When I run:
      """
      bp repeater send --id 42 \
        --set-header "X-Role: superadmin" \
        --tag "priv-esc-test" \
        --format json
      """
    And I run:
      """
      bp log --tag "priv-esc-test" --format json
      """
    Then exit code is 0
    And the Run Ledger query returns at least one entry with tag "priv-esc-test"
    And each returned entry has fields: id, name, tag, timestamp, target, command, burp_op, status

  # ─────────────────────────────────────────────────────────────────────────────
  # Edge paths — serialization contract (§8)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Response includes all fields even when nullable (encodeDefaults=true)
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then exit code is 0
    And the JSON response always contains the key "responseBody" (value may be null, never absent)
    And the JSON response always contains the key "responseHeaders" (value may be [], never absent)
    And the JSON response always contains the key "durationMs" (value may be null, never absent)
    # encodeDefaults=true: all declared fields present regardless of null/default value

  @happy @community
  Scenario: ApiResponse envelope shape is always {success, data, error} — no bare response
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then stdout is a JSON object with exactly the top-level keys: "success", "data", "error"
    And "error" is null on success, "data" is null on error
    # Spec §8: ApiResponse<T> { success:Boolean, data:T?=null, error:ApiError?=null }

  @happy @community
  Scenario: Server tolerates extra unknown fields in the request (ignoreUnknownKeys=true)
    When bp sends a POST /repeater/send body containing an extra unknown field "deprecated_flag":true
    Then exit code is 0
    And the server responds with '"success":true'
    And the extra field is silently dropped (no 400 error)
    # Spec §8: ignoreUnknownKeys=true

  @happy @community
  Scenario: RequestModifications with only non-null fields set — null fields are not applied
    When I run:
      """
      bp repeater send --id 42 \
        --set-body '{"injected":"payload"}' \
        --format json
      """
    Then the REST call body includes '"modifications":{"body":"{\"injected\":\"payload\"}"}'
    And the REST call body does NOT include '"method":' key inside modifications
    And the REST call body does NOT include '"path":' key inside modifications
    And the REST call body does NOT include '"headers":' key inside modifications
    # Spec: RequestModifications — only non-null fields are applied; null fields are not sent

  # ─────────────────────────────────────────────────────────────────────────────
  # Edge paths — Run Ledger (C4)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Failed send is still recorded in the Run Ledger with status "error"
    Given proxy history entry 99999 does NOT exist
    When I run:
      """
      bp repeater send --id 99999 --format json
      """
    Then exit code is non-zero
    And the most recent Run Ledger entry has:
      | field   | value                 |
      | burp_op | POST /repeater/send   |
      | status  | error                 |
    # Even failed operations must be traceable (ISO traceability requirement)

  @happy @community @ledger
  Scenario: Run Ledger entry captures the exact command line verbatim
    When I run:
      """
      bp repeater send --id 42 --set-header "X-Test: 1" --tag "cli-capture-test" --format json
      """
    Then exit code is 0
    And the Run Ledger entry field "command" equals exactly:
      """
      bp repeater send --id 42 --set-header "X-Test: 1" --tag "cli-capture-test" --format json
      """

  # ─────────────────────────────────────────────────────────────────────────────
  # Edge paths — database availability
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Send succeeds even if the extension DB is unavailable (DB write silently skipped)
    Given the extension SQLite DB at ~/.burp-rest/burpdata is unavailable (permissions error)
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    # Spec: "DB optionnelle — enregistrement silencieusement skippé si init échoue"
    # The HTTP send itself must succeed; the DB row is a best-effort side effect.

  @happy @community
  Scenario: Tab create has no DB dependency — succeeds regardless of DB state
    Given the extension SQLite DB at ~/.burp-rest/burpdata is unavailable (permissions error)
    When I run:
      """
      bp repeater tab create --id 42 --name "DB-free tab" --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    # Spec: /tab/create — no traffic, no DB; DB state is irrelevant

  # ─────────────────────────────────────────────────────────────────────────────
  # Edge paths — output format contract
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: JSON output is compact mono-line (prettyPrint=false contract)
    When I run:
      """
      bp repeater send --id 42 --format json
      """
    Then stdout contains exactly one line (no embedded newlines in the JSON object)
    # Spec §8: prettyPrint=false — server responses are compact mono-line

  @happy @community
  Scenario: Batch JSON output contains one compact JSON line per result when streaming
    When I run:
      """
      bp repeater batch --id 42 --id 7 --format json
      """
    Then stdout is a valid compact JSON object (not NDJSON)
    And "data.results" is an array containing the responses in input order

  @happy @community
  Scenario: Raw format returns the Burp raw response bytes for a send
    When I run:
      """
      bp repeater send --id 42 --format raw
      """
    Then exit code is 0
    And stdout begins with "HTTP/1." (raw HTTP response wire format)
    And the full response headers and body are printed without JSON wrapping

  # ─────────────────────────────────────────────────────────────────────────────
  # Scenario Outline — method override variations
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Override HTTP method to various verbs
    When I run:
      """
      bp repeater send --id 7 --method <verb> --format json
      """
    Then exit code is 0
    And the outgoing request uses HTTP method <verb>
    And stdout contains '"success":true'

    Examples:
      | verb    |
      | GET     |
      | POST    |
      | PUT     |
      | PATCH   |
      | DELETE  |
      | HEAD    |
      | OPTIONS |

  # ─────────────────────────────────────────────────────────────────────────────
  # Scenario Outline — path override variations
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Override path to various target endpoints
    When I run:
      """
      bp repeater send --id 42 --path "<path>" --format json
      """
    Then exit code is 0
    And the REST call body contains '"path":"<path>"' inside modifications
    And stdout contains '"success":true'

    Examples:
      | path                             |
      | /api/admin                       |
      | /api/users/0                     |
      | /api/users/-1                    |
      | /api/users/999999                |
      | /../etc/passwd                   |
      | /api/v2/orders?debug=true        |

  # ─────────────────────────────────────────────────────────────────────────────
  # Scenario Outline — header injection variations
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Inject common security-relevant headers via --set-header
    When I run:
      """
      bp repeater send --id 42 --set-header "<header_name>: <header_value>" --format json
      """
    Then exit code is 0
    And stdout contains '"success":true'
    And the modifications.headers map contains '"<header_name>":"<header_value>"'

    Examples:
      | header_name             | header_value                  |
      | X-Forwarded-For         | 127.0.0.1                     |
      | X-Real-IP               | 10.0.0.1                      |
      | X-Original-URL          | /admin                        |
      | X-Rewrite-URL           | /admin                        |
      | X-Custom-IP-Authorization | 127.0.0.1                   |
      | Authorization           | Bearer eyJtest.payload.sig    |
      | Cookie                  | role=admin; session=abc123    |
      | Content-Type            | application/x-www-form-urlencoded |
      | Origin                  | https://evil.example.com      |

  # ─────────────────────────────────────────────────────────────────────────────
  # Scenario Outline — batch size variations
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Batch send with varying number of requests
    When I run a batch with <count> requests using valid request IDs
    Then exit code is 0
    And stdout contains a results array with exactly <count> elements

    Examples:
      | count |
      | 1     |
      | 2     |
      | 5     |
      | 10    |

  # ─────────────────────────────────────────────────────────────────────────────
  # Integration smoke — AX agent full workflow
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Full AX agent workflow — probe, modify, tab, ledger
    # Step 1: probe original
    Given I run and capture:
      """
      bp repeater send --id 42 --format json
      """
    And I store data.statusCode as BASELINE_STATUS
    And I store data.responseLength as BASELINE_LEN

    # Step 2: privilege escalation attempt
    When I run and capture:
      """
      bp repeater send --id 42 \
        --set-header "X-Role: admin" \
        --set-header "Authorization: Bearer tok_escalate" \
        --tag "priv-esc-probe" \
        --format json
      """
    And I store data.statusCode as ESCALATED_STATUS
    And I store data.responseLength as ESCALATED_LEN

    # Step 3: open in Repeater tab for manual inspection if anomalous
    When ESCALATED_STATUS != BASELINE_STATUS or abs(ESCALATED_LEN - BASELINE_LEN) > 20
    Then I run:
      """
      bp repeater tab create \
        --id 42 \
        --name "ANOMALY: priv-esc status=<ESCALATED_STATUS>" \
        --format json
      """
    And exit code is 0
    And stdout contains '"success":true'

    # Step 4: confirm ledger has all 3 operations
    When I run:
      """
      bp log --tag "priv-esc-probe" --format json
      """
    Then the Run Ledger contains at least 1 entry tagged "priv-esc-probe"
    And all entries have status "ok" or "error" (never absent)
