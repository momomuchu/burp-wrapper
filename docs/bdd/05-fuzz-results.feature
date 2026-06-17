Feature: Fuzz Results Retrieval and Output Formatting
  As a security researcher or AI agent driving bp,
  I want to retrieve, filter, and format Intruder attack results
  so that I can triage anomalous responses, pipe data into pipelines,
  and produce human-readable or machine-readable output from any fuzz run.

  # ─────────────────────────────────────────────────────────────────────────
  # BACKGROUND — shared state for happy-path scenarios
  # ─────────────────────────────────────────────────────────────────────────
  Background:
    Given Burp Suite is running and the REST API is reachable at http://127.0.0.1:8089
    And an attack was previously created with id "a1b2c3d4" against https://shop.example.com
    And the attack has completed with 50 results (indices 0-49)
    And results include:
      | index | payload              | statusCode | length | durationMs | contentType       | anomalous | error |
      | 0     | admin                | 200        | 4820   | 312        | application/json  | false     | null  |
      | 1     | root                 | 200        | 4820   | 298        | application/json  | false     | null  |
      | 7     | ' OR 1=1--           | 500        | 312    | 105        | text/html         | true      | null  |
      | 12    | <script>alert(1)</script> | 200   | 4820   | 290        | application/json  | false     | null  |
      | 23    | ../../../etc/passwd  | 403        | 89     | 88         | text/plain        | true      | null  |
      | 31    | null                 | 200        | 9940   | 440        | application/json  | true      | null  |
      | 45    | ../../../../windows  | 500        | 312    | 101        | text/html         | true      | null  |

  # ─────────────────────────────────────────────────────────────────────────
  # §1 — FULL RESULTS RETRIEVAL (all records, no filter)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Retrieve all fuzz results for a completed attack (default table output)
    Given the attack "a1b2c3d4" is complete with 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4
      """
    Then the exit code is 0
    And stdout contains a table with columns: index, payload, status, length, time, contentType, anomalous
    And the table has 50 rows
    And row 0 shows:
      """
      0   admin   200   4820   312   application/json   false
      """
    And row 7 shows:
      """
      7   ' OR 1=1--   500   312   105   text/html   true
      """

  @happy @fuzz @community
  Scenario: Retrieve all results with explicit pagination — offset and limit
    Given the attack "a1b2c3d4" is complete with 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --offset 10 --limit 5
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/results?offset=10&limit=5
    And stdout shows exactly 5 rows starting at index 10

  @happy @fuzz @community
  Scenario: Retrieve all results with limit 0 meaning "return everything"
    Given the attack "a1b2c3d4" has 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --offset 0 --limit 0
      """
    Then the exit code is 0
    And the REST call includes query param limit=0
    And all 50 results are returned
    # limit=0 is the Burp API sentinel for "return all" per §6.4

  # ─────────────────────────────────────────────────────────────────────────
  # §2 — FORMAT JSON (agent / pipeline mode)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Retrieve results in JSON format for AI agent consumption
    Given the attack "a1b2c3d4" is complete with 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And each stdout line is a compact single-line JSON object
    And line 0 matches exactly:
      """
      {"index":0,"payload":"admin","status":200,"length":4820,"time":312,"contentType":"application/json","anomalous":false,"location":null,"requestId":null}
      """
    And line 7 matches exactly:
      """
      {"index":7,"payload":"' OR 1=1--","status":500,"length":312,"time":105,"contentType":"text/html","anomalous":true,"location":null,"requestId":null}
      """
    And the schema is stable (same keys, same order) across all lines

  @happy @fuzz @community
  Scenario: JSON output is emitted automatically when stdout is a pipe (AX-mode)
    Given the attack "a1b2c3d4" is complete
    When I run with stdout piped to jq:
      """
      bp fuzz results --id a1b2c3d4 | jq 'select(.anomalous==true)'
      """
    Then the exit code is 0
    And jq receives valid JSON (one object per line)
    And only records where anomalous is true are emitted by jq

  @happy @fuzz @community
  Scenario: JSON results piped to file for offline analysis
    Given the attack "a1b2c3d4" is complete with 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json > /tmp/fuzz-a1b2c3d4.jsonl
      """
    Then /tmp/fuzz-a1b2c3d4.jsonl contains 50 lines
    And each line is valid JSON with keys: index, payload, status, length, time, contentType, anomalous, location, requestId

  # ─────────────────────────────────────────────────────────────────────────
  # §3 — FORMAT TABLE (human / TTY mode)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Table output is default when stdout is a TTY
    Given stdout is connected to a terminal
    And the attack "a1b2c3d4" is complete
    When I run:
      """
      bp fuzz results --id a1b2c3d4
      """
    Then the exit code is 0
    And stdout is a human-aligned table with a header row
    And columns are padded/aligned for readability
    And the header row contains: INDEX  PAYLOAD  STATUS  LENGTH  TIME  CONTENT-TYPE  ANOMALOUS

  @happy @fuzz @community
  Scenario: Explicit --format table overrides pipe default
    Given stdout is piped (not a TTY)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format table
      """
    Then the exit code is 0
    And stdout is an aligned table (not JSON)

  # ─────────────────────────────────────────────────────────────────────────
  # §4 — FORMAT RAW
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Raw format emits Burp raw bytes for a single result entry
    Given the attack "a1b2c3d4" result at index 7 has a raw request/response captured
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --index 7 --format raw
      """
    Then the exit code is 0
    And stdout contains the raw HTTP response bytes for result index 7

  # ─────────────────────────────────────────────────────────────────────────
  # §5 — WRITE-OUT TEMPLATE (-w / --write-out)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Write-out template prints status and payload one line per result
    Given the attack "a1b2c3d4" is complete with 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 -w "%{status} %{payload}"
      """
    Then the exit code is 0
    And stdout has exactly 50 lines
    And line 0 is exactly:
      """
      200 admin
      """
    And line 7 is exactly:
      """
      500 ' OR 1=1--
      """
    And line 23 is exactly:
      """
      403 ../../../etc/passwd
      """

  @happy @fuzz @community
  Scenario: Write-out template with all supported tokens
    Given the attack "a1b2c3d4" is complete
    When I run:
      """
      bp fuzz results --id a1b2c3d4 -w "%{index} %{status} %{length} %{time} %{payload} %{anomalous} %{contentType} %{location} %{requestId}"
      """
    Then the exit code is 0
    And each output line contains exactly 9 space-separated tokens
    And line 7 is:
      """
      7 500 312 105 ' OR 1=1-- true text/html - -
      """
    # tokens with null value render as "-"

  @happy @fuzz @community
  Scenario: Write-out anomalous filter combined to print only anomalous payloads
    Given the attack "a1b2c3d4" has 4 anomalous results out of 50
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only -w "%{status} %{payload}"
      """
    Then the exit code is 0
    And stdout has exactly 4 lines
    And every line starts with a non-200 status or anomalous marker

  @happy @fuzz @community
  Scenario: Write-out template combined with --format json is an error
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json -w "%{status} %{payload}"
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --format and -w/--write-out are mutually exclusive
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §6 — --fields SELECTION
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --fields selects and orders a subset of result columns
    Given the attack "a1b2c3d4" is complete
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --fields index,status,anomalous
      """
    Then the exit code is 0
    And stdout table has exactly 3 columns: INDEX, STATUS, ANOMALOUS
    And no other fields (payload, length, time, contentType) appear in output

  @happy @fuzz @community
  Scenario: --fields with --format json emits only selected keys in JSON
    Given the attack "a1b2c3d4" is complete
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --fields payload,status,length --format json
      """
    Then the exit code is 0
    And each JSON line has exactly the keys: payload, status, length
    And line 0 is:
      """
      {"payload":"admin","status":200,"length":4820}
      """

  @happy @fuzz @community
  Scenario: --fields ordering is respected — user-defined column order
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --fields anomalous,payload,index
      """
    Then the table column order is: ANOMALOUS, PAYLOAD, INDEX
    # not the canonical field order — user controls it

  @error @fuzz @community
  Scenario: Unknown field name in --fields produces a clear error
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --fields index,nonexistent,status
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: unknown field 'nonexistent'. Valid fields: index,payload,status,length,time,contentType,anomalous,location,requestId
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §7 — --quiet MODE
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --quiet prints only the single most essential value per result (status code)
    Given the attack "a1b2c3d4" has 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout has exactly 50 lines
    And each line contains only the HTTP status code
    And line 0 is:
      """
      200
      """
    And line 7 is:
      """
      500
      """

  @happy @fuzz @community
  Scenario: --quiet combined with --anomalous-only prints only anomalous status codes
    Given the attack "a1b2c3d4" has 4 anomalous results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --quiet --anomalous-only
      """
    Then stdout has exactly 4 lines
    And each line is a bare HTTP status code

  # ─────────────────────────────────────────────────────────────────────────
  # §8 — --anomalous-only FILTER
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --anomalous-only returns only results where anomalous=true
    Given the attack "a1b2c3d4" has 50 results, 4 of which are anomalous (indices 7, 23, 31, 45)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/results?offset=0&limit=0
    And stdout shows exactly 4 rows
    And the displayed indices are 7, 23, 31, 45
    And every row has anomalous=true

  @happy @fuzz @community
  Scenario: --anomalous-only with --format json for pipeline triage
    Given the attack "a1b2c3d4" has 4 anomalous results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only --format json
      """
    Then the exit code is 0
    And stdout has exactly 4 lines of JSON
    And every line has "anomalous":true
    And line 0 is:
      """
      {"index":7,"payload":"' OR 1=1--","status":500,"length":312,"time":105,"contentType":"text/html","anomalous":true,"location":null,"requestId":null}
      """

  @happy @fuzz @community
  Scenario: --anomalous-only on a run with zero anomalous results exits 0 with empty output
    Given the attack "a1b2c3d4" has 50 results, all with anomalous=false
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only
      """
    Then the exit code is 0
    And stdout is empty (or shows "0 anomalous results")
    And stderr is empty

  # ─────────────────────────────────────────────────────────────────────────
  # §9 — STATUS CODE FILTER
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Filter results by HTTP status code
    Given the attack "a1b2c3d4" has results with various status codes (200, 403, 500)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --status 500
      """
    Then the exit code is 0
    And every displayed row has status=500
    And rows 7 and 45 are shown
    And rows with status 200 or 403 are excluded

  @happy @fuzz @community
  Scenario: Filter by status code and combine with --format json
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --status 403 --format json
      """
    Then the exit code is 0
    And all JSON lines have "status":403
    And line 0 is:
      """
      {"index":23,"payload":"../../../etc/passwd","status":403,"length":89,"time":88,"contentType":"text/plain","anomalous":true,"location":null,"requestId":null}
      """

  @happy @fuzz @community
  Scenario: Filter by status code that has no matches returns empty result set
    Given no result in attack "a1b2c3d4" has status 302
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --status 302
      """
    Then the exit code is 0
    And stdout shows 0 rows (empty result set)

  # ─────────────────────────────────────────────────────────────────────────
  # §10 — LENGTH FILTER
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Filter results by minimum response length
    Given the attack "a1b2c3d4" has results with lengths: 89, 312, 4820, 9940
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --min-length 1000
      """
    Then the exit code is 0
    And only rows with length >= 1000 are shown (4820 and 9940)

  @happy @fuzz @community
  Scenario: Filter results by maximum response length
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --max-length 500
      """
    Then only rows with length <= 500 are shown (89 and 312)

  @happy @fuzz @community
  Scenario: Filter by both min and max length (length range)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --min-length 100 --max-length 400
      """
    Then only rows with 100 <= length <= 400 are shown (312)

  # ─────────────────────────────────────────────────────────────────────────
  # §11 — COMBINED FILTERS
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Combine --anomalous-only and --status filters
    Given the attack "a1b2c3d4" has anomalous results at indices 7 (500), 23 (403), 31 (200), 45 (500)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only --status 500
      """
    Then the exit code is 0
    And only indices 7 and 45 are shown (anomalous AND status 500)

  @happy @fuzz @community
  Scenario: Combine filters with write-out template for grep-friendly output
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only -w "%{index}\t%{status}\t%{length}\t%{payload}"
      """
    Then stdout has 4 tab-separated lines
    And line 0 is:
      """
      7	500	312	' OR 1=1--
      """

  @happy @fuzz @community
  Scenario: Combine --fields and --anomalous-only with --format json for agent triage pipeline
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only --fields index,status,payload --format json
      """
    Then the exit code is 0
    And each line has exactly: {"index":N,"status":N,"payload":"..."}
    And no other keys appear

  # ─────────────────────────────────────────────────────────────────────────
  # §12 — SUMMARIZATION OF LARGE RESULT SETS
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Summarize a large fuzz run (status distribution + anomaly count)
    Given the attack "z9x8y7w6" completed with 10000 results
    When I run:
      """
      bp fuzz results --id z9x8y7w6 --summary
      """
    Then the exit code is 0
    And stdout contains a summary block such as:
      """
      Attack:    z9x8y7w6
      Total:     10000
      Anomalous: 42
      Status distribution:
        200 → 9850
        403 → 108
        500 → 42
      Length range: 89 – 51200 bytes
      Duration range: 88 – 2450 ms
      Content-types:
        application/json → 9872
        text/html        → 128
      """
    And no individual result rows are printed

  @happy @fuzz @community
  Scenario: Summarize in JSON format for agent consumption
    Given the attack "z9x8y7w6" has 10000 results
    When I run:
      """
      bp fuzz results --id z9x8y7w6 --summary --format json
      """
    Then stdout is a single JSON object:
      """
      {"attackId":"z9x8y7w6","total":10000,"anomalousCount":42,"statusDistribution":{"200":9850,"403":108,"500":42},"lengthMin":89,"lengthMax":51200,"durationMin":88,"durationMax":2450,"contentTypes":{"application/json":9872,"text/html":128}}
      """

  @happy @fuzz @community
  Scenario: --summary combined with --anomalous-only summarizes only anomalous subset
    When I run:
      """
      bp fuzz results --id z9x8y7w6 --summary --anomalous-only
      """
    Then the summary totals reflect only the anomalous subset
    And the header shows "Anomalous subset: 42 of 10000"

  # ─────────────────────────────────────────────────────────────────────────
  # §13 — LEDGER TAGGING AND RUN TRACKING (C4)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community @ledger
  Scenario: Results retrieval is recorded in the Run Ledger by default
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And a new ledger entry is created in ~/.bp/ with:
      | field       | value                                           |
      | burp_op     | GET /intruder/attack/a1b2c3d4/results           |
      | target      | a1b2c3d4                                        |
      | status      | ok                                              |
      | command     | bp fuzz results --id a1b2c3d4 --format json     |

  @happy @fuzz @community @ledger
  Scenario: --tag names the ledger entry for traceability
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --tag "sqli-triage-round1"
      """
    Then the exit code is 0
    And the ledger entry has tag="sqli-triage-round1"
    And running:
      """
      bp log --tag sqli-triage-round1
      """
    shows this entry

  @happy @fuzz @community @ledger
  Scenario: --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --no-ledger --format json
      """
    Then the exit code is 0
    And no new entry is created in ~/.bp/ for this invocation

  @happy @fuzz @community @ledger
  Scenario: Ledger entry includes timestamp and full command line
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only --fields index,status,payload --tag "lfi-results"
      """
    Then the ledger entry has:
      | field     | value                                                                                      |
      | tag       | lfi-results                                                                                |
      | command   | bp fuzz results --id a1b2c3d4 --anomalous-only --fields index,status,payload --tag lfi-results |
      | timestamp | an ISO-8601 datetime                                                                       |
      | status    | ok                                                                                         |

  # ─────────────────────────────────────────────────────────────────────────
  # §14 — ATTACK STATUS POLLING (prerequisite to results)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Poll attack status before fetching results
    When I run:
      """
      bp fuzz status --id a1b2c3d4
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/status
    And stdout shows:
      """
      attackId:   a1b2c3d4
      status:     completed
      progress:   100
      isComplete: true
      """

  @happy @fuzz @community
  Scenario: Poll attack status in JSON for agent to decide when to fetch results
    When I run:
      """
      bp fuzz status --id a1b2c3d4 --format json
      """
    Then stdout is a single JSON object:
      """
      {"attackId":"a1b2c3d4","status":"completed","progress":100,"isComplete":true}
      """
    # agent polls this until isComplete=true, then calls bp fuzz results

  @happy @fuzz @community
  Scenario: Status of a running attack shows intermediate progress
    Given the attack "b2c3d4e5" is still running at 60% progress
    When I run:
      """
      bp fuzz status --id b2c3d4e5 --format json
      """
    Then stdout is:
      """
      {"attackId":"b2c3d4e5","status":"running","progress":60,"isComplete":false}
      """

  @happy @fuzz @community
  Scenario: Status of a paused attack
    Given the attack "c3d4e5f6" is paused
    When I run:
      """
      bp fuzz status --id c3d4e5f6 --format json
      """
    Then stdout is:
      """
      {"attackId":"c3d4e5f6","status":"paused","progress":35,"isComplete":false}
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §15 — QUICK-FUZZ RESULTS (synchronous — results inline)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Quick-fuzz returns results inline (synchronous, no poll needed)
    Given proxy history entry 3 is a POST to https://api.shop.example.com/login
    When I run:
      """
      bp fuzz quick --request-id 3 --param username \
        --payloads admin,root,"' OR 1=1--"
      """
    Then the exit code is 0
    And the REST call is POST /intruder/quick-fuzz with body:
      """
      {"requestId":3,"param":"username","payloads":["admin","root","' OR 1=1--"],"options":{"throttleMs":0}}
      """
    And stdout is a table with columns: index, payload, status, length, time, contentType, anomalous
    And the table has 3 rows (one per payload)
    And anomalous=true appears for the SQLi payload if its status/length diverges from baseline

  @happy @fuzz @community
  Scenario: Quick-fuzz results in JSON for agent analysis
    When I run:
      """
      bp fuzz quick --request-id 3 --param q \
        --payloads "<script>alert(1)</script>","' OR '1'='1" \
        --format json
      """
    Then the exit code is 0
    And stdout has 2 JSON lines
    And each line has keys: index, payload, status, length, time, contentType, anomalous, error

  @happy @fuzz @community
  Scenario: Quick-fuzz with write-out template prints compact status+payload per probe
    When I run:
      """
      bp fuzz quick --request-id 3 --param role \
        --payloads admin,user,guest \
        -w "%{status} %{payload}"
      """
    Then the exit code is 0
    And stdout has exactly 3 lines, e.g.:
      """
      200 admin
      200 user
      200 guest
      """

  @happy @fuzz @community
  Scenario: Quick-fuzz --anomalous-only shows only divergent results inline
    When I run:
      """
      bp fuzz quick --request-id 3 --param id \
        --payloads 1,2,999999,"1 OR 1=1" \
        --anomalous-only
      """
    Then the exit code is 0
    And only results where anomalous=true are shown
    # anomalous = statusCode differs OR |Δlength| > max(length*0.2, 20) OR contentType differs (per §6.4)

  @happy @fuzz @community
  Scenario: Quick-fuzz --quiet prints only the status code per probe
    When I run:
      """
      bp fuzz quick --request-id 3 --param token \
        --payloads eyJhbG,invalid,expired \
        --quiet
      """
    Then stdout has exactly 3 lines, each a bare HTTP status code

  # ─────────────────────────────────────────────────────────────────────────
  # §16 — SCENARIO OUTLINES: output format variants across all filter combinations
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: Results output in every supported format
    Given the attack "a1b2c3d4" is complete with 50 results
    When I run:
      """
      bp fuzz results --id a1b2c3d4 <filter> --format <format>
      """
    Then the exit code is 0
    And output matches <expected_shape>

    Examples:
      | filter            | format | expected_shape                                                        |
      |                   | json   | 50 compact JSON lines, one per result, stable schema                 |
      |                   | table  | aligned table with 50 rows + header                                  |
      |                   | quiet  | 50 lines each containing only the HTTP status code                   |
      | --anomalous-only  | json   | 4 compact JSON lines, each with "anomalous":true                     |
      | --anomalous-only  | table  | 4-row table, all ANOMALOUS cells show true                           |
      | --anomalous-only  | quiet  | 4 lines with HTTP status codes of anomalous entries only             |
      | --status 500      | json   | lines where "status":500 only                                        |
      | --status 500      | table  | rows where STATUS=500 only                                           |
      | --status 200      | quiet  | lines of 200 only                                                    |

  @happy @fuzz @community
  Scenario Outline: Write-out template tokens render correctly for different result types
    Given the attack "a1b2c3d4" result at index <index> has the given values
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --index <index> -w "<template>"
      """
    Then the exit code is 0
    And stdout is exactly:
      """
      <expected_line>
      """

    Examples:
      | index | template                         | expected_line                                   |
      | 0     | %{status} %{payload}             | 200 admin                                       |
      | 7     | %{status} %{payload}             | 500 ' OR 1=1--                                  |
      | 23    | %{status} %{payload}             | 403 ../../../etc/passwd                          |
      | 31    | %{anomalous} %{length}           | true 9940                                       |
      | 0     | %{index}:%{status}:%{length}     | 0:200:4820                                      |
      | 7     | %{contentType}                   | text/html                                       |
      | 0     | %{time}ms                        | 312ms                                           |

  @happy @fuzz @community
  Scenario Outline: --fields output with format json emits only requested fields
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --fields <fields> --format json --limit 1
      """
    Then line 0 has exactly the keys: <expected_keys>

    Examples:
      | fields                          | expected_keys                              |
      | index,status                    | index, status                              |
      | payload,anomalous               | payload, anomalous                         |
      | index,payload,status,length     | index, payload, status, length             |
      | requestId                       | requestId                                  |
      | contentType,time,anomalous      | contentType, time, anomalous               |

  # ─────────────────────────────────────────────────────────────────────────
  # §17 — AGENT-MODE (AX) END-TO-END SCENARIOS
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: AI agent polls status then retrieves anomalous results in JSON (full AX flow)
    Given the attack "a1b2c3d4" was started by a previous agent turn
    When the agent runs:
      """
      bp fuzz status --id a1b2c3d4 --format json
      """
    And receives {"attackId":"a1b2c3d4","status":"completed","progress":100,"isComplete":true}
    And then the agent runs:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only --format json
      """
    Then the exit code is 0
    And each JSON line has stable schema with keys: index, payload, status, length, time, contentType, anomalous, location, requestId
    And the agent can parse each line independently (newline-delimited JSON)

  @happy @fuzz @community
  Scenario: Agent uses --fields to receive only the minimum data needed for triage
    When the agent runs:
      """
      bp fuzz results --id a1b2c3d4 --anomalous-only --fields index,payload,status --format json --no-ledger
      """
    Then the exit code is 0
    And each line has only: {"index":N,"payload":"...","status":N}
    And the ledger is NOT updated (--no-ledger)

  @happy @fuzz @community
  Scenario: Agent summarizes a large run without downloading all records
    When the agent runs:
      """
      bp fuzz results --id z9x8y7w6 --summary --format json --no-ledger
      """
    Then the exit code is 0
    And stdout is a single JSON summary object (not 10000 lines)
    And the agent can determine anomalousCount without iterating all records

  # ─────────────────────────────────────────────────────────────────────────
  # §18 — ERROR AND EDGE CASES
  # ─────────────────────────────────────────────────────────────────────────

  @error @fuzz @community
  Scenario: Retrieve results for a non-existent attack ID
    Given no attack with id "deadbeef" exists in Burp's in-memory state
    When I run:
      """
      bp fuzz results --id deadbeef
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: attack 'deadbeef' not found (the extension lost state after a Burp restart, or the ID is wrong)
      """
    # In-memory state is lost on Burp reload per §6.4

  @error @fuzz @community
  Scenario: Retrieve results for an attack that is still running (not complete)
    Given the attack "b2c3d4e5" has status=running and 30 results so far
    When I run:
      """
      bp fuzz results --id b2c3d4e5
      """
    Then the exit code is 0
    And stdout shows a warning:
      """
      warning: attack b2c3d4e5 is still running (progress: 60%). Showing 30 partial results.
      """
    And 30 result rows are shown

  @error @fuzz @community
  Scenario: Retrieve results when Burp is not running (connection refused)
    Given no process is listening on port 8089
    When I run:
      """
      bp fuzz results --id a1b2c3d4
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: cannot connect to Burp REST API at http://127.0.0.1:8089 — is Burp running with the extension loaded?
      """

  @error @fuzz @community
  Scenario: Missing --id argument produces usage error
    When I run:
      """
      bp fuzz results
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --id is required
      """
    And stderr contains usage hint for bp fuzz results

  @error @fuzz @community
  Scenario: Non-string attack ID that would confuse the path parameter
    When I run:
      """
      bp fuzz results --id "../../etc"
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: invalid attack id '../../etc'
      """
    # bp must sanitize attackId before building the URL path

  @error @fuzz @community
  Scenario: Invalid --offset value (non-integer)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --offset abc
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --offset must be a non-negative integer
      """

  @error @fuzz @community
  Scenario: Invalid --limit value (negative integer)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --limit -5
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --limit must be a non-negative integer (use 0 for all results)
      """

  @error @fuzz @community
  Scenario: Empty result set for a completed attack (all payloads returned errors)
    Given the attack "f1f2f3f4" completed but all 10 results have statusCode=0 and error set
    When I run:
      """
      bp fuzz results --id f1f2f3f4
      """
    Then the exit code is 0
    And stdout shows 10 rows with status=0 (connection errors)
    And a warning is shown:
      """
      warning: all results have statusCode=0 — the target may have been unreachable during the attack
      """

  @error @fuzz @community
  Scenario: Quick-fuzz with blank param name is rejected with 400
    When I run:
      """
      bp fuzz quick --request-id 3 --param "" --payloads admin,root
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --param must not be blank (Burp API rejects empty param names)
      """
    # Per §6.4: 400 if param blank

  @error @fuzz @community
  Scenario: Quick-fuzz with empty payloads list is rejected with 400
    When I run:
      """
      bp fuzz quick --request-id 3 --param username
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --payloads must not be empty (provide at least one payload value)
      """
    # Per §6.4: 400 if payloads empty

  @error @fuzz @community
  Scenario: Quick-fuzz with neither --request-id nor --request is rejected
    When I run:
      """
      bp fuzz quick --param username --payloads admin,root
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: provide exactly one of --request-id or --request
      """

  @error @fuzz @community
  Scenario: Request-id that is out of bounds causes Burp 500 — bp surfaces the error
    Given proxy history has only 5 entries (indices 0-4)
    When I run:
      """
      bp fuzz quick --request-id 999 --param q --payloads test
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: Burp returned 500 INTERNAL_ERROR — requestId 999 may be out of bounds (proxy history has fewer entries)
      """

  @error @fuzz @community
  Scenario: Status call for an unknown attack ID returns error
    When I run:
      """
      bp fuzz status --id unknownXX
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: attack 'unknownXX' not found
      """

  @error @fuzz @community
  Scenario: Write-out template with an unknown token is flagged at parse time
    When I run:
      """
      bp fuzz results --id a1b2c3d4 -w "%{status} %{badtoken}"
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: unknown write-out token 'badtoken'. Supported tokens: status, length, time, payload, location, anomalous, contentType, index, requestId
      """

  @error @fuzz @community
  Scenario: --summary and --index are mutually exclusive
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --summary --index 7
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --summary and --index are mutually exclusive
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §19 — ATTACK LIFECYCLE (pause / resume / stop) — RESULTS CONSISTENCY
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Pause a running attack then retrieve partial results
    Given the attack "b2c3d4e5" is running with 30 results at 60% progress
    When I run:
      """
      bp fuzz pause --id b2c3d4e5
      """
    Then the exit code is 0
    And the REST call is POST /intruder/attack/b2c3d4e5/pause
    When I run:
      """
      bp fuzz results --id b2c3d4e5 --format json
      """
    Then the exit code is 0
    And stdout has 30 JSON lines (partial results from before pause)
    And a warning notes "attack is paused — results are partial"

  @happy @fuzz @community
  Scenario: Resume a paused attack then wait for completion
    Given the attack "b2c3d4e5" is paused at 60%
    When I run:
      """
      bp fuzz resume --id b2c3d4e5
      """
    Then the exit code is 0
    And the REST call is POST /intruder/attack/b2c3d4e5/resume
    And stdout shows:
      """
      attack b2c3d4e5 resumed
      """

  @happy @fuzz @community
  Scenario: Stop an attack and retrieve the results collected so far
    Given the attack "b2c3d4e5" is running with 30 results
    When I run:
      """
      bp fuzz stop --id b2c3d4e5
      """
    Then the REST call is POST /intruder/attack/b2c3d4e5/stop
    And the exit code is 0
    When I run:
      """
      bp fuzz results --id b2c3d4e5 --format json
      """
    Then the exit code is 0
    And the results reflect what was collected before the stop

  # ─────────────────────────────────────────────────────────────────────────
  # §20 — COMMUNITY vs PRO BOUNDARY FOR INTRUDER
  # ─────────────────────────────────────────────────────────────────────────

  @community @fuzz
  Scenario: Intruder results endpoint works in Burp Community (engine is Repeater-backed)
    Given Burp Suite Community Edition is running at :8089
    And the attack "a1b2c3d4" was executed (using RepeaterService, not Intruder Pro)
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And results are returned without a Pro-required error
    # Per §6.4 and §7: intruder is Community (delegation to Repeater), NOT Pro-gated

  @community @fuzz
  Scenario: Attack type battering-ram, pitchfork, cluster-bomb execute as sniper server-side — results reflect that
    Given an attack was created with type "cluster-bomb" but only sniper is implemented server-side
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And results are present (sniper executed under the hood)
    And bp shows a warning:
      """
      warning: attack type 'cluster-bomb' was requested but only 'sniper' is implemented server-side. Results reflect sniper execution. Full cluster-bomb expansion must be done client-side.
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §21 — IN-MEMORY STATE LOSS WARNING
  # ─────────────────────────────────────────────────────────────────────────

  @error @fuzz @community
  Scenario: After Burp restart, previously created attack IDs are gone (in-memory loss)
    Given Burp was restarted after attack "a1b2c3d4" was created
    When I run:
      """
      bp fuzz results --id a1b2c3d4
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: attack 'a1b2c3d4' not found — Burp's attack state is in-memory and lost on restart. Re-run the attack.
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §22 — STDOUT/STDERR CONTRACT AND EXIT CODES
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: On success, stderr is empty and all result data goes to stdout
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json 2>/tmp/err.txt
      """
    Then the exit code is 0
    And /tmp/err.txt is empty
    And stdout has 50 JSON lines

  @happy @fuzz @community
  Scenario: Warnings go to stderr, data goes to stdout — machine-parseable separation
    Given the attack "b2c3d4e5" is still running with 30 partial results
    When I run:
      """
      bp fuzz results --id b2c3d4e5 --format json 2>/tmp/warn.txt
      """
    Then the exit code is 0
    And stdout has 30 JSON lines (parseable by agent)
    And /tmp/warn.txt contains the partial-results warning
    And the warning does NOT appear in stdout

  @error @fuzz @community
  Scenario: Fatal error exits with non-zero code and all error info on stderr
    Given no process is listening on port 8089
    When I run:
      """
      bp fuzz results --id a1b2c3d4 --format json 2>/tmp/err.txt
      """
    Then the exit code is non-zero
    And stdout is empty
    And /tmp/err.txt contains the connection error message
