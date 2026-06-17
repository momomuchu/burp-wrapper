# =============================================================================
# Domain 15 · History  /history — 5 endpoints · C+DB
# Spec reference: SPEC.md §6.13
#
# CONDITIONAL GROUP: registered ONLY when historyDao != null && sitemapDao != null.
# If the SQLite DB at ~/.burp-rest/burpdata fails to init, ALL 5 endpoints return
# 404 (route absent, not a 4xx from handler). bp must probe + degrade gracefully.
#
# Endpoints covered:
#   GET    /history                  — paginated list with full HistoryFilter
#   GET    /history/{id}             — single entry (req + resp retrieval), id:Long
#   GET    /history/sitemap          — host+path+method tuples + hitCount
#   POST   /history/{id}/replay      — verbatim replay via Burp engine
#   DELETE /history                  — destructive wipe (history + sitemap)
#
# Key contracts from §6.13:
#   - HistoryEntryResponse.id          = Long  (not Int)
#   - HistoryPageResponse.total        = Long
#   - SitemapListResponse.total        = Int   (type inconsistency — assumed, not fixed)
#   - Entries sorted id DESC
#   - Bodies truncated to 1 MB at insert
#   - HistoryFilter query params: host, method, statusCode:Int?, source, search,
#       since, until, page:Int=0, pageSize:Int=50
#   - source enum values: proxy | repeater | replay | intruder
#   - ?search= = SQL LIKE unescaped (% and _ are wildcards)
#   - replay: NOT persisted (id=0, source='replay'), RepeaterService may re-insert
#   - DELETE: irreversible, no confirmation, non-transactional between the 2 tables
#   - DB-absent: 404 (route not registered)
#   - id non-Long / absent: INVALID_REQUEST 400
#
# Output model:
#   --format json|table|raw|quiet   (default table if TTY, json if not-TTY)
#   --fields f1,f2,...              (column selection)
#   -w / --write-out 'TPL'          tokens: %{status} %{length} %{time} %{payload}
#                                   %{location} %{anomalous} %{contentType} %{index}
#                                   %{requestId} %{host} %{method}
#   --quiet                         minimal output (ids / single value)
#   --tag NAME                      ledger annotation
#   --no-ledger                     suppress Run Ledger recording
#   --confirm                       required safety gate for DELETE /history
#
# DB-absent error path (404 group): covered by 12-errors-edges.feature — not
# duplicated here. One reference scenario is included per the task requirement.
#
# Tags used: @happy @error @pro @community @fuzz @ledger @agent
# =============================================================================

@community
Feature: History — paginated traffic log, sitemap, single-entry retrieval, replay, and wipe

  As a bug-bounty hunter or AI security agent driving bp
  I want to query, inspect, replay, and manage the Burp history DB
  So that I can grep secrets, reconstruct request chains, replay verbatim traffic,
  and wipe the slate between engagements — all with full ledger traceability

  Background:
    Given the bp CLI is installed and on PATH
    And the Burp Suite REST extension is listening on http://127.0.0.1:8089
    And the SQLite DB at ~/.burp-rest/burpdata has been successfully initialised
    And historyDao and sitemapDao are non-null (all 5 /history endpoints are registered)
    And the history DB contains at least 20 entries across hosts:
      | host               | method | statusCode | source   |
      | api.acme.corp      | GET    | 200        | proxy    |
      | api.acme.corp      | POST   | 401        | proxy    |
      | api.acme.corp      | POST   | 200        | repeater |
      | admin.acme.corp    | GET    | 403        | proxy    |
      | admin.acme.corp    | DELETE | 200        | intruder |
      | staging.acme.corp  | GET    | 302        | proxy    |
    And the entry with the lowest Long id in the DB is referred to as FIRST_ID
    And the entry with the highest Long id in the DB is referred to as LAST_ID

  # ===========================================================================
  # GET /history — happy paths (full HistoryFilter matrix)
  # ===========================================================================

  @happy @community
  Scenario: List history with default pagination returns first page of 50 sorted id DESC
    When I run:
      """
      bp history list --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON object matches the ApiResponse envelope: {"success":true,"data":{...}}
    And "data.total" is a Long integer >= 20
    And "data.entries" is an array with at most 50 elements
    And each element of "data.entries" has the field "id" of type Long
    And the entries are ordered by "id" descending (highest id first)
    And every element contains the fields: id, host, method, statusCode, source, timestamp

  @happy @community
  Scenario: Filter history by host returns only matching entries
    When I run:
      """
      bp history list --host api.acme.corp --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And every entry in "data.entries" has "host" equal to "api.acme.corp"
    And no entry with host "admin.acme.corp" or "staging.acme.corp" appears

  @happy @community
  Scenario: Filter history by HTTP method returns only entries with that verb
    When I run:
      """
      bp history list --method POST --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "method" equal to "POST"
    And no GET or DELETE entries appear

  @happy @community
  Scenario: Filter history by statusCode returns only entries with that exact status
    When I run:
      """
      bp history list --status-code 401 --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "statusCode" equal to 401
    And "data.total" is a Long >= 1

  @happy @community
  Scenario: Filter history by source proxy returns only proxy-captured entries
    When I run:
      """
      bp history list --source proxy --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "source" equal to "proxy"

  @happy @community
  Scenario: Filter history by source repeater returns only repeater entries
    When I run:
      """
      bp history list --source repeater --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "source" equal to "repeater"

  @happy @community
  Scenario: Filter history by source intruder returns only intruder entries
    When I run:
      """
      bp history list --source intruder --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "source" equal to "intruder"

  @happy @community
  Scenario: Filter history by source replay returns entries with source replay
    When I run:
      """
      bp history list --source replay --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "source" equal to "replay"

  @happy @community
  Scenario: Filter history by since returns only entries at or after the timestamp
    When I run:
      """
      bp history list --since 2024-01-01T00:00:00Z --format json
      """
    Then the exit code is 0
    And every entry's "timestamp" is >= "2024-01-01T00:00:00Z"

  @happy @community
  Scenario: Filter history by until returns only entries at or before the timestamp
    When I run:
      """
      bp history list --until 2024-12-31T23:59:59Z --format json
      """
    Then the exit code is 0
    And every entry's "timestamp" is <= "2024-12-31T23:59:59Z"

  @happy @community
  Scenario: Filter history by since and until range returns entries in the window
    When I run:
      """
      bp history list \
        --since 2024-06-01T00:00:00Z \
        --until 2024-06-30T23:59:59Z \
        --format json
      """
    Then the exit code is 0
    And every entry's "timestamp" falls in the range [2024-06-01T00:00:00Z, 2024-06-30T23:59:59Z]

  @happy @community
  Scenario: Full HistoryFilter — all parameters combined in one call
    When I run:
      """
      bp history list \
        --host api.acme.corp \
        --method POST \
        --status-code 200 \
        --source repeater \
        --since 2024-01-01T00:00:00Z \
        --until 2024-12-31T23:59:59Z \
        --page 0 \
        --page-size 10 \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And every entry has host="api.acme.corp", method="POST", statusCode=200, source="repeater"
    And "data.entries" has at most 10 elements (pageSize=10)
    And "data.total" reflects the total matching count before pagination (not just this page)

  @happy @community
  Scenario: Pagination — page 0 and page 1 return disjoint entry sets
    Given the history contains at least 6 entries for host api.acme.corp
    When I run:
      """
      bp history list --host api.acme.corp --page 0 --page-size 3 --format json
      """
    And I store "data.entries[*].id" as PAGE0_IDS
    And I run:
      """
      bp history list --host api.acme.corp --page 1 --page-size 3 --format json
      """
    And I store "data.entries[*].id" as PAGE1_IDS
    Then PAGE0_IDS and PAGE1_IDS share no common id values (disjoint pages)
    And entries in PAGE0_IDS have higher id values than entries in PAGE1_IDS (DESC order)

  @happy @community
  Scenario: Search with a plain string matches entries whose URL or body contains that string
    When I run:
      """
      bp history list --search "Authorization" --format json
      """
    Then the exit code is 0
    And "data.entries" contains only entries where "Authorization" appears in the stored request or response

  @happy @community
  Scenario: Search with a SQL LIKE wildcard percent matches any prefix
    # ?search= is unescaped SQL LIKE — % is a real wildcard
    When I run:
      """
      bp history list --search "Bearer %" --format json
      """
    Then the exit code is 0
    And every returned entry contains a "Bearer " token prefix in its stored data
    And the total count may be lower than without --search

  @happy @community
  Scenario: pageSize=1 returns exactly one entry per page
    When I run:
      """
      bp history list --page 0 --page-size 1 --format json
      """
    Then the exit code is 0
    And "data.entries" has exactly 1 element
    And "data.total" is the full count of all history entries (not 1)

  @happy @community
  Scenario: List history in table format shows aligned column headers
    When I run:
      """
      bp history list --host api.acme.corp --format table
      """
    Then the exit code is 0
    And stdout contains a table with headers including: ID, HOST, METHOD, STATUS, SOURCE, TIMESTAMP
    And each row contains a numeric Long id, a hostname, an HTTP verb, and a 3-digit status code

  @happy @community
  Scenario: List history in quiet mode returns only Long ids one per line
    When I run:
      """
      bp history list --host api.acme.corp --quiet
      """
    Then the exit code is 0
    And each line of stdout is a single Long integer (the entry id)
    And no other fields appear

  @happy @community
  Scenario: List history with --fields selects only the specified columns
    When I run:
      """
      bp history list --fields id,host,method,statusCode --format json
      """
    Then the exit code is 0
    And each entry in "data.entries" contains exactly the keys: id, host, method, statusCode
    And no other keys (source, timestamp, reqBody, resBody) appear

  @happy @community
  Scenario: Write-out template extracts host and method per entry
    When I run:
      """
      bp history list --host api.acme.corp -w "%{host} %{method} %{status}" --page-size 5
      """
    Then the exit code is 0
    And stdout contains at most 5 lines
    And each line matches the pattern: "api.acme.corp <VERB> <3-digit-int>"
    # e.g. "api.acme.corp POST 200"

  @happy @community
  Scenario: Write-out template with %{requestId} emits the Long id per entry
    When I run:
      """
      bp history list --page-size 3 -w "%{requestId} %{host}"
      """
    Then the exit code is 0
    And stdout contains exactly 3 lines
    And each line starts with a Long integer (the history entry id)

  @happy @community @ledger
  Scenario: history list auto-records a LedgerEntry with burp_op GET /history
    When I run:
      """
      bp history list --host api.acme.corp --format json --tag history-audit-june
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value              |
      | burp_op | GET /history       |
      | target  | api.acme.corp      |
      | status  | ok                 |
      | tag     | history-audit-june |

  @happy @community @ledger
  Scenario: history list with --no-ledger does not record a LedgerEntry
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp history list --no-ledger --format json
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries (unchanged)

  # ===========================================================================
  # GET /history/{id} — single entry retrieval (id:Long)
  # ===========================================================================

  @happy @community
  Scenario: Retrieve a single history entry by Long id returns full req and resp
    When I run:
      """
      bp history get --id $LAST_ID --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches: {"success":true,"data":{...}}
    And "data.id" equals LAST_ID (Long)
    And "data" contains the fields: id, host, method, url, statusCode, source, timestamp
    And "data" contains the nullable fields: reqBody, statusCode, resHeaders, resBody
    # encodeDefaults=true: nullable fields are present even if null, never absent

  @happy @community
  Scenario: Retrieve a single entry — reqBody and resBody are present (may be null)
    # encodeDefaults=true means nullables are always serialised, never dropped
    When I run:
      """
      bp history get --id $LAST_ID --format json
      """
    Then the exit code is 0
    And the JSON response always contains the key "reqBody"  (value may be null, never absent)
    And the JSON response always contains the key "resBody"  (value may be null, never absent)
    And the JSON response always contains the key "resHeaders" (value may be [], never absent)
    And the JSON response always contains the key "statusCode" (value may be null, never absent)

  @happy @community
  Scenario: Retrieve a single entry in table format shows request and response fields
    When I run:
      """
      bp history get --id $LAST_ID --format table
      """
    Then the exit code is 0
    And stdout contains a table row showing id, host, method, statusCode, source

  @happy @community
  Scenario: Retrieve a single entry with --fields narrows JSON output
    When I run:
      """
      bp history get --id $LAST_ID --fields id,method,statusCode,resBody --format json
      """
    Then the exit code is 0
    And the JSON "data" object contains exactly the keys: id, method, statusCode, resBody
    And no other keys appear

  @happy @community
  Scenario: Retrieve entry with -w template extracts status and response length
    When I run:
      """
      bp history get --id $LAST_ID -w "%{status} %{length} %{method}"
      """
    Then the exit code is 0
    And stdout is exactly one line matching: "<3-digit-int> <non-negative-int> <VERB>"
    # e.g. "200 4096 GET"

  @happy @community
  Scenario: Retrieve entry with --quiet prints only the Long id
    When I run:
      """
      bp history get --id $LAST_ID --quiet
      """
    Then the exit code is 0
    And stdout is exactly one line containing the Long id value of LAST_ID

  @happy @community @ledger
  Scenario: history get auto-records a LedgerEntry with burp_op GET /history/{id}
    When I run:
      """
      bp history get --id $LAST_ID --format json --tag single-entry-inspect
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value                    |
      | burp_op | GET /history/{id}        |
      | status  | ok                       |
      | tag     | single-entry-inspect     |

  # ===========================================================================
  # GET /history/sitemap — host+path+method tuples + hitCount
  # ===========================================================================

  @happy @community
  Scenario: Retrieve sitemap without host filter returns all unique host+path+method tuples
    When I run:
      """
      bp history sitemap --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches: {"success":true,"data":{...}}
    And "data.total" is an Int >= 1
    And "data.entries" is an array of sitemap tuple objects
    And each tuple contains the fields: host, path, method, hitCount
    And "data.total" equals the length of "data.entries"
    # Note: SitemapListResponse.total is Int (not Long) per §6.13 type contract

  @happy @community
  Scenario: Retrieve sitemap filtered by host returns only tuples for that host
    When I run:
      """
      bp history sitemap --host api.acme.corp --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "host" equal to "api.acme.corp"
    And no tuple with host "admin.acme.corp" or "staging.acme.corp" appears
    And each tuple has a non-negative integer "hitCount"

  @happy @community
  Scenario: Sitemap entries are unique host+path+method combinations with cumulative hitCount
    Given the history contains 3 GET requests to api.acme.corp/v1/users and 2 POST requests to the same path
    When I run:
      """
      bp history sitemap --host api.acme.corp --format json
      """
    Then the exit code is 0
    And the sitemap contains a tuple {host:"api.acme.corp", path:"/v1/users", method:"GET", hitCount:3}
    And the sitemap contains a tuple {host:"api.acme.corp", path:"/v1/users", method:"POST", hitCount:2}
    And each host+path+method combination appears exactly once (tuples are unique)

  @happy @community
  Scenario: Sitemap in table format displays columns host, path, method, hitCount
    When I run:
      """
      bp history sitemap --format table
      """
    Then the exit code is 0
    And stdout contains a table with headers: HOST, PATH, METHOD, HIT_COUNT
    And each row has a non-empty path and a numeric hitCount

  @happy @community
  Scenario: Sitemap with --fields narrows JSON to only path and hitCount
    When I run:
      """
      bp history sitemap --host api.acme.corp --fields path,hitCount --format json
      """
    Then the exit code is 0
    And each entry in "data.entries" contains exactly the keys: path, hitCount
    And no other keys (host, method) appear

  @happy @community
  Scenario: Sitemap with -w template prints one line per tuple with host and hitCount
    When I run:
      """
      bp history sitemap -w "%{host} %{method} %{status}"
      """
    Then the exit code is 0
    And each line of stdout contains a hostname, an HTTP verb, and a count
    # %{status} here renders hitCount for sitemap tuples (not an HTTP status)

  @happy @community
  Scenario: Sitemap total field type is Int not Long (§6.13 type inconsistency contract)
    When I run:
      """
      bp history sitemap --format json
      """
    Then the exit code is 0
    And "data.total" is serialised as a JSON number within Int range (not Long)
    # SitemapListResponse.total = Int; HistoryPageResponse.total = Long — assumed inconsistency

  @happy @community
  Scenario: Sitemap for a host with no history returns empty entries and total=0
    When I run:
      """
      bp history sitemap --host unknown.nevervisited.corp --format json
      """
    Then the exit code is 0
    And "data.total" is 0
    And "data.entries" is an empty array []
    And the exit code is 0 (empty result is not an error)

  @happy @community @ledger
  Scenario: history sitemap auto-records a LedgerEntry with burp_op GET /history/sitemap
    When I run:
      """
      bp history sitemap --host api.acme.corp --format json --tag sitemap-recon
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value                    |
      | burp_op | GET /history/sitemap     |
      | target  | api.acme.corp            |
      | status  | ok                       |
      | tag     | sitemap-recon            |

  @happy @community @agent
  Scenario: Agent uses sitemap to enumerate all unique paths for a target host (AX mode)
    When an AI agent runs:
      """
      bp history sitemap --host api.acme.corp --format json --fields path,method,hitCount
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (not pretty-printed)
    And "data.entries" is an array of compact objects each with exactly path, method, hitCount
    And the agent can parse this to build a wordlist of discovered paths

  # ===========================================================================
  # POST /history/{id}/replay — verbatim replay
  # ===========================================================================

  @happy @community
  Scenario: Replay a history entry verbatim via Burp engine
    When I run:
      """
      bp history replay --id $LAST_ID --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches: {"success":true,"data":{...}}
    And "data" contains a live HTTP response from Burp (statusCode, responseLength, durationMs)
    And "data.source" is "replay" (if returned in response)
    # Per §6.13: replay is NOT persisted (id=0, source='replay') by the handler;
    # RepeaterService may re-insert but the direct handler does not persist

  @happy @community
  Scenario: Replay response is a live Burp engine response, not a cached copy
    Given history entry LAST_ID is a GET /api/users/me request to api.acme.corp
    When I run:
      """
      bp history replay --id $LAST_ID --format json
      """
    Then the exit code is 0
    And "data.durationMs" is a positive integer (live network time, not 0)
    And "data.statusCode" is a valid HTTP status code integer

  @happy @community
  Scenario: Replay result in table format shows status and response timing
    When I run:
      """
      bp history replay --id $LAST_ID --format table
      """
    Then the exit code is 0
    And stdout contains a table row with at least columns: STATUS, LENGTH, TIME_MS

  @happy @community
  Scenario: Replay with -w template extracts status, length, and time
    When I run:
      """
      bp history replay --id $LAST_ID -w "%{status} %{length} %{time}"
      """
    Then the exit code is 0
    And stdout is exactly one line matching: "<3-digit-int> <non-negative-int> <non-negative-int>"
    # e.g. "200 843 312"

  @happy @community
  Scenario: Replay with --quiet returns only the HTTP status code of the replayed response
    When I run:
      """
      bp history replay --id $LAST_ID --quiet
      """
    Then the exit code is 0
    And stdout is exactly one line containing a 3-digit HTTP status code

  @happy @community
  Scenario: Replay is NOT persisted in history by the /history/{id}/replay handler (id=0, source=replay)
    Given the history entry count is N before the replay
    When I run:
      """
      bp history replay --id $LAST_ID --format json
      """
    Then the exit code is 0
    And calling "bp history list --source replay --format json" immediately after shows
      that any re-inserted entry (if any) has source="replay" confirming the spec contract
    # Note: RepeaterService may re-insert as a side-effect; the handler itself sets id=0, source='replay'

  @happy @community @ledger
  Scenario: history replay auto-records a LedgerEntry with burp_op POST /history/{id}/replay
    When I run:
      """
      bp history replay --id $LAST_ID --format json --tag replay-evidence
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value                          |
      | burp_op | POST /history/{id}/replay      |
      | status  | ok                             |
      | tag     | replay-evidence                |
    And the LedgerEntry's "command" field contains "--id" and the value of LAST_ID

  @happy @community @ledger
  Scenario: history replay with --no-ledger performs the replay without recording in the ledger
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp history replay --id $LAST_ID --no-ledger --format json
      """
    Then the exit code is 0
    And the Burp engine executes the live replay (statusCode present in stdout)
    And the Run Ledger still has exactly N entries (no new row)

  @happy @community @agent
  Scenario: Agent uses replay to re-execute a history entry and inspect the live response in JSON
    When an AI agent runs:
      """
      bp history replay --id $LAST_ID --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And "data.statusCode" is an integer (parseable by the agent for differential analysis)
    And "data.durationMs" is a non-negative integer
    And the agent can compare this against the original stored statusCode to detect state drift

  # ===========================================================================
  # DELETE /history — destructive wipe with --confirm safety gate
  # ===========================================================================

  @happy @community
  Scenario: Delete all history with --confirm wipes history and sitemap tables
    Given the history contains at least 10 entries
    When I run:
      """
      bp history delete --confirm --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line containing {"success":true,"data":{...}}
    And calling "bp history list --format json" immediately after returns "data.total":0
    And calling "bp history sitemap --format json" immediately after returns "data.total":0
    # DELETE is non-transactional between the 2 tables per §6.13 — both should be wiped
    # but if interrupted between the two, one table may still have data

  @happy @community
  Scenario: Delete history with --confirm and --quiet outputs minimal confirmation
    When I run:
      """
      bp history delete --confirm --quiet
      """
    Then the exit code is 0
    And stdout is exactly one line: "deleted" or "ok"
    And the history and sitemap tables are empty

  @happy @community @ledger
  Scenario: history delete auto-records a LedgerEntry with burp_op DELETE /history even though data is gone
    When I run:
      """
      bp history delete --confirm --format json --tag wipe-engagement-1
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value              |
      | burp_op | DELETE /history    |
      | status  | ok                 |
      | tag     | wipe-engagement-1  |
    # The Run Ledger itself is NOT wiped — only the Burp history DB is wiped

  @happy @community @ledger
  Scenario: history delete with --no-ledger still wipes history but skips the LedgerEntry
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp history delete --confirm --no-ledger
      """
    Then the exit code is 0
    And calling "bp history list --format json" returns "data.total":0
    And the Run Ledger still has exactly N entries (no new wipe-record row)

  # ===========================================================================
  # DELETE /history — safety gate enforcement (--confirm required)
  # ===========================================================================

  @error @community
  Scenario: Delete history WITHOUT --confirm is rejected before any REST call is made
    When I run:
      """
      bp history delete --format json
      """
    Then the exit code is 1
    And stderr contains a safety message referencing "--confirm" requirement
    And NO HTTP DELETE request is sent to http://127.0.0.1:8089/history
    And the history table remains unmodified
    # bp must enforce the --confirm gate client-side before ever touching the API

  @error @community
  Scenario: Delete history with --confirm=false explicit value is also rejected
    When I run:
      """
      bp history delete --confirm=false --format json
      """
    Then the exit code is 1
    And stderr contains the --confirm requirement message

  @error @community
  Scenario: Delete history prompt-interactively without --confirm in a TTY context asks for confirmation
    Given stdout IS a TTY (interactive terminal session)
    When I run "bp history delete" without the --confirm flag
    Then bp prompts: "This will irreversibly delete all history and sitemap data. Type 'yes' to confirm:"
    And if the user types anything other than "yes", the exit code is 1 and no REST call is made
    And if the user types "yes", bp proceeds with the DELETE /history call

  # ===========================================================================
  # Error paths — id type enforcement (Long)
  # ===========================================================================

  @error @community
  Scenario: GET /history/{id} with a non-Long string id returns INVALID_REQUEST 400
    When I run:
      """
      bp history get --id "not-a-long" --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains:
      """
      {"success":false,"error":{"code":"INVALID_REQUEST","message":"<any>"}}
      """
    # Per §6.13: id non-Long → INVALID_REQUEST 400

  @error @community
  Scenario: GET /history/{id} with a float id is rejected (Long contract)
    When I run:
      """
      bp history get --id 3.14 --format json
      """
    Then the exit code is non-zero
    And stderr contains a validation error about id being a Long integer

  @error @community
  Scenario: GET /history/{id} with a negative Long id is attempted and returns an error or empty
    When I run:
      """
      bp history get --id -1 --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"success":false' or a not-found error message

  @error @community
  Scenario: GET /history/{id} with a Long id that does not exist in the DB returns error
    When I run:
      """
      bp history get --id 9999999999 --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"success":false'
    And the error message indicates the entry was not found

  @error @community
  Scenario: POST /history/{id}/replay with a non-Long id returns INVALID_REQUEST 400
    When I run:
      """
      bp history replay --id "abc" --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"code":"INVALID_REQUEST"'
    # Per §6.13: id absent or non-Long → 400 INVALID_REQUEST

  @error @community
  Scenario: POST /history/{id}/replay with an id that no longer exists in history returns an error
    When I run:
      """
      bp history replay --id 9999999999 --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"success":false'

  # ===========================================================================
  # Error paths — DB absent (the group is missing, not returning 4xx from handler)
  # Note: Full coverage of this path is in 12-errors-edges.feature.
  # This single reference scenario confirms the bp probe-and-degrade contract.
  # ===========================================================================

  @error @community
  Scenario: All /history endpoints return 404 when DB init failed (reference — see 12-errors-edges)
    Given the SQLite DB at ~/.burp-rest/burpdata failed to initialise (historyDao is null)
    And therefore all 5 /history/* routes are NOT registered in the Ktor router
    When I run:
      """
      bp history list --format json
      """
    Then the exit code is non-zero
    And stderr contains a message indicating history is unavailable (e.g. "history unavailable: DB not initialised")
    And NO entry is written to the Run Ledger (the operation did not succeed)
    # bp probes for the group before use and degrades gracefully per §14 HIGH acceptance criterion

  # ===========================================================================
  # Error paths — Burp extension unreachable
  # ===========================================================================

  @error @community
  Scenario: history list when Burp is not reachable returns a clear connection error
    Given Burp Suite REST extension is NOT reachable at http://127.0.0.1:8089
    When I run:
      """
      bp history list --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "could not reach Burp at http://127.0.0.1:8089"
    And no partial JSON is written to stdout

  @error @community
  Scenario: history replay when Burp is not reachable returns a connection error
    Given Burp Suite REST extension is NOT reachable at http://127.0.0.1:8089
    When I run:
      """
      bp history replay --id 1 --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "could not reach Burp"

  # ===========================================================================
  # Fuzz / edge cases — HistoryFilter boundary and SQL LIKE injection
  # ===========================================================================

  @fuzz @community
  Scenario: statusCode filter with a non-integer value is handled gracefully
    # Per fuzzModels §6.13: statusCode=abc is ignored (Int? parsing returns null → no filter)
    When I run:
      """
      bp history list --status-code abc --format json
      """
    Then the exit code is 0
    And "data.entries" is the unfiltered list (statusCode filter ignored due to parse failure)
    # Or the exit code is non-zero if bp validates client-side — either is acceptable
    # but bp must not crash or produce an unstructured error

  @fuzz @community
  Scenario: page=-1 (negative page) is sent and the server returns results or an error gracefully
    # Per fuzzModels §6.13: page=-1 is a fuzz case
    When I run:
      """
      bp history list --page -1 --format json
      """
    Then the exit code is 0 or non-zero (either response is acceptable)
    And stdout or stderr is valid JSON (no unstructured panic output)
    And if exit code is 0, "data.entries" is an array (may be empty)

  @fuzz @community
  Scenario: pageSize=0 returns all entries or is rejected gracefully
    # Per fuzzModels §6.13: pageSize=0 is a fuzz case
    When I run:
      """
      bp history list --page-size 0 --format json
      """
    Then the exit code is 0 or non-zero
    And stdout or stderr is valid JSON (no unstructured error)

  @fuzz @community
  Scenario: search with literal percent sign returns entries matching the SQL LIKE wildcard
    # Per §6.13: search=% is a wildcard — matches everything (SQL LIKE '%%')
    When I run:
      """
      bp history list --search "%" --format json
      """
    Then the exit code is 0
    And "data.entries" is a non-empty array (% matches all rows in SQL LIKE)
    # Note: bp should document this caveat — % is not escaped

  @fuzz @community
  Scenario: search with underscore wildcard matches any single character in SQL LIKE
    When I run:
      """
      bp history list --search "api_acme" --format json
      """
    Then the exit code is 0
    And "data.entries" may contain entries where the _ matched any character in that position
    # SQL LIKE _ = single char wildcard; not escaped by the server per §6.13

  @fuzz @community
  Scenario: Very large pageSize does not crash — returns all available entries up to DB capacity
    When I run:
      """
      bp history list --page-size 100000 --format json
      """
    Then the exit code is 0
    And "data.entries" contains all available entries (no crash, no 500)

  @fuzz @community
  Scenario: Response body field resBody is truncated to 1 MB if the original was larger
    # Per §6.13: Bodies truncated to 1 MB at insert
    Given a history entry was captured where the response body exceeded 1 048 576 bytes
    When I run:
      """
      bp history get --id <that-entry-id> --format json
      """
    Then the exit code is 0
    And "data.resBody" is present and its length in bytes is at most 1 048 576
    # The truncation happens at insert time — not at retrieval time

  # ===========================================================================
  # Output format matrix — Scenario Outline
  # ===========================================================================

  @happy @community
  Scenario Outline: history list output adapts based on --format flag
    When I run:
      """
      bp history list --page-size 3 --format <format>
      """
    Then the exit code is 0
    And the output matches <expected_shape>

    Examples:
      | format | expected_shape                                                              |
      | json   | single compact JSON line with {"success":true,"data":{"total":...,"entries":[...]}} |
      | table  | aligned column table with header row (ID, HOST, METHOD, STATUS, SOURCE)     |
      | raw    | one raw entry per line (url or method+url dump, no JSON wrapping)           |
      | quiet  | one Long id per line, no other text                                         |

  @happy @community
  Scenario Outline: history get output adapts based on --format flag
    When I run:
      """
      bp history get --id $LAST_ID --format <format>
      """
    Then the exit code is 0
    And the output matches <expected_shape>

    Examples:
      | format | expected_shape                                                        |
      | json   | single compact JSON line with {"success":true,"data":{id,host,...}}   |
      | table  | one-row table with headers ID, HOST, METHOD, STATUS, SOURCE           |
      | raw    | raw HTTP request and response wire format dump                        |
      | quiet  | only the Long id value on a single line                               |

  @happy @community
  Scenario Outline: history replay output adapts based on --format flag
    When I run:
      """
      bp history replay --id $LAST_ID --format <format>
      """
    Then the exit code is 0
    And the output matches <expected_shape>

    Examples:
      | format | expected_shape                                                          |
      | json   | single compact JSON line with live response data                        |
      | table  | one-row table with STATUS, LENGTH, TIME_MS columns                      |
      | raw    | raw HTTP response bytes (starts with HTTP/1.)                           |
      | quiet  | only the HTTP status code integer on a single line                      |

  @happy @community
  Scenario Outline: history sitemap output adapts based on --format flag
    When I run:
      """
      bp history sitemap --format <format>
      """
    Then the exit code is 0
    And the output matches <expected_shape>

    Examples:
      | format | expected_shape                                                                    |
      | json   | single compact JSON line with {"success":true,"data":{"total":...,"entries":[...]}} |
      | table  | aligned column table with headers HOST, PATH, METHOD, HIT_COUNT                   |
      | quiet  | one "host path method" tuple per line, no hitCount                                |

  # ===========================================================================
  # Write-out token matrix — Scenario Outline
  # ===========================================================================

  @happy @community
  Scenario Outline: history list -w renders each supported token correctly
    When I run:
      """
      bp history list --page-size 1 -w "<token>"
      """
    Then the exit code is 0
    And stdout is exactly one line matching <expected_pattern>

    Examples:
      | token        | expected_pattern                              |
      | %{status}    | 3-digit integer (HTTP status code)            |
      | %{length}    | non-negative integer (response body length)   |
      | %{host}      | hostname string (e.g. api.acme.corp)          |
      | %{method}    | HTTP verb string (GET, POST, etc.)            |
      | %{requestId} | Long integer (history entry id)               |
      | %{contentType} | MIME type string or empty                   |
      | %{index}     | non-negative integer (page-relative position) |

  @happy @community
  Scenario Outline: history replay -w renders each supported token from the live response
    When I run:
      """
      bp history replay --id $LAST_ID -w "<token>"
      """
    Then the exit code is 0
    And stdout is exactly one line matching <expected_pattern>

    Examples:
      | token        | expected_pattern                              |
      | %{status}    | 3-digit integer (HTTP status code)            |
      | %{length}    | non-negative integer                          |
      | %{time}      | non-negative integer (round-trip ms)          |
      | %{contentType} | MIME type string or empty                   |

  # ===========================================================================
  # Serialisation contract (§8) — history-specific assertions
  # ===========================================================================

  @happy @community
  Scenario: ApiResponse envelope shape is always {success, data, error} for history list
    When I run:
      """
      bp history list --format json
      """
    Then stdout is a JSON object with exactly the top-level keys: "success", "data", "error"
    And "error" is null on success and "data" is null on error
    # §8: ApiResponse<T> { success:Boolean, data:T?=null, error:ApiError?=null }
    # encodeDefaults=true: both "data" and "error" keys are always present

  @happy @community
  Scenario: HistoryEntryResponse id is a JSON Long integer (not a string, not an Int)
    When I run:
      """
      bp history get --id $LAST_ID --format json
      """
    Then "data.id" in the JSON response is a numeric JSON value representable as a 64-bit Long
    And "data.id" is NOT a quoted string

  @happy @community
  Scenario: HistoryPageResponse total is a JSON Long integer
    When I run:
      """
      bp history list --format json
      """
    Then "data.total" is a numeric JSON value representable as a 64-bit Long
    And "data.total" is NOT a quoted string
    # Contrast with SitemapListResponse.total which is Int

  @happy @community
  Scenario: SitemapListResponse total is a JSON Int (inconsistent with HistoryPageResponse.total)
    When I run:
      """
      bp history sitemap --format json
      """
    Then "data.total" is a numeric JSON value within Int range (32-bit signed)
    # §6.13 type contract: SitemapListResponse.total = Int (assumed inconsistency from spec)

  @happy @community
  Scenario: All history JSON responses are compact single-line (prettyPrint=false)
    When I run each of:
      """
      bp history list --format json
      bp history get --id $LAST_ID --format json
      bp history sitemap --format json
      bp history replay --id $LAST_ID --format json
      """
    Then each command's stdout contains exactly one line (no embedded newlines in the JSON)
    # §8: prettyPrint=false — server responses and bp output are compact mono-line

  # ===========================================================================
  # Agent mode (AX) — full JSON pipeline scenarios
  # ===========================================================================

  @happy @community @agent
  Scenario: Agent lists history in JSON mode with --fields for minimal schema (AX-friendly)
    When an AI agent runs:
      """
      bp history list \
        --host api.acme.corp \
        --source proxy \
        --format json \
        --fields id,method,statusCode,host
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And each entry in "data.entries" contains exactly the keys: id, method, statusCode, host
    And each "id" is a Long integer (parseable as int64)
    And the agent can iterate the array to build a differential status map per endpoint

  @happy @community @agent
  Scenario: Agent retrieves a single entry in JSON to inspect raw request and response bodies
    When an AI agent runs:
      """
      bp history get --id $LAST_ID --format json --fields id,method,url,reqBody,resBody,statusCode
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And "data" contains exactly the keys: id, method, url, reqBody, resBody, statusCode
    And "data.reqBody" and "data.resBody" are present (may be null — encodeDefaults=true)
    And the agent can scan "data.resBody" for secrets, JWTs, or API keys

  @happy @community @agent
  Scenario: Agent uses sitemap to discover all unique endpoints then replays anomalous ones
    Given an AI agent has already run:
      """
      bp history sitemap --host api.acme.corp --format json --fields path,method,hitCount
      """
    And the agent identified path="/api/admin" method="GET" as suspicious (low hitCount)
    When the agent looks up a history entry for that path and replays it:
      """
      bp history list --host api.acme.corp --method GET --search "/api/admin" --page-size 1 --format json --fields id
      """
    And extracts the id as ADMIN_ENTRY_ID
    And runs:
      """
      bp history replay --id $ADMIN_ENTRY_ID --format json
      """
    Then the exit code is 0
    And "data.statusCode" is a valid HTTP status code
    And the agent can compare the live status against the stored status to detect state changes

  @happy @community @agent
  Scenario: Agent grep for JWT tokens across history using --search
    When an AI agent runs:
      """
      bp history list --search "eyJ" --format json --fields id,host,method,statusCode
      """
    Then the exit code is 0
    And "data.entries" contains entries whose stored request or response body contains "eyJ" (JWT header prefix)
    And each entry's id is a Long usable to retrieve the full entry via "bp history get --id <id>"

  @happy @community @agent
  Scenario: Agent uses -w template to produce a single line per entry for pipeline processing
    When an AI agent runs:
      """
      bp history list --host api.acme.corp -w "%{requestId} %{method} %{status}" --page-size 20
      """
    Then the exit code is 0
    And stdout contains at most 20 lines
    And each line is: "<Long-id> <VERB> <3-digit-int>"
    And the output is suitable for awk/jq pipeline processing without further JSON parsing

  @happy @community @agent
  Scenario: Agent pipes --quiet history list IDs directly into history get for bulk inspection
    When an AI agent runs:
      """
      bp history list --host api.acme.corp --quiet --page-size 5
      """
    Then stdout contains exactly 5 lines each containing a Long id
    And each id can be passed directly to "bp history get --id <id>" without transformation

  @happy @community @agent
  Scenario: Agent uses --format json in non-TTY context (default output mode matches AX expectation)
    Given stdout is not a TTY (piped to another process)
    When an AI agent runs:
      """
      bp history list --host api.acme.corp
      """
    Then stdout is compact JSON (default when not-TTY, no --format needed)
    And the JSON schema is stable: "success", "data.total", "data.entries" always present

  # ===========================================================================
  # Pro / Community matrix — history is Community + DB (no Pro required)
  # ===========================================================================

  @happy @community
  Scenario: All /history endpoints are accessible on Burp Suite Community (no Pro required)
    Given Burp Suite Community Edition is running at http://127.0.0.1:8089
    And the SQLite DB has been successfully initialised
    When I run each of the following and collect exit codes:
      """
      bp history list --page-size 1 --format json
      bp history get --id $LAST_ID --format json
      bp history sitemap --format json
      bp history replay --id $LAST_ID --format json
      """
    Then all commands exit with code 0
    And none of the responses contains '"code":"SERVICE_UNAVAILABLE"'
    # §7: history group is Community (C) + DB — not Pro-gated

  # ===========================================================================
  # Ledger integration — cross-scenario assertions
  # ===========================================================================

  @happy @community @ledger
  Scenario: All five /history operations produce distinct LedgerEntry burp_op values
    When I run in sequence:
      """
      bp history list --format json --tag ledger-fullcoverage
      bp history get --id $LAST_ID --format json --tag ledger-fullcoverage
      bp history sitemap --format json --tag ledger-fullcoverage
      bp history replay --id $LAST_ID --format json --tag ledger-fullcoverage
      """
    And I run:
      """
      bp log --tag ledger-fullcoverage --format json --fields burp_op,status
      """
    Then the exit code is 0
    And the returned entries include at least these burp_op values:
      | burp_op                        |
      | GET /history                   |
      | GET /history/{id}              |
      | GET /history/sitemap           |
      | POST /history/{id}/replay      |
    And all entries have "status": "ok"

  @happy @community @ledger
  Scenario Outline: --tag global flag is honoured for every /history sub-command
    When I run:
      """
      bp history <subcommand> <args> --tag <tag_value> --format json
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has "tag": "<tag_value>"
    And the "burp_op" matches <expected_burp_op>

    Examples:
      | subcommand | args                         | tag_value       | expected_burp_op            |
      | list       | --page-size 1                | tag-list-test   | GET /history                |
      | get        | --id $LAST_ID                | tag-get-test    | GET /history/{id}           |
      | sitemap    | --host api.acme.corp         | tag-sitemap-test| GET /history/sitemap        |
      | replay     | --id $LAST_ID                | tag-replay-test | POST /history/{id}/replay   |

  @happy @community @ledger
  Scenario: bp history delete also records in the Run Ledger before wiping Burp history
    # The Run Ledger (~/.bp/ledger.db) is independent of the Burp history DB (~/.burp-rest/burpdata)
    # — deleting Burp history does NOT delete Run Ledger entries
    Given the Run Ledger has N entries and Burp history has M entries
    When I run:
      """
      bp history delete --confirm --tag wipe-run --format json
      """
    Then the exit code is 0
    And calling "bp history list --format json" returns "data.total":0  (Burp history wiped)
    And calling "bp log --format json" returns an array with at least N+1 entries (ledger NOT wiped)
    And the most recent ledger entry has burp_op="DELETE /history" and tag="wipe-run"
