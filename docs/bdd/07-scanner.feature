# ============================================================
# Feature: 07-scanner — §6.6 /scanner/* (9 endpoints)
#
# Ground-truth: SPEC.md §6.6 only.
# Pro required: POST /scanner/crawl | /audit | /crawl-and-audit
#               GET  /scanner/{id}/status
#               GET  /scanner/{id}/issues
#               POST /scanner/{id}/pause  (STUB — returns status, does NOT pause)
#               POST /scanner/{id}/resume (STUB — returns nothing useful)
#               POST /scanner/{id}/stop   (removes from map; Burp task continues)
# Community-safe: GET /scanner/issue-definitions (reads sitemap; empty list on unavail)
#
# Kotlin types (source-of-truth):
#   ScanRequest    { url:String, config:ScanConfig=() }
#   ScanConfig     { /* fields passed through */ }
#   ScanStatus     { issueCount:Int, crawlProgress:Int=0, auditProgress:Int=0 }
#   ScanIssue      { name:String, url:String,
#                    severity:  HIGH|MEDIUM|LOW|INFORMATION|FALSE_POSITIVE,
#                    confidence: CERTAIN|FIRM|TENTATIVE }
#   scanId         : 8-char String (UUID prefix)
#   ApiResponse<T> : { success:Boolean, data:T?, error:ApiError? }
#   ApiError       : { code:String, message:String }
#
# Spec caveats (must be disclosed by bp CLI):
#   - audit: url field is IGNORED — scope is taken from Burp project scope
#   - pause/resume: STUBS — handler returns scan status; no actual pause in Burp engine
#   - stop: removes scan from in-memory map; underlying Burp task is NOT interrupted
#   - crawlProgress / auditProgress: ALWAYS 0 (stub in current extension)
#   - typeIndex: always 0L
#   - Entire /scanner group is ABSENT from /docs (OpenAPI 0.2.0)
#   - Community: crawl/audit/crawl-and-audit raise IllegalStateException → HTTP 500
#     with message "requires Burp Suite Professional"
#   - issue-definitions: reads sitemap → empty list if unavailable (graceful, Community-safe)
#
# Output model (all scenarios):
#   --format json    compact NDJSON (single line, stable schema) — agent/AX mode
#   --format table   human-aligned table with headers (default when TTY)
#   --format raw     newline-separated text
#   --quiet          suppress body output; exit code carries result
#   --fields f1,f2  filter output columns / JSON keys
#   -w / --write-out 'TPL'  tokens: %{status} %{length} %{time} %{payload}
#                            %{location} %{anomalous} %{contentType}
#                            %{index} %{requestId} %{host} %{method}
#   --tag NAME       tag operation in C4 Run Ledger
#   --no-ledger      skip C4 Run Ledger recording entirely
# ============================================================

@scanner
Feature: Scanner — §6.6 /scanner/* Pro lifecycle (crawl/audit/crawl-and-audit),
         status/issues/control (pause/resume/stop) and Community issue-definitions

  Background:
    Given the Burp Suite REST extension is listening on http://127.0.0.1:8089
    And the bp CLI is installed and on PATH
    And the default base URL is http://127.0.0.1:8089

  # ═══════════════════════════════════════════════════════════
  # §1  POST /scanner/crawl  — Pro required
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Crawl a URL — happy path returns 8-char scanId and records to ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop
      """
    Then the exit code is 0
    And stdout is a table row containing "SCAN_ID" with an 8-character alphanumeric value
    And the C4 Run Ledger records an entry with:
      | field   | value                    |
      | burp_op | POST /scanner/crawl      |
      | target  | https://ginandjuice.shop |
      | status  | ok                       |

  @happy @pro
  Scenario: Crawl — --format json produces a single compact NDJSON line (agent mode)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout is exactly one line
    And that line is valid JSON matching:
      """
      {"success":true,"data":{"scanId":"<8-char-alphanum>"}}
      """
    And the JSON field "success" equals true
    And the JSON field "data.scanId" has length 8

  @happy @pro
  Scenario: Crawl — -w '%{payload}' extracts the raw scanId payload
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop -w '%{payload}'
      """
    Then the exit code is 0
    And stdout matches the pattern:
      """
      \{"scanId":"[0-9a-f]{8}"\}
      """

  @happy @pro
  Scenario: Crawl — --quiet suppresses output and exits 0 on success
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @pro
  Scenario: Crawl — passes ScanConfig fields to the server
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl \
        --url https://ginandjuice.shop \
        --config '{"maximumCrawlLinks":200}'
      """
    Then the exit code is 0
    And stdout or stderr contains a scanId

  @happy @pro @ledger
  Scenario: Crawl — --tag labels the C4 ledger entry
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop --tag gin-crawl-01
      """
    Then the exit code is 0
    And the C4 ledger entry has tag="gin-crawl-01"
    And the C4 ledger entry has burp_op="POST /scanner/crawl"

  @happy @pro @ledger
  Scenario: Crawl — --no-ledger suppresses C4 recording entirely
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop --no-ledger
      """
    Then the exit code is 0
    And no new C4 ledger entry is created for this invocation

  @error @community
  Scenario: Crawl on Community edition — server raises IllegalStateException → PRO_REQUIRED
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop --format json
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"
    And the HTTP response code from Burp was 500
    And the JSON error envelope has "success":false and "error.code" one of "SERVICE_UNAVAILABLE" or "INTERNAL_ERROR"

  @error
  Scenario: Crawl — missing --url flag is rejected before any HTTP call
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl
      """
    Then the exit code is non-zero
    And stderr contains "url" and "required"
    And no request is sent to http://127.0.0.1:8089

  @error
  Scenario: Crawl — empty --url string is rejected with a clear error
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url ""
      """
    Then the exit code is non-zero
    And stderr contains a user-readable error about the empty URL value

  # ═══════════════════════════════════════════════════════════
  # §2  POST /scanner/audit  — Pro required; url field IGNORED
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Audit — url field accepted but silently ignored by the server (scope = Burp project scope)
    Given Burp Suite Professional is active
    And the Burp Suite project scope includes "https://ginandjuice.shop"
    When I run:
      """
      bp scanner audit --url https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout matches:
      """
      {"success":true,"data":{"scanId":"[0-9a-f]{8}"}}
      """
    And bp emits a warning on stderr: "Note: --url is ignored for audit; scope is taken from Burp project scope"

  @happy @pro
  Scenario: Audit — omitting --url still starts (url ignored server-side anyway)
    Given Burp Suite Professional is active
    And the Burp Suite project scope includes "https://ginandjuice.shop"
    When I run:
      """
      bp scanner audit --format json
      """
    Then the exit code is 0
    And stdout contains the key "scanId"

  @happy @pro @ledger
  Scenario: Audit — tagged operation is recorded in the C4 Run Ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner audit --url https://ginandjuice.shop --tag audit-run-01 --format json
      """
    Then the exit code is 0
    And the C4 ledger entry has burp_op="POST /scanner/audit" and tag="audit-run-01"

  @happy @pro
  Scenario: Audit — --quiet exits 0 without producing output
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner audit --url https://ginandjuice.shop --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @error @community
  Scenario: Audit on Community edition — Pro-required error surfaced to user
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner audit --url https://ginandjuice.shop --format json
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"

  # ═══════════════════════════════════════════════════════════
  # §3  POST /scanner/crawl-and-audit  — Pro required
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Crawl-and-audit — happy path returns scanId and records to ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl-and-audit --url https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line:
      """
      {"success":true,"data":{"scanId":"<8-char-alphanum>"}}
      """
    And the C4 ledger records burp_op="POST /scanner/crawl-and-audit"

  @happy @pro
  Scenario: Crawl-and-audit — --format table shows SCAN_ID column
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl-and-audit --url https://ginandjuice.shop --format table
      """
    Then the exit code is 0
    And stdout contains a table with column header "SCAN_ID"
    And the SCAN_ID value is 8 alphanumeric characters

  @happy @pro
  Scenario: Crawl-and-audit — -w '%{payload}' returns the data object
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl-and-audit --url https://ginandjuice.shop -w '%{payload}'
      """
    Then the exit code is 0
    And stdout matches:
      """
      \{"scanId":"[0-9a-f]{8}"\}
      """

  @error @community
  Scenario: Crawl-and-audit on Community edition — fails with Pro-required message
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner crawl-and-audit --url https://ginandjuice.shop
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"

  # ═══════════════════════════════════════════════════════════
  # §4  Full happy-path lifecycle:
  #     crawl-and-audit → status → issues → stop
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Full scanner lifecycle — create, poll status, list issues, then stop
    Given Burp Suite Professional is active

    When I run step 1 (start scan):
      """
      bp scanner crawl-and-audit --url https://ginandjuice.shop --format json --tag lifecycle-01
      """
    Then step 1 exits 0
    And I capture the JSON field "data.scanId" into $SID
    And $SID has length 8

    When I run step 2 (poll status immediately after start):
      """
      bp scanner status $SID --format json
      """
    Then step 2 exits 0
    And stdout is a single compact JSON line
    And the JSON contains key "issueCount" with a non-negative integer value
    And the JSON field "crawlProgress" equals 0
    And the JSON field "auditProgress" equals 0

    When I run step 3 (list issues after scan completes):
      """
      bp scanner issues $SID --format json
      """
    Then step 3 exits 0
    And stdout is valid JSON with "success":true
    And the "data" field is a JSON array
    And each element in the array contains keys "name", "url", "severity", "confidence"

    When I run step 4 (stop tracking):
      """
      bp scanner stop $SID --quiet
      """
    Then step 4 exits 0

    When I run step 5 (status after stop — scan removed from map):
      """
      bp scanner status $SID --format json
      """
    Then step 5 exits non-zero or stdout has "success":false
    And the response indicates scan $SID is no longer tracked

  # ═══════════════════════════════════════════════════════════
  # §5  GET /scanner/{id}/status  — Pro required
  #     ScanStatus { issueCount:Int, crawlProgress:Int, auditProgress:Int }
  #     crawlProgress and auditProgress are ALWAYS 0 (spec stub)
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Status — default table output shows issueCount and both progress fields
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" was started
    When I run:
      """
      bp scanner status a1b2c3d4
      """
    Then the exit code is 0
    And stdout is a table with column headers including "ISSUE_COUNT", "CRAWL_PROGRESS", "AUDIT_PROGRESS"
    And the CRAWL_PROGRESS value is 0
    And the AUDIT_PROGRESS value is 0
    And the ISSUE_COUNT value is a non-negative integer

  @happy @pro
  Scenario: Status — --format json produces compact NDJSON for agent polling loop
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner status a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is exactly one line
    And that line parses as JSON with all three keys present:
      """
      {"success":true,"data":{"issueCount":<int>,"crawlProgress":0,"auditProgress":0}}
      """
    And "crawlProgress" is 0
    And "auditProgress" is 0

  @happy @pro
  Scenario: Status — crawlProgress and auditProgress are always 0 regardless of actual Burp scan progress (spec stub)
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has been running for 60 seconds
    When I run:
      """
      bp scanner status a1b2c3d4 --format json
      """
    Then the JSON field "data.crawlProgress" is 0
    And the JSON field "data.auditProgress" is 0
    And bp emits a note (once per session): "crawlProgress and auditProgress are stub values — always 0 in current extension"

  @happy @pro
  Scenario: Status — -w '%{payload}' returns the full ScanStatus object inline
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has issueCount 7
    When I run:
      """
      bp scanner status a1b2c3d4 -w 'count:%{payload}'
      """
    Then the exit code is 0
    And stdout equals:
      """
      count:{"issueCount":7,"crawlProgress":0,"auditProgress":0}
      """

  @happy @pro
  Scenario: Status — --fields issueCount hides progress columns
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner status a1b2c3d4 --fields issueCount --format table
      """
    Then the exit code is 0
    And stdout contains "issueCount" or "ISSUE_COUNT"
    And stdout does not contain "crawlProgress" or "CRAWL_PROGRESS"
    And stdout does not contain "auditProgress" or "AUDIT_PROGRESS"

  @happy @pro
  Scenario: Status — --quiet outputs only the issueCount integer value
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running with issueCount 3
    When I run:
      """
      bp scanner status a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is the single line "3"
    And stderr is empty

  @error @pro
  Scenario: Status — unknown scanId returns structured error (exceptions swallowed as HTTP 200 with error body)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner status zzzzzzzz --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains one of: "not found", "error", "unknown scan"

  @error @community
  Scenario: Status on Community edition — Pro-required error surfaced
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner status a1b2c3d4
      """
    Then the exit code is non-zero
    And stderr or stdout references "Professional"

  # ═══════════════════════════════════════════════════════════
  # §6  GET /scanner/{id}/issues  — Pro required
  #     ScanIssue { name:String, url:String,
  #                 severity: HIGH|MEDIUM|LOW|INFORMATION|FALSE_POSITIVE,
  #                 confidence: CERTAIN|FIRM|TENTATIVE }
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Issues — default table output shows all four ScanIssue fields
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has 3 issues
    When I run:
      """
      bp scanner issues a1b2c3d4
      """
    Then the exit code is 0
    And stdout is a table with column headers: "NAME", "URL", "SEVERITY", "CONFIDENCE"
    And the table has 3 data rows

  @happy @pro
  Scenario: Issues — --format json returns NDJSON array for agent triage pipeline
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has 2 issues
    When I run:
      """
      bp scanner issues a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And stdout matches:
      """
      {"success":true,"data":[<issue_object>,<issue_object>]}
      """
    And each issue object contains keys "name", "url", "severity", "confidence"

  @happy @pro
  Scenario: Issues — --format raw emits newline-separated text (one issue name per line)
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has 1 issue named "SQL injection"
    When I run:
      """
      bp scanner issues a1b2c3d4 --format raw
      """
    Then the exit code is 0
    And stdout contains "SQL injection"

  @happy @pro
  Scenario: Issues — --quiet exits 0 silently when issues are found
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has 1 issue
    When I run:
      """
      bp scanner issues a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @pro
  Scenario: Issues — --fields name,severity filters JSON output to two keys only
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has issues
    When I run:
      """
      bp scanner issues a1b2c3d4 --fields name,severity --format json
      """
    Then the exit code is 0
    And each JSON object in the "data" array contains only "name" and "severity"
    And the keys "url" and "confidence" do not appear in any object

  @happy @pro
  Scenario: Issues — -w '%{status} %{payload}' emits severity and name per issue
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has an issue:
      | name          | SQL injection                    |
      | url           | https://ginandjuice.shop/search  |
      | severity      | HIGH                             |
      | confidence    | CERTAIN                          |
    When I run:
      """
      bp scanner issues a1b2c3d4 -w '%{status} %{payload}'
      """
    Then stdout contains a line matching:
      """
      HIGH SQL injection
      """

  @happy @pro
  Scenario: Issues — empty list returned when scan found zero vulnerabilities (not an error)
    Given Burp Suite Professional is active
    And a completed scan with id "b9c8d7e6" found 0 issues
    When I run:
      """
      bp scanner issues b9c8d7e6 --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[]}
      """
    And bp does not emit any error

  @happy @pro
  Scenario: Issues — unknown scanId returns empty list (exceptions swallowed to HTTP 200 per spec)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner issues zzzzzzzz --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[]}
      """

  @happy @pro
  Scenario Outline: Issues — all severity and confidence enum combinations are valid and displayed
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has an issue with severity <severity> and confidence <confidence>
    When I run:
      """
      bp scanner issues a1b2c3d4 --format json
      """
    Then the exit code is 0
    And the response JSON contains an issue with "severity":"<severity>" and "confidence":"<confidence>"

    Examples:
      | severity        | confidence |
      | HIGH            | CERTAIN    |
      | HIGH            | FIRM       |
      | HIGH            | TENTATIVE  |
      | MEDIUM          | CERTAIN    |
      | MEDIUM          | FIRM       |
      | MEDIUM          | TENTATIVE  |
      | LOW             | CERTAIN    |
      | LOW             | FIRM       |
      | LOW             | TENTATIVE  |
      | INFORMATION     | CERTAIN    |
      | INFORMATION     | FIRM       |
      | INFORMATION     | TENTATIVE  |
      | FALSE_POSITIVE  | CERTAIN    |
      | FALSE_POSITIVE  | FIRM       |
      | FALSE_POSITIVE  | TENTATIVE  |

  @error @community
  Scenario: Issues on Community edition — Pro-required error surfaced
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner issues a1b2c3d4
      """
    Then the exit code is non-zero
    And stderr or stdout contains "Professional"

  # ═══════════════════════════════════════════════════════════
  # §7  POST /scanner/{id}/pause  — Pro; STUB
  #     Handler returns current scan status — does NOT pause
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Pause — stub returns current scan status (does NOT actually pause the Burp scan)
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner pause a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line containing "issueCount"
    And the response body is a ScanStatus object (not a "paused" confirmation)
    And bp emits a warning: "pause is a stub — the Burp scan engine continues running"

  @happy @pro
  Scenario: Pause — --quiet suppresses stub response body
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner pause a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @pro
  Scenario: Pause then status — scan is still "running" confirming stub caveat
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run pause:
      """
      bp scanner pause a1b2c3d4 --quiet
      """
    And then immediately run status:
      """
      bp scanner status a1b2c3d4 --format json
      """
    Then the status response does not contain "paused" as the scan state
    And the scan is still actively running in Burp

  @happy @pro
  Scenario: Pause — -w '%{payload}' surfaces the returned ScanStatus object
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has issueCount 4
    When I run:
      """
      bp scanner pause a1b2c3d4 -w '%{payload}'
      """
    Then the exit code is 0
    And stdout matches:
      """
      \{"issueCount":4,"crawlProgress":0,"auditProgress":0\}
      """

  # ═══════════════════════════════════════════════════════════
  # §8  POST /scanner/{id}/resume  — Pro; STUB
  #     Handler does not resume anything; returns no useful body
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Resume — stub succeeds with HTTP 200 but does not resume any paused Burp scan
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is in any state
    When I run:
      """
      bp scanner resume a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout contains "success":true
    And bp emits a warning: "resume is a stub — no actual pause was in effect, no action taken"

  @happy @pro
  Scenario: Resume — --quiet suppresses stub response
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is in any state
    When I run:
      """
      bp scanner resume a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @pro
  Scenario: Resume — -w '%{payload}' returns whatever stub body the server sends
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has issueCount 3
    When I run:
      """
      bp scanner resume a1b2c3d4 -w 'resume:%{payload}'
      """
    Then the exit code is 0
    And stdout starts with "resume:"

  # ═══════════════════════════════════════════════════════════
  # §9  POST /scanner/{id}/stop  — Pro
  #     Removes scanId from in-memory map.
  #     The underlying Burp task is NOT interrupted.
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Stop — removes scan from tracking map and records to ledger; Burp task continues
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner stop a1b2c3d4 --tag stop-manual-01
      """
    Then the exit code is 0
    And stdout confirms that scan "a1b2c3d4" was removed from bp tracking
    And bp emits a note: "the underlying Burp scan task is not interrupted — only bp tracking is removed"
    And the C4 ledger entry has burp_op="POST /scanner/a1b2c3d4/stop" and tag="stop-manual-01"

  @happy @pro
  Scenario: Stop — --format json returns compact confirmation envelope
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner stop a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line with "success":true

  @happy @pro
  Scenario: Stop — --quiet suppresses output; exit code carries success signal
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner stop a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @pro
  Scenario: Stop then status — scan no longer tracked; status returns error or not-found
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run stop:
      """
      bp scanner stop a1b2c3d4 --quiet
      """
    And then I run status:
      """
      bp scanner status a1b2c3d4 --format json
      """
    Then the stop command exits 0
    And the status command exits non-zero or returns "success":false
    And the status response indicates scan "a1b2c3d4" is not tracked

  @error @pro
  Scenario: Stop — unknown scanId results in error (or swallowed exception returning HTTP 200 with error state)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner stop zzzzzzzz --format json
      """
    Then bp emits a clear diagnostic indicating "zzzzzzzz" was not found or already stopped

  # ═══════════════════════════════════════════════════════════
  # §10  GET /scanner/issue-definitions  — Community-safe
  #      Reads sitemap; returns empty list on unavailability (graceful degradation)
  # ═══════════════════════════════════════════════════════════

  @happy @community
  Scenario: Issue-definitions on Community — returns empty list (graceful, not an error)
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[]}
      """
    And bp does not emit any Pro-required error

  @happy @community
  Scenario: Issue-definitions — empty list when sitemap is unavailable is displayed as empty table (not error)
    Given Burp Suite Community edition is active
    And the sitemap service is unavailable
    When I run:
      """
      bp scanner issue-definitions --format table
      """
    Then the exit code is 0
    And stdout shows an empty table or "no results" indicator

  @happy @pro
  Scenario: Issue-definitions on Pro with populated sitemap — returns definition objects
    Given Burp Suite Professional is active
    And the Burp sitemap contains issue definitions
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then the exit code is 0
    And stdout is valid JSON with "success":true
    And the "data" field is a non-empty array of issue definition objects

  @happy @pro
  Scenario: Issue-definitions — --format json (agent mode) produces compact single-line output
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then the exit code is 0
    And stdout is exactly one line
    And that line is valid compact JSON wrapped in ApiResponse envelope

  @happy @pro
  Scenario: Issue-definitions — --fields name,severity filters output columns
    Given Burp Suite Professional is active
    And the Burp sitemap contains issue definitions
    When I run:
      """
      bp scanner issue-definitions --fields name,severity --format table
      """
    Then the exit code is 0
    And stdout contains column headers "name" and "severity"

  @happy @pro
  Scenario: Issue-definitions — --quiet exits 0 silently
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner issue-definitions --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @pro @ledger
  Scenario: Issue-definitions — --tag records the call in the C4 ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner issue-definitions --tag defn-audit-01
      """
    Then the exit code is 0
    And the C4 ledger entry has burp_op="GET /scanner/issue-definitions" and tag="defn-audit-01"

  @happy @community @ledger
  Scenario: Issue-definitions — --no-ledger suppresses C4 recording even on Community
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner issue-definitions --no-ledger --format json
      """
    Then the exit code is 0
    And no new C4 ledger entry is created for this invocation

  # ═══════════════════════════════════════════════════════════
  # §11  Community degradation — all Pro scan-start commands
  # ═══════════════════════════════════════════════════════════

  @error @community
  Scenario Outline: All three scan-start endpoints fail on Community with Pro-required message
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner <subcommand> --url https://ginandjuice.shop --format json
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"
    And stdout is empty or is a JSON error envelope with "success":false
    And no scan tracking entry is created in bp

    Examples:
      | subcommand       |
      | crawl            |
      | audit            |
      | crawl-and-audit  |

  @happy @community
  Scenario: Community-safe endpoint issue-definitions is NOT gated by Pro check
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then the exit code is 0
    And bp does NOT emit "requires Burp Suite Professional"

  # ═══════════════════════════════════════════════════════════
  # §12  Output format parity across all scanner subcommands
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario Outline: status and issues respect --format flag
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner <subcommand> a1b2c3d4 --format <format>
      """
    Then the exit code is 0
    And stdout is formatted as <format>

    Examples:
      | subcommand | format |
      | status     | json   |
      | status     | table  |
      | status     | raw    |
      | issues     | json   |
      | issues     | table  |
      | issues     | raw    |

  @happy @pro
  Scenario Outline: pause/resume/stop respect --quiet flag
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is in any state
    When I run:
      """
      bp scanner <subcommand> a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is empty

    Examples:
      | subcommand |
      | pause      |
      | resume     |
      | stop       |

  # ═══════════════════════════════════════════════════════════
  # §13  ApiResponse envelope contract (§8 Kotlin serialisation)
  #      prettyPrint=false → always compact
  #      encodeDefaults=true → null fields present
  #      success:Boolean, data:T?, error:ApiError?
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Crawl response is wrapped in ApiResponse envelope — all top-level keys present
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout matches the pattern:
      """
      \{"success":true,"data":\{"scanId":"[0-9a-f]{8}"\},"error":null\}
      """
    And "error" is present with value null (encodeDefaults=true)

  @error @pro
  Scenario: Error response is a valid ApiResponse envelope with success=false and error object
    Given Burp Suite Professional is active
    When the server returns an error for scan id "00000000"
    And I run:
      """
      bp scanner status 00000000 --format json
      """
    Then the response JSON has "success":false
    And the response JSON has an "error" object containing "code" and "message" string fields

  # ═══════════════════════════════════════════════════════════
  # §14  C4 Run Ledger integration
  # ═══════════════════════════════════════════════════════════

  @ledger @pro
  Scenario: Every scanner command records a ledger entry with timestamp, target, command, and status
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop
      """
    Then the C4 ledger entry contains:
      | field     | value                                               |
      | burp_op   | POST /scanner/crawl                                 |
      | target    | https://ginandjuice.shop                            |
      | status    | ok                                                  |
      | command   | bp scanner crawl --url https://ginandjuice.shop     |
    And the "timestamp" field is a valid ISO8601 datetime string

  @ledger @community
  Scenario: Failed scan-start on Community records ledger entry with status=err
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scanner crawl --url https://ginandjuice.shop
      """
    Then the exit code is non-zero
    And the C4 ledger entry has status="err" and burp_op="POST /scanner/crawl"

  @ledger @pro
  Scenario: --no-ledger suppresses recording for any scanner subcommand
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl-and-audit --url https://ginandjuice.shop --no-ledger
      """
    Then the exit code is 0
    And no new C4 ledger entry is created for this invocation

  # ═══════════════════════════════════════════════════════════
  # §15  Agent-mode (--format json) pipeline scenarios
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Agent pipeline — extract scanId from crawl response and pipe into status poll
    Given Burp Suite Professional is active
    When I run the shell pipeline:
      """
      SID=$(bp scanner crawl --url https://ginandjuice.shop --format json | jq -r '.data.scanId')
      bp scanner status "$SID" --format json
      """
    Then both commands exit 0
    And the status JSON contains "issueCount"
    And $SID has length 8

  @happy @pro
  Scenario: Agent pipeline — filter HIGH severity issues from issues list
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has issues of varying severity
    When I run the shell pipeline:
      """
      bp scanner issues a1b2c3d4 --format json | jq '.data[] | select(.severity=="HIGH")'
      """
    Then the exit code is 0
    And stdout contains only issue objects with "severity":"HIGH"

  @happy @community
  Scenario: Agent pipeline — issue-definitions on Community returns parseable empty array
    Given Burp Suite Community edition is active
    When I run the shell pipeline:
      """
      bp scanner issue-definitions --format json | jq '.data | length'
      """
    Then the exit code is 0
    And stdout is "0"

  @happy @pro
  Scenario: Agent pipeline — stop a scan after extracting its id from crawl-and-audit
    Given Burp Suite Professional is active
    When I run the shell pipeline:
      """
      SID=$(bp scanner crawl-and-audit --url https://ginandjuice.shop --format json | jq -r '.data.scanId')
      bp scanner stop "$SID" --format json
      """
    Then both commands exit 0
    And the stop response has "success":true

  # ═══════════════════════════════════════════════════════════
  # §16  Spec caveat disclosure scenarios
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: bp discloses the pause stub caveat when --format table is used
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner pause a1b2c3d4 --format table
      """
    Then stdout or stderr contains a human-readable note that pause does not affect the Burp engine
    And bp does NOT claim the scan is paused in Burp

  @happy @pro
  Scenario: bp discloses the resume stub caveat in output
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is in any state
    When I run:
      """
      bp scanner resume a1b2c3d4 --format table
      """
    Then stdout or stderr contains a note that resume is a stub with no effect on the Burp engine

  @happy @pro
  Scenario: bp discloses the stop tracking-vs-execution decoupling caveat
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scanner stop a1b2c3d4 --format table
      """
    Then stdout or stderr contains: "the underlying Burp scan task is not interrupted"
    And bp does NOT claim the Burp scan was halted

  @happy @pro
  Scenario: bp discloses that the entire /scanner group is absent from /docs (OpenAPI 0.2.0)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner --help
      """
    Then the help text notes that scanner endpoints are absent from the embedded /docs OpenAPI spec
    And the help text references SPEC.md §6.6 as the authoritative source

  @happy @pro
  Scenario: bp discloses audit url-ignored caveat regardless of output format
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner audit --url https://ginandjuice.shop --format json
      """
    Then stderr contains a note that --url is ignored for audit scans

  # ═══════════════════════════════════════════════════════════
  # §17  Fuzz / edge-case scenarios
  # ═══════════════════════════════════════════════════════════

  @fuzz
  Scenario: Crawl with a non-URL string — bp does not panic; error is structured
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner crawl --url "not-a-url-at-all"
      """
    Then bp does not crash with an unhandled exception
    And any error output is a structured JSON envelope or a clean stderr message
    And stdout does not contain a raw Java/Kotlin stack trace

  @fuzz
  Scenario: Status with a path-traversal-shaped scan id is sanitised before sending
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner status "../../../etc/passwd"
      """
    Then bp does not construct a path-traversal URL to http://127.0.0.1:8089
    And the exit code is non-zero
    And stderr contains a validation error about the scan id format

  @fuzz
  Scenario: Issues with a 64-character scan id is handled gracefully
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner issues aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      """
    Then the exit code is 0 or non-zero
    And stdout is valid JSON or stderr is a clean error message
    And no unhandled exception stack trace appears in output

  @fuzz
  Scenario: Stop with a blank scan id is rejected before any HTTP call
    Given Burp Suite Professional is active
    When I run:
      """
      bp scanner stop "" --format json
      """
    Then the exit code is non-zero
    And stderr contains a user-readable error about the invalid or empty scan id

  @fuzz
  Scenario: Issue-definitions when sitemap is unavailable — returns graceful empty list (not a crash)
    Given Burp Suite Professional is active
    And the sitemap service is unavailable
    When I run:
      """
      bp scanner issue-definitions --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[]}
      """
    And no error or stack trace is emitted

  @fuzz
  Scenario: Crawl-and-audit with very long URL (1000 chars) does not cause bp to hang
    Given Burp Suite Professional is active
    When I run with a 1000-character URL value:
      """
      bp scanner crawl-and-audit --url <1000-char-url>
      """
    Then the command completes within 10 seconds
    And stdout or stderr is a structured response (not silence)
