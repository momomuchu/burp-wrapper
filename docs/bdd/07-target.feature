# Feature: Target — 6 /target endpoints (§6.8)
#
# Ground truth: SPEC.md §6.8 · 6 endpoints · Community (C) · scope in-memory.
#
# Real Kotlin types:
#   SetScopeRequest  { includes:List<String> (required), excludes:List<String>=[] }
#   AddScopeRequest  { url:String (required) }   — used for BOTH /add AND /remove
#   SitemapEntry     { url:String, method:String, statusCode:Int?, mimeType:String? }
#                     statusCode and mimeType are nullable → rendered as null (encodeDefaults=true)
#
# Critical behavioural flags (§6.8):
#   POST /target/scope   = FULL REPLACE: includes=[] wipes the entire scope (destructive).
#   GET  /target/scope   = reads in-memory scope ONLY — does NOT reflect scope set in Burp UI.
#   GET  /target/scope/check = authoritative Burp engine verdict — DOES reflect UI scope.
#   GET  /target/scope/check without ?url= → INVALID_PARAM inside HTTP 200 envelope (early-return).
#   ScopeCheckRequest DTO = DEAD (never used by server; url comes from query param only).
#   POST /target/scope/remove uses the SAME DTO as /target/scope/add (AddScopeRequest).
#   GET  /target/sitemap accepts optional ?url= prefix filter; returns SitemapEntry list.
#
# Error codes (§8 StatusPages):
#   INVALID_REQUEST    400  (malformed JSON / missing required field)
#   INVALID_PARAM      —    (scope/check without url — wrapped in HTTP 200 response envelope)
#   INTERNAL_ERROR     500
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
#   @happy       nominal success path
#   @error       error / rejection / destructive edge path
#   @community   all target endpoints run without Burp Pro
#   @fuzz        enumeration / discovery oriented scenario
#   @ledger      exercises C4 run-ledger behaviour

Feature: Target — sitemap dump, scope management, and authoritative scope check via /target (§6.8)

  As a bug-bounty hunter using `bp`
  I want to dump the Burp sitemap, manage the in-memory scope, and verify scope membership
  so that I can enumerate discovered endpoints, control what is in-scope for scanning,
  and get an authoritative verdict from the Burp engine — all with a traceable ledger.

  Background:
    Given the Burp extension is running and reachable at http://127.0.0.1:8089
    And GET /health returns {"success":true,"data":{"status":"ok","version":"0.1.0"}}

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /target/sitemap — optional prefix filter; SitemapEntry list
  # SitemapEntry: { url, method, statusCode:Int?, mimeType:String? }
  # statusCode and mimeType are nullable → present as null (encodeDefaults=true)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Sitemap dump with no filter returns all discovered entries as JSON
    Given Burp has discovered entries for multiple hosts
    When I run:
      """
      bp target sitemap --format json
      """
    Then the exit code is 0
    And each stdout line is valid JSON
    And each JSON line contains fields "url", "method", "statusCode", "mimeType"
    And "statusCode" and "mimeType" may be null (encodeDefaults=true renders them explicitly)

  @happy @community
  Scenario: Sitemap dump with no filter returns table output by default when TTY
    Given Burp has discovered entries for https://target.example.com
    When I run:
      """
      bp target sitemap
      """
    Then the exit code is 0
    And the output table contains columns "url", "method", "statusCode", "mimeType"

  @happy @community
  Scenario: Sitemap dump with prefix filter returns only entries under that prefix
    Given Burp has discovered entries for https://target.example.com/api and https://other.example.com
    When I run:
      """
      bp target sitemap --url https://target.example.com --format json
      """
    Then the exit code is 0
    And every JSON line has "url" starting with "https://target.example.com"
    And no JSON line has "url" starting with "https://other.example.com"

  @happy @community
  Scenario: Sitemap dump with deep path prefix filters to that sub-path only
    Given Burp has entries for /api/users, /api/orders, /api/admin, and /health
    When I run:
      """
      bp target sitemap --url https://target.example.com/api/users --format json
      """
    Then the exit code is 0
    And every JSON line has "url" starting with "https://target.example.com/api/users"
    And no JSON line has "url" containing "/api/orders" or "/api/admin" or "/health"

  @happy @community
  Scenario: Sitemap dump returns empty list when no entries match the prefix
    Given Burp has no discovered entries under https://unknown.example.com
    When I run:
      """
      bp target sitemap --url https://unknown.example.com --format json
      """
    Then the exit code is 0
    And stdout is an empty JSON array or produces zero JSON lines

  @happy @community
  Scenario: Sitemap entry with null statusCode is rendered as null (not omitted)
    Given Burp has a sitemap entry for https://target.example.com/ws with no recorded status
    When I run:
      """
      bp target sitemap --url https://target.example.com/ws --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"statusCode\":null"

  @happy @community
  Scenario: Sitemap entry with null mimeType is rendered as null (not omitted)
    Given Burp has a sitemap entry for https://target.example.com/binary with no recorded MIME
    When I run:
      """
      bp target sitemap --url https://target.example.com/binary --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"mimeType\":null"

  @happy @community
  Scenario: Sitemap dump with --fields limits table to url and method columns only
    When I run:
      """
      bp target sitemap --fields url,method
      """
    Then the exit code is 0
    And the output table contains only columns "url", "method"
    And the output table does not contain column "statusCode"
    And the output table does not contain column "mimeType"

  @happy @community
  Scenario: Sitemap dump with -w '%{host} %{method}' prints one line per entry
    Given Burp has 3 sitemap entries for target.example.com
    When I run:
      """
      bp target sitemap --url https://target.example.com -w '%{host} %{method}'
      """
    Then the exit code is 0
    And stdout contains exactly 3 lines each matching "target.example.com <METHOD>"

  @happy @community
  Scenario: Sitemap dump with --quiet produces no stdout and exits 0
    When I run:
      """
      bp target sitemap --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community @ledger
  Scenario: Sitemap dump with --tag records a C4 ledger entry
    When I run:
      """
      bp target sitemap \
        --url https://target.example.com \
        --tag sitemap-recon-phase1
      """
    Then the exit code is 0
    And running "bp log --tag sitemap-recon-phase1" returns 1 entry
    And the ledger entry records burp_op "GET /target/sitemap"
    And the ledger entry records target "target.example.com"

  @happy @community @ledger
  Scenario: Sitemap dump with --no-ledger does not create a ledger entry
    When I run:
      """
      bp target sitemap --url https://target.example.com --no-ledger --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  @fuzz @community
  Scenario Outline: Sitemap fuzz with various URL prefix filters
    When I run:
      """
      bp target sitemap --url <prefix> --format json
      """
    Then the exit code is 0
    And every JSON line (if any) has "url" starting with "<prefix>"

    Examples:
      | prefix                                   |
      | https://target.example.com              |
      | https://target.example.com/api          |
      | https://target.example.com/api/v1       |
      | https://target.example.com/api/v2/users |
      | https://admin.target.example.com        |
      | https://target.example.com/static       |

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /target/scope — reads in-memory scope (NOT the Burp UI scope)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Get scope returns the current in-memory scope as JSON
    Given the in-memory scope includes "https://target.example.com"
    When I run:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And the JSON output contains "https://target.example.com" in the includes list

  @happy @community
  Scenario: Get scope returns table output with includes and excludes by default
    Given the in-memory scope includes "https://target.example.com"
    When I run:
      """
      bp target scope get
      """
    Then the exit code is 0
    And the output table contains columns "type", "url"

  @happy @community
  Scenario: Get scope returns empty includes list when no scope has been set
    Given no scope has been configured via POST /target/scope
    When I run:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And the JSON output contains an empty "includes" list

  @happy @community
  Scenario: Get scope reflects excludes list when excludes have been set
    Given the in-memory scope includes "https://target.example.com"
    And the in-memory scope excludes "https://target.example.com/logout"
    When I run:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And the JSON output contains "https://target.example.com/logout" in the excludes list

  @happy @community
  Scenario: Get scope does NOT reflect scope set in the Burp UI directly
    Given the Burp UI scope contains "https://ui-only.example.com" (set via Burp GUI)
    And no POST /target/scope call has been made for "https://ui-only.example.com"
    When I run:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And the JSON output does NOT contain "https://ui-only.example.com"
    And a comment in the output warns that GET /target/scope shows in-memory state only

  @happy @community
  Scenario: Get scope with --fields limits output to url column only
    When I run:
      """
      bp target scope get --fields url
      """
    Then the exit code is 0
    And the output table contains only column "url"
    And the output table does not contain column "type"

  @happy @community
  Scenario: Get scope with --quiet produces no stdout and exits 0
    When I run:
      """
      bp target scope get --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community @ledger
  Scenario: Get scope with --tag records ledger entry with burp_op GET /target/scope
    When I run:
      """
      bp target scope get --tag scope-audit-start
      """
    Then the exit code is 0
    And running "bp log --tag scope-audit-start" returns 1 entry
    And the ledger entry records burp_op "GET /target/scope"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /target/scope — SetScopeRequest { includes:List<String>, excludes:List<String>=[] }
  # FULL REPLACE: clear + set. includes=[] wipes the entire scope. DESTRUCTIVE.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Set scope with one include URL replaces the entire scope
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --format json
      """
    Then the exit code is 0
    And the JSON output confirms the scope was set
    And GET /target/scope now returns includes containing only "https://target.example.com"

  @happy @community
  Scenario: Set scope with multiple includes sets all of them
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --include https://api.target.example.com \
        --include https://staging.target.example.com \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope returns exactly 3 include entries

  @happy @community
  Scenario: Set scope with excludes list sets both includes and excludes
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --exclude https://target.example.com/logout \
        --exclude https://target.example.com/static \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope returns includes containing "https://target.example.com"
    And GET /target/scope returns excludes containing "https://target.example.com/logout"
    And GET /target/scope returns excludes containing "https://target.example.com/static"

  @happy @community
  Scenario: Set scope default excludes is empty list when --exclude is omitted
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --format json
      """
    Then the exit code is 0
    And the POST /target/scope body sent to :8089 contains "\"excludes\":[]"

  @error @community
  Scenario: Set scope with empty includes list WIPES the entire scope (full replace — destructive)
    Given the in-memory scope previously included "https://target.example.com"
    When I run:
      """
      bp target scope set --format json
      """
    Then the exit code is 0
    And GET /target/scope now returns an empty includes list
    And the previously set URL "https://target.example.com" is no longer in scope

  @error @community
  Scenario: Set scope with includes=[] wipe is non-reversible without re-setting
    Given the in-memory scope includes "https://target.example.com" and "https://api.target.example.com"
    When I run:
      """
      bp target scope set --format json
      """
    Then the exit code is 0
    And GET /target/scope returns an empty scope
    And the only way to restore is to run POST /target/scope again with the desired URLs

  @happy @community
  Scenario: Set scope replaces previous scope completely — old entries are removed
    Given the in-memory scope includes "https://old.example.com"
    When I run:
      """
      bp target scope set \
        --include https://new.example.com \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope does NOT contain "https://old.example.com"
    And GET /target/scope contains "https://new.example.com"

  @happy @community
  Scenario: Set scope with table output shows the new scope state
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --exclude https://target.example.com/logout
      """
    Then the exit code is 0
    And the output table contains columns "type", "url"
    And the output table contains a row with type "include" and url "https://target.example.com"
    And the output table contains a row with type "exclude" and url "https://target.example.com/logout"

  @happy @community
  Scenario: Set scope with --quiet produces no stdout and exits 0
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community @ledger
  Scenario: Set scope with --tag records destructive operation in C4 ledger
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --tag scope-set-engagement-1
      """
    Then the exit code is 0
    And running "bp log --tag scope-set-engagement-1" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope"

  @happy @community @ledger
  Scenario: Set scope wipe with --tag records the destructive wipe in ledger for auditability
    When I run:
      """
      bp target scope set \
        --tag scope-wipe-danger
      """
    Then the exit code is 0
    And running "bp log --tag scope-wipe-danger" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope"
    And the ledger entry status is "ok"

  @fuzz @community
  Scenario Outline: Set scope fuzz with various include/exclude combinations
    When I run:
      """
      bp target scope set <flags> --format json
      """
    Then the exit code is 0
    And GET /target/scope reflects the new scope state

    Examples:
      | flags                                                                                               |
      | --include https://a.example.com                                                                     |
      | --include https://a.example.com --include https://b.example.com                                     |
      | --include https://a.example.com --exclude https://a.example.com/logout                              |
      | --include https://a.example.com --exclude https://a.example.com/logout --exclude https://a.example.com/register |
      | --include https://a.example.com --include https://b.example.com --exclude https://b.example.com/admin |

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /target/scope/add — AddScopeRequest { url:String (required) }
  # Adds a single URL to the in-memory scope (additive, not replace).
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope add appends one URL to the existing in-memory scope
    Given the in-memory scope is empty
    When I run:
      """
      bp target scope add \
        --url https://target.example.com/api \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope returns includes containing "https://target.example.com/api"

  @happy @community
  Scenario: Scope add does not remove previously added URLs (additive behaviour)
    Given the in-memory scope includes "https://target.example.com"
    When I run:
      """
      bp target scope add \
        --url https://api.target.example.com \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope returns includes containing "https://target.example.com"
    And GET /target/scope returns includes containing "https://api.target.example.com"

  @happy @community
  Scenario: Scope add sends AddScopeRequest with url field to /target/scope/add
    When I run:
      """
      bp target scope add --url https://target.example.com/api
      """
    Then the exit code is 0
    And the POST /target/scope/add body sent to :8089 is {"url":"https://target.example.com/api"}

  @happy @community
  Scenario: Scope add with table output shows confirmation of added URL
    When I run:
      """
      bp target scope add --url https://target.example.com/api
      """
    Then the exit code is 0
    And the output table contains "https://target.example.com/api"

  @happy @community
  Scenario: Scope add with --quiet produces no stdout and exits 0
    When I run:
      """
      bp target scope add \
        --url https://target.example.com/api \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Scope add with -w '%{payload}' prints the added URL
    When I run:
      """
      bp target scope add \
        --url https://target.example.com/api \
        -w '%{payload}'
      """
    Then the exit code is 0
    And stdout is exactly "https://target.example.com/api"

  @happy @community @ledger
  Scenario: Scope add with --tag records the URL addition in the C4 ledger
    When I run:
      """
      bp target scope add \
        --url https://target.example.com/api \
        --tag scope-add-api
      """
    Then the exit code is 0
    And running "bp log --tag scope-add-api" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope/add"

  @happy @community @ledger
  Scenario: Scope add with --no-ledger does not create a ledger entry
    When I run:
      """
      bp target scope add \
        --url https://target.example.com/api \
        --no-ledger \
        --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  @error @community
  Scenario: Scope add with missing --url returns INVALID_REQUEST
    When I run:
      """
      bp target scope add
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "url"

  @error @community
  Scenario: Scope add with empty url string returns INVALID_REQUEST
    When I run:
      """
      bp target scope add --url ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @fuzz @community
  Scenario Outline: Scope add fuzz with various URL patterns
    When I run:
      """
      bp target scope add --url <url> --format json
      """
    Then the exit code is 0
    And GET /target/scope includes "<url>"

    Examples:
      | url                                          |
      | https://target.example.com                  |
      | https://target.example.com/api              |
      | https://target.example.com/api/v1           |
      | https://api.target.example.com              |
      | https://staging.target.example.com/api      |
      | https://target.example.com:8443/secure      |
      | http://target.example.com                   |

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /target/scope/remove — AddScopeRequest { url:String (required) }
  # SAME DTO as /scope/add. Removes/excludes a URL from the in-memory scope.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope remove uses AddScopeRequest DTO — same shape as scope add
    When I run:
      """
      bp target scope remove \
        --url https://target.example.com/logout \
        --format json
      """
    Then the exit code is 0
    And the POST /target/scope/remove body sent to :8089 is {"url":"https://target.example.com/logout"}

  @happy @community
  Scenario: Scope remove excludes the URL from the in-memory scope
    Given the in-memory scope includes "https://target.example.com"
    When I run:
      """
      bp target scope remove \
        --url https://target.example.com/logout \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope returns excludes containing "https://target.example.com/logout"

  @happy @community
  Scenario: Scope remove does not affect other included URLs
    Given the in-memory scope includes "https://target.example.com" and "https://api.target.example.com"
    When I run:
      """
      bp target scope remove \
        --url https://target.example.com/logout \
        --format json
      """
    Then the exit code is 0
    And GET /target/scope still includes "https://target.example.com"
    And GET /target/scope still includes "https://api.target.example.com"

  @happy @community
  Scenario: Scope remove with table output shows confirmation
    When I run:
      """
      bp target scope remove --url https://target.example.com/logout
      """
    Then the exit code is 0
    And the output table contains "https://target.example.com/logout"

  @happy @community
  Scenario: Scope remove with --quiet produces no stdout and exits 0
    When I run:
      """
      bp target scope remove \
        --url https://target.example.com/logout \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Scope remove with -w '%{payload}' prints the removed URL
    When I run:
      """
      bp target scope remove \
        --url https://target.example.com/static \
        -w '%{payload}'
      """
    Then the exit code is 0
    And stdout is exactly "https://target.example.com/static"

  @happy @community @ledger
  Scenario: Scope remove with --tag records the removal in the C4 ledger
    When I run:
      """
      bp target scope remove \
        --url https://target.example.com/logout \
        --tag scope-remove-logout
      """
    Then the exit code is 0
    And running "bp log --tag scope-remove-logout" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope/remove"

  @error @community
  Scenario: Scope remove with missing --url returns INVALID_REQUEST
    When I run:
      """
      bp target scope remove
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "url"

  @error @community
  Scenario: Scope remove with empty url string returns INVALID_REQUEST
    When I run:
      """
      bp target scope remove --url ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @fuzz @community
  Scenario Outline: Scope remove fuzz with various exclusion URL patterns
    Given the in-memory scope includes "https://target.example.com"
    When I run:
      """
      bp target scope remove --url <url> --format json
      """
    Then the exit code is 0
    And GET /target/scope excludes contains "<url>"

    Examples:
      | url                                               |
      | https://target.example.com/logout                |
      | https://target.example.com/register              |
      | https://target.example.com/static                |
      | https://target.example.com/assets                |
      | https://target.example.com/favicon.ico           |
      | https://target.example.com/api/health            |

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /target/scope/check — authoritative Burp engine verdict
  # Query param: url:String (required)
  # Reflects the Burp UI scope (unlike GET /target/scope which is in-memory only).
  # Missing url → INVALID_PARAM inside HTTP 200 envelope (NOT a 400 or 404).
  # ScopeCheckRequest DTO is DEAD — url comes from query param only.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope check returns true for a URL that is in the Burp engine scope
    Given the Burp engine scope includes "https://target.example.com"
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api/users \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"inScope\":true"

  @happy @community
  Scenario: Scope check returns false for a URL not in the Burp engine scope
    Given the Burp engine scope does NOT include "https://out-of-scope.example.com"
    When I run:
      """
      bp target scope check \
        --url https://out-of-scope.example.com/api \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"inScope\":false"

  @happy @community
  Scenario: Scope check reflects Burp UI scope — URL set only via UI is checked correctly
    Given the Burp UI scope contains "https://ui-configured.example.com" (set via Burp GUI, not via POST /target/scope)
    When I run:
      """
      bp target scope check \
        --url https://ui-configured.example.com/api \
        --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"inScope\":true"

  @happy @community
  Scenario: Scope check with table output shows url and inScope columns
    When I run:
      """
      bp target scope check --url https://target.example.com/api
      """
    Then the exit code is 0
    And the output table contains columns "url", "inScope"

  @happy @community
  Scenario: Scope check with --quiet produces no stdout and exits 0
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api \
        --quiet
      """
    Then the exit code is 0
    And stdout is empty

  @happy @community
  Scenario: Scope check with -w '%{status} %{payload}' prints verdict on one line
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api \
        -w '%{status} %{payload}'
      """
    Then the exit code is 0
    And stdout matches the pattern "<true_or_false>"

  @happy @community
  Scenario: Scope check with --fields url,inScope narrows output
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api \
        --fields url,inScope
      """
    Then the exit code is 0
    And the output table contains only columns "url", "inScope"

  @happy @community @ledger
  Scenario: Scope check with --tag records the verdict in the C4 ledger
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api \
        --tag scope-check-api
      """
    Then the exit code is 0
    And running "bp log --tag scope-check-api" returns 1 entry
    And the ledger entry records burp_op "GET /target/scope/check"
    And the ledger entry records target "target.example.com"

  @happy @community @ledger
  Scenario: Scope check with --no-ledger does not create a ledger entry
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api \
        --no-ledger \
        --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  @error @community
  Scenario: Scope check without --url returns INVALID_PARAM wrapped in HTTP 200 envelope (early-return)
    # The server sends HTTP 200 but the ApiResponse contains error code INVALID_PARAM.
    # bp must surface this as a non-zero exit code even though HTTP status is 200.
    When I run:
      """
      bp target scope check --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_PARAM"
    And the HTTP response from :8089 was 200 (bp unwraps the envelope to detect the error)

  @error @community
  Scenario: Scope check without --url in raw mode still surfaces INVALID_PARAM from the 200 envelope
    When I run:
      """
      bp target scope check --format raw
      """
    Then the exit code is non-zero
    And the raw response body contains "INVALID_PARAM"
    And the raw response body does NOT contain "\"inScope\""

  @error @community
  Scenario: Scope check with empty url string returns INVALID_PARAM in HTTP 200 envelope
    When I run:
      """
      bp target scope check --url "" --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_PARAM"

  @fuzz @community
  Scenario Outline: Scope check fuzz across various URL patterns to probe engine scope boundary
    When I run:
      """
      bp target scope check --url <url> --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"inScope\":" followed by true or false

    Examples:
      | url                                              |
      | https://target.example.com                      |
      | https://target.example.com/api/v1/users         |
      | https://target.example.com/api/v1/admin         |
      | https://out-of-scope.example.com                |
      | https://target.example.com:8443/secure          |
      | http://target.example.com                       |
      | https://target.example.com/../../etc/passwd     |

  # ═══════════════════════════════════════════════════════════════════════════
  # Agent-mode scenarios (--format json for AX / pipeline integration)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Agent mode — sitemap dump returns compact NDJSON suitable for jq piping
    Given Burp has 5 sitemap entries for target.example.com
    When I run:
      """
      bp target sitemap --url https://target.example.com --format json
      """
    Then the exit code is 0
    And each stdout line is parseable by "jq .url"
    And no line contains pretty-printed JSON (no indentation)

  @happy @community
  Scenario: Agent mode — scope get returns single compact JSON object
    When I run:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON is parseable by "jq .includes"
    And the JSON is parseable by "jq .excludes"

  @happy @community
  Scenario: Agent mode — scope check returns single compact JSON with inScope boolean
    When I run:
      """
      bp target scope check \
        --url https://target.example.com/api \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON is parseable by "jq .inScope"

  @happy @community
  Scenario: Agent mode — scope set returns compact confirmation JSON
    When I run:
      """
      bp target scope set \
        --include https://target.example.com \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (no pretty-print)

  @happy @community
  Scenario: Agent mode — scope check error (missing url) exits non-zero with no JSON on stdout
    When I run:
      """
      bp target scope check --format json
      """
    Then the exit code is non-zero
    And stdout is empty (error is on stderr only, not mixed into NDJSON stream)
    And stderr contains "INVALID_PARAM"

  # ═══════════════════════════════════════════════════════════════════════════
  # Community-edition confirmation — all 6 target endpoints are C (no Pro gate)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: All six target endpoints work under Burp Suite Community edition
    Given Burp Suite Community edition is running at :8089
    When I run each of the following commands:
      | bp target sitemap --format json                                                               |
      | bp target scope get --format json                                                             |
      | bp target scope set --include https://target.example.com --format json                        |
      | bp target scope add --url https://target.example.com/api --format json                        |
      | bp target scope remove --url https://target.example.com/logout --format json                 |
      | bp target scope check --url https://target.example.com/api --format json                     |
    Then all six commands exit with code 0
    And none of the outputs contains "requires Burp Suite Professional"
    And none of the outputs contains "SERVICE_UNAVAILABLE" due to Pro check

  # ═══════════════════════════════════════════════════════════════════════════
  # End-to-end / combined scenarios
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Full scope lifecycle — set, add, remove, verify, all tagged for audit trail
    When I run the set step:
      """
      bp target scope set \
        --include https://target.example.com \
        --tag lifecycle-set
      """
    And I run the add step:
      """
      bp target scope add \
        --url https://api.target.example.com \
        --tag lifecycle-add
      """
    And I run the remove step:
      """
      bp target scope remove \
        --url https://target.example.com/logout \
        --tag lifecycle-remove
      """
    And I run the check step:
      """
      bp target scope check \
        --url https://target.example.com/api/users \
        --tag lifecycle-check \
        --format json
      """
    Then all four commands exit with code 0
    And running "bp log --last 4" shows 4 ledger entries tagged lifecycle-set, lifecycle-add, lifecycle-remove, lifecycle-check
    And the scope check JSON line contains "\"inScope\":true"

  @happy @community
  Scenario: Scope set wipe then re-add — scope is empty after wipe, restored after re-add
    Given the in-memory scope includes "https://target.example.com"
    When I run the wipe step:
      """
      bp target scope set --format json
      """
    Then GET /target/scope returns empty includes
    When I run the restore step:
      """
      bp target scope add --url https://target.example.com --format json
      """
    Then GET /target/scope returns includes containing "https://target.example.com"

  @happy @community
  Scenario: Sitemap-to-scope workflow — dump sitemap, add discovered hosts to scope
    Given Burp has sitemap entries for https://target.example.com and https://api.target.example.com
    When I run:
      """
      bp target sitemap --format json
      """
    And I parse the unique hosts from the JSON output
    And I add each discovered host to scope:
      """
      bp target scope add --url https://target.example.com --format json
      bp target scope add --url https://api.target.example.com --format json
      """
    Then both scope-add commands exit with code 0
    And GET /target/scope returns includes containing both hosts

  @happy @community
  Scenario: Scope check disambiguates in-memory scope from Burp UI scope
    Given POST /target/scope has NOT been called for "https://ui-only.example.com"
    And the Burp UI scope contains "https://ui-only.example.com"
    When I run the in-memory check:
      """
      bp target scope get --format json
      """
    Then the JSON does NOT contain "https://ui-only.example.com"
    When I run the authoritative check:
      """
      bp target scope check --url https://ui-only.example.com --format json
      """
    Then the JSON line contains "\"inScope\":true"
    And this confirms that /scope/check reflects UI scope while /scope/get does not

  @error @community
  Scenario: Scope set wipe is surfaced as a warning by bp when --include is omitted
    When I run:
      """
      bp target scope set
      """
    Then the exit code is 0
    And stderr contains a warning such as "WARNING: includes is empty — all scope entries will be wiped"
    And the POST /target/scope body sent to :8089 contains "\"includes\":[]"

  @happy @community
  Scenario: Repeated scope add of same URL is idempotent — no duplicate entries
    When I run:
      """
      bp target scope add --url https://target.example.com --format json
      """
    And I run again:
      """
      bp target scope add --url https://target.example.com --format json
      """
    Then both commands exit with code 0
    And GET /target/scope does not contain "https://target.example.com" twice in the includes list
