Feature: Target Scope — sitemap dump and in-memory scope management
  As a security researcher or AI agent using `bp`,
  I want to inspect Burp's sitemap and manage the in-memory target scope
  so that I can precisely control which URLs are fuzzed, scanned, or audited.

  Background:
    Given the Burp Suite extension is running and listening on http://127.0.0.1:8089
    And the `bp` CLI is installed and reachable on PATH

  # ─────────────────────────────────────────────────────────────────
  # §6.8 · GET /target/sitemap
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Dump full sitemap in table format (human DX)
    Given Burp's sitemap contains entries for https://shop.example.com
    When I run:
      """
      bp target sitemap --format table
      """
    Then the output is a human-aligned table with columns url, method, statusCode, mimeType
    And at least one row contains "https://shop.example.com"
    And the exit code is 0

  @happy @community
  Scenario: Dump full sitemap in JSON mode (agent AX)
    Given Burp's sitemap contains entries for https://api.example.com
    When I run:
      """
      bp target sitemap --format json
      """
    Then stdout contains one compact JSON object per line, each with schema:
      """
      {"url":"https://api.example.com/v1/users","method":"GET","statusCode":200,"mimeType":"JSON"}
      """
    And null fields are serialised as null (encodeDefaults=true), not omitted
    And the exit code is 0

  @happy @community
  Scenario: Filter sitemap by URL prefix
    Given Burp's sitemap contains entries for both https://api.example.com and https://shop.example.com
    When I run:
      """
      bp target sitemap --url https://api.example.com --format json
      """
    Then every JSON line has a "url" value that starts with "https://api.example.com"
    And no line contains "shop.example.com"
    And the exit code is 0

  @happy @community
  Scenario: Sitemap with --fields restricts output columns (AX field selection)
    Given Burp's sitemap contains entries for https://api.example.com
    When I run:
      """
      bp target sitemap --format json --fields url,method
      """
    Then each JSON line contains only the keys "url" and "method"
    And keys "statusCode" and "mimeType" are absent from every line
    And the exit code is 0

  @happy @community
  Scenario: Sitemap with --write-out template (curl-style DX)
    Given Burp's sitemap contains entries for https://api.example.com/login with status 200
    When I run:
      """
      bp target sitemap --url https://api.example.com -w "%{status} %{payload}"
      """
    Then stdout contains lines of the form "<statusCode> <url>", e.g.:
      """
      200 https://api.example.com/login
      """
    And the exit code is 0

  @happy @community
  Scenario: Sitemap with --quiet prints only essential value per entry
    Given Burp's sitemap contains 3 entries for https://target.example.com
    When I run:
      """
      bp target sitemap --url https://target.example.com --quiet
      """
    Then stdout contains exactly 3 lines, each being the bare URL, e.g.:
      """
      https://target.example.com/
      https://target.example.com/login
      https://target.example.com/api/v1
      """
    And the exit code is 0

  @happy @community @ledger
  Scenario: Sitemap dump is recorded in the Run Ledger by default
    Given Burp's sitemap contains entries for https://target.example.com
    When I run:
      """
      bp target sitemap --url https://target.example.com --tag recon-phase1
      """
    Then the Run Ledger records an entry with:
      | field     | value                             |
      | tag       | recon-phase1                      |
      | burp_op   | GET /target/sitemap               |
      | target    | https://target.example.com        |
      | status    | ok                                |
    And the exit code is 0

  @happy @community @ledger
  Scenario: Sitemap dump skips the Run Ledger when --no-ledger is passed
    When I run:
      """
      bp target sitemap --no-ledger --format json
      """
    Then no entry is written to the Run Ledger
    And the exit code is 0

  @error
  Scenario: Sitemap returns empty result when no Burp traffic has been captured
    Given Burp's sitemap is empty (no traffic proxied yet)
    When I run:
      """
      bp target sitemap --format json
      """
    Then stdout is an empty stream (0 lines)
    And the exit code is 0

  @error
  Scenario: Sitemap prefix filter that matches nothing produces empty output
    Given Burp's sitemap contains entries only for https://shop.example.com
    When I run:
      """
      bp target sitemap --url https://notpresent.example.com --format json
      """
    Then stdout is an empty stream (0 lines)
    And stderr contains a notice such as "no sitemap entries matched prefix https://notpresent.example.com"
    And the exit code is 0

  @error
  Scenario: Sitemap command fails gracefully when Burp is unreachable
    Given the Burp REST API at http://127.0.0.1:8089 is not running
    When I run:
      """
      bp target sitemap --format json
      """
    Then the exit code is non-zero (e.g. 1)
    And stderr contains "connection refused" or "Burp is not reachable at http://127.0.0.1:8089"
    And nothing is written to stdout

  # ─────────────────────────────────────────────────────────────────
  # §6.8 · GET /target/scope  (read in-memory scope)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Read the current in-memory scope in table format
    Given the in-memory scope includes https://api.example.com and excludes https://api.example.com/logout
    When I run:
      """
      bp target scope get --format table
      """
    Then the output shows two sections, "includes" and "excludes", e.g.:
      """
      INCLUDES
      https://api.example.com

      EXCLUDES
      https://api.example.com/logout
      """
    And the exit code is 0

  @happy @community
  Scenario: Read in-memory scope in JSON mode (agent AX)
    Given the in-memory scope includes https://api.example.com
    When I run:
      """
      bp target scope get --format json
      """
    Then stdout is a single compact JSON object:
      """
      {"includes":["https://api.example.com"],"excludes":[]}
      """
    And the exit code is 0

  @happy @community
  Scenario: In-memory scope is empty after a fresh Burp restart
    Given the Burp extension was just loaded (no scope set via API)
    When I run:
      """
      bp target scope get --format json
      """
    Then stdout is:
      """
      {"includes":[],"excludes":[]}
      """
    And the exit code is 0

  @happy @community
  Scenario: Scope get with --quiet prints only include URLs one per line
    Given the in-memory scope includes https://api.example.com and https://admin.example.com
    When I run:
      """
      bp target scope get --quiet
      """
    Then stdout is exactly:
      """
      https://api.example.com
      https://admin.example.com
      """
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # §6.8 · POST /target/scope  (full-replace scope)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Set (full-replace) scope with includes and excludes
    When I run:
      """
      bp target scope set \
        --include https://api.example.com \
        --include https://shop.example.com \
        --exclude https://api.example.com/logout \
        --format json
      """
    Then the REST call sends:
      """
      POST /target/scope
      {"includes":["https://api.example.com","https://shop.example.com"],"excludes":["https://api.example.com/logout"]}
      """
    And stdout is:
      """
      {"success":true,"data":{"includes":["https://api.example.com","https://shop.example.com"],"excludes":["https://api.example.com/logout"]},"error":null}
      """
    And the exit code is 0

  @happy @community
  Scenario: Set scope in quiet mode prints confirmation token only
    When I run:
      """
      bp target scope set --include https://api.example.com --quiet
      """
    Then stdout is exactly:
      """
      ok
      """
    And the exit code is 0

  @happy @community
  Scenario: Set scope with --write-out template showing new include count
    When I run:
      """
      bp target scope set --include https://api.example.com --include https://shop.example.com -w "%{status}"
      """
    Then stdout is exactly:
      """
      200
      """
    And the exit code is 0

  @error
  Scenario: Set scope with empty includes list wipes the entire scope (destructive — spec-documented)
    Given the in-memory scope previously had https://api.example.com as an include
    When I run:
      """
      bp target scope set --format json
      """
    Then the REST call sends:
      """
      POST /target/scope
      {"includes":[],"excludes":[]}
      """
    And the in-memory scope is now empty
    And stderr contains a warning such as "WARNING: --include not provided; this will clear the entire scope"
    And the exit code is 0

  @error
  Scenario: Set scope fails gracefully when Burp is unreachable
    Given the Burp REST API at http://127.0.0.1:8089 is not running
    When I run:
      """
      bp target scope set --include https://api.example.com
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "Burp is not reachable"

  @happy @community @ledger
  Scenario: Scope set is recorded in the Run Ledger
    When I run:
      """
      bp target scope set --include https://api.example.com --tag scope-init
      """
    Then the Run Ledger records an entry with:
      | field   | value                    |
      | tag     | scope-init               |
      | burp_op | POST /target/scope       |
      | status  | ok                       |
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # §6.8 · POST /target/scope/add  (add single URL)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Add a single URL to the in-memory scope
    Given the in-memory scope already includes https://api.example.com
    When I run:
      """
      bp target scope add https://shop.example.com --format json
      """
    Then the REST call sends:
      """
      POST /target/scope/add
      {"url":"https://shop.example.com"}
      """
    And the in-memory scope now includes both https://api.example.com and https://shop.example.com
    And the exit code is 0

  @happy @community
  Scenario: Add URL in quiet mode prints the added URL only
    When I run:
      """
      bp target scope add https://shop.example.com --quiet
      """
    Then stdout is exactly:
      """
      https://shop.example.com
      """
    And the exit code is 0

  @happy @community
  Scenario: Add URL with --write-out template
    When I run:
      """
      bp target scope add https://shop.example.com -w "%{status} %{payload}"
      """
    Then stdout contains:
      """
      200 https://shop.example.com
      """
    And the exit code is 0

  @error
  Scenario: Add URL without providing a URL argument returns error
    When I run:
      """
      bp target scope add --format json
      """
    Then the exit code is non-zero
    And stderr contains "url is required" or similar usage error

  @error
  Scenario: Add URL sends AddScopeRequest with malformed URL — server accepts leniently (isLenient=true)
    When I run:
      """
      bp target scope add not-a-url --format json
      """
    Then the REST call sends:
      """
      POST /target/scope/add
      {"url":"not-a-url"}
      """
    And the server response is HTTP 200 (Burp's scope engine accepts the string as-is)
    And the exit code is 0

  @happy @community @ledger
  Scenario: Scope add is recorded in the Run Ledger with target URL
    When I run:
      """
      bp target scope add https://shop.example.com --tag add-shop
      """
    Then the Run Ledger records an entry with:
      | field   | value                     |
      | tag     | add-shop                  |
      | burp_op | POST /target/scope/add    |
      | target  | https://shop.example.com  |
      | status  | ok                        |
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # §6.8 · POST /target/scope/remove  (exclude / remove single URL)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Remove (exclude) a single URL from the in-memory scope
    Given the in-memory scope includes https://api.example.com and https://api.example.com/logout
    When I run:
      """
      bp target scope remove https://api.example.com/logout --format json
      """
    Then the REST call sends:
      """
      POST /target/scope/remove
      {"url":"https://api.example.com/logout"}
      """
    And the in-memory scope no longer includes https://api.example.com/logout
    And the exit code is 0

  @happy @community
  Scenario: Remove URL in quiet mode prints only the removed URL
    When I run:
      """
      bp target scope remove https://api.example.com/logout --quiet
      """
    Then stdout is exactly:
      """
      https://api.example.com/logout
      """
    And the exit code is 0

  @happy @community
  Scenario: Remove and add share the same DTO shape (AddScopeRequest — spec note)
    # The spec documents that POST /target/scope/remove uses AddScopeRequest { url:String }
    # i.e. the same DTO as /target/scope/add. This scenario validates the wire format.
    When I run:
      """
      bp target scope remove https://api.example.com/logout --format json
      """
    Then the outgoing JSON body is exactly:
      """
      {"url":"https://api.example.com/logout"}
      """
    And the exit code is 0

  @error
  Scenario: Remove URL without a URL argument returns error
    When I run:
      """
      bp target scope remove --format json
      """
    Then the exit code is non-zero
    And stderr contains "url is required" or similar usage error

  @error
  Scenario: Remove URL when Burp is unreachable
    Given the Burp REST API at http://127.0.0.1:8089 is not running
    When I run:
      """
      bp target scope remove https://api.example.com/logout
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "Burp is not reachable"

  # ─────────────────────────────────────────────────────────────────
  # §6.8 · GET /target/scope/check  (authoritative scope verdict)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Check URL that is in scope — table format
    Given https://api.example.com is in Burp's scope (as set via the UI or API)
    When I run:
      """
      bp target scope check https://api.example.com --format table
      """
    Then the REST call is:
      """
      GET /target/scope/check?url=https%3A%2F%2Fapi.example.com
      """
    And the output table shows:
      """
      URL                         IN_SCOPE
      https://api.example.com     true
      """
    And the exit code is 0

  @happy @community
  Scenario: Check URL that is in scope — JSON mode (agent AX)
    Given https://api.example.com is in Burp's scope
    When I run:
      """
      bp target scope check https://api.example.com --format json
      """
    Then stdout is a single compact JSON line:
      """
      {"url":"https://api.example.com","inScope":true}
      """
    And the exit code is 0

  @happy @community
  Scenario: Check URL that is NOT in scope — JSON mode
    Given https://evil.example.com is not in Burp's scope
    When I run:
      """
      bp target scope check https://evil.example.com --format json
      """
    Then stdout is:
      """
      {"url":"https://evil.example.com","inScope":false}
      """
    And the exit code is 0

  @happy @community
  Scenario: Check URL in quiet mode prints only the boolean verdict
    Given https://api.example.com is in Burp's scope
    When I run:
      """
      bp target scope check https://api.example.com --quiet
      """
    Then stdout is exactly:
      """
      true
      """
    And the exit code is 0

  @happy @community
  Scenario: Scope check reflects Burp UI scope (authoritative engine) not the in-memory API scope
    # Spec §6.8: GET /target/scope (in-memory) ≠ /scope/check (Burp engine)
    # A URL set only via UI will appear in check but not in GET /target/scope.
    Given https://burp-ui-only.example.com is added to scope only via the Burp Pro UI
    And the in-memory API scope (GET /target/scope) does NOT include https://burp-ui-only.example.com
    When I run:
      """
      bp target scope check https://burp-ui-only.example.com --format json
      """
    Then stdout is:
      """
      {"url":"https://burp-ui-only.example.com","inScope":true}
      """
    And the exit code is 0

  @happy @community
  Scenario: Check scope with --write-out template
    Given https://api.example.com is in Burp's scope
    When I run:
      """
      bp target scope check https://api.example.com -w "%{payload}"
      """
    Then stdout is exactly:
      """
      true
      """
    And the exit code is 0

  @error
  Scenario: Check scope without a URL argument — server returns INVALID_PARAM in HTTP 200 envelope
    # Spec §6.8: /scope/check without url → INVALID_PARAM inside HTTP 200 (early-return, not 400)
    When I run:
      """
      bp target scope check --format json
      """
    Then the exit code is non-zero
    And stderr contains "url is required" (caught by bp before sending to server)

  @error
  Scenario: Check scope sends empty url param — server wraps INVALID_PARAM in HTTP 200
    # Spec note: ScopeCheckRequest DTO is dead/unused; the handler uses query param directly.
    # If bp sends ?url= (empty string), server returns HTTP 200 with INVALID_PARAM in body.
    When bp sends:
      """
      GET /target/scope/check?url=
      """
    Then the server response body is:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_PARAM","message":"url is required"}}
      """
    And bp surfaces this as an error (exit code non-zero) and prints the error message to stderr

  @error
  Scenario: Check scope when Burp is unreachable
    Given the Burp REST API at http://127.0.0.1:8089 is not running
    When I run:
      """
      bp target scope check https://api.example.com --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "Burp is not reachable"

  @happy @community @ledger
  Scenario: Scope check is recorded in the Run Ledger
    When I run:
      """
      bp target scope check https://api.example.com --tag scope-verify
      """
    Then the Run Ledger records an entry with:
      | field   | value                        |
      | tag     | scope-verify                 |
      | burp_op | GET /target/scope/check      |
      | target  | https://api.example.com      |
      | status  | ok                           |
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # Scope divergence: in-memory vs Burp-UI scope
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Explicit warning when GET /target/scope and /scope/check disagree
    # bp should surface the divergence documented in spec §6.8 to avoid user confusion
    Given the in-memory scope (GET /target/scope) includes https://api.example.com
    And Burp's scope engine (/scope/check) returns inScope=false for https://api.example.com
    When I run:
      """
      bp target scope get --format json
      """
    Then stdout includes https://api.example.com in the includes list
    And stderr contains a notice such as:
      """
      NOTE: /target/scope reflects in-memory state only. Use `bp target scope check <url>` for the authoritative Burp engine verdict.
      """
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # Scope lifecycle — combined workflow
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Full scope lifecycle: set, add, check, remove, verify
    # This scenario walks the complete set → add → check → remove lifecycle in sequence.
    Given Burp is running and the in-memory scope is empty
    When I run:
      """
      bp target scope set --include https://api.example.com --format json
      """
    Then stdout confirms: {"includes":["https://api.example.com"],"excludes":[]}

    When I run:
      """
      bp target scope add https://shop.example.com --format json
      """
    Then stdout confirms the add succeeded

    When I run:
      """
      bp target scope get --format json
      """
    Then stdout includes both https://api.example.com and https://shop.example.com in "includes"

    When I run:
      """
      bp target scope remove https://shop.example.com --format json
      """
    Then stdout confirms the remove succeeded

    When I run:
      """
      bp target scope get --format json
      """
    Then stdout includes only https://api.example.com in "includes"
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # Scope Outline — check bulk list of URLs
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario Outline: Check scope verdict for various URL shapes
    Given Burp is running with scope configured for https://api.example.com
    When I run:
      """
      bp target scope check <url> --format json
      """
    Then stdout is:
      """
      {"url":"<url>","inScope":<expected>}
      """
    And the exit code is 0

    Examples:
      | url                                        | expected |
      | https://api.example.com                    | true     |
      | https://api.example.com/v1/users           | true     |
      | https://api.example.com/v1/orders/42       | true     |
      | https://evil.example.com                   | false    |
      | http://api.example.com                     | false    |
      | https://api.example.com:8443               | false    |
      | https://sub.api.example.com                | false    |

  @happy @community
  Scenario Outline: Sitemap prefix filter with various prefixes
    Given Burp's sitemap contains entries for https://api.example.com and https://shop.example.com
    When I run:
      """
      bp target sitemap --url <prefix> --format json
      """
    Then the output contains <match_count> JSON lines
    And the exit code is 0

    Examples:
      | prefix                         | match_count |
      | https://api.example.com        | many        |
      | https://api.example.com/v1/    | fewer       |
      | https://shop.example.com       | many        |
      | https://notpresent.example.com | 0           |

  @happy @community
  Scenario Outline: Scope set with various include/exclude combinations
    When I run:
      """
      bp target scope set <flags> --format json
      """
    Then the REST body sent is:
      """
      {"includes":<includes_json>,"excludes":<excludes_json>}
      """
    And the exit code is 0

    Examples:
      | flags                                                                                      | includes_json                                         | excludes_json                               |
      | --include https://api.example.com                                                          | ["https://api.example.com"]                           | []                                          |
      | --include https://api.example.com --exclude https://api.example.com/logout                | ["https://api.example.com"]                           | ["https://api.example.com/logout"]          |
      | --include https://api.example.com --include https://shop.example.com                      | ["https://api.example.com","https://shop.example.com"]| []                                          |
      | --include https://api.example.com --exclude https://api.example.com/logout --exclude https://api.example.com/register | ["https://api.example.com"] | ["https://api.example.com/logout","https://api.example.com/register"] |

  # ─────────────────────────────────────────────────────────────────
  # Scope persistence warning (in-memory, resets on Burp restart)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: bp warns that the in-memory scope is lost on Burp restart
    When I run:
      """
      bp target scope set --include https://api.example.com --format json
      """
    Then stderr contains a notice such as:
      """
      NOTE: scope is stored in-memory by the Burp extension and will be reset on restart.
      """
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # ScopeCheckRequest DTO is dead (spec §6.8 flag)
  # ─────────────────────────────────────────────────────────────────

  @error
  Scenario: bp does NOT send a JSON body for GET /target/scope/check (DTO dead — spec flag)
    # Spec §6.8: ScopeCheckRequest = DTO mort (non utilisé). The handler reads only the ?url= query param.
    # bp must send it as a query parameter, NOT as a JSON body.
    Given https://api.example.com is in Burp's scope
    When I run:
      """
      bp target scope check https://api.example.com --format json
      """
    Then the outgoing HTTP request is:
      """
      GET /target/scope/check?url=https%3A%2F%2Fapi.example.com
      """
    And the request has no body
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # ApiResponse envelope validation
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Scope get response is wrapped in ApiResponse envelope
    Given the in-memory scope includes https://api.example.com
    When bp calls GET /target/scope internally
    Then the raw Burp response body matches the ApiResponse<T> schema:
      """
      {"success":true,"data":{"includes":["https://api.example.com"],"excludes":[]},"error":null}
      """
    And bp unwraps .data before presenting output to the user

  @happy @community
  Scenario: Scope add response envelope has success:true on success
    When bp calls POST /target/scope/add with {"url":"https://shop.example.com"}
    Then the raw Burp response body is:
      """
      {"success":true,"data":{...},"error":null}
      """
    And bp presents the unwrapped data to the user
    And the exit code is 0

  @error
  Scenario: Server error response is surfaced with the ApiError code and message
    Given the Burp extension throws an unexpected internal error when processing scope set
    When I run:
      """
      bp target scope set --include https://api.example.com --format json
      """
    Then the server returns:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected failure"}}
      """
    And bp prints to stderr:
      """
      Error [INTERNAL_ERROR]: unexpected failure
      """
    And the exit code is non-zero

  # ─────────────────────────────────────────────────────────────────
  # Sitemap SitemapEntry nullables (encodeDefaults=true)
  # ─────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Sitemap entries with null statusCode and mimeType are serialised as null not omitted
    # Spec §6.8: SitemapEntry statusCode/mimeType are nullable → encodeDefaults=true serialises them as null
    Given Burp's sitemap contains an entry where statusCode and mimeType are unknown
    When I run:
      """
      bp target sitemap --format json
      """
    Then the JSON line for that entry is:
      """
      {"url":"https://api.example.com/unknown","method":"GET","statusCode":null,"mimeType":null}
      """
    And bp does not omit null fields from the output
    And the exit code is 0

  # ─────────────────────────────────────────────────────────────────
  # --no-ledger and --tag interaction
  # ─────────────────────────────────────────────────────────────────

  @ledger
  Scenario: --tag and --no-ledger are mutually exclusive — bp surfaces an error
    When I run:
      """
      bp target scope check https://api.example.com --tag my-tag --no-ledger
      """
    Then the exit code is non-zero
    And stderr contains "--tag and --no-ledger cannot be used together"

  @ledger
  Scenario: scope check without --tag is still recorded in the Run Ledger with auto-generated id
    When I run:
      """
      bp target scope check https://api.example.com --format json
      """
    Then a Run Ledger entry is created with:
      | field   | value                       |
      | burp_op | GET /target/scope/check     |
      | target  | https://api.example.com     |
      | status  | ok                          |
    And the entry has an auto-generated id
    And the exit code is 0
