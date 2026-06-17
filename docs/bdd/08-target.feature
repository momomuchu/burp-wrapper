Feature: Target — scope management and sitemap inspection via bp target commands
  As a security engineer or AI agent driving Burp Suite via `bp`,
  I want to read the Burp sitemap, set/add/remove scope entries,
  and authoritatively check whether a URL is in scope,
  so that I can precisely control what Burp crawls, audits, and fuzzes
  with full observability and clear disclosure of in-memory vs Burp-engine distinctions.

  # ─────────────────────────────────────────────
  # Background: §6.8 contract (source: RestServer.kt / TargetRoutes.kt)
  #
  # All 6 endpoints are Community-compatible (no Pro required).
  # Scope is tracked IN MEMORY (heap JVM) — resets on Burp/extension restart.
  # GET /target/scope  → reads the in-memory scope (NOT the Burp UI scope).
  # GET /target/scope/check → delegates to the Burp scope ENGINE (reflects Burp UI).
  # POST /target/scope → FULL REPLACE: includes=[] WIPES all scope.
  # POST /target/scope/add / /remove → use the SAME DTO: AddScopeRequest {url:String}.
  # GET /target/scope/check without ?url → INVALID_PARAM wrapped in HTTP 200 (not 400).
  # ScopeCheckRequest DTO is DEAD (not used by the handler).
  # SitemapEntry fields statusCode/mimeType are nullable → serialised as null when absent.
  #
  # Output model (all bp commands):
  #   --format json|table|raw|quiet
  #   --fields f1,f2,...
  #   -w, --write-out 'TPL'   tokens: %{status} %{length} %{time} %{payload}
  #                                   %{location} %{anomalous} %{contentType}
  #                                   %{index} %{requestId}
  #   --quiet                 single most essential value
  #   --tag NAME              tag in Run Ledger
  #   --no-ledger             do NOT record in Run Ledger
  #
  # JSON mode = compact single-line-per-record, STABLE schema (AX-friendly).
  # ─────────────────────────────────────────────

  # ══════════════════════════════════════════════
  # GET /target/sitemap
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: Dump the full Burp sitemap as a human-readable table
    Given Burp Suite is running at http://127.0.0.1:8089
    And the proxy history contains traffic for multiple hosts
    When the user runs:
      """
      bp target sitemap --format table
      """
    Then the exit code is 0
    And the output is an aligned table with columns: url, method, statusCode, mimeType
    And at least one row is present

  @happy @community @agent
  Scenario: Dump the full sitemap in JSON mode for AI-agent endpoint discovery
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap contains entries for shop.internal.example.com
    When the user runs:
      """
      bp target sitemap --format json
      """
    Then the exit code is 0
    And stdout is one compact JSON object per line, each matching:
      """
      {"url":"<string>","method":"<string>","statusCode":<int|null>,"mimeType":"<string|null>"}
      """
    And statusCode and mimeType may be null (encodeDefaults=true, nullable per spec)
    And the JSON schema is stable across invocations

  @happy @community
  Scenario: Filter sitemap by URL prefix to narrow results to one host
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap contains entries for api.example.com and shop.example.com
    When the user runs:
      """
      bp target sitemap --url https://api.example.com --format table
      """
    Then the exit code is 0
    And every row in the output has a url starting with "https://api.example.com"
    And no rows for shop.example.com appear in the output

  @happy @community
  Scenario: Filter sitemap by a path prefix to scope discovery to a subtree
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap contains /api/v1/users, /api/v1/orders, /api/v2/products
    When the user runs:
      """
      bp target sitemap --url https://app.example.com/api/v1 --format table
      """
    Then the exit code is 0
    And all returned entries have URLs beginning with "https://app.example.com/api/v1"
    And /api/v2/products does not appear

  @happy @community
  Scenario: Sitemap returns empty list when no traffic has been captured (graceful)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the Burp sitemap is empty
    When the user runs:
      """
      bp target sitemap --format json
      """
    Then the exit code is 0
    And stdout is {"success":true,"data":[]} or an empty JSON array
    And bp does NOT raise an error — an empty sitemap is valid

  @happy @community
  Scenario: Sitemap with --quiet prints the count of discovered entries
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap contains 47 entries
    When the user runs:
      """
      bp target sitemap --quiet
      """
    Then stdout is a single integer on one line: "47"
    And stderr is empty

  @happy @community
  Scenario: Sitemap with --fields url,method limits output columns
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap contains several entries
    When the user runs:
      """
      bp target sitemap --fields url,method --format table
      """
    Then the output table shows exactly two columns: url and method
    And statusCode and mimeType columns do not appear

  @happy @community
  Scenario: Sitemap with -w write-out template to extract only url per line (wordlist generation)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap contains entries for target.example.com
    When the user runs:
      """
      bp target sitemap --url https://target.example.com -w "%{location}"
      """
    Then stdout contains one URL per line, for example:
      """
      https://target.example.com/api/v1/users
      https://target.example.com/api/v1/orders
      https://target.example.com/admin/dashboard
      """
    And each line is a bare URL with no extra columns

  @happy @community @ledger
  Scenario: Sitemap dump is tagged and recorded in the Run Ledger
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target sitemap --tag recon-sitemap-2026 --format json
      """
    Then the exit code is 0
    And the Run Ledger records an entry tagged "recon-sitemap-2026" with burp_op="/target/sitemap"

  @happy @community
  Scenario: Sitemap with --no-ledger suppresses Run Ledger recording
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target sitemap --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is written for this invocation

  @error @community
  Scenario: Sitemap fails when Burp REST API is unreachable
    Given no process is listening on http://127.0.0.1:8089
    When the user runs:
      """
      bp target sitemap --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "unable to reach Burp at http://127.0.0.1:8089"

  # ══════════════════════════════════════════════
  # GET /target/scope
  # in-memory scope — does NOT reflect the Burp UI scope
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: Read the current in-memory scope as a human-readable table
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope contains includes=[https://app.example.com] excludes=[https://app.example.com/logout]
    When the user runs:
      """
      bp target scope get --format table
      """
    Then the exit code is 0
    And the output table shows columns: type, url
    And a row with type="include" and url="https://app.example.com" is present
    And a row with type="exclude" and url="https://app.example.com/logout" is present

  @happy @community @agent
  Scenario: Read in-memory scope in JSON mode for agent scope-awareness check
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope has includes and excludes populated
    When the user runs:
      """
      bp target scope get --format json
      """
    Then stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"includes":["<url>",...],"excludes":["<url>",...]}}
      """
    And the JSON schema is stable

  @happy @community
  Scenario: GET /target/scope returns empty lists when in-memory scope is blank
    Given Burp Suite is running at http://127.0.0.1:8089
    And no scope has been set via bp (in-memory scope is empty)
    When the user runs:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And stdout is {"success":true,"data":{"includes":[],"excludes":[]}}

  @happy @community
  Scenario: GET scope with --quiet prints the count of included URLs only
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope includes 3 URLs
    When the user runs:
      """
      bp target scope get --quiet
      """
    Then stdout is a single integer: "3"
    And stderr is empty

  @happy @community
  Scenario: bp discloses that GET /target/scope reads in-memory state (not Burp UI scope)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the user has added URLs to scope via the Burp Suite UI (not via bp)
    When the user runs:
      """
      bp target scope get --format json
      """
    Then the exit code is 0
    And the response does NOT include URLs set only via the Burp UI
    And bp emits a note: "Note: GET /target/scope reads the bp in-memory scope, which does not reflect URLs added via the Burp Suite UI. Use 'bp target scope check --url <url>' for authoritative Burp engine verdict."

  # ══════════════════════════════════════════════
  # POST /target/scope  (FULL REPLACE — critical caveat)
  # SetScopeRequest { includes:List<String> (required), excludes:List<String>=[] }
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: Set scope with includes and excludes — replaces any previous scope (table output)
    Given Burp Suite is running at http://127.0.0.1:8089
    And a previous scope exists with includes=[https://old.example.com]
    When the user runs:
      """
      bp target scope set \
        --includes https://shop.internal.example.com,https://api.shop.example.com \
        --excludes https://shop.internal.example.com/logout \
        --format table
      """
    Then the exit code is 0
    And the output table confirms the new scope:
      | type    | url                                        |
      | include | https://shop.internal.example.com          |
      | include | https://api.shop.example.com               |
      | exclude | https://shop.internal.example.com/logout   |
    And the old scope entry "https://old.example.com" is no longer present

  @happy @community @agent
  Scenario: Set scope in JSON mode for pipeline automation
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set \
        --includes https://api.target.example.com,https://auth.target.example.com \
        --excludes https://api.target.example.com/health \
        --format json
      """
    Then stdout is a single compact JSON line:
      """
      {"success":true,"data":{"includes":["https://api.target.example.com","https://auth.target.example.com"],"excludes":["https://api.target.example.com/health"]}}
      """
    And the JSON is parseable with stable field names

  @happy @community
  Scenario: Set scope with only includes (no excludes) — excludes defaults to empty list
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set \
        --includes https://intranet.example.com \
        --format json
      """
    Then the exit code is 0
    And stdout contains {"success":true,"data":{"includes":["https://intranet.example.com"],"excludes":[]}}

  @error @community
  Scenario: Set scope with empty includes list WIPES the entire scope (critical full-replace caveat)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope currently contains includes=[https://app.example.com]
    When the user runs:
      """
      bp target scope set --includes "" --format json
      """
    Then the exit code is 0
    And stdout contains {"success":true,"data":{"includes":[],"excludes":[]}}
    And the in-memory scope is now empty (all includes wiped)
    And bp emits a prominent warning on stderr:
      """
      Warning: POST /target/scope is a FULL REPLACE. Passing empty --includes has wiped all scope entries.
      """

  @error @community
  Scenario: Set scope without --includes argument returns an error (includes is required)
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set --format json
      """
    Then the exit code is non-zero
    And stderr contains "includes is required"
    And the existing scope is NOT modified

  @happy @community @ledger
  Scenario: Set scope is tagged and recorded in the Run Ledger
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set \
        --includes https://audit.example.com \
        --tag scope-set-engagement-2026 --format table
      """
    Then the Run Ledger entry tagged "scope-set-engagement-2026" has:
      | field   | value               |
      | burp_op | /target/scope (POST)|
      | target  | audit.example.com   |

  @happy @community
  Scenario Outline: Set scope with various include/exclude combinations
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set --includes <includes> --excludes <excludes> --format json
      """
    Then the exit code is 0
    And stdout contains {"success":true,...}
    And the in-memory scope reflects the new values

    Examples:
      | includes                                                      | excludes                                |
      | https://app.example.com                                       |                                         |
      | https://app.example.com,https://api.example.com               | https://app.example.com/static          |
      | https://internal.corp.example.com/api/v2                      | https://internal.corp.example.com/ping  |
      | https://staging.example.com,https://staging-api.example.com   | https://staging.example.com/logout      |

  @happy @community
  Scenario: Full-replace: POST scope after add operations resets to only the posted includes
    Given Burp Suite is running at http://127.0.0.1:8089
    And the user previously added https://extra.example.com via "bp target scope add"
    When the user runs:
      """
      bp target scope set \
        --includes https://app.example.com \
        --format json
      """
    Then the exit code is 0
    And the in-memory scope includes list contains ONLY "https://app.example.com"
    And "https://extra.example.com" is no longer in the includes list

  @happy @community
  Scenario: Set scope with --no-ledger suppresses Run Ledger recording
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set --includes https://target.example.com --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is written for this operation

  # ══════════════════════════════════════════════
  # POST /target/scope/add
  # AddScopeRequest { url:String (required) }
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: Add a single URL to the in-memory scope (table output)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope includes=[https://app.example.com]
    When the user runs:
      """
      bp target scope add --url https://api.app.example.com --format table
      """
    Then the exit code is 0
    And the output confirms the URL was added
    And the in-memory scope now includes both "https://app.example.com" and "https://api.app.example.com"

  @happy @community @agent
  Scenario: Add a URL to scope in JSON mode for programmatic scope building
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --url https://auth.example.com --format json
      """
    Then stdout is a single compact JSON line:
      """
      {"success":true,"data":{"url":"https://auth.example.com","added":true}}
      """
    And the JSON field "added" is true

  @happy @community
  Scenario: Add a URL with --quiet prints only the confirmation value
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --url https://new.example.com --quiet
      """
    Then stdout is a single line: "added"
    And stderr is empty

  @happy @community @ledger
  Scenario: Add scope URL is tagged and recorded in the Run Ledger
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add \
        --url https://intranet.example.com/api \
        --tag add-scope-intranet --format table
      """
    Then the Run Ledger entry tagged "add-scope-intranet" has burp_op="/target/scope/add"
    And the target field shows "intranet.example.com"

  @error @community
  Scenario: Add scope fails when --url argument is missing
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --format json
      """
    Then the exit code is non-zero
    And stderr or stdout contains "url is required"
    And the in-memory scope is NOT modified

  @error @community
  Scenario: Add scope fails when --url is an empty string
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --url "" --format json
      """
    Then the exit code is non-zero
    And stdout contains {"success":false,"error":{"code":"INVALID_REQUEST",...}}

  @happy @community
  Scenario: Add the same URL twice — second add is idempotent (no duplicate in scope)
    Given Burp Suite is running at http://127.0.0.1:8089
    And "https://app.example.com" is already in the in-memory scope
    When the user runs:
      """
      bp target scope add --url https://app.example.com --format json
      """
    Then the exit code is 0
    And the in-memory scope includes list does not contain duplicates of "https://app.example.com"

  @happy @community
  Scenario: Add scope with --no-ledger suppresses Run Ledger recording
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --url https://target.example.com --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is written for this operation

  @happy @community
  Scenario Outline: Add various URL forms to scope
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --url <url> --format json
      """
    Then the exit code is 0
    And stdout contains {"success":true,...}

    Examples:
      | url                                          |
      | https://app.example.com                      |
      | https://api.example.com/v1                   |
      | https://internal.corp.example.com:8443/admin |
      | http://legacy.example.com                    |

  # ══════════════════════════════════════════════
  # POST /target/scope/remove
  # AddScopeRequest { url:String } — SAME DTO as add (per spec)
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: Remove a URL from the in-memory scope (table output)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope includes=[https://app.example.com, https://api.example.com]
    When the user runs:
      """
      bp target scope remove --url https://api.example.com --format table
      """
    Then the exit code is 0
    And the output confirms the URL was removed
    And the in-memory scope no longer contains "https://api.example.com"
    And "https://app.example.com" is still present in the scope

  @happy @community @agent
  Scenario: Remove a URL from scope in JSON mode for automated scope trimming
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope contains https://staging.example.com
    When the user runs:
      """
      bp target scope remove --url https://staging.example.com --format json
      """
    Then stdout is a single compact JSON line:
      """
      {"success":true,"data":{"url":"https://staging.example.com","removed":true}}
      """

  @happy @community
  Scenario: Remove a URL that was never in scope — graceful no-op
    Given Burp Suite is running at http://127.0.0.1:8089
    And "https://ghost.example.com" is NOT in the in-memory scope
    When the user runs:
      """
      bp target scope remove --url https://ghost.example.com --format json
      """
    Then the exit code is 0
    And bp does NOT error — removing a non-existent URL is a graceful no-op
    And the in-memory scope is unchanged

  @error @community
  Scenario: Remove scope fails when --url is missing
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope remove --format json
      """
    Then the exit code is non-zero
    And stderr or stdout contains "url is required"

  @happy @community @ledger
  Scenario: Remove scope URL is recorded in the Run Ledger
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://retired.example.com is in the in-memory scope
    When the user runs:
      """
      bp target scope remove \
        --url https://retired.example.com \
        --tag remove-scope-retired --format table
      """
    Then the Run Ledger entry tagged "remove-scope-retired" has burp_op="/target/scope/remove"

  @happy @community
  Scenario: bp discloses that add and remove share the same AddScopeRequest DTO
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --help
      """
    Then the help text notes that "scope add" and "scope remove" share the same request shape: { url: String }

  # ══════════════════════════════════════════════
  # GET /target/scope/check  (authoritative — Burp engine)
  # query: url:String (required)
  # Key caveat: missing url → INVALID_PARAM in HTTP 200 body (not a 4xx response)
  # ScopeCheckRequest DTO is DEAD — handler uses query param only
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: Check a URL that is in scope — Burp engine returns in-scope verdict (table)
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://app.example.com is configured in the Burp Suite scope (UI)
    When the user runs:
      """
      bp target scope check --url https://app.example.com/api/v1/users --format table
      """
    Then the exit code is 0
    And the output table shows columns: url, inScope
    And the inScope column is "true"

  @happy @community @agent
  Scenario: Check a URL in JSON mode for agent scope-gating decisions
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://api.target.example.com is in the Burp Suite UI scope
    When the user runs:
      """
      bp target scope check --url https://api.target.example.com/v2/orders --format json
      """
    Then stdout is a single compact JSON line:
      """
      {"success":true,"data":{"url":"https://api.target.example.com/v2/orders","inScope":true}}
      """
    And the JSON field "data.inScope" is true
    And the JSON schema is stable

  @happy @community
  Scenario: Check a URL that is NOT in scope — Burp engine returns false verdict
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://out-of-scope.example.com is NOT configured in the Burp Suite scope
    When the user runs:
      """
      bp target scope check --url https://out-of-scope.example.com/login --format json
      """
    Then the exit code is 0
    And stdout contains {"success":true,"data":{"url":"https://out-of-scope.example.com/login","inScope":false}}

  @happy @community
  Scenario: Scope check with --quiet prints only the boolean verdict
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://app.example.com is in scope
    When the user runs:
      """
      bp target scope check --url https://app.example.com --quiet
      """
    Then stdout is a single line: "true"
    And stderr is empty

  @error @community
  Scenario: Scope check without --url returns INVALID_PARAM wrapped in HTTP 200 (not a 4xx)
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope check --format json
      """
    Then the HTTP response from Burp is 200 (not 400 or 422)
    And the response body contains {"success":false,"error":{"code":"INVALID_PARAM",...}}
    And the exit code is non-zero (bp translates the INVALID_PARAM to a non-zero exit)
    And bp emits a clear message: "url query parameter is required for scope check"

  @error @community
  Scenario: Scope check with an empty --url string returns INVALID_PARAM
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope check --url "" --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains a reference to "INVALID_PARAM" or "url is required"

  @happy @community
  Scenario: bp discloses that scope/check reflects the Burp UI scope (not the in-memory scope)
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://ui-only.example.com is added via Burp Suite UI scope but NOT via bp
    When the user runs:
      """
      bp target scope check --url https://ui-only.example.com --format json
      """
    Then stdout contains {"success":true,"data":{"url":"https://ui-only.example.com","inScope":true}}
    And bp emits a note: "Note: scope check uses the Burp engine (reflects Burp UI scope). This may differ from 'bp target scope get' which reads the bp in-memory scope only."

  @happy @community
  Scenario: bp discloses that ScopeCheckRequest DTO is dead — handler uses query param only
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope check --help
      """
    Then the help text notes: "scope check uses the ?url= query parameter. Any request body (ScopeCheckRequest DTO) is ignored by the Burp extension handler."

  @happy @community @ledger
  Scenario: Scope check is tagged and recorded in the Run Ledger
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope check \
        --url https://api.example.com/payments \
        --tag scope-check-payments --format json
      """
    Then the Run Ledger entry tagged "scope-check-payments" has:
      | field   | value                            |
      | burp_op | /target/scope/check              |
      | target  | api.example.com                  |

  @happy @community
  Scenario: Scope check with --no-ledger suppresses Run Ledger recording
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope check \
        --url https://target.example.com \
        --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is written

  @happy @community
  Scenario Outline: Scope check on a variety of URL forms (in-scope vs out-of-scope)
    Given Burp Suite is running at http://127.0.0.1:8089
    And the Burp Suite scope is configured with https://app.example.com
    When the user runs:
      """
      bp target scope check --url <url> --format json
      """
    Then the exit code is 0
    And stdout contains {"success":true,"data":{"url":"<url>","inScope":<expected>}}

    Examples:
      | url                                              | expected |
      | https://app.example.com                          | true     |
      | https://app.example.com/api/v1/users             | true     |
      | https://app.example.com/admin                    | true     |
      | https://other.example.com                        | false    |
      | https://app.other-domain.com                     | false    |
      | http://app.example.com                           | false    |

  # ══════════════════════════════════════════════
  # CROSS-CUTTING: in-memory vs Burp-engine distinction
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: GET scope vs scope/check show different results when Burp UI scope differs from in-memory scope
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://ui-configured.example.com is in the Burp Suite UI scope
    And the bp in-memory scope is empty (no bp scope commands have been run)
    When the user runs "bp target scope get --format json"
    Then stdout shows includes=[] (in-memory is empty)
    When the user runs "bp target scope check --url https://ui-configured.example.com --format json"
    Then stdout shows inScope=true (Burp engine sees the UI scope)
    And bp makes the divergence visible to the user

  @happy @community
  Scenario: After POST /target/scope set, GET /target/scope reflects new in-memory state immediately
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set --includes https://newscope.example.com --format json
      """
    And the user runs:
      """
      bp target scope get --format json
      """
    Then the second command shows includes=["https://newscope.example.com"] in the response
    And the state is updated synchronously (no eventual consistency lag)

  @happy @community
  Scenario: Add then remove a URL leaves in-memory scope unchanged from baseline
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope starts empty
    When the user runs:
      """
      bp target scope add --url https://temp.example.com --format json
      """
    And then runs:
      """
      bp target scope remove --url https://temp.example.com --format json
      """
    And then runs:
      """
      bp target scope get --format json
      """
    Then the final GET response shows includes=[] (scope restored to empty)

  # ══════════════════════════════════════════════
  # CROSS-CUTTING: Burp restart / in-memory reset
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: bp warns that in-memory scope is lost on Burp/extension restart
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set --includes https://app.example.com --format table
      """
    Then bp emits a note: "Note: scope is held in-memory (JVM heap). It will be lost when Burp Suite or the bp extension is restarted. Use 'bp target scope set' to restore scope at the start of each session."

  # ══════════════════════════════════════════════
  # CROSS-CUTTING: output model coverage
  # ══════════════════════════════════════════════

  @happy @community @agent
  Scenario: Scope check format matrix — table vs json vs quiet
    Given Burp Suite is running at http://127.0.0.1:8089
    And https://app.example.com is in the Burp UI scope

    When the user runs "bp target scope check --url https://app.example.com --format table"
    Then stdout is a human-aligned table with column headers url and inScope

    When the user runs "bp target scope check --url https://app.example.com --format json"
    Then stdout is a single compact JSON line {"success":true,"data":{"url":"https://app.example.com","inScope":true}}

    When the user runs "bp target scope check --url https://app.example.com --quiet"
    Then stdout is exactly: "true"

  @happy @community
  Scenario: Sitemap with -w write-out using %{status} and %{contentType} tokens
    Given Burp Suite is running at http://127.0.0.1:8089
    And the sitemap has entries including a 200/HTML and a 302/null entry
    When the user runs:
      """
      bp target sitemap --url https://app.example.com -w "%{status} %{contentType}"
      """
    Then stdout contains lines like:
      """
      200 HTML
      302 null
      404 null
      """
    And each line has exactly two space-separated tokens (status code and MIME type or "null")

  @happy @community
  Scenario: Scope get with --fields includes to show only the includes list
    Given Burp Suite is running at http://127.0.0.1:8089
    And the in-memory scope has includes and excludes
    When the user runs:
      """
      bp target scope get --fields includes --format json
      """
    Then stdout contains only the "includes" field in the data object
    And the "excludes" field is not present in the output

  # ══════════════════════════════════════════════
  # EDGE CASES: malformed input and error paths
  # ══════════════════════════════════════════════

  @error @community
  Scenario: Scope set with malformed JSON body (when using raw API pass-through) returns INVALID_REQUEST
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs a raw API call equivalent to:
      """
      POST /target/scope  body: {includes: [unclosed}
      """
    Then the Burp extension returns HTTP 400 with {"success":false,"error":{"code":"INVALID_REQUEST",...}}
    And bp surfaces the error with exit code non-zero

  @error @community
  Scenario: Scope add with a URL containing no scheme is rejected by bp before sending to Burp
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope add --url "app.example.com" --format json
      """
    Then the exit code is non-zero
    And stderr contains a validation error about missing URL scheme (https:// or http://)

  @error @community
  Scenario: All target commands fail gracefully when Burp REST API is down
    Given no process is listening on http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope get --format json
      """
    Then the exit code is non-zero
    And stderr contains "connection refused" or "unable to reach Burp at http://127.0.0.1:8089"
    And no Run Ledger entry is created for a failed connection

  @error @community
  Scenario: Scope check with a URL longer than a reasonable limit is handled gracefully
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs a scope check with a URL of 4096+ characters
    Then bp either rejects it locally with a clear error or passes it to Burp and surfaces the response
    And the exit code and stderr make the failure reason clear

  # ══════════════════════════════════════════════
  # CROSS-CUTTING: Run Ledger full coverage
  # ══════════════════════════════════════════════

  @ledger @community
  Scenario: Run Ledger records all target operations with correct burp_op fields
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs "bp target sitemap --tag op-sitemap"
    And the user runs "bp target scope get --tag op-scope-get"
    And the user runs "bp target scope set --includes https://a.example.com --tag op-scope-set"
    And the user runs "bp target scope add --url https://b.example.com --tag op-scope-add"
    And the user runs "bp target scope remove --url https://b.example.com --tag op-scope-remove"
    And the user runs "bp target scope check --url https://a.example.com --tag op-scope-check"
    Then "bp log --tag op-sitemap" shows burp_op="/target/sitemap"
    And "bp log --tag op-scope-get" shows burp_op="/target/scope" (GET)
    And "bp log --tag op-scope-set" shows burp_op="/target/scope" (POST)
    And "bp log --tag op-scope-add" shows burp_op="/target/scope/add"
    And "bp log --tag op-scope-remove" shows burp_op="/target/scope/remove"
    And "bp log --tag op-scope-check" shows burp_op="/target/scope/check"

  @ledger @community
  Scenario: --no-ledger suppresses recording for any target subcommand
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs "bp target sitemap --no-ledger --format json"
    And the user runs "bp target scope get --no-ledger --format json"
    And the user runs "bp target scope check --url https://app.example.com --no-ledger --format json"
    Then the Run Ledger has no new entries from any of these three invocations

  # ══════════════════════════════════════════════
  # CAVEAT DISCLOSURE: spec flags surfaced to users
  # ══════════════════════════════════════════════

  @happy @community
  Scenario: bp discloses the full-replace semantics of POST /target/scope in --help
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope set --help
      """
    Then the help text includes: "WARNING: POST /target/scope performs a FULL REPLACE of all scope entries. Passing --includes with an empty list will wipe all scope."
    And the help text mentions: "Use 'bp target scope add' to append a single URL without replacing existing scope."

  @happy @community
  Scenario: bp discloses that GET /target/scope and Burp UI scope are independent in --help
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target scope --help
      """
    Then the help text includes: "Note: 'bp target scope get' reads bp's in-memory scope (heap JVM, reset on restart). It does not reflect scope configured via the Burp Suite UI. Use 'bp target scope check --url <url>' for the authoritative Burp engine verdict."

  @happy @community
  Scenario: bp discloses that the entire /target group is absent from the embedded /docs OpenAPI
    Given Burp Suite is running at http://127.0.0.1:8089
    When the user runs:
      """
      bp target --help
      """
    Then the help text includes a note that /target endpoints are absent from the Burp /docs OpenAPI (version 0.2.0)
    And the help text directs users to SPEC.md §6.8 as the authoritative source
