# =============================================================================
# Domain 14 · Config (/config and /extensions)
# Spec reference: SPEC.md §6.10 — 5 endpoints, Community tier (C)
#
# LOAD-BEARING CAVEATS (all scenarios must honour these):
#   1. GET /config/project  → hardcoded stub: always returns {"type":"project"}
#   2. PUT /config/project  → echo stub: reflects the sent payload, no durable write
#   3. GET /config/user     → hardcoded stub: always returns {"type":"user"}
#   4. PUT /config/user     → echo stub: reflects the sent payload, no durable write
#   5. GET /extensions      → self-metadata only; total is ALWAYS 1 (Montoya limit)
#   6. /extensions is mounted at the ROOT (/extensions), NOT at /config/extensions
#
# Kotlin request model for PUT endpoints:
#   ConfigUpdateRequest { config: Map<String,String> }
#
# Global output flags: --format json|table|raw|quiet  (default: table if TTY, json if pipe)
#                      --fields f1,f2,...
#                      -w / --write-out 'TEMPLATE'   tokens: %{status} %{length} %{time} %{payload}
#                      --quiet
#                      --tag NAME
#                      --no-ledger
# =============================================================================

@config
Feature: 14-config — project config, user config, and extension metadata (§6.10)

  As a bug-bounty hunter or AI agent driving bp against Burp Suite on :8089
  I want to read and write project/user configuration and inspect loaded extensions
  So that I can confirm Burp state, script config probes, and surface stub-caveat warnings
  that prevent me from treating echo responses as proof of durable writes.

  Background:
    Given the bp binary is installed and on PATH
    And the Burp REST extension is listening on http://127.0.0.1:8089
    And the default BURP_REST_URL is "http://127.0.0.1:8089"

  # ===========================================================================
  # §6.10 GET /config/project — stub, always {"type":"project"}
  # ===========================================================================

  @happy @community
  Scenario: GET project config returns the hardcoded stub map in table format
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get
      """
    Then the exit code is 0
    And stdout contains a table with at least the column "type"
    And the "type" cell equals "project"
    And stderr is empty

  @happy @community
  Scenario: GET project config in JSON agent mode returns stable single-line envelope
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line matching:
      """
      {"success":true,"data":{"type":"project"},"error":null}
      """
    And the JSON field "success" is true
    And the JSON field "data.type" equals "project"
    And the JSON field "error" is null
    And stderr is empty

  @happy @community
  Scenario: GET project config with --quiet prints only the type value
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --quiet
      """
    Then the exit code is 0
    And stdout is exactly "project"
    And stderr is empty

  @happy @community
  Scenario: GET project config with --write-out extracts the type token
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get -w "%{payload}"
      """
    Then the exit code is 0
    And stdout is exactly "project"
    And stderr is empty

  @happy @community
  Scenario: GET project config with --write-out %{status} returns HTTP 200
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly "200"
    And stderr is empty

  @happy @community
  Scenario: GET project config with --write-out %{time} returns elapsed milliseconds
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get -w "%{time}"
      """
    Then the exit code is 0
    And stdout is a non-negative integer string
    And stderr is empty

  @happy @community
  Scenario: GET project config with --write-out %{length} returns response byte count
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get -w "%{length}"
      """
    Then the exit code is 0
    And stdout is a positive integer string
    And stderr is empty

  @happy @community
  Scenario: GET project config with --write-out multi-token template for scripting
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get -w "%{status} %{time}ms %{length}b"
      """
    Then the exit code is 0
    And stdout matches the pattern "<3-digit-int> <int>ms <int>b"
    And stderr is empty

  @happy @community
  Scenario: GET project config with --fields restricts output columns
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --fields type --format table
      """
    Then the exit code is 0
    And stdout contains the column "type"
    And stdout does NOT contain any column other than "type"
    And stderr is empty

  @happy @community
  Scenario: GET project config raw format returns unmodified HTTP body bytes
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --format raw
      """
    Then the exit code is 0
    And stdout begins with '{"success":true'
    And stdout contains '"type":"project"'
    And stderr is empty

  @happy @community
  Scenario: GET project config in non-TTY pipe context defaults to JSON without --format flag
    Given Burp Suite is running with the REST extension active on port 8089
    When stdout is a pipe (not a TTY) and I run:
      """
      bp config project get | cat
      """
    Then the output is valid compact JSON (not a table)
    And the JSON field "success" is true
    And the JSON field "data.type" equals "project"

  # CAVEAT assertion — bp must warn, not silently lie
  @happy @community
  Scenario: GET project config emits a stub-caveat warning so the caller is not misled
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get
      """
    Then the exit code is 0
    And stderr contains a warning matching "stub" or "hardcoded" or "not the live Burp config"
    And stderr does NOT suppress or hide the caveat when --quiet is NOT passed

  @happy @community
  Scenario: GET project config --quiet suppresses the stub-caveat warning on stderr
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --quiet
      """
    Then the exit code is 0
    And stdout is exactly "project"
    And stderr is empty

  # ===========================================================================
  # §6.10 PUT /config/project — echo stub, ConfigUpdateRequest{config:Map<String,String>}
  # ===========================================================================

  @happy @community
  Scenario: PUT project config echoes the sent payload and warns of no durable write
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"proxy.intercept":"disabled","scanner.enabled":"false"}'
      """
    Then the exit code is 0
    And stdout contains "proxy.intercept"
    And stdout contains "disabled"
    And stderr contains a warning matching "echo" or "stub" or "not persisted" or "no durable write"

  @happy @community
  Scenario: PUT project config in JSON mode returns the echoed config inside data field
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"proxy.intercept":"disabled"}' --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.config.proxy.intercept" equals "disabled"
    And the JSON field "error" is null
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT project config echo stub does not perform a second GET to verify persistence
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"any.key":"any.value"}' --format json
      """
    Then the exit code is 0
    And bp does NOT make a subsequent GET /config/project call to verify the write
    And the JSON field "data.config.any.key" equals "any.value"

  @happy @community
  Scenario: PUT project config with multiple key-value pairs in ConfigUpdateRequest
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set \
        --config '{"upstream.proxy":"127.0.0.1:8080","ssl.verify":"false","timeout.ms":"5000"}' \
        --format json
      """
    Then the exit code is 0
    And the JSON field "data.config.upstream.proxy" equals "127.0.0.1:8080"
    And the JSON field "data.config.ssl.verify" equals "false"
    And the JSON field "data.config.timeout.ms" equals "5000"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT project config --quiet suppresses table/json output but not the caveat warning
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"k":"v"}' --quiet
      """
    Then the exit code is 0
    And stdout is empty or contains only "ok"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT project config with --write-out template extracts echo status
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"x":"y"}' -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly "200"

  @error @community
  Scenario: PUT project config with malformed JSON config value exits non-zero with usage error
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config 'not-valid-json'
      """
    Then the exit code is non-zero (1 or 2)
    And stderr contains "invalid JSON" or "malformed config" or "parse error"
    And stdout is empty

  @error @community
  Scenario: PUT project config with empty config map is rejected or warned
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{}'
      """
    Then the exit code is non-zero OR stderr contains "empty config map has no effect"

  # ===========================================================================
  # §6.10 GET /config/user — stub, always {"type":"user"}
  # ===========================================================================

  @happy @community
  Scenario: GET user config returns the hardcoded stub map in table format
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get
      """
    Then the exit code is 0
    And stdout contains a table with at least the column "type"
    And the "type" cell equals "user"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: GET user config in JSON agent mode returns stable single-line envelope
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line matching:
      """
      {"success":true,"data":{"type":"user"},"error":null}
      """
    And the JSON field "success" is true
    And the JSON field "data.type" equals "user"
    And the JSON field "error" is null
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: GET user config --quiet prints only the type value
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --quiet
      """
    Then the exit code is 0
    And stdout is exactly "user"
    And stderr is empty

  @happy @community
  Scenario: GET user config with --write-out %{payload} returns the type string
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get -w "%{payload}"
      """
    Then the exit code is 0
    And stdout is exactly "user"
    And stderr is empty

  @happy @community
  Scenario: GET user config with --write-out %{status} returns HTTP 200
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly "200"
    And stderr is empty

  @happy @community
  Scenario: GET user config raw format returns unmodified HTTP body bytes
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --format raw
      """
    Then the exit code is 0
    And stdout begins with '{"success":true'
    And stdout contains '"type":"user"'

  # CAVEAT — GET user config must warn identically to GET project config
  @happy @community
  Scenario: GET user config stub caveat warning text is consistent with project config caveat
    Given Burp Suite is running with the REST extension active on port 8089
    When I run both:
      """
      bp config project get 2>&1
      bp config user get 2>&1
      """
    Then both commands emit a matching stub-caveat warning pattern on stderr
    And the warning in each case is not empty and does not differ in severity level

  # Parallel-format contract for GET /config/user
  @happy @community
  Scenario Outline: GET user config output format contract for all supported --format values
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --format <format>
      """
    Then the exit code is 0
    And stdout matches the expected shape for format "<format>"

    Examples:
      | format | expected shape                                              |
      | json   | single compact JSON line; {"success":true,"data":{"type":"user"},...} |
      | table  | aligned column table with at least column TYPE              |
      | raw    | raw bytes from HTTP body; begins with {"success":true       |
      | quiet  | single word: user                                           |

  # ===========================================================================
  # §6.10 PUT /config/user — echo stub, ConfigUpdateRequest{config:Map}
  # ===========================================================================

  @happy @community
  Scenario: PUT user config echoes the sent payload and warns of no durable write
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{"theme":"dark","shortcuts.enabled":"true"}'
      """
    Then the exit code is 0
    And stdout contains "theme"
    And stdout contains "dark"
    And stderr contains a warning matching "echo" or "stub" or "not persisted" or "no durable write"

  @happy @community
  Scenario: PUT user config in JSON mode returns echoed payload in data.config field
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{"theme":"dark","font.size":"14"}' --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.config.theme" equals "dark"
    And the JSON field "data.config.font.size" equals "14"
    And the JSON field "error" is null
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT user config --quiet suppresses normal output but still emits caveat on stderr
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{"k":"v"}' --quiet
      """
    Then the exit code is 0
    And stdout is empty or contains only "ok"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT user config with --write-out template for scripting
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{"display":"compact"}' -w "%{status} %{length}b"
      """
    Then the exit code is 0
    And stdout matches the pattern "200 <int>b"

  @error @community
  Scenario: PUT user config with malformed JSON exits non-zero with parse error
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{bad-json'
      """
    Then the exit code is non-zero
    And stderr contains "invalid JSON" or "parse error" or "malformed config"
    And stdout is empty

  @error @community
  Scenario: PUT user config without --config argument exits with usage error
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set
      """
    Then the exit code is non-zero (2)
    And stderr contains "required" or "missing" or "--config"

  # ===========================================================================
  # §6.10 GET /extensions — mounted at root /extensions (NOT /config/extensions)
  #        total is ALWAYS 1; returns self-metadata (filename of the active extension)
  # ===========================================================================

  @happy @community
  Scenario: GET extensions returns total=1 and the active extension filename in table format
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions
      """
    Then the exit code is 0
    And stdout contains a table with columns: total  filename (or name)
    And the "total" cell equals "1"
    And the "filename" or "name" cell is a non-empty string ending with ".jar" or containing "burp"
    And stderr is empty

  @happy @community
  Scenario: GET extensions in JSON agent mode returns total=1 in stable single-line envelope
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.total" equals 1
    And the JSON field "data.extensions" is an array of length 1
    And the JSON field "error" is null
    And stderr is empty

  @happy @community
  Scenario: GET extensions total is always exactly 1 regardless of how many extensions Burp has loaded
    Given Burp Suite is running with multiple extensions loaded
    When I run:
      """
      bp config extensions --format json
      """
    Then the exit code is 0
    And the JSON field "data.total" equals 1
    And the JSON array "data.extensions" has exactly 1 element
    And stderr contains a caveat matching "Montoya" or "self-metadata" or "total always 1" or "active extension only"

  @happy @community
  Scenario: GET extensions --quiet prints only the filename of the active extension
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --quiet
      """
    Then the exit code is 0
    And stdout is a single non-empty string (the extension filename or name)
    And stderr is empty

  @happy @community
  Scenario: GET extensions with --write-out %{payload} returns the filename token
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions -w "%{payload}"
      """
    Then the exit code is 0
    And stdout is a non-empty string
    And stderr is empty

  @happy @community
  Scenario: GET extensions with --write-out %{status} returns HTTP 200
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions -w "%{status}"
      """
    Then the exit code is 0
    And stdout is exactly "200"
    And stderr is empty

  @happy @community
  Scenario: GET extensions raw format returns unmodified HTTP body bytes
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --format raw
      """
    Then the exit code is 0
    And stdout begins with '{"success":true'
    And stdout contains '"total":1'

  @happy @community
  Scenario: GET extensions with --fields total shows only the total column
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --fields total --format table
      """
    Then the exit code is 0
    And stdout contains the column "total"
    And stdout does NOT contain "filename" or "name"

  # CAVEAT — /extensions is at ROOT not /config/extensions
  @happy @community
  Scenario: bp routes config extensions to /extensions (root) not /config/extensions
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --format json
      """
    Then the exit code is 0
    And the HTTP request made by bp targets the path "/extensions" (not "/config/extensions")
    And the JSON field "data.total" equals 1

  @happy @community
  Scenario: GET extensions Montoya caveat is surfaced to the caller on stderr
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions
      """
    Then the exit code is 0
    And stderr contains a warning matching "only the active extension" or "total always 1" or "Montoya limit"
    And the warning does NOT suppress the normal stdout output

  # ===========================================================================
  # Output format Scenario Outlines — all five endpoints across all formats
  # ===========================================================================

  @happy @community
  Scenario Outline: config project get output adapts to --format flag
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --format <format>
      """
    Then the exit code is 0
    And stdout matches the expected shape for <description>

    Examples:
      | format | description                                          |
      | json   | compact NDJSON: {"success":true,"data":{"type":"project"},"error":null} |
      | table  | aligned table with TYPE column showing "project"     |
      | raw    | raw HTTP body bytes starting with {"success":true    |
      | quiet  | single line containing only "project"                |

  @happy @community
  Scenario Outline: config user get output adapts to --format flag
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --format <format>
      """
    Then the exit code is 0
    And stdout matches the expected shape for <description>

    Examples:
      | format | description                                          |
      | json   | compact NDJSON: {"success":true,"data":{"type":"user"},"error":null} |
      | table  | aligned table with TYPE column showing "user"        |
      | raw    | raw HTTP body bytes starting with {"success":true    |
      | quiet  | single line containing only "user"                   |

  @happy @community
  Scenario Outline: config extensions output adapts to --format flag
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --format <format>
      """
    Then the exit code is 0
    And stdout matches the expected shape for <description>

    Examples:
      | format | description                                                     |
      | json   | compact NDJSON: {"success":true,"data":{"total":1,"extensions":[...]},"error":null} |
      | table  | aligned table with TOTAL column showing "1" and FILENAME column |
      | raw    | raw HTTP body bytes starting with {"success":true               |
      | quiet  | single line with the active extension filename                  |

  # ===========================================================================
  # Run Ledger integration — --tag, --no-ledger for config operations
  # ===========================================================================

  @ledger @happy @community
  Scenario: GET project config with --tag records a LedgerEntry with correct burp_op
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --tag config-probe-001
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value                    |
      | tag     | config-probe-001         |
      | burp_op | GET /config/project      |
      | status  | ok                       |
    And the entry's "command" field contains "bp config project get --tag config-probe-001"

  @ledger @happy @community
  Scenario: PUT project config with --tag records a LedgerEntry with burp_op PUT /config/project
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"k":"v"}' --tag config-write-001
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value                    |
      | tag     | config-write-001         |
      | burp_op | PUT /config/project      |
      | status  | ok                       |

  @ledger @happy @community
  Scenario: GET user config with --tag records a LedgerEntry with burp_op GET /config/user
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --tag user-config-read
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value              |
      | tag     | user-config-read   |
      | burp_op | GET /config/user   |
      | status  | ok                 |

  @ledger @happy @community
  Scenario: PUT user config with --tag records a LedgerEntry with burp_op PUT /config/user
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{"x":"y"}' --tag user-config-write
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value               |
      | tag     | user-config-write   |
      | burp_op | PUT /config/user    |
      | status  | ok                  |

  @ledger @happy @community
  Scenario: GET extensions with --tag records a LedgerEntry with burp_op GET /extensions
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --tag ext-probe-001
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value           |
      | tag     | ext-probe-001   |
      | burp_op | GET /extensions |
      | status  | ok              |

  @ledger @happy @community
  Scenario: --no-ledger on GET project config suppresses Run Ledger recording
    Given Burp Suite is running with the REST extension active on port 8089
    And the Run Ledger currently has N entries
    When I run:
      """
      bp config project get --no-ledger
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  @ledger @happy @community
  Scenario: --no-ledger on PUT project config suppresses Run Ledger recording
    Given Burp Suite is running with the REST extension active on port 8089
    And the Run Ledger currently has N entries
    When I run:
      """
      bp config project set --config '{"k":"v"}' --no-ledger
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  @ledger @happy @community
  Scenario: --no-ledger on GET extensions suppresses Run Ledger recording
    Given Burp Suite is running with the REST extension active on port 8089
    And the Run Ledger currently has N entries
    When I run:
      """
      bp config extensions --no-ledger
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  @ledger @error @community
  Scenario: A failed config GET (Burp down) still records a LedgerEntry with status err
    Given Burp Suite REST extension is NOT reachable at http://127.0.0.1:8089
    When I run:
      """
      bp config project get --tag failed-config-probe
      """
    Then the exit code is non-zero
    And running "bp log --tag failed-config-probe --format json" returns 1 entry
    And that entry has "status": "err"
    And that entry has a non-null "command" field

  # ===========================================================================
  # Agent mode (AX) — stable JSON for AI callers
  # ===========================================================================

  @happy @community
  Scenario: AX agent reads project config to confirm stub shape before scripting
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp config project get --format json --no-ledger
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (no trailing newline issues)
    And the JSON schema is stable: fields success(bool), data.type(str="project"), error(null)
    And the agent can assert data.type == "project" but must NOT treat this as the live Burp project config

  @happy @community
  Scenario: AX agent reads user config in JSON mode and parses the stub type field
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp config user get --format json --no-ledger
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "data.type" equals "user"
    And the agent can assert data.type == "user" but must NOT treat this as live user preferences

  @happy @community
  Scenario: AX agent reads extensions in JSON mode and asserts total=1 (Montoya invariant)
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp config extensions --format json --no-ledger
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data.total" equals 1
    And the agent knows that total will always be 1 regardless of how many extensions are loaded

  @happy @community
  Scenario: AX agent uses -w "%{status} %{payload}" pattern on config project get
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp config project get -w "%{status} %{payload}" --no-ledger
      """
    Then the exit code is 0
    And stdout is exactly "200 project"
    And stderr is empty or contains only the stub-caveat warning

  @happy @community
  Scenario: AX agent uses -w "%{status} %{payload}" pattern on config user get
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp config user get -w "%{status} %{payload}" --no-ledger
      """
    Then the exit code is 0
    And stdout is exactly "200 user"

  @happy @community
  Scenario: AX agent writes project config echo-stub and does NOT assume persistence
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs:
      """
      bp config project set --config '{"scanner.enabled":"false"}' --format json --no-ledger
      """
    Then the exit code is 0
    And the JSON field "data.config.scanner.enabled" equals "false"
    And the agent notes the response is an echo and schedules a GET /config/project to verify
    And the subsequent GET returns {"type":"project"} (the hardcoded stub), not the written value

  @happy @community
  Scenario: AX agent confirms echo-stub by writing then immediately reading — values diverge
    Given Burp Suite is running with the REST extension active on port 8089
    When an AI agent runs in sequence:
      """
      bp config project set --config '{"my.key":"my.value"}' --format json --no-ledger
      bp config project get --format json --no-ledger
      """
    Then the first command returns JSON where "data.config.my.key" equals "my.value"
    And the second command returns JSON where "data.type" equals "project"
    And the second command response does NOT contain "my.key" (proving no durable write occurred)

  @error @community
  Scenario: AX agent receives machine-readable error when Burp is down during config probe
    Given Burp Suite REST extension is NOT reachable at http://127.0.0.1:8089
    When an AI agent runs:
      """
      bp config project get --format json --no-ledger
      """
    Then the exit code is non-zero
    And stdout is a single compact JSON line
    And the JSON field "success" is false
    And the JSON field "error.code" equals "CONNECTION_REFUSED"
    And the agent can branch on success==false to abort the session

  # ===========================================================================
  # Fuzz / edge cases
  # ===========================================================================

  @fuzz @community
  Scenario: PUT project config with a very long string value in the map is echo'd without truncation
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"long.key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.config.long.key" has length 199

  @fuzz @community
  Scenario: PUT project config with special characters in map values is echo'd correctly
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"inject.test":"<script>alert(1)</script>","sql.test":"'' OR ''1''=''1"}' --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.config.inject.test" equals "<script>alert(1)</script>"
    And the JSON field "data.config.sql.test" equals "' OR '1'='1"

  @fuzz @community
  Scenario: PUT user config with Unicode values is echo'd without corruption
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user set --config '{"locale":"日本語","emoji":"🔒"}' --format json
      """
    Then the exit code is 0
    And the JSON field "data.config.locale" equals "日本語"
    And the JSON field "data.config.emoji" equals "🔒"

  @fuzz @community
  Scenario: PUT project config with a large number of keys in the map
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"k1":"v1","k2":"v2","k3":"v3","k4":"v4","k5":"v5","k6":"v6","k7":"v7","k8":"v8","k9":"v9","k10":"v10"}' --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON array "data.config" or the JSON object "data.config" contains all 10 keys

  @fuzz @community
  Scenario: GET project config is idempotent — repeated calls always return {"type":"project"}
    Given Burp Suite is running with the REST extension active on port 8089
    When I run "bp config project get --format json" three times in sequence
    Then all three runs exit 0
    And all three stdout lines are identical: {"success":true,"data":{"type":"project"},"error":null}

  @fuzz @community
  Scenario: GET user config is idempotent — repeated calls always return {"type":"user"}
    Given Burp Suite is running with the REST extension active on port 8089
    When I run "bp config user get --format json" three times in sequence
    Then all three runs exit 0
    And all three stdout lines are identical: {"success":true,"data":{"type":"user"},"error":null}

  @fuzz @community
  Scenario: GET extensions is idempotent — total is always 1 on every call
    Given Burp Suite is running with the REST extension active on port 8089
    When I run "bp config extensions --format json" three times in sequence
    Then all three runs exit 0
    And all three stdout lines contain "\"total\":1"

  @fuzz @community
  Scenario: PUT project config followed immediately by GET project config shows stub divergence
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project set --config '{"foo":"bar"}' --format json --no-ledger
      """
    And then I run:
      """
      bp config project get --format json --no-ledger
      """
    Then the first command's data.config.foo equals "bar"
    And the second command's data equals {"type":"project"} with no "foo" key present
    And this divergence confirms the PUT is an echo stub with no durable side effect

  # ===========================================================================
  # Error paths — Burp not running
  # ===========================================================================

  @error
  Scenario: bp config project get exits non-zero with clear message when Burp is not running
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp config project get
      """
    Then the exit code is non-zero (1 or 2)
    And stderr contains "connection refused" or "Burp is not running" or "unreachable"
    And stderr contains "http://127.0.0.1:8089"
    And stdout is empty

  @error
  Scenario: bp config project get --format json emits machine-readable error when Burp is down
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp config project get --format json
      """
    Then the exit code is non-zero
    And stdout is exactly one JSON line matching:
      """
      {"success":false,"data":null,"error":{"code":"CONNECTION_REFUSED","message":"<non-empty string>"}}
      """
    And the JSON field "success" is false
    And the JSON field "error.code" equals "CONNECTION_REFUSED"

  @error
  Scenario: bp config project set exits non-zero with structured error when Burp is down
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp config project set --config '{"k":"v"}' --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "CONNECTION_REFUSED"

  @error
  Scenario: bp config user get exits non-zero with clear message when Burp is not running
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp config user get --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "CONNECTION_REFUSED"

  @error
  Scenario: bp config user set exits non-zero with structured error when Burp is down
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp config user set --config '{"k":"v"}' --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "CONNECTION_REFUSED"

  @error
  Scenario: bp config extensions exits non-zero with clear message when Burp is not running
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp config extensions --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "CONNECTION_REFUSED"
    And stderr contains "http://127.0.0.1:8089"

  @error
  Scenario: bp config returns HTTP 500 error envelope when extension throws internally
    Given Burp Suite extension returns HTTP 500 with body {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected Throwable"}}
    When I run:
      """
      bp config project get --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "INTERNAL_ERROR"

  # ===========================================================================
  # Cross-domain caveat: /extensions is mounted at root, not /config/extensions
  # ===========================================================================

  @error @community
  Scenario: Accessing /config/extensions via bp returns 404 or error (wrong path guard)
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --raw-path /config/extensions --format json
      """
    Then the exit code is non-zero OR stderr contains "not found" or "404"
    And the response does NOT contain "total":1 on a successful 200

  @happy @community
  Scenario: Confirming /extensions (root path) succeeds while /config/extensions would fail
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --format json
      """
    Then the exit code is 0
    And the HTTP request made by bp targets the path "/extensions"
    And the JSON field "data.total" equals 1
    And the stdout does NOT contain any reference to "/config/extensions"

  # ===========================================================================
  # --fields fine-grained output control
  # ===========================================================================

  @happy @community
  Scenario: GET extensions --fields total,filename returns only those two columns
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config extensions --fields total,filename --format table
      """
    Then the exit code is 0
    And the output table header contains exactly the columns: total, filename
    And no other columns appear

  @happy @community
  Scenario: GET project config --fields type returns only the type column
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config project get --fields type --format json
      """
    Then the exit code is 0
    And the JSON object "data" contains exactly the key "type"
    And no other keys appear inside "data"

  @happy @community
  Scenario: GET user config --fields type returns only the type column
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config user get --fields type --format json
      """
    Then the exit code is 0
    And the JSON object "data" contains exactly the key "type"
    And no other keys appear inside "data"

  # ===========================================================================
  # Scenario Outline: PUT echo-stub contract across project and user
  # ===========================================================================

  @happy @community
  Scenario Outline: PUT config echo stub reflects exactly the sent keys for both resources
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config <resource> set --config '{"<key>":"<value>"}' --format json --no-ledger
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.config.<key>" equals "<value>"
    And stderr contains a stub-caveat warning

    Examples:
      | resource | key              | value           |
      | project  | proxy.intercept  | disabled        |
      | project  | scanner.enabled  | false           |
      | project  | timeout.ms       | 3000            |
      | user     | theme            | dark            |
      | user     | font.size        | 14              |
      | user     | shortcuts        | true            |

  # ===========================================================================
  # BURP_REST_URL override — config group respects env var
  # ===========================================================================

  @happy @community
  Scenario: bp config project get respects a custom BURP_REST_URL environment variable
    Given Burp Suite is running on port 8089 and also listening on port 9089 via forward
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:9089"
    When I run:
      """
      bp config project get --format json
      """
    Then the exit code is 0
    And the HTTP request targets "http://127.0.0.1:9089/config/project"
    And the JSON field "data.type" equals "project"

  @error @community
  Scenario: bp config project get fails cleanly when BURP_REST_URL points to wrong port
    Given no service is listening on port 9999
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:9999"
    When I run:
      """
      bp config project get --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stderr contains "http://127.0.0.1:9999"
