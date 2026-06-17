# =============================================================================
# Domain 11 · Run Ledger (C4 — observability / ISO traceability)
# Spec reference: SPEC.md §9 — C4 Run Ledger
# Every bp operation is auto-recorded in ~/.bp/ SQLite (LedgerEntry aggregate).
# Fields per entry: id(local), name/tag, timestamp, target(host/url),
#   command(raw bp argv), request_ref, response_ref, status(ok/err), burp_op.
# CLI surface: `bp log`, `bp tag <id> <label>`, `bp show <id>`.
# Global flags under test: --tag, --no-ledger, --format, --fields, -w, --quiet.
# =============================================================================

@ledger
Feature: Run Ledger — every bp operation is recorded, queryable, and replayable

  As a bug-bounty hunter or security auditor
  I want every bp operation automatically recorded in a local SQLite ledger
  So that I can prove, date, and replay every action taken against a target (ISO traceability)

  Background:
    Given the bp CLI is installed and on PATH
    And the Burp Suite REST extension is listening on http://127.0.0.1:8089
    And the Run Ledger DB has been initialised at ~/.bp/ledger.db
    And the proxy history contains at least one entry with requestId 7 targeting api.acme.corp

  # ---------------------------------------------------------------------------
  # AUTO-RECORDING — every op writes a LedgerEntry
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: A repeater send auto-records a LedgerEntry with status ok
    Given no prior ledger entries exist for tag "baseline-check"
    When I run:
      """
      bp repeater send --id 7 --tag baseline-check
      """
    Then the exit code is 0
    And a new entry appears in `bp log` with fields:
      | field       | value                                        |
      | tag         | baseline-check                               |
      | target      | api.acme.corp                                |
      | burp_op     | POST /repeater/send                          |
      | status      | ok                                           |
    And the entry's `command` field contains the exact string "bp repeater send --id 7 --tag baseline-check"
    And the entry's `timestamp` is an ISO-8601 datetime within the last 60 seconds

  @happy @community @ledger
  Scenario: A quick-fuzz auto-records a LedgerEntry with status ok
    When I run:
      """
      bp fuzz quick --id 12 --param q \
        --payloads "' OR '1'='1,<script>alert(1)</script>,../../../etc/passwd" \
        --tag xss-sqli-lfi
      """
    Then the exit code is 0
    And `bp log --tag xss-sqli-lfi` returns exactly 1 entry
    And that entry's `burp_op` is "POST /intruder/quick-fuzz"
    And that entry's `status` is "ok"
    And that entry's `target` matches "api.acme.corp"

  @happy @community @ledger
  Scenario: An intruder attack (create+start) auto-records a LedgerEntry per phase
    When I run:
      """
      bp fuzz attack --id 3 \
        --pos "body:username" \
        --payloads usernames.txt \
        --type sniper \
        --throttle-ms 200 \
        --tag enum-users-2024
      """
    Then the exit code is 0
    And `bp log --tag enum-users-2024` returns at least 2 entries
    And one entry has `burp_op` = "POST /intruder/attack/create"
    And one entry has `burp_op` = "POST /intruder/attack/{id}/start"
    And all entries have `status` = "ok"

  @happy @community @ledger
  Scenario: A session send auto-records even when no --tag is provided
    When I run:
      """
      bp session send --method GET --url https://api.acme.corp/v1/profile
      """
    Then the exit code is 0
    And `bp log --target api.acme.corp` shows a new entry for this operation
    And the entry's `tag` field is empty or null
    And the entry's `burp_op` is "POST /session/send"

  @happy @community @ledger
  Scenario: A security scan (auth-bypass) auto-records with the full command
    When I run:
      """
      bp scan auth-bypass \
        --base-url https://api.acme.corp \
        --endpoints /api/admin,/api/users \
        --method GET \
        --tag auth-bypass-sprint42
      """
    Then the exit code is 0
    And `bp log --tag auth-bypass-sprint42` returns 1 entry
    And the entry's `burp_op` is "POST /scan/auth-bypass"
    And the entry's `command` starts with "bp scan auth-bypass"

  # ---------------------------------------------------------------------------
  # bp log — list and filter
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: bp log with no filter lists all entries sorted newest first
    Given the ledger contains 5 entries recorded in the last hour
    When I run:
      """
      bp log
      """
    Then the exit code is 0
    And the output table has at least 5 rows
    And the rows are ordered by timestamp descending

  @happy @community @ledger
  Scenario: bp log --format json returns compact JSON array (AX-friendly)
    Given the ledger contains entries for target "api.acme.corp"
    When I run:
      """
      bp log --target api.acme.corp --format json
      """
    Then the exit code is 0
    And stdout is a JSON array where each element contains keys: id, name, tag, timestamp, target, command, status, burp_op
    And each JSON object is on a single line (compact, not pretty-printed)
    And the array is ordered by timestamp descending

  @happy @community @ledger
  Scenario: bp log --fields filters and orders output columns
    When I run:
      """
      bp log --fields id,tag,status,target --format table
      """
    Then the exit code is 0
    And the output table header contains exactly the columns: id, tag, status, target
    And no other columns (name, command, burp_op, timestamp) appear

  @happy @community @ledger
  Scenario: bp log --tag filters to only matching entries
    Given the ledger contains entries tagged "sprint-42" and entries tagged "sprint-43"
    When I run:
      """
      bp log --tag sprint-42
      """
    Then the exit code is 0
    And every row in the output has tag = "sprint-42"
    And no row with tag = "sprint-43" appears

  @happy @community @ledger
  Scenario: bp log --target filters entries by hostname
    Given the ledger contains entries targeting "api.acme.corp" and "staging.acme.corp"
    When I run:
      """
      bp log --target api.acme.corp
      """
    Then every returned entry's target contains "api.acme.corp"
    And no entry targeting "staging.acme.corp" appears

  @happy @community @ledger
  Scenario: bp log --since and --until filter entries by time window
    Given the ledger contains entries from today and from 2 days ago
    When I run:
      """
      bp log --since 2024-06-01T00:00:00Z --until 2024-06-01T23:59:59Z
      """
    Then the exit code is 0
    And every returned entry's timestamp falls within the range 2024-06-01T00:00:00Z to 2024-06-01T23:59:59Z

  @happy @community @ledger
  Scenario: bp log --status err shows only failed operations
    Given the ledger contains both successful and failed entries
    When I run:
      """
      bp log --status err --format json
      """
    Then the exit code is 0
    And every entry in the JSON array has "status": "err"
    And the entry's "burp_op" and "command" fields are populated even for failed ops

  @happy @community @ledger
  Scenario: bp log --burp-op filters by the REST endpoint called
    When I run:
      """
      bp log --burp-op "POST /repeater/send" --format json
      """
    Then every returned entry has "burp_op": "POST /repeater/send"

  @happy @community @ledger
  Scenario: bp log with --limit caps the number of rows returned
    Given the ledger contains 200 entries
    When I run:
      """
      bp log --limit 10
      """
    Then the output contains at most 10 rows

  @happy @community @ledger
  Scenario: bp log -w prints a curl-style template per entry
    When I run:
      """
      bp log -w "%{status} %{requestId} %{target}" --limit 5
      """
    Then the exit code is 0
    And stdout contains exactly 5 lines
    And each line matches the pattern: "ok|err <requestId> <hostname>"

  @happy @community @ledger
  Scenario: bp log --quiet prints only entry IDs, one per line
    When I run:
      """
      bp log --quiet --tag xss-sqli-lfi
      """
    Then the exit code is 0
    And stdout contains exactly 1 line
    And that line is a numeric or UUID-format ledger entry ID

  # ---------------------------------------------------------------------------
  # bp tag — annotate a posteriori
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: bp tag adds a label to an existing entry by ID
    Given a ledger entry with id "42" and no tag
    When I run:
      """
      bp tag 42 "confirmed-xss-bounty"
      """
    Then the exit code is 0
    And `bp show 42` shows tag = "confirmed-xss-bounty"
    And the entry's other fields (timestamp, command, burp_op, target) are unchanged

  @happy @community @ledger
  Scenario: bp tag overwrites a previous tag on an entry
    Given a ledger entry with id "17" and tag "triage"
    When I run:
      """
      bp tag 17 "escalated-p1"
      """
    Then the exit code is 0
    And `bp show 17 --format json` returns JSON where "tag" is "escalated-p1"
    And the old value "triage" no longer appears in the tag field

  @happy @community @ledger
  Scenario: bp tag with --format json confirms the update in machine-readable form
    When I run:
      """
      bp tag 99 "idor-confirmed" --format json
      """
    Then the exit code is 0
    And stdout is a single JSON object:
      """
      {"id":99,"tag":"idor-confirmed","status":"ok"}
      """

  @error @community @ledger
  Scenario: bp tag on a non-existent entry ID prints an error and exits non-zero
    When I run:
      """
      bp tag 99999 "ghost"
      """
    Then the exit code is 1
    And stderr contains "entry 99999 not found in ledger"

  @error @community @ledger
  Scenario: bp tag with an empty label is rejected
    When I run:
      """
      bp tag 42 ""
      """
    Then the exit code is 1
    And stderr contains "tag label must not be empty"

  # ---------------------------------------------------------------------------
  # bp show — inspect a single entry (req + resp detail)
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: bp show displays full detail of a recorded operation
    Given a ledger entry with id "55" from a repeater send to https://api.acme.corp/v1/login
    When I run:
      """
      bp show 55
      """
    Then the exit code is 0
    And the output contains: id, name, tag, timestamp, target, command, request_ref, response_ref, status, burp_op
    And the burp_op field is "POST /repeater/send"
    And the target field contains "api.acme.corp"

  @happy @community @ledger
  Scenario: bp show --format json returns a stable JSON object for AI agent parsing
    When I run:
      """
      bp show 55 --format json
      """
    Then the exit code is 0
    And stdout is a single-line JSON object with all LedgerEntry fields present
    And the JSON object contains "burp_op": "POST /repeater/send"
    And the JSON object contains "status": "ok"

  @happy @community @ledger
  Scenario: bp show -w extracts a specific field from a single entry
    When I run:
      """
      bp show 55 -w "%{status} %{target}"
      """
    Then stdout is exactly one line: "ok api.acme.corp"

  @error @community @ledger
  Scenario: bp show on an unknown entry ID exits non-zero with a clear message
    When I run:
      """
      bp show 88888 --format json
      """
    Then the exit code is 1
    And stdout is:
      """
      {"success":false,"error":{"code":"NOT_FOUND","message":"ledger entry 88888 not found"}}
      """

  # ---------------------------------------------------------------------------
  # --tag global flag — tag at operation time
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: --tag on a fuzz command writes the tag into the LedgerEntry immediately
    When I run:
      """
      bp fuzz quick --id 7 --param role \
        --payloads "admin,guest,superuser" \
        --tag role-escalation-test
      """
    Then the exit code is 0
    And `bp log --tag role-escalation-test --format json` returns a non-empty array
    And the first element has "tag": "role-escalation-test"

  @happy @community @ledger
  Scenario: --tag on a scan command writes the tag into the LedgerEntry
    When I run:
      """
      bp scan cors --url https://api.acme.corp/data --tag cors-check-june
      """
    Then the exit code is 0
    And `bp log --tag cors-check-june --format json` returns 1 entry
    And that entry's "burp_op" is "POST /scan/cors"

  @happy @community @ledger
  Scenario: Multiple sequential operations with the same --tag share the tag value
    When I run:
      """
      bp repeater send --id 1 --tag recon-wave-1
      bp repeater send --id 2 --tag recon-wave-1
      bp repeater send --id 3 --tag recon-wave-1
      """
    Then `bp log --tag recon-wave-1` returns exactly 3 entries
    And all 3 entries have "tag": "recon-wave-1"

  # ---------------------------------------------------------------------------
  # --no-ledger opt-out — operation runs but is NOT recorded
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: --no-ledger suppresses ledger recording for a repeater send
    Given the current ledger entry count for target "api.acme.corp" is N
    When I run:
      """
      bp repeater send --id 7 --no-ledger
      """
    Then the exit code is 0
    And the Burp REST call to POST /repeater/send completes successfully
    And `bp log --target api.acme.corp` still returns exactly N entries (no new row)

  @happy @community @ledger
  Scenario: --no-ledger on a fuzz run suppresses all ledger entries for that operation
    When I run:
      """
      bp fuzz quick --id 12 --param q \
        --payloads "test1,test2" \
        --no-ledger
      """
    Then the exit code is 0
    And `bp log --burp-op "POST /intruder/quick-fuzz"` returns the same count as before

  @happy @community @ledger
  Scenario: --no-ledger still prints normal output — it only disables recording
    When I run:
      """
      bp repeater send --id 7 --no-ledger --format json
      """
    Then the exit code is 0
    And stdout is a valid JSON object containing "success": true
    And no entry is written to the ledger DB

  @happy @community @ledger
  Scenario: --no-ledger and --tag together — --tag is silently ignored when --no-ledger is set
    When I run:
      """
      bp session send --url https://api.acme.corp/v1/me \
        --tag this-tag-will-be-ignored \
        --no-ledger
      """
    Then the exit code is 0
    And `bp log --tag this-tag-will-be-ignored` returns 0 entries

  # ---------------------------------------------------------------------------
  # NAMING A RUN — --name / --tag for human-readable run identity
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: Naming a run with --name gives the LedgerEntry a human-readable identifier
    When I run:
      """
      bp fuzz quick --id 3 --param username \
        --payloads "admin,root,administrator" \
        --name "username-enum-sprint-7" \
        --tag sprint-7
      """
    Then `bp log --tag sprint-7 --format json` contains an entry where "name" is "username-enum-sprint-7"
    And the entry also has "tag": "sprint-7"

  @happy @community @ledger
  Scenario: bp log --name filters entries by run name
    Given a ledger entry named "header-bypass-round2"
    When I run:
      """
      bp log --name "header-bypass-round2" --format json
      """
    Then the exit code is 0
    And every returned entry has "name": "header-bypass-round2"

  # ---------------------------------------------------------------------------
  # VERIFY / REPLAY — reproduce a recorded operation from the ledger
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: bp replay re-executes a ledger entry's bp command verbatim
    Given a ledger entry with id "30" whose command is
      """
      bp repeater send --id 7 --tag baseline-check
      """
    When I run:
      """
      bp replay 30
      """
    Then the exit code is 0
    And a new LedgerEntry is created with the same command string and burp_op
    And the new entry's "name" contains "replay-of-30"
    And the original entry with id "30" is unchanged

  @happy @community @ledger
  Scenario: bp replay --format json returns the replay result plus the new ledger id
    Given a ledger entry with id "30"
    When I run:
      """
      bp replay 30 --format json
      """
    Then stdout is a JSON object containing:
      | field           | description                              |
      | replay_id       | the new LedgerEntry id for this replay   |
      | original_id     | 30                                       |
      | status          | ok                                       |
      | burp_op         | same as original entry's burp_op         |

  @happy @community @ledger
  Scenario: bp replay --no-ledger re-runs without creating a new ledger entry
    Given a ledger entry with id "30"
    When I run:
      """
      bp replay 30 --no-ledger
      """
    Then the exit code is 0
    And the Burp REST call succeeds
    And no new entry is written to the ledger (total count unchanged)

  @error @community @ledger
  Scenario: bp replay on a non-existent ledger id fails cleanly
    When I run:
      """
      bp replay 77777
      """
    Then the exit code is 1
    And stderr contains "ledger entry 77777 not found"

  @happy @community @ledger
  Scenario: bp replay --dry-run prints the command that would be executed without running it
    Given a ledger entry with id "30" whose command is
      """
      bp repeater send --id 7 --tag baseline-check
      """
    When I run:
      """
      bp replay 30 --dry-run
      """
    Then the exit code is 0
    And stdout contains exactly: "bp repeater send --id 7 --tag baseline-check"
    And no Burp REST call is made
    And no new ledger entry is created

  # ---------------------------------------------------------------------------
  # AGENT-MODE — AX (AI agent calling bp) scenarios
  # ---------------------------------------------------------------------------

  @happy @community @ledger @agent
  Scenario: Agent queries the ledger in JSON mode to find all failed operations against a target
    When an AI agent runs:
      """
      bp log --target api.acme.corp --status err --format json --fields id,tag,burp_op,timestamp,command
      """
    Then the exit code is 0
    And stdout is a JSON array (possibly empty)
    And each element is a compact single-line JSON object
    And each element contains exactly the keys: id, tag, burp_op, timestamp, command
    And no other keys appear (--fields is honoured)

  @happy @community @ledger @agent
  Scenario: Agent uses --quiet to get only the latest ledger entry ID for piping
    When an AI agent runs:
      """
      bp log --limit 1 --quiet
      """
    Then the exit code is 0
    And stdout is a single token (the most recent ledger entry id) with no surrounding text

  @happy @community @ledger @agent
  Scenario: Agent uses -w template to extract status and target for each ledger entry
    When an AI agent runs:
      """
      bp log --target api.acme.corp -w "%{status} %{target}" --limit 10
      """
    Then the exit code is 0
    And stdout contains at most 10 lines
    And each line matches the pattern: "ok api.acme.corp" or "err api.acme.corp"

  @happy @community @ledger @agent
  Scenario: Agent replays a specific ledger entry by ID and inspects the new record in JSON
    Given a ledger entry with id "55" exists
    When an AI agent runs:
      """
      bp replay 55 --format json
      """
    Then stdout is a single-line JSON object
    And the object contains "original_id": 55
    And the object contains "status": "ok"
    And the object contains "replay_id" (a new integer or UUID)

  @happy @community @ledger @agent
  Scenario: Agent tags an entry then queries to confirm, all in JSON mode
    When an AI agent runs in sequence:
      """
      bp tag 55 "escalated-idor" --format json
      bp show 55 --format json
      """
    Then the first command's stdout is:
      """
      {"id":55,"tag":"escalated-idor","status":"ok"}
      """
    And the second command's stdout is a JSON object where "tag" is "escalated-idor"

  # ---------------------------------------------------------------------------
  # TRACEABILITY GUARANTEES — ISO / audit evidence
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: The ledger entry's command field is the exact argv used, enabling forensic replay
    When I run:
      """
      bp scan headers --url https://api.acme.corp/admin --method POST --tag forensic-evidence-001
      """
    Then `bp show` for the new entry returns a `command` field that is verbatim:
      """
      bp scan headers --url https://api.acme.corp/admin --method POST --tag forensic-evidence-001
      """
    And the `burp_op` is "POST /scan/headers"
    And the `timestamp` is a stable ISO-8601 value that does not change on subsequent reads

  @happy @community @ledger
  Scenario: The ledger persists across bp process restarts (SQLite durability)
    Given a ledger entry with id "10" was created in a previous bp process
    When I start a new bp process and run:
      """
      bp show 10 --format json
      """
    Then the exit code is 0
    And the same entry (id, command, burp_op, tag, timestamp) is returned as before the restart

  @happy @community @ledger
  Scenario: bp log --format json output is stable across bp versions (schema contract)
    When I run:
      """
      bp log --limit 1 --format json
      """
    Then the JSON array element always contains these top-level keys:
      | id | name | tag | timestamp | target | command | request_ref | response_ref | status | burp_op |
    And no key is conditionally absent (encodeDefaults=true equivalent for ledger)

  @happy @community @ledger
  Scenario: A fuzz result entry links request_ref and response_ref for full chain traceability
    When I run:
      """
      bp fuzz quick --id 7 --param role \
        --payloads "admin,superadmin" \
        --tag idor-chain-trace
      """
    Then the ledger entry's `request_ref` is non-null
    And the ledger entry's `response_ref` is non-null
    And `bp show <id> --format json` returns both refs so the full request/response can be retrieved

  # ---------------------------------------------------------------------------
  # FAILURE / ERROR PATH — ledger records failures too
  # ---------------------------------------------------------------------------

  @error @community @ledger
  Scenario: A failed Burp REST call still creates a LedgerEntry with status err
    Given Burp Suite is running but the proxy history entry 9999 does not exist
    When I run:
      """
      bp repeater send --id 9999 --tag failed-send
      """
    Then the exit code is 1
    And `bp log --tag failed-send --format json` returns 1 entry
    And that entry has "status": "err"
    And that entry has a non-null "command" field

  @error @community @ledger
  Scenario: When Burp is unreachable, bp still creates a LedgerEntry with status err
    Given Burp Suite REST extension is NOT reachable at http://127.0.0.1:8089
    When I run:
      """
      bp repeater send --id 7 --tag burp-down-test
      """
    Then the exit code is 1
    And stderr contains a connection error message referencing 127.0.0.1:8089
    And `bp log --tag burp-down-test --format json` returns 1 entry with "status": "err"

  @error @community @ledger
  Scenario: When the ledger DB itself is unavailable, bp prints a warning but still executes the op
    Given the ledger DB at ~/.bp/ledger.db is locked or missing
    When I run:
      """
      bp repeater send --id 7
      """
    Then the exit code is 0
    And the Burp REST call to POST /repeater/send succeeds
    And stderr contains a warning: "ledger unavailable — operation not recorded"

  # ---------------------------------------------------------------------------
  # EDGE CASES
  # ---------------------------------------------------------------------------

  @error @community @ledger
  Scenario: bp log --since with an invalid datetime format exits with usage error
    When I run:
      """
      bp log --since "not-a-date"
      """
    Then the exit code is 1
    And stderr contains "invalid datetime format for --since"
    And the error message shows the expected format: ISO-8601 (e.g. 2024-06-01T00:00:00Z)

  @error @community @ledger
  Scenario: bp log --status with an invalid value exits with usage error
    When I run:
      """
      bp log --status unknown
      """
    Then the exit code is 1
    And stderr contains "invalid --status value: must be ok or err"

  @happy @community @ledger
  Scenario: bp log returns empty array (not an error) when no entries match the filter
    When I run:
      """
      bp log --tag nonexistent-tag-xyz --format json
      """
    Then the exit code is 0
    And stdout is "[]"

  @happy @community @ledger
  Scenario: bp log returns empty table (not an error) when no entries match, in table mode
    When I run:
      """
      bp log --tag nonexistent-tag-xyz --format table
      """
    Then the exit code is 0
    And stdout contains "(no entries)" or an empty table with the header row only

  @happy @community @ledger
  Scenario: Ledger entries from different domains (fuzz, scan, session) coexist and are queryable together
    Given the ledger contains one entry from `bp fuzz quick`, one from `bp scan cors`, one from `bp session send`
    When I run:
      """
      bp log --target api.acme.corp --format json
      """
    Then the exit code is 0
    And the returned array contains entries with burp_op values:
      | POST /intruder/quick-fuzz |
      | POST /scan/cors           |
      | POST /session/send        |

  @happy @community @ledger
  Scenario Outline: bp log output mode adapts based on --format flag
    When I run:
      """
      bp log --limit 3 --format <format>
      """
    Then the exit code is 0
    And the output is in <expected_shape>

    Examples:
      | format | expected_shape                                               |
      | table  | aligned column table with header row                         |
      | json   | compact JSON array, one object per line                      |
      | raw    | raw text dump of stored command strings, one per line        |
      | quiet  | only the first entry's id, one line                          |

  @happy @community @ledger
  Scenario Outline: bp tag --format adapts confirmation output format
    When I run:
      """
      bp tag 42 "label" --format <format>
      """
    Then the exit code is 0
    And the output matches <expected_shape>

    Examples:
      | format | expected_shape                              |
      | table  | one-row table: id=42, tag=label, status=ok  |
      | json   | {"id":42,"tag":"label","status":"ok"}       |
      | quiet  | "42" (just the updated entry id)            |

  # ---------------------------------------------------------------------------
  # --fields fine-grained output control
  # ---------------------------------------------------------------------------

  @happy @community @ledger
  Scenario: bp show with --fields id,command,status shows only those fields
    When I run:
      """
      bp show 55 --fields id,command,status --format json
      """
    Then stdout is a JSON object containing exactly the keys: id, command, status
    And the "command" value is the original bp argv stored in the ledger

  @happy @community @ledger
  Scenario: bp log with --fields timestamp,tag produces minimal output for spreadsheet export
    When I run:
      """
      bp log --fields timestamp,tag --format table
      """
    Then the exit code is 0
    And the output table has exactly 2 columns: timestamp and tag
    And each row's timestamp is a valid ISO-8601 datetime string

  # ---------------------------------------------------------------------------
  # INTEGRATION — ledger + fuzz output fields cross-reference
  # ---------------------------------------------------------------------------

  @happy @community @fuzz @ledger
  Scenario: bp fuzz quick output fields and ledger entry are independently accessible
    When I run:
      """
      bp fuzz quick --id 7 --param role \
        --payloads "admin,guest" \
        --tag xref-test \
        --format json \
        --fields index,payload,status,length,anomalous
      """
    Then the exit code is 0
    And the fuzz result stdout is a JSON array where each element has keys: index, payload, status, length, anomalous
    And separately, `bp log --tag xref-test --format json` returns the ledger entry for this operation
    And the ledger entry's "burp_op" is "POST /intruder/quick-fuzz"
    And the two outputs are independent (fuzz result ≠ ledger entry schema)

  @happy @community @fuzz @ledger
  Scenario: bp fuzz with -w template prints one line per payload result (DX mode), ledger records the whole op
    When I run:
      """
      bp fuzz quick --id 7 --param role \
        --payloads "admin,guest,root" \
        -w "%{status} %{payload}" \
        --tag wtemplate-ledger-test
      """
    Then stdout contains exactly 3 lines (one per payload)
    And each line matches "<status_code> <payload>" e.g. "200 admin"
    And `bp log --tag wtemplate-ledger-test --format json` returns exactly 1 ledger entry (not 3)
    And that ledger entry's "command" contains '-w "%{status} %{payload}"'
