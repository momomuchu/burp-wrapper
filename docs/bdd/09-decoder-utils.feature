# Feature: Decoder & Utils — encode / decode / hash / smart-decode / diff / extract-endpoints
#
# Domain: §6.9 /decoder (4 endpoints · Community · pure JVM)
#         §6.12 /utils  (2 endpoints · Community · requires SessionService / HTTP engine)
#
# These operations are entirely offline for decoder; utils needs Burp's HTTP engine running.
# Both groups are Community-only (no Pro required).
# All decoder endpoints POST JSON → ApiResponse<T> envelope (success/data/error).
# Utils endpoints also POST JSON → ApiResponse<T>.
#
# Endpoints covered:
#   POST /decoder/encode
#   POST /decoder/decode
#   POST /decoder/hash
#   POST /decoder/smart-decode
#   POST /utils/diff
#   POST /utils/extract-endpoints
#
# Output model canonical flags (applied consistently across all scenarios):
#   --format json|table|raw|quiet
#   --fields f1,f2,...
#   -w, --write-out 'TPL'   tokens: %{status} %{length} %{time} %{payload} %{location}
#                                   %{anomalous} %{contentType} %{index} %{requestId}
#   --quiet                 (single most-essential value)
#   --tag NAME              (tag op in Run Ledger)
#   --no-ledger             (skip Run Ledger recording)

Feature: Decoder & Utils — encode, decode, hash, smart-decode, diff, extract-endpoints

  As a security researcher using bp (burpctl),
  I want to encode/decode/hash payloads, peel multi-layer encodings, diff two live HTTP
  responses, and extract API endpoints from HTML/JS — all offline-capable for decoder,
  using Burp's HTTP engine for utils —
  so that I can craft and analyse payloads precisely without leaving the terminal.

  Background:
    Given the Burp REST extension is listening on http://127.0.0.1:8089
    And the bp CLI is installed and on PATH

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.9 POST /decoder/encode
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Encode a XSS payload to base64
    Given the payload "<script>alert(1)</script>" needs to bypass a WAF
    When I run:
      """
      bp decoder encode --data '<script>alert(1)</script>' --encoding base64
      """
    Then the exit code is 0
    And stdout contains a JSON envelope line like:
      """
      {"success":true,"data":{"encoding":"base64","result":"PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},"error":null}
      """

  @happy @community @decoder
  Scenario: Encode a payload to URL encoding
    When I run:
      """
      bp decoder encode --data 'admin OR 1=1--' --encoding url
      """
    Then the exit code is 0
    And stdout contains the URL-encoded result "admin+OR+1%3D1--" in the data.result field

  @happy @community @decoder
  Scenario: Encode a payload to hex
    When I run:
      """
      bp decoder encode --data 'SELECT * FROM users' --encoding hex
      """
    Then the exit code is 0
    And the data.result field equals "53454c454354202a2046524f4d207573657273"

  @happy @community @decoder
  Scenario: Encode special HTML entities (only 5 entities covered — & < > " ')
    # SPEC FLAG: html encoding covers only: & < > " '
    When I run:
      """
      bp decoder encode --data '<img src="x" onerror='"'"'alert(1)'"'"'>' --encoding html
      """
    Then the exit code is 0
    And the data.result field equals "&lt;img src=&quot;x&quot; onerror=&#x27;alert(1)&#x27;&gt;"

  @happy @community @decoder @format
  Scenario: Encode in table format for human DX
    When I run:
      """
      bp decoder encode --data 'password123' --encoding base64 --format table
      """
    Then the exit code is 0
    And stdout contains aligned columns with headers "ENCODING" and "RESULT"
    And a row shows "base64" and "cGFzc3dvcmQxMjM="

  @happy @community @decoder @format
  Scenario: Encode in JSON mode for AI-agent (AX) consumption
    # AX mode: --format json → compact single-line-per-record, stable schema
    When I run:
      """
      bp decoder encode --data 'Bearer eyJhbGci' --encoding url --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (no pretty-print)
    And the JSON contains keys: success, data, error
    And data contains keys: encoding, result

  @happy @community @decoder @quiet
  Scenario: Encode with --quiet returns only the encoded value
    When I run:
      """
      bp decoder encode --data 'test' --encoding hex --quiet
      """
    Then the exit code is 0
    And stdout equals "74657374"

  @happy @community @decoder @write-out
  Scenario: Encode with -w template for scripting
    When I run:
      """
      bp decoder encode --data '<s>' --encoding base64 -w '%{payload}'
      """
    Then the exit code is 0
    And stdout equals "PHM+"

  @happy @community @decoder @ledger
  Scenario: Encode operation is recorded in the Run Ledger
    When I run:
      """
      bp decoder encode --data 'secret' --encoding base64 --tag encode-waf-bypass
      """
    Then the exit code is 0
    And the Run Ledger records an entry with tag "encode-waf-bypass"
    And the ledger entry has burp_op "/decoder/encode"

  @happy @community @decoder @ledger
  Scenario: Encode with --no-ledger skips Run Ledger recording
    When I run:
      """
      bp decoder encode --data 'canary' --encoding hex --no-ledger
      """
    Then the exit code is 0
    And no new Run Ledger entry is created for this operation

  @error @community @decoder
  Scenario: Encode with unsupported encoding returns 400 INVALID_REQUEST
    # encoding ∈ {base64, url, hex, html} — anything else → 400
    When I run:
      """
      bp decoder encode --data 'test' --encoding rot13
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "encoding"

  @error @community @decoder
  Scenario: Encode with missing --data flag returns usage error
    When I run:
      """
      bp decoder encode --encoding base64
      """
    Then the exit code is non-zero
    And stderr contains "required" or "missing"

  @error @community @decoder
  Scenario Outline: Encode with each unsupported encoding variant fails
    When I run:
      """
      bp decoder encode --data 'payload' --encoding <bad_encoding>
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

    Examples:
      | bad_encoding |
      | base32       |
      | base58       |
      | utf8         |
      | unicode      |
      | gzip         |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.9 POST /decoder/decode
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Decode a base64-encoded JWT token with explicit encoding
    Given the base64 token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    When I run:
      """
      bp decoder decode \
        --data 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' \
        --encoding base64
      """
    Then the exit code is 0
    And the data.result field equals '{"alg":"HS256","typ":"JWT"}'
    And the data.encoding field equals "base64"

  @happy @community @decoder
  Scenario: Decode a URL-encoded query parameter with explicit encoding
    When I run:
      """
      bp decoder decode \
        --data 'admin%40example.com%3Fref%3Dhome' \
        --encoding url
      """
    Then the exit code is 0
    And the data.result field equals "admin@example.com?ref=home"

  @happy @community @decoder
  Scenario: Decode a hex-encoded payload with explicit encoding
    When I run:
      """
      bp decoder decode \
        --data '53454c454354202a2046524f4d207573657273' \
        --encoding hex
      """
    Then the exit code is 0
    And the data.result field equals "SELECT * FROM users"

  @happy @community @decoder
  Scenario: Decode HTML entities with explicit encoding
    When I run:
      """
      bp decoder decode \
        --data '&lt;script&gt;alert(1)&lt;/script&gt;' \
        --encoding html
      """
    Then the exit code is 0
    And the data.result field equals "<script>alert(1)</script>"

  @happy @community @decoder
  Scenario: Decode with auto-detect (encoding omitted) — base64 input
    # SPEC FLAG: auto-detect may mis-identify short/ambiguous inputs
    When I run:
      """
      bp decoder decode --data 'cGFzc3dvcmQxMjM='
      """
    Then the exit code is 0
    And the data.result field equals "password123"
    And the data.encoding field is one of "base64", "auto"

  @happy @community @decoder
  Scenario: Decode with auto-detect — URL-encoded input
    When I run:
      """
      bp decoder decode --data 'hello%20world%21'
      """
    Then the exit code is 0
    And the data.result field equals "hello world!"

  @happy @community @decoder @format
  Scenario: Decode in JSON mode for AX pipeline (AI agent)
    # AX pattern: pipe output to jq for field extraction
    When I run:
      """
      bp decoder decode --data 'dXNlcjpwYXNz' --encoding base64 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON has schema: {"success":true,"data":{"encoding":"<str>","result":"<str>"},"error":null}

  @happy @community @decoder @quiet
  Scenario: Decode with --quiet returns only the decoded string
    When I run:
      """
      bp decoder decode --data 'cm9vdA==' --encoding base64 --quiet
      """
    Then the exit code is 0
    And stdout equals "root"

  @happy @community @decoder @write-out
  Scenario: Decode with -w template extracts result inline
    When I run:
      """
      bp decoder decode --data 'YWRtaW4=' --encoding base64 -w 'decoded=%{payload}'
      """
    Then the exit code is 0
    And stdout equals "decoded=admin"

  @error @community @decoder
  Scenario: Decode invalid base64 (odd padding) returns 400 INVALID_REQUEST
    When I run:
      """
      bp decoder decode --data 'not-valid-base64!!!' --encoding base64
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Decode odd-length hex string returns 400 INVALID_REQUEST
    # SPEC: hex with odd number of characters → INVALID_REQUEST
    When I run:
      """
      bp decoder decode --data 'abc' --encoding hex
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Decode with unsupported explicit encoding returns 400
    When I run:
      """
      bp decoder decode --data 'dGVzdA==' --encoding base32
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Decode with malformed JSON body returns 400
    # Verifies that bp validates input before sending to API
    When I run with raw JSON body '{"data":42,"encoding":"base64"}':
      """
      bp decoder decode --raw-json '{"data":42,"encoding":"base64"}'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario Outline: Decode with valid encoding but wrong content fails gracefully
    When I run:
      """
      bp decoder decode --data '<encoding_mismatch>' --encoding <encoding>
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

    Examples:
      | encoding_mismatch       | encoding |
      | %%invalid-url-escape%%  | url      |
      | ZZZZ!!!notbase64        | base64   |
      | 0x1g2h3k                | hex      |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.9 POST /decoder/hash
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Hash a password with MD5
    When I run:
      """
      bp decoder hash --data 'password123' --algorithm md5
      """
    Then the exit code is 0
    And the data.result field equals "482c811da5d5b4bc6d497ffa98491e38"
    And the data.algorithm field equals "md5"

  @happy @community @decoder
  Scenario: Hash a token with SHA-256
    When I run:
      """
      bp decoder hash --data 'supersecret' --algorithm sha256
      """
    Then the exit code is 0
    And the data.result field equals "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
    And the data.algorithm field equals "sha256"

  @happy @community @decoder
  Scenario: Hash with SHA-1
    When I run:
      """
      bp decoder hash --data 'admin' --algorithm sha1
      """
    Then the exit code is 0
    And the data.result is a 40-character hex string
    And the data.algorithm field equals "sha1"

  @happy @community @decoder
  Scenario: Hash with SHA-384
    When I run:
      """
      bp decoder hash --data 'test-payload' --algorithm sha384
      """
    Then the exit code is 0
    And the data.result is a 96-character hex string
    And the data.algorithm field equals "sha384"

  @happy @community @decoder
  Scenario: Hash with SHA-512
    When I run:
      """
      bp decoder hash --data 'api-secret-key-v2' --algorithm sha512
      """
    Then the exit code is 0
    And the data.result is a 128-character hex string
    And the data.algorithm field equals "sha512"

  @happy @community @decoder @format
  Scenario: Hash in JSON mode for AX use (compare token to candidate hash)
    # AX pattern: agent hashes a candidate and compares to a stolen hash
    When I run:
      """
      bp decoder hash --data 'letmein' --algorithm md5 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON path $.data.algorithm equals "md5"
    And the JSON path $.data.result is a 32-character hex string

  @happy @community @decoder @quiet
  Scenario: Hash with --quiet returns only the digest
    When I run:
      """
      bp decoder hash --data 'root' --algorithm sha256 --quiet
      """
    Then the exit code is 0
    And stdout is a 64-character hex string with no trailing newline beyond LF

  @happy @community @decoder @write-out
  Scenario: Hash with -w template for chaining in shell scripts
    When I run:
      """
      bp decoder hash --data 'token-value' --algorithm md5 -w '%{payload}'
      """
    Then the exit code is 0
    And stdout is the MD5 hex digest of "token-value"

  @happy @community @decoder @ledger
  Scenario: Hash operation is tagged in the Run Ledger
    When I run:
      """
      bp decoder hash --data 'victim-hash' --algorithm sha1 --tag hash-compare-idor
      """
    Then the exit code is 0
    And the Run Ledger entry with tag "hash-compare-idor" has burp_op "/decoder/hash"

  @error @community @decoder
  Scenario: Hash with unsupported algorithm returns 400 INVALID_REQUEST
    # SPEC: algorithm is echoed as-is; unsupported JVM MessageDigest → INVALID_REQUEST
    When I run:
      """
      bp decoder hash --data 'test' --algorithm bcrypt
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Hash with missing algorithm returns usage error
    When I run:
      """
      bp decoder hash --data 'test'
      """
    Then the exit code is non-zero
    And stderr contains "required" or "algorithm"

  @error @community @decoder
  Scenario Outline: Hash with all supported algorithms succeeds
    When I run:
      """
      bp decoder hash --data 'canary' --algorithm <algo>
      """
    Then the exit code is 0
    And the data.algorithm field equals "<algo>"
    And the data.result is a non-empty hex string

    Examples:
      | algo   |
      | md5    |
      | sha1   |
      | sha256 |
      | sha384 |
      | sha512 |

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.9 POST /decoder/smart-decode
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Smart-decode peels a single base64 layer and returns step trace
    Given the value "dXNlcjpwYXNz" is base64("user:pass")
    When I run:
      """
      bp decoder smart-decode --data 'dXNlcjpwYXNz'
      """
    Then the exit code is 0
    And the data.steps array has 1 entry
    And steps[0].encoding equals "base64"
    And steps[0].result equals "user:pass"
    And the data.final field equals "user:pass"

  @happy @community @decoder
  Scenario: Smart-decode peels double-encoded base64 (base64 of base64)
    # dXNlcjpwYXNz → user:pass, then base64 again
    Given "ZFhObGNqcHdZWE56" is base64(base64("user:pass"))
    When I run:
      """
      bp decoder smart-decode --data 'ZFhObGNqcHdZWE56'
      """
    Then the exit code is 0
    And the data.steps array has at least 2 entries
    And the data.final field equals "user:pass"

  @happy @community @decoder
  Scenario: Smart-decode peels URL then base64 layered encoding
    # Cookie value: URL-encoded base64 of "admin:secret"
    Given the value "YWRtaW46c2VjcmV0" is base64("admin:secret")
    And the URL-encoded form is "YWRtaW46c2VjcmV0%3D"
    When I run:
      """
      bp decoder smart-decode --data 'YWRtaW46c2VjcmV0%3D'
      """
    Then the exit code is 0
    And the data.steps array has at least 2 entries
    And the data.final field contains "admin:secret"

  @happy @community @decoder
  Scenario: Smart-decode ignores the encoding field (spec-mandated behaviour)
    # SPEC FLAG: smart-decode ignores the encoding parameter
    When I run:
      """
      bp decoder smart-decode --data 'dXNlcjpwYXNz' --encoding hex
      """
    Then the exit code is 0
    And the data.final field equals "user:pass"
    And no error is returned (encoding field is silently ignored)

  @happy @community @decoder
  Scenario: Smart-decode stops at plain text (no layers detected)
    # Input is already plain text — no encoding detected
    When I run:
      """
      bp decoder smart-decode --data 'hello world'
      """
    Then the exit code is 0
    And the data.steps array has 0 entries
    And the data.final field equals "hello world"

  @happy @community @decoder
  Scenario: Smart-decode respects the 10-layer cap
    # SPEC: smart-decode peels up to 10 layers maximum
    # This scenario verifies bp surfaces the cap in output metadata
    Given a pathologically nested encoding with more than 10 layers
    When I run:
      """
      bp decoder smart-decode --data '<deeply-nested-payload>'
      """
    Then the exit code is 0
    And the data.steps array has at most 10 entries
    And the data.final field is the result after at most 10 peeling rounds

  @happy @community @decoder @format
  Scenario: Smart-decode in JSON mode for AX agent analysis
    # AX: agent reads steps[] array to understand encoding chain
    When I run:
      """
      bp decoder smart-decode \
        --data 'YWRtaW46c2VjcmV0' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema is:
      """
      {
        "success": true,
        "data": {
          "steps": [{"encoding": "<str>", "result": "<str>"}],
          "final": "<str>"
        },
        "error": null
      }
      """

  @happy @community @decoder @fields
  Scenario: Smart-decode with --fields final returns only the final decoded value
    When I run:
      """
      bp decoder smart-decode --data 'dXNlcjpwYXNz' --fields final --format json
      """
    Then the exit code is 0
    And stdout contains only the "final" key in data (steps omitted)

  @happy @community @decoder @quiet
  Scenario: Smart-decode with --quiet returns only the final decoded value
    When I run:
      """
      bp decoder smart-decode --data 'cm9vdA==' --quiet
      """
    Then the exit code is 0
    And stdout equals "root"

  @happy @community @decoder @write-out
  Scenario: Smart-decode with -w template for pipeline integration
    When I run:
      """
      bp decoder smart-decode --data 'YWRtaW4=' -w 'final=%{payload}'
      """
    Then the exit code is 0
    And stdout equals "final=admin"

  @error @community @decoder
  Scenario: Smart-decode with empty data string behaves gracefully
    When I run:
      """
      bp decoder smart-decode --data ''
      """
    Then the exit code is 0 or non-zero (implementation-defined)
    And no panic or 500 INTERNAL_ERROR is returned
    And if successful the data.final field is an empty string

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.12 POST /utils/diff
  # ─────────────────────────────────────────────────────────────────────────────
  # SPEC: diff issues TWO live HTTP requests via Burp's engine (SessionService).
  # Requires Burp running with HTTP engine; works on Community.
  # DiffTarget { url:String (required), method="GET", body:String?, extraHeaders:Map? }
  # body-diff = set-based summary (NOT unified diff).
  # SPEC FLAG: /utils and /utils/diff are ABSENT from /docs (OpenAPI).

  @happy @community @utils
  Scenario: Diff two endpoints to detect access-control divergence (GET)
    Given Burp's HTTP engine is running
    When I run:
      """
      bp utils diff \
        --a-url 'https://api.example.com/orders/123' \
        --b-url 'https://api.example.com/orders/456' \
        --a-method GET \
        --b-method GET
      """
    Then the exit code is 0
    And stdout contains a JSON envelope with data.statusA, data.statusB
    And data.lengthA and data.lengthB are present
    And data.headersChanged lists any differing response headers

  @happy @community @utils
  Scenario: Diff authenticated vs unauthenticated request to detect IDOR
    # Classic IDOR check: same resource, different auth header
    When I run:
      """
      bp utils diff \
        --a-url 'https://api.example.com/profile/me' \
        --a-method GET \
        --a-header 'Authorization: Bearer eyJhbGci.victim-token' \
        --b-url 'https://api.example.com/profile/me' \
        --b-method GET \
        --b-header 'Authorization: Bearer eyJhbGci.attacker-token'
      """
    Then the exit code is 0
    And if data.statusA == 200 and data.statusB == 200 then data.lengthA and data.lengthB are compared
    And bp prints a warning if response lengths differ by more than 20 bytes

  @happy @community @utils
  Scenario: Diff a POST endpoint body with different payloads
    When I run:
      """
      bp utils diff \
        --a-url 'https://api.example.com/search' \
        --a-method POST \
        --a-body '{"q":"normal"}' \
        --b-url 'https://api.example.com/search' \
        --b-method POST \
        --b-body '{"q":"'"'"' OR 1=1--'"'"'}'
      """
    Then the exit code is 0
    And data.statusA and data.statusB are present
    And data.bodySummary contains a set-based summary of body differences

  @happy @community @utils @format
  Scenario: Diff in JSON mode for AX agent to compare access-control responses
    # AX: agent uses diff to detect privilege escalation
    When I run:
      """
      bp utils diff \
        --a-url 'https://staging.corp.internal/api/admin/users' \
        --b-url 'https://staging.corp.internal/api/users' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON contains: success, data.statusA, data.statusB, data.lengthA, data.lengthB

  @happy @community @utils @quiet
  Scenario: Diff with --quiet returns only a status summary line
    When I run:
      """
      bp utils diff \
        --a-url 'https://example.com/page' \
        --b-url 'https://example.com/page?debug=1' \
        --quiet
      """
    Then the exit code is 0
    And stdout is a single line like "200 vs 200 | length 4521 vs 4521"

  @happy @community @utils @write-out
  Scenario: Diff with -w template for scripting access-control checks
    When I run:
      """
      bp utils diff \
        --a-url 'https://api.example.com/resource/1' \
        --b-url 'https://api.example.com/resource/2' \
        -w '%{status}'
      """
    Then the exit code is 0
    And stdout contains two status codes, one per target

  @happy @community @utils @ledger
  Scenario: Diff operation is tagged in the Run Ledger for audit trail
    When I run:
      """
      bp utils diff \
        --a-url 'https://target.io/api/me' \
        --b-url 'https://target.io/api/other-user' \
        --tag idor-diff-check
      """
    Then the exit code is 0
    And the Run Ledger records an entry with tag "idor-diff-check"
    And the ledger entry has burp_op "/utils/diff"
    And the ledger entry has target "target.io"

  @happy @community @utils @format
  Scenario: Diff in table format for human review
    When I run:
      """
      bp utils diff \
        --a-url 'https://shop.example.com/cart/123' \
        --b-url 'https://shop.example.com/cart/999' \
        --format table
      """
    Then the exit code is 0
    And stdout contains aligned columns including "STATUS_A", "STATUS_B", "LENGTH_A", "LENGTH_B"

  @error @community @utils
  Scenario: Diff when Burp HTTP engine is unreachable returns 503
    Given Burp REST is NOT listening on :8089
    When I run:
      """
      bp utils diff \
        --a-url 'https://example.com/a' \
        --b-url 'https://example.com/b'
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE" or "connection refused" or "Burp is not running"

  @error @community @utils
  Scenario: Diff with missing --a-url returns usage error
    When I run:
      """
      bp utils diff --b-url 'https://example.com/b'
      """
    Then the exit code is non-zero
    And stderr contains "required" or "a-url"

  @error @community @utils
  Scenario: Diff with missing --b-url returns usage error
    When I run:
      """
      bp utils diff --a-url 'https://example.com/a'
      """
    Then the exit code is non-zero
    And stderr contains "required" or "b-url"

  @error @community @utils
  Scenario: Diff with malformed URL in target returns INVALID_REQUEST
    When I run:
      """
      bp utils diff \
        --a-url 'not-a-url' \
        --b-url 'https://example.com/b'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST" or "invalid URL"

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.12 POST /utils/extract-endpoints
  # ─────────────────────────────────────────────────────────────────────────────
  # SPEC: fetches the target URL + up to 10 JS bundles (cap), errors per bundle
  # are silently swallowed. Filters out static assets and w3.org references.
  # Uses regex to extract API endpoints from HTML + JS.
  # Requires Burp's HTTP engine; Community; no DB needed.
  # SPEC FLAG: /utils/extract-endpoints is ABSENT from /docs (OpenAPI).

  @happy @community @utils
  Scenario: Extract API endpoints from a web app home page
    Given the URL "https://app.example.com" returns HTML with embedded API references
    When I run:
      """
      bp utils extract-endpoints --url 'https://app.example.com'
      """
    Then the exit code is 0
    And stdout contains a JSON envelope where data.endpoints is a non-empty list
    And each endpoint entry has a path field
    And static assets (.png, .jpg, .css, .woff) are NOT included in the list

  @happy @community @utils
  Scenario: Extract endpoints includes API paths found in linked JS bundles
    Given "https://spa.example.com" loads a React app with a bundle at /static/js/main.chunk.js
    When I run:
      """
      bp utils extract-endpoints --url 'https://spa.example.com'
      """
    Then the exit code is 0
    And data.endpoints includes paths like "/api/v1/users", "/api/v1/auth/login"
    And data.bundlesScanned is at most 10

  @happy @community @utils
  Scenario: Extract endpoints caps JS bundle fetching at 10
    # SPEC: extract-endpoints fetches at most 10 JS bundles; errors per bundle swallowed
    Given "https://large-spa.example.com" references 15 distinct JS bundles
    When I run:
      """
      bp utils extract-endpoints --url 'https://large-spa.example.com'
      """
    Then the exit code is 0
    And data.bundlesScanned is exactly 10
    And data.bundlesCapped is true or data.bundlesSkipped is 5

  @happy @community @utils
  Scenario: Extract endpoints filters w3.org and spec URLs from results
    # SPEC FLAG: w3.org URLs are explicitly filtered
    When I run:
      """
      bp utils extract-endpoints --url 'https://app.example.com'
      """
    Then the exit code is 0
    And no endpoint in data.endpoints contains "w3.org"

  @happy @community @utils
  Scenario: Extract endpoints with empty app returns empty list gracefully
    Given the URL "https://empty.example.com" returns minimal HTML with no JS or API refs
    When I run:
      """
      bp utils extract-endpoints --url 'https://empty.example.com'
      """
    Then the exit code is 0
    And data.endpoints is an empty list []
    And no error is returned

  @happy @community @utils @format
  Scenario: Extract endpoints in JSON mode for AX agent reconnaissance
    # AX: agent feeds extracted endpoints into a fuzz loop
    When I run:
      """
      bp utils extract-endpoints \
        --url 'https://api.target.io' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema is:
      """
      {
        "success": true,
        "data": {
          "endpoints": [{"path": "<str>", "method": "<str|null>"}],
          "bundlesScanned": <int>
        },
        "error": null
      }
      """

  @happy @community @utils @format
  Scenario: Extract endpoints in table format for human review
    When I run:
      """
      bp utils extract-endpoints \
        --url 'https://shop.example.com' \
        --format table
      """
    Then the exit code is 0
    And stdout contains aligned columns including "PATH" and optionally "METHOD"

  @happy @community @utils @quiet
  Scenario: Extract endpoints with --quiet prints only the paths (one per line)
    When I run:
      """
      bp utils extract-endpoints \
        --url 'https://api.example.com' \
        --quiet
      """
    Then the exit code is 0
    And each line of stdout is a bare path string like "/api/v2/users"

  @happy @community @utils @fields
  Scenario: Extract endpoints with --fields path returns only path column
    When I run:
      """
      bp utils extract-endpoints \
        --url 'https://api.example.com' \
        --fields path \
        --format json
      """
    Then the exit code is 0
    And each item in data.endpoints has only the "path" key

  @happy @community @utils @ledger
  Scenario: Extract-endpoints is recorded in the Run Ledger for engagement traceability
    When I run:
      """
      bp utils extract-endpoints \
        --url 'https://target.bugbounty.io' \
        --tag recon-js-endpoints
      """
    Then the exit code is 0
    And the Run Ledger records an entry with tag "recon-js-endpoints"
    And the ledger entry has burp_op "/utils/extract-endpoints"
    And the ledger entry has target "target.bugbounty.io"

  @happy @community @utils @ledger
  Scenario: Extract-endpoints with --no-ledger skips Run Ledger entirely
    When I run:
      """
      bp utils extract-endpoints \
        --url 'https://app.example.com' \
        --no-ledger
      """
    Then the exit code is 0
    And no new Run Ledger entry is created

  @error @community @utils
  Scenario: Extract endpoints when Burp HTTP engine unreachable returns 503
    Given Burp REST is NOT listening on :8089
    When I run:
      """
      bp utils extract-endpoints --url 'https://example.com'
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE" or "Burp is not running"

  @error @community @utils
  Scenario: Extract endpoints with missing --url returns usage error
    When I run:
      """
      bp utils extract-endpoints
      """
    Then the exit code is non-zero
    And stderr contains "required" or "url"

  @error @community @utils
  Scenario: Extract endpoints with malformed URL returns INVALID_REQUEST
    When I run:
      """
      bp utils extract-endpoints --url 'javascript:alert(1)'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST" or "invalid URL"

  @error @community @utils
  Scenario: Extract endpoints when target URL returns non-200 handles gracefully
    Given "https://gone.example.com" returns HTTP 404
    When I run:
      """
      bp utils extract-endpoints --url 'https://gone.example.com'
      """
    Then the exit code is 0 or non-zero (implementation-defined)
    And if successful data.endpoints is an empty list
    And no 500 INTERNAL_ERROR is propagated to the user

  @error @community @utils
  Scenario: Extract endpoints when a JS bundle fetch fails — bundle error is swallowed
    # SPEC FLAG: errors per individual JS bundle are silently swallowed
    Given "https://flaky.example.com" has one JS bundle returning 500
    When I run:
      """
      bp utils extract-endpoints --url 'https://flaky.example.com'
      """
    Then the exit code is 0
    And data.endpoints lists all endpoints found in bundles that succeeded
    And no error is surfaced for the failed bundle

  # ─────────────────────────────────────────────────────────────────────────────
  # Cross-cutting: Burp-down scenarios (shared concern for utils group)
  # ─────────────────────────────────────────────────────────────────────────────

  @error @community @decoder
  Scenario: Decoder endpoints work when Burp REST is down (pure JVM — offline capable)
    # SPEC: decoder = pure JVM (Base64/URL/hex/HTML + MessageDigest) — no Burp needed
    Given Burp REST is NOT listening on :8089
    When I run:
      """
      bp decoder encode --data 'offline-test' --encoding base64
      """
    Then the exit code is 0
    And the data.result field equals "b2ZmbGluZS10ZXN0"
    # Verifies bp handles decoder locally or routes through a local JVM path,
    # confirming the "no Montoya, no Pro" spec property.

  @error @community @utils
  Scenario: Utils diff surfaces a clear error message when Burp is down — not a raw stacktrace
    Given Burp REST is NOT listening on :8089
    When I run:
      """
      bp utils diff \
        --a-url 'https://example.com/a' \
        --b-url 'https://example.com/b'
      """
    Then the exit code is non-zero
    And stderr contains a human-readable message (not a Java stacktrace)
    And the message references "Burp" or "8089" or "connection"

  # ─────────────────────────────────────────────────────────────────────────────
  # AX (AI-agent) end-to-end pipeline scenarios
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder @ax
  Scenario: AX agent encodes multiple payloads via Scenario Outline for WAF bypass matrix
    # AX pattern: agent iterates encoding variants programmatically via --format json
    When I run:
      """
      bp decoder encode --data '<script>alert(1)</script>' --encoding <encoding> --format json
      """
    Then stdout is a single compact JSON line with $.data.encoding == "<encoding>"
    And $.data.result is a non-empty string

    Examples:
      | encoding |
      | base64   |
      | url      |
      | hex      |
      | html     |

  @happy @community @decoder @ax
  Scenario: AX agent uses smart-decode to analyse an unknown token from a response cookie
    # Full AX pipeline: capture cookie → smart-decode → inspect steps → report encoding chain
    Given an AX agent has captured a cookie "X-Auth=YWRtaW4lM0FzZWNyZXQ%3D" from a response
    When the agent runs:
      """
      bp decoder smart-decode --data 'YWRtaW4lM0FzZWNyZXQ%3D' --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the agent can read $.data.steps[] to identify the encoding chain
    And $.data.final contains plaintext credential material

  @happy @community @utils @ax
  Scenario: AX agent extracts endpoints then feeds them into a diff comparison
    # Two-step AX recon: extract → diff selected pair
    Given the agent has extracted endpoints from "https://api.example.com" in a prior step
    And the extracted list includes "/api/v1/users/me" and "/api/v1/users/other"
    When the agent runs:
      """
      bp utils diff \
        --a-url 'https://api.example.com/api/v1/users/me' \
        --b-url 'https://api.example.com/api/v1/users/other' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And $.data.statusA and $.data.statusB are integers
    And the agent determines IDOR risk if statusB == 200 and lengthB differs from lengthA

  @happy @community @decoder @ax
  Scenario: AX agent hashes a candidate password to compare against a leaked MD5 digest
    # AX: agent computes hash and compares programmatically via --quiet
    Given a leaked hash "5f4dcc3b5aa765d61d8327deb882cf99" (MD5 of "password")
    When the agent runs:
      """
      bp decoder hash --data 'password' --algorithm md5 --quiet
      """
    Then the exit code is 0
    And stdout equals "5f4dcc3b5aa765d61d8327deb882cf99"
    And the agent confirms the password match without any wrapper JSON to parse

  # ─────────────────────────────────────────────────────────────────────────────
  # Scenario Outline: full encoding round-trip (encode → decode)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario Outline: Encode then decode produces original value (round-trip)
    Given the original value "<original>"
    When I run encode:
      """
      bp decoder encode --data '<original>' --encoding <encoding> --quiet
      """
    And I capture the encoded output as $ENCODED
    And I run decode:
      """
      bp decoder decode --data '$ENCODED' --encoding <encoding> --quiet
      """
    Then the decoded output equals "<original>"

    Examples:
      | original                        | encoding |
      | hello world                     | base64   |
      | <script>alert(1)</script>       | base64   |
      | admin OR 1=1                    | url      |
      | SELECT * FROM users WHERE id=1  | hex      |
      | <img src="x" onerror="alert()"> | html     |
      | Bearer token-value-123          | base64   |
      | user@example.com                | url      |

  # ─────────────────────────────────────────────────────────────────────────────
  # Edge cases and spec-flag coverage
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Auto-detect on ambiguous short input may produce unexpected result — bp warns
    # SPEC FLAG: auto-detect can mis-identify short/ambiguous inputs
    # e.g. "YQ==" is valid base64 for "a" but also a valid string
    When I run:
      """
      bp decoder decode --data 'YQ==' --format json
      """
    Then the exit code is 0
    And if data.encoding is "base64" then data.result is "a"
    And bp optionally surfaces a "low-confidence auto-detect" warning in the envelope

  @happy @community @decoder
  Scenario: Hash echoes the algorithm name as given (not normalized JVM name)
    # SPEC FLAG: hash echoes algorithm as-is, not the JVM-normalized form
    # e.g. "sha-1" may be accepted by JVM but echoed as "sha-1" not "SHA-1"
    When I run:
      """
      bp decoder hash --data 'test' --algorithm sha-1 --format json
      """
    Then the exit code is 0 or non-zero depending on JVM alias acceptance
    And if successful $.data.algorithm equals "sha-1" (not "SHA-1" or "sha1")

  @happy @community @utils
  Scenario: Extract-endpoints does not include w3.org schema references
    # SPEC FLAG: w3.org URLs explicitly filtered
    When I run:
      """
      bp utils extract-endpoints --url 'https://example.com' --format json
      """
    Then the exit code is 0
    And no element in $.data.endpoints[*].path contains "w3.org"
    And no element contains "schemas.xmlsoap.org"

  @happy @community @decoder @no-ledger
  Scenario: Decoder operations without --tag are still recorded with auto-generated ledger entry
    When I run:
      """
      bp decoder encode --data 'test' --encoding base64
      """
    Then the exit code is 0
    And the Run Ledger records an entry with an auto-generated id
    And the ledger entry has burp_op "/decoder/encode"
    And the ledger entry has timestamp set to the current time (within 5 seconds)

  @happy @community @utils @fields
  Scenario: Diff with --fields status returns only status fields
    When I run:
      """
      bp utils diff \
        --a-url 'https://example.com/a' \
        --b-url 'https://example.com/b' \
        --fields statusA,statusB \
        --format json
      """
    Then the exit code is 0
    And $.data contains only statusA and statusB keys

  @happy @community @decoder @fields
  Scenario: Encode with --fields result returns only the encoded value in data
    When I run:
      """
      bp decoder encode --data 'admin' --encoding hex --fields result --format json
      """
    Then the exit code is 0
    And $.data contains only the "result" key (encoding field omitted)
