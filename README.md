# burp-wrapper

Python wrapper for the Burp Suite MCP Server API. Gives AI agents (Claude Code, Gemini CLI, etc.) full programmatic access to every Burp Suite Pro tool.

```python
from burp_wrapper import BurpClient

burp = BurpClient()

# Browse proxy history
history = burp.proxy.get_history(limit=50, filter_host="target.com")

# Replay a request
response = burp.repeater.send(request_id="req-1")

# Fuzz a parameter
results = burp.intruder.quick_fuzz(
    request_id="req-1",
    param_name="username",
    payloads=["admin", "test", "' OR 1=1--"],
)

# Out-of-band testing
collab = burp.collaborator.generate_payload()
# inject collab["payload"] somewhere...
interactions = burp.collaborator.poll_until(collab["interaction_id"], timeout_seconds=30)
```

## Requirements

- Python 3.11+
- Burp Suite Pro with the [MCP Server extension](https://portswigger.net/burp/documentation/desktop/extensions) running on `localhost:9876`

## Install

```bash
pip install burp-wrapper
```

Or from source:

```bash
git clone https://github.com/momomuchu/burp-wrapper.git
cd burp-wrapper
pip install -e ".[dev]"
```

## Tools Covered

| Tool | Methods | Priority |
|------|---------|----------|
| **Proxy** | `get_history`, `get_request`, `get_websocket_history`, `intercept_*`, `add_match_replace_rule` | P1 |
| **Repeater** | `send`, `send_modified`, `send_batch`, `create_tab` | P1 |
| **Intruder** | `create_attack`, `start`, `quick_fuzz`, `status`, `results`, `pause`, `resume`, `stop` | P1 |
| **Scanner** | `crawl`, `audit`, `crawl_and_audit`, `status`, `issues`, `pause`, `resume`, `stop`, `get_issue_definitions` | P1 |
| **Decoder** | `encode`, `decode`, `smart_decode`, `hash`, `hash_all` | P1 |
| **Collaborator** | `generate_payload`, `generate_payloads`, `poll`, `poll_until` | P1 |
| **Target** | `get_sitemap`, `get_scope`, `set_scope`, `add_to_scope`, `is_in_scope`, `get_issues` | P1 |
| **Dashboard** | `get_tasks`, `get_issues_summary` | P1 |
| **Sequencer** | `start_live_capture`, `capture_status`, `analyze`, `analyze_manual`, `results` | P2 |
| **Comparer** | `diff`, `diff_responses` | P2 |
| **Logger** | `query`, `annotate`, `export` | P2 |
| **Inspector** | `parse_request`, `parse_response`, `build_request` | P2 |
| **Engagement** | `analyze_target`, `discover_content`, `content_discovery_results`, `generate_csrf_poc` | P2 |
| **Search** | `find` | P2 |
| **Config** | `get_project`, `get_user`, `export_project`, `import_project` | P2 |
| **Organizer** | `add`, `list`, `annotate`, `get_collections`, `create_collection` | P3 |
| **Extensions** | `list`, `enable`, `disable`, `reload` | P3 |
| **Clickbandit** | `generate` | P3 |

**18 tools, 70+ methods** covering every Burp Suite Pro feature accessible via API.

## Architecture

```
Agent (Claude Code / Gemini CLI)
  |
  |  from burp_wrapper import BurpClient
  v
BurpClient  -->  POST /mcp  -->  Burp Suite Pro + MCP Server Extension
  .proxy                          (localhost:9876)
  .repeater
  .intruder
  .scanner
  .decoder
  .collaborator
  ...
```

The wrapper sends JSON-RPC-style requests to the Burp MCP Server extension. No MCP protocol overhead - just simple HTTP calls.

## Usage Examples

### Scan a target

```python
burp = BurpClient()

# Add target to scope
burp.target.add_to_scope("https://target.com")

# Launch crawl + audit
scan = burp.scanner.crawl_and_audit("https://target.com", config={
    "crawl_strategy": "most_complete",
    "audit_optimization": "thorough",
})

# Check progress
status = burp.scanner.status(scan["scan_id"])
print(f"Progress: {status['audit_progress']['percentage']}%")

# Get findings
issues = burp.scanner.issues(scan_id=scan["scan_id"], filters={"severity": "high"})
```

### Intercept and modify traffic

```python
burp.proxy.intercept_toggle(True)

msg = burp.proxy.intercept_get_message()
if msg["has_message"]:
    # Modify and forward
    modified = msg["message"]["raw"].replace("User-Agent: Chrome", "User-Agent: Bot")
    burp.proxy.intercept_forward(msg["message"]["id"], modified_raw=modified)
```

### Compare responses for access control testing

```python
# Send same request as admin vs regular user
admin_resp = burp.repeater.send_modified("req-1", modifications={
    "headers": {"Cookie": "session=admin_token"}
})
user_resp = burp.repeater.send_modified("req-1", modifications={
    "headers": {"Cookie": "session=user_token"}
})

# Compare
diff = burp.comparer.diff(
    request_id_1=admin_resp["new_request_id"],
    request_id_2=user_resp["new_request_id"],
    options={"compare": "response"}
)
print(f"Similarity: {diff['similarity_percentage']}%")
```

### Token randomness analysis

```python
result = burp.sequencer.analyze_manual([
    "abc123", "def456", "ghi789",  # ... 200+ tokens
])
analysis = burp.sequencer.results(result["analysis_id"])
print(f"Entropy: {analysis['effective_entropy_bits']} bits")
print(f"FIPS: {'PASS' if analysis['fips_tests']['overall_passed'] else 'FAIL'}")
```

## Configuration

```python
# Custom host/port
burp = BurpClient(base_url="http://192.168.1.100:9876")

# Custom timeout (seconds)
burp = BurpClient(timeout=60.0)
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/
```

## Tests

125 tests covering every tool and method. All tests use mocked HTTP responses (no Burp instance required).

```bash
pytest -v
```

## License

MIT
