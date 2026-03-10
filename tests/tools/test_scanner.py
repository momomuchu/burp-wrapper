"""Tests for Scanner tools (Pro only)."""

import json

import httpx


class TestScannerCrawl:
    def test_crawl_single_target(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"scan_id": "scan-1", "status": "crawling"}}
            )
        )
        result = client.scanner.crawl("https://example.com")
        assert result["scan_id"] == "scan-1"
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["target"] == "https://example.com"

    def test_crawl_with_config(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"scan_id": "scan-2", "status": "crawling"}}
            )
        )
        client.scanner.crawl(
            "https://example.com",
            config={
                "max_crawl_depth": 5,
                "crawl_strategy": "most_complete",
                "scope": {"include": [".*\\.example\\.com"]},
            },
        )
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["config"]["crawl_strategy"] == "most_complete"


class TestScannerAudit:
    def test_audit_target(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"scan_id": "scan-3", "status": "auditing"}}
            )
        )
        result = client.scanner.audit(target="https://example.com")
        assert result["status"] == "auditing"

    def test_audit_request(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"scan_id": "scan-4", "status": "auditing"}}
            )
        )
        client.scanner.audit(request_id="req-1")
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["request_id"] == "req-1"

    def test_audit_with_checks_config(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"scan_id": "scan-5", "status": "auditing"}}
            )
        )
        client.scanner.audit(
            target="https://example.com",
            config={
                "audit_optimization": "thorough",
                "audit_checks": {"sql_injection": True, "xss": True, "ssrf": False},
            },
        )
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["config"]["audit_checks"]["sql_injection"] is True


class TestScannerCrawlAndAudit:
    def test_crawl_and_audit(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"scan_id": "scan-6", "status": "crawling"}}
            )
        )
        result = client.scanner.crawl_and_audit("https://example.com")
        assert result["scan_id"] == "scan-6"


class TestScannerStatus:
    def test_status(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "scan_id": "scan-1",
                        "status": "auditing",
                        "crawl_progress": {"requests_made": 100, "unique_locations": 50, "forms_discovered": 5},
                        "audit_progress": {"requests_made": 200, "items_completed": 30, "items_total": 50, "percentage": 60.0},
                        "issues_found": {"high": 1, "medium": 2, "low": 3, "info": 5},
                        "elapsed_seconds": 120,
                    }
                },
            )
        )
        result = client.scanner.status("scan-1")
        assert result["issues_found"]["high"] == 1
        assert result["audit_progress"]["percentage"] == 60.0


class TestScannerIssues:
    def test_get_issues(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "issues": [
                            {
                                "id": "issue-1",
                                "type": "sql_injection",
                                "name": "SQL injection",
                                "severity": "high",
                                "confidence": "certain",
                                "url": "https://example.com/login",
                                "path": "/login",
                                "host": "example.com",
                                "detail": "<p>SQL injection found</p>",
                                "background": "",
                                "remediation": "Use parameterized queries",
                                "remediation_background": "",
                                "references": [],
                                "evidence": {"request": "POST /login", "response": "SQL error", "highlight_markers": []},
                                "request_id": "req-50",
                            }
                        ]
                    }
                },
            )
        )
        result = client.scanner.issues(scan_id="scan-1")
        assert len(result["issues"]) == 1
        assert result["issues"][0]["severity"] == "high"

    def test_issues_with_filters(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"issues": []}})
        )
        client.scanner.issues(filters={"severity": "high", "confidence": "certain"})
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["filters"]["severity"] == "high"


class TestScannerControl:
    def test_pause(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.scanner.pause("scan-1")["success"] is True

    def test_resume(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.scanner.resume("scan-1")["success"] is True

    def test_stop(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.scanner.stop("scan-1")["success"] is True


class TestScannerIssueDefinitions:
    def test_get_definitions(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "definitions": [
                            {
                                "type_index": 1049088,
                                "name": "SQL injection",
                                "severity": "high",
                                "description": "SQL injection vulnerabilities arise...",
                                "remediation": "Use parameterized queries",
                                "references": [],
                                "vulnerability_classifications": ["CWE-89"],
                            }
                        ]
                    }
                },
            )
        )
        result = client.scanner.get_issue_definitions()
        assert result["definitions"][0]["name"] == "SQL injection"
