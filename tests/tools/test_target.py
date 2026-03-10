"""Tests for Target tools."""

import json

import httpx


class TestTargetSitemap:
    def test_get_sitemap(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "hosts": [
                            {
                                "host": "example.com",
                                "port": 443,
                                "protocol": "https",
                                "in_scope": True,
                                "items": [
                                    {
                                        "url": "https://example.com/",
                                        "method": "GET",
                                        "status_code": 200,
                                        "mime_type": "text/html",
                                        "has_response": True,
                                        "response_length": 5000,
                                        "issue_count": 0,
                                        "request_id": "req-1",
                                    }
                                ],
                            }
                        ]
                    }
                },
            )
        )
        result = client.target.get_sitemap()
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["host"] == "example.com"

    def test_get_sitemap_filtered(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"hosts": []}})
        )
        client.target.get_sitemap(root_url="https://example.com")
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["root_url"] == "https://example.com"


class TestTargetScope:
    def test_get_scope(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "include": [
                            {"enabled": True, "protocol": "any", "host": "example\\.com", "port": "any", "file": ".*"}
                        ],
                        "exclude": [],
                    }
                },
            )
        )
        result = client.target.get_scope()
        assert len(result["include"]) == 1

    def test_set_scope(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        result = client.target.set_scope(
            include=[{"enabled": True, "protocol": "https", "host": "target\\.com", "port": "443", "file": ".*"}],
            exclude=[],
        )
        assert result["success"] is True

    def test_add_to_scope(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        result = client.target.add_to_scope("https://target.com")
        assert result["success"] is True

    def test_is_in_scope(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"in_scope": True}})
        )
        result = client.target.is_in_scope("https://example.com/login")
        assert result["in_scope"] is True


class TestTargetIssues:
    def test_get_issues(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"issues": []}})
        )
        result = client.target.get_issues(host="example.com")
        assert result["issues"] == []
