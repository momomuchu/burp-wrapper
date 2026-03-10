"""Tests for Logger tools."""

import json

import httpx


class TestLoggerQuery:
    def test_query_with_filters(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "total": 1,
                        "entries": [
                            {
                                "id": "log-1",
                                "tool": "proxy",
                                "timestamp": "2025-01-01T00:00:00Z",
                                "method": "GET",
                                "url": "https://example.com/",
                                "host": "example.com",
                                "status_code": 200,
                                "response_length": 1234,
                                "mime_type": "text/html",
                                "comment": "",
                                "highlight": "none",
                            }
                        ],
                    }
                },
            )
        )
        result = client.logger.query(
            filters={"tools": ["proxy"], "hosts": ["example.com"], "in_scope_only": True},
            limit=50,
        )
        assert result["total"] == 1
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["filters"]["tools"] == ["proxy"]


class TestLoggerAnnotate:
    def test_annotate(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        result = client.logger.annotate("req-1", comment="Interesting", highlight="red")
        assert result["success"] is True


class TestLoggerExport:
    def test_export_as_curl(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"data": "curl -X GET https://example.com/"}}
            )
        )
        result = client.logger.export(["req-1"], format="curl")
        assert "curl" in result["data"]
