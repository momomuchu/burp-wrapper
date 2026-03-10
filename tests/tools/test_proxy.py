"""Tests for Proxy tools."""

import httpx


class TestProxyGetHistory:
    def test_returns_entries(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "total": 1,
                        "entries": [
                            {
                                "id": "req-1",
                                "index": 0,
                                "timestamp": "2025-01-01T00:00:00Z",
                                "method": "GET",
                                "url": "https://example.com/",
                                "host": "example.com",
                                "path": "/",
                                "status_code": 200,
                                "response_length": 1234,
                                "mime_type": "text/html",
                                "extension": "html",
                                "has_params": False,
                                "param_count": 0,
                                "in_scope": True,
                                "comment": "",
                                "highlight": "none",
                            }
                        ],
                    }
                },
            )
        )
        result = client.proxy.get_history(limit=10)
        assert result["total"] == 1
        assert result["entries"][0]["id"] == "req-1"
        assert result["entries"][0]["method"] == "GET"

    def test_passes_filters(self, client, mock_api):
        import json

        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"total": 0, "entries": []}})
        )
        client.proxy.get_history(
            limit=50,
            offset=10,
            filter_host="target.com",
            filter_method="POST",
            in_scope_only=True,
        )
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["limit"] == 50
        assert body["params"]["offset"] == 10
        assert body["params"]["filter_host"] == "target.com"
        assert body["params"]["filter_method"] == "POST"
        assert body["params"]["in_scope_only"] is True

    def test_default_limit(self, client, mock_api):
        import json

        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"total": 0, "entries": []}})
        )
        client.proxy.get_history()
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["limit"] == 100


class TestProxyGetRequest:
    def test_returns_full_request_detail(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "id": "req-1",
                        "request": {
                            "raw": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "method": "GET",
                            "url": "https://example.com/",
                            "path": "/",
                            "http_version": "HTTP/1.1",
                            "headers": [{"name": "Host", "value": "example.com"}],
                            "cookies": [],
                            "body": "",
                            "body_base64": "",
                            "content_type": "",
                            "parameters": [],
                        },
                        "response": {
                            "raw": "HTTP/1.1 200 OK\r\n\r\n",
                            "status_code": 200,
                            "status_text": "OK",
                            "http_version": "HTTP/1.1",
                            "headers": [],
                            "cookies_set": [],
                            "body": "<html></html>",
                            "body_base64": "",
                            "mime_type": "text/html",
                            "length": 13,
                        },
                        "timing": {
                            "request_time": "2025-01-01T00:00:00Z",
                            "response_time": "2025-01-01T00:00:01Z",
                            "duration_ms": 1000,
                        },
                    }
                },
            )
        )
        result = client.proxy.get_request("req-1")
        assert result["id"] == "req-1"
        assert result["request"]["method"] == "GET"
        assert result["response"]["status_code"] == 200
        assert result["timing"]["duration_ms"] == 1000


class TestProxyWebSocket:
    def test_get_websocket_history(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "total": 1,
                        "connections": [
                            {
                                "id": "ws-1",
                                "url": "wss://example.com/ws",
                                "status": "closed",
                                "message_count": 2,
                                "messages": [],
                            }
                        ],
                    }
                },
            )
        )
        result = client.proxy.get_websocket_history()
        assert result["total"] == 1
        assert result["connections"][0]["url"] == "wss://example.com/ws"


class TestProxyIntercept:
    def test_toggle_on(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"intercept_enabled": True}})
        )
        result = client.proxy.intercept_toggle(True)
        assert result["intercept_enabled"] is True

    def test_toggle_off(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"intercept_enabled": False}})
        )
        result = client.proxy.intercept_toggle(False)
        assert result["intercept_enabled"] is False

    def test_get_intercepted_message(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "has_message": True,
                        "message": {
                            "id": "msg-1",
                            "type": "request",
                            "raw": "GET / HTTP/1.1\r\n",
                            "host": "example.com",
                            "method": "GET",
                            "url": "https://example.com/",
                        },
                    }
                },
            )
        )
        result = client.proxy.intercept_get_message()
        assert result["has_message"] is True
        assert result["message"]["id"] == "msg-1"

    def test_forward_message(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        result = client.proxy.intercept_forward("msg-1")
        assert result["success"] is True

    def test_forward_modified_message(self, client, mock_api):
        import json

        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        client.proxy.intercept_forward("msg-1", modified_raw="GET /admin HTTP/1.1\r\n")
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["modified_raw"] == "GET /admin HTTP/1.1\r\n"

    def test_drop_message(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        result = client.proxy.intercept_drop("msg-1")
        assert result["success"] is True


class TestProxyMatchReplace:
    def test_add_rule(self, client, mock_api):
        import json

        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"rule_id": "rule-1", "success": True}}
            )
        )
        result = client.proxy.add_match_replace_rule(
            enabled=True,
            rule_type="request_header",
            match="User-Agent: .*",
            replace="User-Agent: BurpBot",
            is_regex=True,
            comment="Override UA",
        )
        assert result["rule_id"] == "rule-1"
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["rule"]["is_regex"] is True
