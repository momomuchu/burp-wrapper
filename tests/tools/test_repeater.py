"""Tests for Repeater tools."""

import json

import httpx


class TestRepeaterSend:
    def test_send_by_request_id(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "request_sent": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "response": {
                            "raw": "HTTP/1.1 200 OK\r\n\r\n",
                            "status_code": 200,
                            "headers": [],
                            "body": "OK",
                            "length": 2,
                        },
                        "timing": {
                            "request_time": "2025-01-01T00:00:00Z",
                            "response_time": "2025-01-01T00:00:01Z",
                            "duration_ms": 500,
                        },
                        "new_request_id": "req-2",
                    }
                },
            )
        )
        result = client.repeater.send(request_id="req-1")
        assert result["response"]["status_code"] == 200
        assert result["new_request_id"] == "req-2"

    def test_send_raw_request(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "request_sent": "GET / HTTP/1.1\r\n",
                        "response": {"raw": "", "status_code": 200, "headers": [], "body": "", "length": 0},
                        "timing": {"request_time": "", "response_time": "", "duration_ms": 100},
                        "new_request_id": "req-3",
                    }
                },
            )
        )
        client.repeater.send(
            raw_request="GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
            host="test.com",
            port=443,
            https=True,
        )
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["raw_request"] == "GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        assert body["params"]["host"] == "test.com"
        assert body["params"]["port"] == 443

    def test_send_with_follow_redirects(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "request_sent": "",
                        "response": {"raw": "", "status_code": 302, "headers": [], "body": "", "length": 0},
                        "timing": {"request_time": "", "response_time": "", "duration_ms": 0},
                        "new_request_id": "req-4",
                    }
                },
            )
        )
        client.repeater.send(request_id="req-1", follow_redirects=True)
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["follow_redirects"] is True


class TestRepeaterSendModified:
    def test_send_with_modifications(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "request_sent": "",
                        "response": {"raw": "", "status_code": 200, "headers": [], "body": "", "length": 0},
                        "timing": {"request_time": "", "response_time": "", "duration_ms": 0},
                        "new_request_id": "req-5",
                    }
                },
            )
        )
        client.repeater.send_modified(
            request_id="req-1",
            modifications={
                "headers": {"Authorization": "Bearer token123"},
                "method": "POST",
                "body": '{"key": "value"}',
            },
        )
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["request_id"] == "req-1"
        assert body["params"]["modifications"]["method"] == "POST"


class TestRepeaterSendBatch:
    def test_send_batch_variations(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "results": [
                            {
                                "variation_name": "admin",
                                "response": {"raw": "", "status_code": 403, "headers": [], "body": "", "length": 0},
                                "duration_ms": 100,
                                "new_request_id": "req-10",
                            },
                            {
                                "variation_name": "user",
                                "response": {"raw": "", "status_code": 200, "headers": [], "body": "", "length": 0},
                                "duration_ms": 80,
                                "new_request_id": "req-11",
                            },
                        ]
                    }
                },
            )
        )
        result = client.repeater.send_batch(
            request_id="req-1",
            variations=[
                {"name": "admin", "modifications": {"headers": {"X-Role": "admin"}}},
                {"name": "user", "modifications": {"headers": {"X-Role": "user"}}},
            ],
        )
        assert len(result["results"]) == 2
        assert result["results"][0]["variation_name"] == "admin"
        assert result["results"][1]["response"]["status_code"] == 200


class TestRepeaterCreateTab:
    def test_create_tab(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"tab_id": "tab-1", "success": True}}
            )
        )
        result = client.repeater.create_tab("req-1", name="Login Test")
        assert result["tab_id"] == "tab-1"
        assert result["success"] is True
