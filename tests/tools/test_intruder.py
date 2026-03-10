"""Tests for Intruder tools."""

import json

import httpx


class TestIntruderCreateAttack:
    def test_create_sniper_attack(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "attack_id": "atk-1",
                        "total_requests": 100,
                        "estimated_time_seconds": 20,
                    }
                },
            )
        )
        result = client.intruder.create_attack(
            request_id="req-1",
            attack_type="sniper",
            positions=[{"param_name": "username", "param_type": "body"}],
            payloads=[{"position_index": 0, "type": "simple_list", "values": ["admin", "test"]}],
        )
        assert result["attack_id"] == "atk-1"
        assert result["total_requests"] == 100


class TestIntruderStart:
    def test_start_attack(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"status": "started", "attack_id": "atk-1"}}
            )
        )
        result = client.intruder.start("atk-1")
        assert result["status"] == "started"


class TestIntruderQuickFuzz:
    def test_quick_fuzz_returns_results(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "results": [
                            {
                                "index": 0,
                                "payload": "admin",
                                "status_code": 200,
                                "response_length": 500,
                                "response_time_ms": 50,
                                "grep_matches": [],
                                "error": None,
                            },
                            {
                                "index": 1,
                                "payload": "' OR 1=1--",
                                "status_code": 500,
                                "response_length": 1200,
                                "response_time_ms": 200,
                                "grep_matches": ["SQL syntax"],
                                "error": None,
                            },
                        ],
                        "statistics": {
                            "total": 2,
                            "by_status": {"200": 1, "500": 1},
                            "anomalies": 1,
                            "errors": 0,
                        },
                    }
                },
            )
        )
        result = client.intruder.quick_fuzz(
            request_id="req-1",
            param_name="username",
            payloads=["admin", "' OR 1=1--"],
        )
        assert result["statistics"]["anomalies"] == 1
        assert result["results"][1]["grep_matches"] == ["SQL syntax"]

    def test_quick_fuzz_passes_concurrent(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"results": [], "statistics": {"total": 0, "by_status": {}, "anomalies": 0, "errors": 0}}},
            )
        )
        client.intruder.quick_fuzz("req-1", "id", ["1", "2"], concurrent=10)
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["concurrent"] == 10


class TestIntruderStatus:
    def test_status_running(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "status": "running",
                        "progress": {"current": 50, "total": 100, "percentage": 50.0},
                        "speed": {"requests_per_second": 10.0, "elapsed_seconds": 5, "eta_seconds": 5},
                        "issues_found": 0,
                    }
                },
            )
        )
        result = client.intruder.status("atk-1")
        assert result["status"] == "running"
        assert result["progress"]["percentage"] == 50.0


class TestIntruderResults:
    def test_results_with_filters(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "total": 1,
                        "results": [
                            {
                                "index": 0,
                                "payload": "test",
                                "status_code": 200,
                                "response_length": 500,
                                "response_time_ms": 50,
                                "grep_matches": [],
                                "grep_extracts": {},
                                "is_anomaly": False,
                                "error": None,
                                "request_id": "req-100",
                            }
                        ],
                        "statistics": {
                            "total_requests": 1,
                            "completed": 1,
                            "errors": 0,
                            "by_status_code": {"200": 1},
                            "avg_response_time_ms": 50.0,
                            "avg_response_length": 500.0,
                            "length_std_dev": 0.0,
                        },
                    }
                },
            )
        )
        result = client.intruder.results("atk-1", filters={"anomaly_only": True})
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["filters"]["anomaly_only"] is True
        assert result["total"] == 1


class TestIntruderControl:
    def test_pause(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.intruder.pause("atk-1")["success"] is True

    def test_resume(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.intruder.resume("atk-1")["success"] is True

    def test_stop(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"success": True, "requests_completed": 50}}
            )
        )
        result = client.intruder.stop("atk-1")
        assert result["requests_completed"] == 50
