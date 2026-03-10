"""Tests for Collaborator tools (Pro only)."""

import json

import httpx


class TestCollaboratorGeneratePayload:
    def test_generate_single_payload(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "payload": "abc123.oastify.com",
                        "interaction_id": "int-1",
                        "polling_location": "https://polling.oastify.com/...",
                    }
                },
            )
        )
        result = client.collaborator.generate_payload()
        assert "oastify.com" in result["payload"]
        assert result["interaction_id"] == "int-1"

    def test_generate_multiple_payloads(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "payloads": [
                            {"payload": "a.oastify.com", "interaction_id": "int-1"},
                            {"payload": "b.oastify.com", "interaction_id": "int-2"},
                            {"payload": "c.oastify.com", "interaction_id": "int-3"},
                        ]
                    }
                },
            )
        )
        result = client.collaborator.generate_payloads(3)
        assert len(result["payloads"]) == 3


class TestCollaboratorPoll:
    def test_poll_all(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "interactions": [
                            {
                                "interaction_id": "int-1",
                                "type": "dns",
                                "timestamp": "2025-01-01T00:00:00Z",
                                "client_ip": "1.2.3.4",
                                "protocol": "dns",
                                "query_type": "A",
                                "query_domain": "abc123.oastify.com",
                            }
                        ]
                    }
                },
            )
        )
        result = client.collaborator.poll()
        assert len(result["interactions"]) == 1
        assert result["interactions"][0]["type"] == "dns"

    def test_poll_specific_interaction(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"interactions": []}}
            )
        )
        client.collaborator.poll(interaction_id="int-1")
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["interaction_id"] == "int-1"


class TestCollaboratorPollUntil:
    def test_poll_until_found(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "found": True,
                        "interaction": {
                            "interaction_id": "int-1",
                            "type": "http",
                            "timestamp": "2025-01-01T00:00:00Z",
                            "client_ip": "1.2.3.4",
                            "protocol": "http",
                            "request": "GET / HTTP/1.1",
                            "response": "HTTP/1.1 200 OK",
                        },
                        "elapsed_seconds": 5,
                    }
                },
            )
        )
        result = client.collaborator.poll_until("int-1", timeout_seconds=30)
        assert result["found"] is True
        assert result["interaction"]["type"] == "http"

    def test_poll_until_timeout(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"found": False, "interaction": None, "elapsed_seconds": 30}},
            )
        )
        result = client.collaborator.poll_until("int-1", timeout_seconds=30)
        assert result["found"] is False
