"""Tests for the core BurpClient transport layer."""

import httpx
import pytest
import respx

from burp_wrapper.client import BurpAPIError, BurpClient


class TestBurpClientInit:
    def test_default_base_url(self):
        client = BurpClient()
        assert client.base_url == "http://127.0.0.1:9876"

    def test_custom_base_url(self):
        client = BurpClient(base_url="http://localhost:8080")
        assert client.base_url == "http://localhost:8080"

    def test_custom_timeout(self):
        client = BurpClient(timeout=60.0)
        assert client._http.timeout.read == 60.0


class TestBurpClientCall:
    def test_call_sends_post_to_mcp_endpoint(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"data": "ok"}})
        )
        result = client._call("proxy.getHistory", {"limit": 10})
        assert result == {"data": "ok"}

    def test_call_sends_correct_json_rpc_body(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {}})
        )
        client._call("scanner.crawl", {"target": "https://example.com"})

        request = route.calls.last.request
        body = request.content.decode()
        import json

        parsed = json.loads(body)
        assert parsed["method"] == "scanner.crawl"
        assert parsed["params"] == {"target": "https://example.com"}

    def test_call_without_params(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"tasks": []}})
        )
        result = client._call("dashboard.getTasks")

        request = route.calls.last.request
        import json

        parsed = json.loads(request.content.decode())
        assert parsed["params"] == {}
        assert result == {"tasks": []}

    def test_call_raises_on_http_error(self, client, mock_api):
        mock_api.post("/mcp").mock(return_value=httpx.Response(500))
        with pytest.raises(BurpAPIError, match="HTTP 500"):
            client._call("proxy.getHistory")

    def test_call_raises_on_api_error_response(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"error": {"code": -1, "message": "Not found"}}
            )
        )
        with pytest.raises(BurpAPIError, match="Not found"):
            client._call("proxy.getRequest", {"id": "bad"})

    def test_call_raises_on_connection_error(self, client):
        with respx.mock(base_url="http://127.0.0.1:9876") as mock_api:
            mock_api.post("/mcp").mock(side_effect=httpx.ConnectError("Connection refused"))
            with pytest.raises(BurpAPIError, match="Connection"):
                client._call("proxy.getHistory")


class TestBurpClientToolNamespaces:
    def test_has_proxy_namespace(self, client):
        assert hasattr(client, "proxy")

    def test_has_repeater_namespace(self, client):
        assert hasattr(client, "repeater")

    def test_has_intruder_namespace(self, client):
        assert hasattr(client, "intruder")

    def test_has_scanner_namespace(self, client):
        assert hasattr(client, "scanner")

    def test_has_decoder_namespace(self, client):
        assert hasattr(client, "decoder")

    def test_has_collaborator_namespace(self, client):
        assert hasattr(client, "collaborator")

    def test_has_target_namespace(self, client):
        assert hasattr(client, "target")

    def test_has_sequencer_namespace(self, client):
        assert hasattr(client, "sequencer")

    def test_has_comparer_namespace(self, client):
        assert hasattr(client, "comparer")

    def test_has_logger_namespace(self, client):
        assert hasattr(client, "logger")

    def test_has_dashboard_namespace(self, client):
        assert hasattr(client, "dashboard")

    def test_has_organizer_namespace(self, client):
        assert hasattr(client, "organizer")

    def test_has_search_namespace(self, client):
        assert hasattr(client, "search")

    def test_has_inspector_namespace(self, client):
        assert hasattr(client, "inspector")

    def test_has_engagement_namespace(self, client):
        assert hasattr(client, "engagement")

    def test_has_extensions_namespace(self, client):
        assert hasattr(client, "extensions")

    def test_has_config_namespace(self, client):
        assert hasattr(client, "config")

    def test_has_clickbandit_namespace(self, client):
        assert hasattr(client, "clickbandit")

    def test_namespace_instances_are_cached(self, client):
        assert client.proxy is client.proxy
