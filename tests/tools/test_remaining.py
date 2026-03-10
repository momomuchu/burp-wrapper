"""Tests for remaining tools: Organizer, Search, Inspector, Engagement, Extensions, Config, Clickbandit."""

import json

import httpx

# --- ORGANIZER ---

class TestOrganizer:
    def test_add(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"organizer_id": "org-1"}})
        )
        result = client.organizer.add("req-1", collection="auth")
        assert result["organizer_id"] == "org-1"

    def test_list(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "items": [
                            {
                                "id": "org-1",
                                "request_id": "req-1",
                                "url": "https://example.com/",
                                "method": "GET",
                                "collection": "auth",
                                "notes": "",
                                "timestamp_added": "2025-01-01T00:00:00Z",
                            }
                        ]
                    }
                },
            )
        )
        result = client.organizer.list()
        assert len(result["items"]) == 1

    def test_annotate(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.organizer.annotate("org-1", "Needs review")["success"] is True

    def test_get_collections(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"collections": ["auth", "api"]}})
        )
        result = client.organizer.get_collections()
        assert "auth" in result["collections"]

    def test_create_collection(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.organizer.create_collection("payments")["success"] is True


# --- SEARCH ---

class TestSearch:
    def test_find(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "total_matches": 2,
                        "results": [
                            {
                                "tool": "proxy",
                                "request_id": "req-1",
                                "url": "https://example.com/api",
                                "match_location": "response_body",
                                "match_context": "...password: secret123...",
                                "match_position": {"start": 50, "end": 63},
                            }
                        ],
                    }
                },
            )
        )
        result = client.search.find("password")
        assert result["total_matches"] == 2

    def test_find_with_scope(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"total_matches": 0, "results": []}})
        )
        client.search.find("token", scope={"tools": ["proxy"], "is_regex": False})
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["scope"]["tools"] == ["proxy"]


# --- INSPECTOR ---

class TestInspector:
    def test_parse_request(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "method": "POST",
                        "path": "/login",
                        "http_version": "HTTP/1.1",
                        "headers": [{"name": "Host", "value": "example.com"}],
                        "cookies": [],
                        "body": "user=admin&pass=test",
                        "content_type": "application/x-www-form-urlencoded",
                        "parameters": {
                            "query": [],
                            "body": [{"name": "user", "value": "admin"}, {"name": "pass", "value": "test"}],
                            "json": None,
                            "xml": None,
                        },
                        "attributes": {"has_body": True, "is_json": False, "is_xml": False, "is_multipart": False},
                    }
                },
            )
        )
        result = client.inspector.parse_request("POST /login HTTP/1.1\r\n...")
        assert result["method"] == "POST"
        assert len(result["parameters"]["body"]) == 2

    def test_parse_response(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "status_code": 200,
                        "status_text": "OK",
                        "http_version": "HTTP/1.1",
                        "headers": [],
                        "cookies_set": [],
                        "body": "{}",
                        "content_type": "application/json",
                        "attributes": {"is_json": True, "is_html": False, "is_xml": False, "is_binary": False, "encoding": "utf-8", "length": 2},
                    }
                },
            )
        )
        result = client.inspector.parse_response("HTTP/1.1 200 OK\r\n...")
        assert result["status_code"] == 200
        assert result["attributes"]["is_json"] is True

    def test_build_request(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}},
            )
        )
        result = client.inspector.build_request(
            method="GET", path="/", host="example.com", headers=[], body=""
        )
        assert "GET / HTTP/1.1" in result["raw_request"]


# --- ENGAGEMENT ---

class TestEngagement:
    def test_analyze_target(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "summary": {"total_links": 50, "total_forms": 3, "total_params": 10, "static_urls": 30, "dynamic_urls": 20},
                        "parameters": [{"name": "id", "type": "url", "url_count": 5, "values_seen": ["1", "2"]}],
                        "forms": [{"action": "/login", "method": "POST", "fields": ["username", "password"]}],
                    }
                },
            )
        )
        result = client.engagement.analyze_target("https://example.com")
        assert result["summary"]["total_forms"] == 3

    def test_discover_content(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"task_id": "disc-1"}})
        )
        result = client.engagement.discover_content("https://example.com")
        assert result["task_id"] == "disc-1"

    def test_content_discovery_results(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "status": "completed",
                        "discovered": [
                            {"url": "https://example.com/admin", "status_code": 200, "response_length": 1000, "content_type": "text/html"}
                        ],
                    }
                },
            )
        )
        result = client.engagement.content_discovery_results("disc-1")
        assert result["status"] == "completed"
        assert len(result["discovered"]) == 1

    def test_generate_csrf_poc(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"html": "<html><form>...</form></html>", "auto_submit": True}},
            )
        )
        result = client.engagement.generate_csrf_poc("req-1")
        assert "<form>" in result["html"]


# --- EXTENSIONS ---

class TestExtensions:
    def test_list(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "extensions": [
                            {"name": "Logger++", "enabled": True, "type": "java", "filename": "logger.jar", "errors": []}
                        ]
                    }
                },
            )
        )
        result = client.extensions.list()
        assert len(result["extensions"]) == 1

    def test_enable(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.extensions.enable("Logger++")["success"] is True

    def test_disable(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.extensions.disable("Logger++")["success"] is True

    def test_reload(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.extensions.reload("Logger++")["success"] is True


# --- CONFIG ---

class TestConfig:
    def test_get_project(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"project_name": "Test", "project_file": "/tmp/test.burp", "config": {}}},
            )
        )
        result = client.config.get_project()
        assert result["project_name"] == "Test"

    def test_get_user(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"config": {"theme": "dark"}}})
        )
        result = client.config.get_user()
        assert result["config"]["theme"] == "dark"

    def test_export_project(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"json": "{}"}})
        )
        result = client.config.export_project()
        assert result["json"] == "{}"

    def test_import_project(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"success": True}})
        )
        assert client.config.import_project("{}")["success"] is True


# --- CLICKBANDIT ---

class TestClickbandit:
    def test_generate(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"html": "<html>...</html>", "interactive": True}},
            )
        )
        result = client.clickbandit.generate("https://example.com/settings")
        assert "<html>" in result["html"]
        assert result["interactive"] is True
