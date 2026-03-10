"""Tests for Comparer tools."""

import json

import httpx


class TestComparerDiff:
    def test_diff_by_request_ids(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "similarity_percentage": 85.0,
                        "comparison_mode": "words",
                        "summary": {"total_items": 100, "matching": 85, "added": 5, "removed": 5, "modified": 5},
                        "differences": [
                            {
                                "type": "modified",
                                "position": 10,
                                "item1": "old_value",
                                "item2": "new_value",
                                "context_before": "...",
                                "context_after": "...",
                            }
                        ],
                        "highlighted_text1": "...",
                        "highlighted_text2": "...",
                    }
                },
            )
        )
        result = client.comparer.diff(request_id_1="req-1", request_id_2="req-2")
        assert result["similarity_percentage"] == 85.0
        assert result["summary"]["modified"] == 5

    def test_diff_by_raw_text(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "similarity_percentage": 100.0,
                        "comparison_mode": "words",
                        "summary": {"total_items": 1, "matching": 1, "added": 0, "removed": 0, "modified": 0},
                        "differences": [],
                        "highlighted_text1": "same",
                        "highlighted_text2": "same",
                    }
                },
            )
        )
        result = client.comparer.diff(text1="same", text2="same")
        assert result["similarity_percentage"] == 100.0

    def test_diff_with_options(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "similarity_percentage": 90.0,
                        "comparison_mode": "bytes",
                        "summary": {"total_items": 50, "matching": 45, "added": 2, "removed": 2, "modified": 1},
                        "differences": [],
                        "highlighted_text1": "",
                        "highlighted_text2": "",
                    }
                },
            )
        )
        client.comparer.diff(
            request_id_1="req-1",
            request_id_2="req-2",
            options={"compare": "response", "mode": "bytes", "ignore_whitespace": True},
        )
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["options"]["mode"] == "bytes"


class TestComparerDiffResponses:
    def test_diff_multiple_responses(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "comparisons": [
                            {"pair": ["req-1", "req-2"], "similarity": 95.0, "key_differences": ["Content-Length"]},
                            {"pair": ["req-1", "req-3"], "similarity": 70.0, "key_differences": ["body content"]},
                        ],
                        "common_content": "HTTP/1.1 200 OK",
                        "unique_per_request": {"req-1": ["x-custom: 1"], "req-2": ["x-custom: 2"], "req-3": ["x-custom: 3"]},
                    }
                },
            )
        )
        result = client.comparer.diff_responses(["req-1", "req-2", "req-3"])
        assert len(result["comparisons"]) == 2
