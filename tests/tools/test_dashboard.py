"""Tests for Dashboard tools."""

import httpx


class TestDashboardTasks:
    def test_get_tasks(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "tasks": [
                            {
                                "id": "task-1",
                                "type": "scan",
                                "status": "running",
                                "target": "https://example.com",
                                "progress": 50.0,
                                "issues_found": 3,
                                "start_time": "2025-01-01T00:00:00Z",
                            }
                        ]
                    }
                },
            )
        )
        result = client.dashboard.get_tasks()
        assert len(result["tasks"]) == 1
        assert result["tasks"][0]["progress"] == 50.0


class TestDashboardIssuesSummary:
    def test_get_issues_summary(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "total": 10,
                        "by_severity": {"high": 2, "medium": 3, "low": 3, "info": 2},
                        "by_confidence": {"certain": 5, "firm": 3, "tentative": 2},
                        "recent": [{"name": "SQL injection", "url": "https://example.com/login", "severity": "high", "timestamp": "2025-01-01"}],
                    }
                },
            )
        )
        result = client.dashboard.get_issues_summary()
        assert result["total"] == 10
        assert result["by_severity"]["high"] == 2
