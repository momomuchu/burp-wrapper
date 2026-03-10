"""Dashboard tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class DashboardTools(BaseTools):
    def get_tasks(self) -> dict[str, Any]:
        return self._call("dashboard.getTasks")

    def get_issues_summary(self) -> dict[str, Any]:
        return self._call("dashboard.getIssuesSummary")
