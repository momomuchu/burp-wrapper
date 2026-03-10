"""Scanner tools (Pro only)."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class ScannerTools(BaseTools):
    def crawl(
        self,
        target: str | list[str],
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"target": target}
        if config is not None:
            params["config"] = config
        return self._call("scanner.crawl", params)

    def audit(
        self,
        target: str | list[str] | None = None,
        request_id: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if target is not None:
            params["target"] = target
        if request_id is not None:
            params["request_id"] = request_id
        if config is not None:
            params["config"] = config
        return self._call("scanner.audit", params)

    def crawl_and_audit(
        self,
        target: str | list[str],
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"target": target}
        if config is not None:
            params["config"] = config
        return self._call("scanner.crawlAndAudit", params)

    def status(self, scan_id: str) -> dict[str, Any]:
        return self._call("scanner.status", {"scan_id": scan_id})

    def issues(
        self,
        scan_id: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if scan_id is not None:
            params["scan_id"] = scan_id
        if filters is not None:
            params["filters"] = filters
        return self._call("scanner.issues", params)

    def pause(self, scan_id: str) -> dict[str, Any]:
        return self._call("scanner.pause", {"scan_id": scan_id})

    def resume(self, scan_id: str) -> dict[str, Any]:
        return self._call("scanner.resume", {"scan_id": scan_id})

    def stop(self, scan_id: str) -> dict[str, Any]:
        return self._call("scanner.stop", {"scan_id": scan_id})

    def get_issue_definitions(self) -> dict[str, Any]:
        return self._call("scanner.getIssueDefinitions")
