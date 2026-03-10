"""Engagement tools (Pro only)."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class EngagementTools(BaseTools):
    def analyze_target(self, url: str) -> dict[str, Any]:
        return self._call("engagement.analyzeTarget", {"url": url})

    def discover_content(
        self,
        url: str,
        wordlist: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"url": url}
        if wordlist is not None:
            params["wordlist"] = wordlist
        if config is not None:
            params["config"] = config
        return self._call("engagement.discoverContent", params)

    def content_discovery_results(self, task_id: str) -> dict[str, Any]:
        return self._call(
            "engagement.contentDiscoveryResults", {"task_id": task_id}
        )

    def generate_csrf_poc(self, request_id: str) -> dict[str, Any]:
        return self._call("engagement.generateCsrfPoc", {"request_id": request_id})
