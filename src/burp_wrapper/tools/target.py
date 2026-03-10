"""Target tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class TargetTools(BaseTools):
    def get_sitemap(
        self, root_url: str | None = None, include_responses: bool = False
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"include_responses": include_responses}
        if root_url is not None:
            params["root_url"] = root_url
        return self._call("target.getSitemap", params)

    def get_scope(self) -> dict[str, Any]:
        return self._call("target.getScope")

    def set_scope(
        self,
        include: list[dict[str, Any]],
        exclude: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return self._call(
            "target.setScope",
            {"include": include, "exclude": exclude or []},
        )

    def add_to_scope(self, url: str) -> dict[str, Any]:
        return self._call("target.addToScope", {"url": url})

    def is_in_scope(self, url: str) -> dict[str, Any]:
        return self._call("target.isInScope", {"url": url})

    def get_issues(self, host: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if host is not None:
            params["host"] = host
        return self._call("target.getIssues", params)
