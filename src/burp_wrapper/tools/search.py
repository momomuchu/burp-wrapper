"""Search tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class SearchTools(BaseTools):
    def find(
        self,
        query: str,
        scope: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"query": query, "limit": limit}
        if scope is not None:
            params["scope"] = scope
        return self._call("search.find", params)
