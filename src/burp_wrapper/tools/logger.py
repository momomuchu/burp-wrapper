"""Logger tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class LoggerTools(BaseTools):
    def query(
        self,
        filters: dict[str, Any] | None = None,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "sort_by": sort_by,
            "sort_order": sort_order,
            "limit": limit,
            "offset": offset,
        }
        if filters is not None:
            params["filters"] = filters
        return self._call("logger.query", params)

    def annotate(
        self,
        request_id: str,
        comment: str | None = None,
        highlight: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"request_id": request_id}
        if comment is not None:
            params["comment"] = comment
        if highlight is not None:
            params["highlight"] = highlight
        return self._call("logger.annotate", params)

    def export(self, request_ids: list[str], format: str) -> dict[str, Any]:
        return self._call(
            "logger.export", {"request_ids": request_ids, "format": format}
        )
