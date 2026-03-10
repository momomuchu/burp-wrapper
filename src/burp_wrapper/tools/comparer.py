"""Comparer tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class ComparerTools(BaseTools):
    def diff(
        self,
        request_id_1: str | None = None,
        request_id_2: str | None = None,
        text1: str | None = None,
        text2: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if request_id_1 is not None:
            params["request_id_1"] = request_id_1
        if request_id_2 is not None:
            params["request_id_2"] = request_id_2
        if text1 is not None:
            params["text1"] = text1
        if text2 is not None:
            params["text2"] = text2
        if options is not None:
            params["options"] = options
        return self._call("comparer.diff", params)

    def diff_responses(self, request_ids: list[str]) -> dict[str, Any]:
        return self._call("comparer.diffResponses", {"request_ids": request_ids})
