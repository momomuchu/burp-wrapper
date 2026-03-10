"""Repeater tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class RepeaterTools(BaseTools):
    def send(
        self,
        request_id: str | None = None,
        raw_request: str | None = None,
        host: str | None = None,
        port: int = 443,
        https: bool = True,
        follow_redirects: bool = False,
        timeout_ms: int = 30000,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "follow_redirects": follow_redirects,
            "timeout_ms": timeout_ms,
        }
        if request_id is not None:
            params["request_id"] = request_id
        if raw_request is not None:
            params["raw_request"] = raw_request
            params["host"] = host
            params["port"] = port
            params["https"] = https
        return self._call("repeater.send", params)

    def send_modified(
        self,
        request_id: str,
        modifications: dict[str, Any],
        follow_redirects: bool = False,
    ) -> dict[str, Any]:
        return self._call(
            "repeater.sendModified",
            {
                "request_id": request_id,
                "modifications": modifications,
                "follow_redirects": follow_redirects,
            },
        )

    def send_batch(
        self,
        request_id: str,
        variations: list[dict[str, Any]],
        parallel: bool = False,
        delay_ms: int = 0,
    ) -> dict[str, Any]:
        return self._call(
            "repeater.sendBatch",
            {
                "request_id": request_id,
                "variations": variations,
                "parallel": parallel,
                "delay_ms": delay_ms,
            },
        )

    def create_tab(self, request_id: str, name: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"request_id": request_id}
        if name is not None:
            params["name"] = name
        return self._call("repeater.createTab", params)
