"""Inspector tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class InspectorTools(BaseTools):
    def parse_request(self, raw_request: str) -> dict[str, Any]:
        return self._call("inspector.parseRequest", {"raw_request": raw_request})

    def parse_response(self, raw_response: str) -> dict[str, Any]:
        return self._call("inspector.parseResponse", {"raw_response": raw_response})

    def build_request(
        self,
        method: str,
        path: str,
        host: str,
        headers: list[dict[str, str]] | None = None,
        body: str = "",
    ) -> dict[str, Any]:
        return self._call(
            "inspector.buildRequest",
            {
                "method": method,
                "path": path,
                "host": host,
                "headers": headers or [],
                "body": body,
            },
        )
