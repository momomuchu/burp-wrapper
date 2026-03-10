"""Clickbandit tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class ClickbanditTools(BaseTools):
    def generate(
        self, url: str, config: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"url": url}
        if config is not None:
            params["config"] = config
        return self._call("clickbandit.generate", params)
