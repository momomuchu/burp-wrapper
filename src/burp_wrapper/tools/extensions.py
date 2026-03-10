"""Extensions tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class ExtensionsTools(BaseTools):
    def list(self) -> dict[str, Any]:
        return self._call("extensions.list")

    def enable(self, name: str) -> dict[str, Any]:
        return self._call("extensions.enable", {"name": name})

    def disable(self, name: str) -> dict[str, Any]:
        return self._call("extensions.disable", {"name": name})

    def reload(self, name: str) -> dict[str, Any]:
        return self._call("extensions.reload", {"name": name})
