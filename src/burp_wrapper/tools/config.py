"""Project & Config tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class ConfigTools(BaseTools):
    def get_project(self) -> dict[str, Any]:
        return self._call("config.getProject")

    def get_user(self) -> dict[str, Any]:
        return self._call("config.getUser")

    def export_project(self) -> dict[str, Any]:
        return self._call("config.exportProject")

    def import_project(self, json_config: str) -> dict[str, Any]:
        return self._call("config.importProject", {"json_config": json_config})
