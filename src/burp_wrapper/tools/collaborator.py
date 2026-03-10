"""Collaborator tools (Pro only)."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class CollaboratorTools(BaseTools):
    def generate_payload(self) -> dict[str, Any]:
        return self._call("collaborator.generatePayload")

    def generate_payloads(self, count: int) -> dict[str, Any]:
        return self._call("collaborator.generatePayloads", {"count": count})

    def poll(self, interaction_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if interaction_id is not None:
            params["interaction_id"] = interaction_id
        return self._call("collaborator.poll", params)

    def poll_until(
        self, interaction_id: str, timeout_seconds: int = 30
    ) -> dict[str, Any]:
        return self._call(
            "collaborator.pollUntil",
            {"interaction_id": interaction_id, "timeout_seconds": timeout_seconds},
        )
